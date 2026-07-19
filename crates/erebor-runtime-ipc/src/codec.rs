use std::io::{ErrorKind, Read, Write};

use snafu::ResultExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    error::{EndOfStreamSnafu, IoSnafu, PayloadTooLargeSnafu, TruncatedFrameSnafu},
    EreborIpcFrame, Result, HEADER_LEN, MAX_PAYLOAD_LEN,
};

/// Bounded synchronous `ERB1` frame I/O for ordinary Unix and test streams.
pub struct SyncFrameCodec;

impl SyncFrameCodec {
    pub fn read_frame(reader: &mut impl Read) -> Result<EreborIpcFrame> {
        let mut header = [0_u8; HEADER_LEN];
        let read = reader.read(&mut header).context(IoSnafu)?;
        if read == 0 {
            return EndOfStreamSnafu.fail();
        }
        Self::read_remaining(reader, &mut header[read..])?;

        let payload_len = Self::payload_len(&header)?;
        let mut encoded = header.to_vec();
        encoded.resize(HEADER_LEN + payload_len, 0);
        Self::read_remaining(reader, &mut encoded[HEADER_LEN..])?;
        EreborIpcFrame::decode(&encoded)
    }

    pub fn write_frame(writer: &mut impl Write, frame: &EreborIpcFrame) -> Result<()> {
        writer.write_all(&frame.encode()?).context(IoSnafu)
    }

    fn payload_len(header: &[u8; HEADER_LEN]) -> Result<usize> {
        let payload_len =
            u32::from_le_bytes([header[8], header[9], header[10], header[11]]) as usize;
        if payload_len > MAX_PAYLOAD_LEN {
            return PayloadTooLargeSnafu {
                actual: payload_len,
                maximum: MAX_PAYLOAD_LEN,
            }
            .fail();
        }
        Ok(payload_len)
    }

    fn read_remaining(reader: &mut impl Read, destination: &mut [u8]) -> Result<()> {
        reader.read_exact(destination).map_err(|source| {
            if source.kind() == ErrorKind::UnexpectedEof {
                TruncatedFrameSnafu.build()
            } else {
                crate::IpcProtocolError::Io {
                    source,
                    location: snafu::Location::default(),
                }
            }
        })
    }
}

/// Bounded asynchronous `ERB1` frame I/O for daemon and client transports.
pub struct AsyncFrameCodec;

impl AsyncFrameCodec {
    pub async fn read_frame(reader: &mut (impl AsyncRead + Unpin)) -> Result<EreborIpcFrame> {
        let mut header = [0_u8; HEADER_LEN];
        let read = reader.read(&mut header).await.context(IoSnafu)?;
        if read == 0 {
            return EndOfStreamSnafu.fail();
        }
        Self::read_remaining(reader, &mut header[read..]).await?;

        let payload_len = SyncFrameCodec::payload_len(&header)?;
        let mut encoded = header.to_vec();
        encoded.resize(HEADER_LEN + payload_len, 0);
        Self::read_remaining(reader, &mut encoded[HEADER_LEN..]).await?;
        EreborIpcFrame::decode(&encoded)
    }

    pub async fn write_frame(
        writer: &mut (impl AsyncWrite + Unpin),
        frame: &EreborIpcFrame,
    ) -> Result<()> {
        writer.write_all(&frame.encode()?).await.context(IoSnafu)
    }

    async fn read_remaining(
        reader: &mut (impl AsyncRead + Unpin),
        destination: &mut [u8],
    ) -> Result<()> {
        reader
            .read_exact(destination)
            .await
            .map(|_read| ())
            .map_err(|source| {
                if source.kind() == ErrorKind::UnexpectedEof {
                    TruncatedFrameSnafu.build()
                } else {
                    crate::IpcProtocolError::Io {
                        source,
                        location: snafu::Location::default(),
                    }
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor};

    use crate::{EreborIpcFrame, IpcProtocolError};

    use super::{AsyncFrameCodec, SyncFrameCodec};

    #[test]
    fn synchronous_codec_handles_fragmented_frames_and_clean_eof(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let frame = EreborIpcFrame::new(0, b"payload".to_vec())?;
        let encoded = frame.encode()?;
        let mut reader = FragmentedReader::new(encoded, 2);
        assert_eq!(SyncFrameCodec::read_frame(&mut reader)?, frame);
        assert!(matches!(
            SyncFrameCodec::read_frame(&mut reader),
            Err(IpcProtocolError::EndOfStream { .. })
        ));
        Ok(())
    }

    #[test]
    fn synchronous_codec_rejects_oversized_payload_before_allocation() {
        let mut header = Vec::from(crate::MAGIC);
        header.extend_from_slice(&crate::FRAME_VERSION.to_le_bytes());
        header.extend_from_slice(&0_u16.to_le_bytes());
        header.extend_from_slice(&((crate::MAX_PAYLOAD_LEN + 1) as u32).to_le_bytes());
        let mut reader = Cursor::new(header);
        assert!(matches!(
            SyncFrameCodec::read_frame(&mut reader),
            Err(IpcProtocolError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn synchronous_codec_distinguishes_partial_frame_eof() {
        let mut reader = Cursor::new(Vec::from(crate::MAGIC));
        assert!(matches!(
            SyncFrameCodec::read_frame(&mut reader),
            Err(IpcProtocolError::TruncatedFrame { .. })
        ));
    }

    struct FragmentedReader {
        source: Cursor<Vec<u8>>,
        maximum_read: usize,
    }

    impl FragmentedReader {
        fn new(source: Vec<u8>, maximum_read: usize) -> Self {
            Self {
                source: Cursor::new(source),
                maximum_read,
            }
        }
    }

    impl io::Read for FragmentedReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let limit = buffer.len().min(self.maximum_read);
            self.source.read(&mut buffer[..limit])
        }
    }

    #[test]
    fn synchronous_codec_writes_whole_frame() -> Result<(), Box<dyn std::error::Error>> {
        let frame = EreborIpcFrame::new(0, b"payload".to_vec())?;
        let mut output = Vec::new();
        SyncFrameCodec::write_frame(&mut output, &frame)?;
        assert_eq!(EreborIpcFrame::decode(&output)?, frame);
        Ok(())
    }

    #[tokio::test]
    async fn asynchronous_codec_handles_fragmented_frames_and_clean_eof(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let frame = EreborIpcFrame::new(0, b"payload".to_vec())?;
        let encoded = frame.encode()?;
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let writer_task = tokio::spawn(async move {
            for chunk in encoded.chunks(2) {
                tokio::io::AsyncWriteExt::write_all(&mut writer, chunk).await?;
            }
            Ok::<(), std::io::Error>(())
        });

        assert_eq!(AsyncFrameCodec::read_frame(&mut reader).await?, frame);
        writer_task.await??;
        assert!(matches!(
            AsyncFrameCodec::read_frame(&mut reader).await,
            Err(IpcProtocolError::EndOfStream { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn asynchronous_codec_distinguishes_partial_frame_eof(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        tokio::io::AsyncWriteExt::write_all(&mut writer, &crate::MAGIC).await?;
        drop(writer);
        assert!(matches!(
            AsyncFrameCodec::read_frame(&mut reader).await,
            Err(IpcProtocolError::TruncatedFrame { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn asynchronous_codec_writes_complete_frame() -> Result<(), Box<dyn std::error::Error>> {
        let frame = EreborIpcFrame::new(0, b"payload".to_vec())?;
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let expected = frame.clone();
        let writer_task =
            tokio::spawn(async move { AsyncFrameCodec::write_frame(&mut writer, &expected).await });

        assert_eq!(AsyncFrameCodec::read_frame(&mut reader).await?, frame);
        writer_task.await??;
        Ok(())
    }
}
