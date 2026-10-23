use std::mem::size_of;

use super::Publication;

impl Publication {
    pub(super) async fn expire(
        &self,
        mut data: super::SendableRecordBatchStream,
        context: &std::sync::Arc<super::TaskContext>,
    ) -> super::Result<u64> {
        use futures_util::TryStreamExt as _;

        let memory = self.owner.session.memory().reserve_input(0)?;
        let mut batches = Vec::new();
        while let Some(batch) = data.try_next().await? {
            self.owner.session.memory().retain_input(&batch, &memory)?;
            let before = batches.capacity();
            batches.push(batch);
            memory
                .try_grow((batches.capacity() - before) * size_of::<super::sdk::RecordBatch>())?;
        }
        let receipt = super::ExecutionReceipt::from_context(context)?;
        let captured = receipt.clone();
        let owner = self.clone();
        let operation = std::sync::Arc::clone(context);
        let acknowledgement = receipt.clone();
        let (output, complete) = receipt
            .blocking(context, memory, move |control| {
                let Some(converted) = crate::graph::GraphConversion::expiry(
                    &owner.owner.session,
                    &operation,
                    &captured,
                    &batches,
                    control,
                )?
                else {
                    return Ok((None, true));
                };
                let complete = converted.completed;
                let packet = converted.packet;
                let id = packet.request.result_id.clone();
                let mut prepared = Some(packet.graph);
                let mut committed = None;
                owner.owner.authorize(control, &mut || {
                    committed =
                        Some(owner.owner.session.engine().store().commit_graph_snapshot(
                            packet.request.clone(),
                            prepared.take().ok_or_else(|| {
                                super::Code::Invalid.error("graph expiry callback")
                            })?,
                            &packet.contexts,
                            &packet.proofs,
                            &packet.sources,
                            packet.advance,
                            || {
                                owner.owner.grant.remaining()?;
                                owner.owner.session.control().check()?;
                                control.check()
                            },
                        )?);
                    Ok(())
                })?;
                Ok((
                    Some((
                        id,
                        committed.ok_or_else(|| {
                            super::Code::Incomplete.error("graph expiry authority")
                        })?,
                    )),
                    complete,
                ))
            })
            .await?;
        let count = u64::from(output.is_some());
        if let Some(output) = output {
            let revision = output.1.commit_revision;
            *self
                .receipt
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = Some(output);
            if complete {
                acknowledgement.acknowledge(context, revision)?;
            }
        }
        Ok(count)
    }
}
