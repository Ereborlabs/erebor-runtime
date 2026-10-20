use std::mem::size_of;

use crate::{Definition, ImagePin, ResolvedDefinition, Source};

impl Definition {
    pub fn allocation_bytes(&self) -> Option<usize> {
        let source = match self.program.source() {
            Source::Inline { inline } => inline.capacity(),
            Source::File { file } => file.capacity(),
        };
        self.labels.iter().try_fold(
            size_of::<Self>()
                .checked_add(self.name.capacity())?
                .checked_add(self.description.capacity())?
                .checked_add(source)?,
            |bytes, (key, value)| {
                bytes
                    .checked_add(size_of::<(String, String)>())?
                    .checked_add(key.capacity())?
                    .checked_add(value.capacity())
            },
        )
    }
}

impl ResolvedDefinition {
    pub fn allocation_bytes(&self) -> Option<usize> {
        self.images.iter().try_fold(
            size_of::<Self>()
                .checked_add(
                    self.definition
                        .allocation_bytes()?
                        .checked_sub(size_of::<Definition>())?,
                )?
                .checked_add(self.sql.capacity())?
                .checked_add(self.images.capacity().checked_mul(size_of::<ImagePin>())?)?,
            |bytes, pin| {
                bytes
                    .checked_add(pin.image.package_id.capacity())?
                    .checked_add(pin.image.revision.capacity())?
                    .checked_add(pin.digest.capacity())
            },
        )
    }
}
