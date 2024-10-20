use crate::{
    entry_point::EntryPoint,
    pe::{
        hash::Hashes, imports::Imports, resource::Resources, rich_headers::RichTable,
        signatures::PeAuthenticodes, tls::TlsCallbacks,
    },
    sections::SectionTable,
    Result,
};
use exe::VecPE;
use serde::Serialize;

pub mod hash;
pub mod imports;
pub mod resource;
pub mod rich_headers;
pub mod signatures;
pub mod tls;
pub(crate) mod util;

#[derive(Clone, Debug, Default, Serialize)]
pub struct PeFileInformation {
    pub entry_point: EntryPoint,
    pub hashes: Hashes,
    pub signature: PeAuthenticodes,
    pub rich_headers: RichTable,
    pub section_table: SectionTable,
    pub imports: Imports,
    pub resources: Option<Resources>,
    pub tls: TlsCallbacks,
}

impl PeFileInformation {
    pub fn parse(pe: &VecPE) -> Result<PeFileInformation> {
        Ok(PeFileInformation {
            entry_point: EntryPoint::try_from(pe)?,
            hashes: Hashes::parse(pe),
            signature: PeAuthenticodes::parse(pe)?,
            rich_headers: RichTable::parse(pe),
            section_table: SectionTable::try_from(pe)?,
            imports: Imports::parse(pe)?,
            resources: Resources::parse(pe)?,
            tls: TlsCallbacks::parse(pe)?,
        })
    }
}
