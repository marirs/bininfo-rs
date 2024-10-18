use crate::entry_point::EntryPoint;
use crate::pe::hash::Hashes;
use crate::pe::imports::Imports;
use crate::pe::resource::Resources;
use crate::pe::rich_headers::RichTable;
use crate::pe::signatures::PeAuthenticodes;
use crate::pe::tls::TlsCallbacks;
use crate::sections::SectionTable;
use crate::Result;
use exe::VecPE;
use serde::{Deserialize, Serialize};

pub mod hash;
pub mod imports;
pub mod resource;
pub mod rich_headers;
pub mod signatures;
pub mod tls;
pub(crate) mod util;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
