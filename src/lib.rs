use crate::elf::ElfFileInformation;
use crate::entry_point::EntryPoint;
use crate::pe::imports::Imports;
use crate::pe::resource::Resources;
use crate::pe::rich_headers::RichTable;
use crate::pe::signatures::PeAuthenticodes;
use crate::pe::tls::TlsCallbacks;
use crate::pe::PeFileInformation;
use crate::sections::SectionTable;
use exe::VecPE;
use serde::{Deserialize, Serialize};

pub mod elf;
pub mod entry_point;
pub mod error;
pub mod pe;
pub mod sections;

pub type Result<T> = std::result::Result<T, error::Error>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileExInfo {
    /// Entry point (ELF & PE)
    pub entry_point: Option<EntryPoint>,
    /// Signatures (PE only)
    pub signature: Option<PeAuthenticodes>,
    /// Rich Headers (PE only)
    pub rich_headers: Option<RichTable>,
    /// Section Table (ELF & PE)
    pub section_table: Option<SectionTable>,
    /// Imports (PE only)
    pub imports: Option<Imports>,
    /// Resources (PE only)
    pub resources: Option<Resources>,
    /// TLS Callbacks (PE only)
    pub tls_callbacks: Option<TlsCallbacks>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum FileInformation {
    Pe(PeFileInformation),
    Elf(ElfFileInformation),
}

impl From<PeFileInformation> for FileExInfo {
    fn from(val: PeFileInformation) -> Self {
        FileExInfo {
            entry_point: Some(val.entry_point),
            signature: Some(val.signature),
            rich_headers: Some(val.rich_headers),
            section_table: Some(val.section_table),
            imports: Some(val.imports),
            resources: val.resources,
            tls_callbacks: Some(val.tls),
        }
    }
}

impl From<ElfFileInformation> for FileExInfo {
    fn from(val: ElfFileInformation) -> Self {
        FileExInfo {
            entry_point: Some(val.entry_point),
            signature: None,
            rich_headers: None,
            section_table: Some(val.section_table),
            imports: None,
            resources: None,
            tls_callbacks: None,
        }
    }
}

pub fn get_file_information(file_path: &str) -> Result<FileExInfo> {
    let payload = std::fs::read(file_path)?;
    match goblin::Object::parse(&payload)? {
        goblin::Object::PE(_) => {
            let image = VecPE::from_disk_data(&payload);
            Ok(PeFileInformation::parse(&image)?.into())
        }
        goblin::Object::Elf(elf) => Ok(ElfFileInformation::parse(&elf)?.into()),
        _ => Err(error::Error::UnsupportedFileType),
    }
}
