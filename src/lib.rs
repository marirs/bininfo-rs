use crate::{
    elf::ElfFileInformation,
    entry_point::EntryPoint,
    error::Error,
    pe::{
        imports::Imports, resource::Resources, rich_headers::RichTable,
        signatures::PeAuthenticodes, tls::TlsCallbacks, PeFileInformation,
    },
    sections::SectionTable,
};
use exe::VecPE;
use serde::{Deserialize, Serialize};
use std::{fs::read, path::Path};

pub mod elf;
pub mod entry_point;
pub mod error;
pub mod pe;
pub mod sections;

pub type Result<T> = std::result::Result<T, error::Error>;

/// Extended Information for a given file
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct FileExInfo {
    /// Entry point (ELF & PE)
    #[serde(default)]
    pub entry_point: Option<EntryPoint>,
    /// Signatures (PE only)
    #[serde(default)]
    pub signature: Option<PeAuthenticodes>,
    /// Rich Headers (PE only)
    #[serde(default)]
    pub rich_headers: Option<RichTable>,
    /// Section Table (ELF & PE)
    #[serde(default)]
    pub section_table: Option<SectionTable>,
    /// Imports (PE only)
    #[serde(default)]
    pub imports: Option<Imports>,
    /// Resources (PE only)
    #[serde(default)]
    pub resources: Option<Resources>,
    /// TLS Callbacks (PE only)
    #[serde(default)]
    pub tls_callbacks: Option<TlsCallbacks>,
}

//#[derive(Clone, Debug, Serialize)]
//enum FileInformation {
//    Pe(PeFileInformation),
//    Elf(ElfFileInformation),
//}

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
            imports: Some(val.imports),
            resources: None,
            tls_callbacks: None,
        }
    }
}

pub fn get_file_extended_information<P: AsRef<Path>>(file_path: P) -> Result<FileExInfo> {
    if !file_path.as_ref().is_file() {
        return Err(Error::FileNotFound);
    }
    let payload = read(file_path)?;
    let image = VecPE::from_disk_data(&payload);
    if let Ok(pe) = PeFileInformation::parse(&image) {
        Ok(pe.into())
    } else {
        match goblin::Object::parse(&payload)? {
            goblin::Object::Elf(elf) => Ok(ElfFileInformation::parse(&elf)?.into()),
            _ => Err(Error::UnsupportedFileType),
        }
    }
}
