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
use serde::{Deserialize, Serialize};
use std::{fs::read, path::Path};

pub mod elf;
pub mod entry_point;
pub mod error;
pub mod pe;
pub mod sections;

pub type Result<T> = std::result::Result<T, Error>;

/// Extended Information for a given binary
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct BinExInfo {
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

impl From<PeFileInformation> for BinExInfo {
    fn from(val: PeFileInformation) -> Self {
        BinExInfo {
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

impl From<ElfFileInformation> for BinExInfo {
    fn from(val: ElfFileInformation) -> Self {
        BinExInfo {
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

/// Get the Extended Information for given Binary
///
/// ```ignore
/// use bininfo::get_file_extended_information;
///
/// let bin_info = get_file_extended_information("/path/to/file");
///
/// println!("{:?}", bin_info)
/// ```
pub fn get_file_extended_information<P: AsRef<Path>>(file_path: P) -> Result<BinExInfo> {
    if !file_path.as_ref().is_file() {
        return Err(Error::FileNotFound);
    }
    let payload = read(file_path)?;
    match goblin::Object::parse(&payload)? {
        goblin::Object::Elf(elf) => Ok(ElfFileInformation::parse(&elf)?.into()),
        goblin::Object::PE(pe) => Ok(PeFileInformation::parse((&pe, &payload))?.into()),
        _ => Err(Error::UnsupportedFileType),
    }
}
