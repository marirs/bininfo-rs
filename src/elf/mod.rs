use crate::{entry_point::EntryPoint, sections::SectionTable, Result};
use goblin::{
    container::{Container, Endian},
    elf,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ElfFileInformation {
    pub entry_point: EntryPoint,
    pub section_table: SectionTable,
    pub header: Header,
}

impl ElfFileInformation {
    pub fn parse(elf_file: &elf::Elf) -> Result<ElfFileInformation> {
        Ok(ElfFileInformation {
            entry_point: EntryPoint::try_from(elf_file)?,
            section_table: SectionTable::try_from(elf_file)?,
            header: Header::try_from(elf_file)?,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum Identifier {
    #[default]
    Elf32,
    Elf64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum Endianness {
    #[default]
    Little,
    Big,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Header {
    pub version: u32,
    pub r#type: String,
    pub ident: Identifier,
    pub endianness: Endianness,
    pub program_headers_count: u16,
    pub program_headers_offset: u64,
    pub program_header_size: u16,
    pub section_headers_count: u16,
    pub section_headers_offset: u64,
    pub section_header_size: u16,
}

impl TryFrom<&elf::Elf<'_>> for Header {
    type Error = crate::error::Error;
    fn try_from(elf: &elf::Elf) -> std::result::Result<Self, Self::Error> {
        Ok(Header {
            version: elf.header.e_version,
            r#type: elf.header.e_type.to_string(),
            ident: match elf.header.container() {
                Ok(Container::Little) => Identifier::Elf32,
                Ok(Container::Big) => Identifier::Elf64,
                _ => return Err(crate::error::Error::InvalidIdentifier),
            },
            endianness: match elf.header.endianness() {
                Ok(Endian::Little) => Endianness::Little,
                Ok(Endian::Big) => Endianness::Big,
                _ => return Err(crate::error::Error::InvalidEndianness),
            },
            program_headers_count: elf.header.e_phnum,
            program_headers_offset: elf.header.e_phoff,
            program_header_size: elf.header.e_phentsize,
            section_headers_count: elf.header.e_shnum,
            section_headers_offset: elf.header.e_shoff,
            section_header_size: elf.header.e_shentsize,
        })
    }
}
