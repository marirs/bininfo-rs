use crate::pe::util::safe_read;
use exe::{CCharString, VecPE, PE};
use goblin::elf::SectionHeader;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub virt_addr: u64,
    pub virt_size: u64,
    pub raw_addr: u64,
    pub raw_size: u64,
    #[serde(skip_serializing)]
    pub data: Vec<u8>,
    pub entropy: Option<f32>,
}

#[derive(Default, Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct SectionTable {
    pub sections: Vec<Section>,
}

impl TryFrom<&VecPE> for SectionTable {
    type Error = crate::error::Error;

    fn try_from(pe: &VecPE) -> Result<Self, Self::Error> {
        let mut result = SectionTable { sections: vec![] };
        let sec_tbl = pe.get_section_table()?;
        for sec in sec_tbl {
            let data_offset: usize = sec.data_offset(pe.get_type());
            let data_size = sec.data_size(pe.get_type());
            let section_data = safe_read(pe, data_offset, data_size);

            result.sections.push(Section {
                name: sec.name.as_str().unwrap().to_string(),
                virt_addr: sec.virtual_address.0 as u64,
                virt_size: sec.virtual_size as u64,
                raw_addr: sec.pointer_to_raw_data.0 as u64,
                raw_size: sec.size_of_raw_data as u64,
                data: section_data.to_vec(),
                entropy: Some(entropy::shannon_entropy(section_data)),
            });
        }
        Ok(result)
    }
}

impl TryFrom<&goblin::elf::Elf<'_>> for SectionTable {
    type Error = crate::error::Error;

    fn try_from(elf: &goblin::elf::Elf) -> Result<Self, Self::Error> {
        let mut result = SectionTable { sections: vec![] };
        for sec in &elf.section_headers {
            result.sections.push(sec.into());
        }
        Ok(result)
    }
}

impl From<&SectionHeader> for Section {
    fn from(section: &SectionHeader) -> Self {
        Section {
            name: section.sh_name.to_string(),
            virt_addr: section.sh_addr,
            virt_size: section.sh_size,
            raw_addr: section.sh_offset,
            raw_size: section.sh_size,
            data: vec![],
            entropy: None,
        }
    }
}

pub fn get_section_name_from_offset(offset: u64, pe: &VecPE) -> Option<String> {
    let sections = match SectionTable::try_from(pe) {
        Ok(sections) => sections,
        Err(_) => return None,
    };

    for section in sections.sections {
        if offset >= (section.virt_addr) && ((offset) < (section.virt_size + section.virt_addr)) {
            return Some(section.name.to_owned());
        }
    }
    None
}
