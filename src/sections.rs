use crate::pe::util::safe_read;
use goblin::{elf::SectionHeader, pe::PE};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub virt_addr: u64,
    pub virt_size: u64,
    pub raw_addr: u64,
    pub raw_size: u64,
    #[serde(skip)]
    pub data: Vec<u8>,
    pub entropy: Option<f32>,
    pub characteristics: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct SectionTable {
    pub sections: Vec<Section>,
}

impl TryFrom<(&PE<'_>, &[u8])> for SectionTable {
    type Error = crate::error::Error;

    fn try_from(pe: (&PE, &[u8])) -> Result<Self, Self::Error> {
        let mut result = SectionTable { sections: vec![] };
        for sec in &pe.0.sections {
            let data_offset: usize = sec.pointer_to_raw_data as usize;
            let data_size = sec.size_of_raw_data as usize;
            let section_data = safe_read(pe.1, data_offset, data_size);
            let section_characteristics = format!(
                "{:X} ({:?})",
                sec.characteristics,
                exe::headers::SectionCharacteristics::from_bits(sec.characteristics).unwrap()
            );
            let nul_range_end = sec
                .name
                .iter()
                .position(|&c| c == b'\0')
                .unwrap_or(sec.name.len());
            result.sections.push(Section {
                name: String::from_utf8(sec.name[..nul_range_end].to_vec()).unwrap(),
                virt_addr: sec.virtual_address as u64,
                virt_size: sec.virtual_size as u64,
                raw_addr: sec.pointer_to_raw_data as u64,
                raw_size: sec.size_of_raw_data as u64,
                data: section_data.to_vec(),
                entropy: Some(entropy::shannon_entropy(section_data)),
                characteristics: Some(section_characteristics),
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
            characteristics: None,
        }
    }
}
