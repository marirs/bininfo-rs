use crate::sections::{Section, SectionTable};
use goblin::pe::PE;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct EntryPoint {
    pub address: u64,
    pub section: Option<Section>,
}
impl TryFrom<(&goblin::pe::PE<'_>, &[u8])> for EntryPoint {
    type Error = crate::error::Error;

    fn try_from(pe: (&PE, &[u8])) -> Result<Self, Self::Error> {
        let entry_point = pe.0.entry as u64;
        let sections = SectionTable::try_from(pe)?;
        let entry_section = sections.sections.into_iter().find(|section| {
            entry_point >= (section.virt_addr)
                && ((entry_point) < (section.virt_size + section.virt_addr))
        });
        Ok(EntryPoint {
            address: entry_point,
            section: entry_section,
        })
    }
}

impl TryFrom<&goblin::elf::Elf<'_>> for EntryPoint {
    type Error = crate::error::Error;

    fn try_from(elf: &goblin::elf::Elf) -> Result<Self, Self::Error> {
        let entry_point = elf.entry;
        let entry_section = elf
            .section_headers
            .iter()
            .find(|section| {
                entry_point >= section.sh_addr && entry_point < section.sh_addr + section.sh_size
            })
            .map(|section| section.into());
        Ok(EntryPoint {
            address: entry_point,
            section: entry_section,
        })
    }
}
