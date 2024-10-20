use exe::{
    ImageDirectoryEntry, ImageResourceDataEntry, PETranslation, ResolvedDirectoryID,
    ResourceDirectory, ResourceID, PE, RVA,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub struct ResourceEntry {
    pub rsrc_type: String,
    pub type_id: Option<u32>,
    pub rsrc_id: String,
    pub lang_id: String,
    pub data_start: Option<usize>,
    pub data_end: Option<usize>,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub struct Resources {
    pub minor_version: u16,
    pub major_version: u16,
    pub number_of_id_entries: u16,
    pub number_of_named_entries: u16,
    pub timestamp: u32,
    pub resources: Vec<ResourceEntry>,
}

impl Resources {
    pub fn parse<P: PE>(pe: &P) -> Result<Option<Resources>, exe::Error> {
        if !pe.has_data_directory(ImageDirectoryEntry::Resource) {
            return Ok(None);
        }
        let rsrc = ResourceDirectory::parse(pe)?;

        let mut result: Resources = Resources {
            minor_version: rsrc.root_node.directory.minor_version,
            major_version: rsrc.root_node.directory.major_version,
            number_of_id_entries: rsrc.root_node.directory.number_of_id_entries,
            number_of_named_entries: rsrc.root_node.directory.number_of_named_entries,
            timestamp: rsrc.root_node.directory.time_date_stamp,
            resources: vec![],
        };
        for entry in rsrc.resources {
            let mut resource_entry = ResourceEntry::default();
            resource_entry.rsrc_type = match &entry.type_id {
                ResolvedDirectoryID::ID(id) => {
                    resource_entry.type_id = Some(*id);
                    resource_id_to_type(ResourceID::from_u32(*id))
                }
                ResolvedDirectoryID::Name(name) => name.to_owned(),
            };
            resource_entry.data_end = None;
            resource_entry.data_start = None;
            resource_entry.rsrc_id = format!("{:?}", entry.rsrc_id).to_string();
            resource_entry.lang_id = format!("{:?}", entry.lang_id).to_string();

            let data_entry = entry.get_data_entry(pe).unwrap_or(&ImageResourceDataEntry {
                offset_to_data: RVA(0),
                size: 0,
                code_page: 0,
                reserved: 0,
            });

            let offset = pe.translate(PETranslation::Memory(data_entry.offset_to_data));
            if let Ok(offset) = offset {
                resource_entry.data_start = Some(offset);
                resource_entry.data_end = Some(offset + data_entry.size as usize);
            };

            result.resources.push(resource_entry);
        }

        Ok(Some(result))
    }
}

pub fn resource_id_to_type(id: ResourceID) -> String {
    match id {
        ResourceID::Cursor => "Cursor".to_owned(),
        ResourceID::Bitmap => "Bitmap".to_owned(),
        ResourceID::Icon => "Icon".to_owned(),
        ResourceID::Menu => "Menu".to_owned(),
        ResourceID::Dialog => "Dialog".to_owned(),
        ResourceID::String => "String".to_owned(),
        ResourceID::FontDir => "FontDir".to_owned(),
        ResourceID::Font => "Font".to_owned(),
        ResourceID::Accelerator => "Accelerator".to_owned(),
        ResourceID::RCData => "RCData".to_owned(),
        ResourceID::MessageTable => "MessageTable".to_owned(),
        ResourceID::GroupCursor => "GroupCursor".to_owned(),
        ResourceID::Reserved => "Reserved".to_owned(),
        ResourceID::GroupIcon => "GroupIcon".to_owned(),
        ResourceID::Reserved2 => "Reserved2".to_owned(),
        ResourceID::Version => "Version".to_owned(),
        ResourceID::DlgInclude => "DlgInclude".to_owned(),
        ResourceID::Reserved3 => "Reserved3".to_owned(),
        ResourceID::PlugPlay => "PlugPlay".to_owned(),
        ResourceID::VXD => "VXD".to_owned(),
        ResourceID::AniCursor => "AniCursor".to_owned(),
        ResourceID::AniIcon => "AniIcon".to_owned(),
        ResourceID::HTML => "HTML".to_owned(),
        ResourceID::Manifest => "Manifest".to_owned(),
        ResourceID::Unknown => "Unknown".to_owned(),
    }
}
