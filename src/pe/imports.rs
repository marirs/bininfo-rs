use exe::{CCharString, ImageDirectoryEntry, ImportData, ImportDirectory, VecPE, PE};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Imports {
    pub modules: Vec<ImportEntry>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ImportFunction {
    pub name: String,
    pub import_by_ordinal: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ImportEntry {
    pub name: String,
    pub imports: Vec<ImportFunction>,
}

impl Imports {
    pub fn parse<P: PE>(pe: &P) -> Result<Imports, exe::Error> {
        let mut result = Imports::default();
        let import_directory = match ImportDirectory::parse(pe) {
            Ok(import_dir) => import_dir,
            Err(_) => {
                return Err(exe::Error::BadDirectory(ImageDirectoryEntry::Import));
            }
        };
        for import in import_directory.descriptors {
            let mut entry = ImportEntry::default();

            entry.name = match import.get_name(pe) {
                Ok(n) => match n.as_str() {
                    Ok(s) => s.to_string().to_ascii_lowercase(),
                    Err(e) => return Err(e),
                },
                Err(e) => return Err(e),
            };

            let import_entries = match import.get_imports(pe) {
                Ok(import_entries) => import_entries,
                Err(_) => {
                    return Err(exe::Error::BadDirectory(ImageDirectoryEntry::Import));
                }
            };
            for import_data in import_entries {
                let function_name = match import_data {
                    ImportData::Ordinal(x) => format!("Ordinal({x})"),
                    ImportData::ImportByName(s) => s.to_string(),
                };
                let is_import_by_ordinal = matches!(import_data, ImportData::Ordinal(_));
                entry.imports.push(ImportFunction {
                    name: function_name,
                    import_by_ordinal: is_import_by_ordinal,
                });
            }
            result.modules.push(entry);
        }
        Ok(result)
    }
}

pub fn pimp(pe: &VecPE) -> Option<Imports> {
    match Imports::parse(pe) {
        Ok(imports) => Some(imports),
        Err(_) => None,
    }
}
