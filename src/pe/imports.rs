use std::collections::HashMap;

//use exe::{CCharString, ImageDirectoryEntry, ImportData, ImportDirectory, VecPE, PE};
use goblin::pe::PE;
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
    pub fn parse(pe: (&PE, &[u8])) -> Result<Self, crate::Error> {
        let modules =
            pe.0.imports
                .iter()
                .fold(HashMap::new(), |mut acc, import| {
                    #[allow(clippy::unwrap_or_default)]
                    let entr = acc.entry(import.dll).or_insert(vec![]);
                    entr.push(if import.ordinal > 0 {
                        ImportFunction {
                            name: format!("Ordinal({})", import.ordinal),
                            import_by_ordinal: true,
                        }
                    } else {
                        ImportFunction {
                            name: import.name.to_string(),
                            import_by_ordinal: false,
                        }
                    });
                    acc
                })
                .into_iter()
                .map(|(dll, funcs)| ImportEntry {
                    name: dll.to_string(),
                    imports: funcs,
                })
                .collect();
        Ok(Self { modules })
    }
}

pub fn pimp(pe: (&PE, &[u8])) -> Option<Imports> {
    match Imports::parse(pe) {
        Ok(imports) => Some(imports),
        Err(_) => None,
    }
}
