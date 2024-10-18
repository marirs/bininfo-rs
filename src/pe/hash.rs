use exe::{HashData, VecPE};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Hash {
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Hashes {
    pub hashes: Vec<Hash>,
}

impl Hashes {
    pub fn parse(pe: &VecPE) -> Hashes {
        Hashes {
            hashes: vec![
                Hash {
                    name: "MD5".to_string(),
                    value: pe.md5(),
                },
                Hash {
                    name: "SHA1".to_string(),
                    value: pe.sha1(),
                },
                Hash {
                    name: "SHA256".to_string(),
                    value: pe.sha256(),
                },
            ],
        }
    }
}
