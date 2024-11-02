use crypto::{digest::Digest, md5::Md5, sha1::Sha1, sha2::Sha256};
use serde::{Deserialize, Serialize};

pub trait HashData {
    /// Produce an MD5 hash.
    fn md5(&self) -> Vec<u8>;
    /// Produce a SHA1 hash.
    fn sha1(&self) -> Vec<u8>;
    /// Produce a SHA256 hash.
    fn sha256(&self) -> Vec<u8>;
}
impl HashData for [u8] {
    fn md5(&self) -> Vec<u8> {
        let mut hash = Md5::new();
        hash.input(self); // Update the hash input with the byte slice
        hash.result_str().as_bytes().to_vec() // Convert to Vec<u8>
    }

    fn sha1(&self) -> Vec<u8> {
        let mut hash = Sha1::new();
        hash.input(self); // Update the hash input with the byte slice
        hash.result_str().as_bytes().to_vec() // Convert to Vec<u8>
    }

    fn sha256(&self) -> Vec<u8> {
        let mut hash = Sha256::new();
        hash.input(self); // Update the hash input with the byte slice
        hash.result_str().as_bytes().to_vec() // Convert to Vec<u8>
    }
}

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
    pub fn parse(pe: &[u8]) -> Hashes {
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
