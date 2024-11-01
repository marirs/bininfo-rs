use crate::Result;
//use exe::{ImageTLSDirectory32, ImageTLSDirectory64, VecPE, PE};
use goblin::pe::PE;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TlsCallbacks {
    pub callbacks: Vec<u64>,
}

impl TlsCallbacks {
    pub fn parse(pe: (&PE, &[u8])) -> Result<TlsCallbacks> {
        if let Some(tls) = &pe.0.tls_data {
            Ok(TlsCallbacks {
                callbacks: tls.callbacks.to_vec(),
            })
        } else {
            Ok(TlsCallbacks { callbacks: vec![] })
        }
    }
}
