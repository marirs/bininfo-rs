use crate::Result;
use exe::{ImageTLSDirectory32, ImageTLSDirectory64, VecPE, PE};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TlsCallbacks {
    callbacks: Vec<u64>,
}

impl TlsCallbacks {
    pub fn parse(pe: &VecPE) -> Result<TlsCallbacks> {
        let callbacks = match pe.get_arch()? {
            exe::Arch::X86 => {
                let tls = ImageTLSDirectory32::parse(pe)?;
                tls.get_callbacks(pe)?
                    .iter()
                    .map(|x| x.0.into())
                    .collect::<Vec<u64>>()
            }
            exe::Arch::X64 => ImageTLSDirectory64::parse(pe)?
                .get_callbacks(pe)?
                .iter()
                .map(|x| x.0)
                .collect::<Vec<u64>>(),
        };
        Ok(TlsCallbacks { callbacks })
    }
}
