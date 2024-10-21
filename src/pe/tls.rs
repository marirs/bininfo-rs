use crate::Result;
use exe::{ImageTLSDirectory32, ImageTLSDirectory64, VecPE, PE};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TlsCallbacks {
    pub callbacks: Vec<u64>,
}

impl TlsCallbacks {
    pub fn parse(pe: &VecPE) -> Result<TlsCallbacks> {
        let callbacks = match pe.get_arch()? {
            exe::Arch::X86 => match ImageTLSDirectory32::parse(pe) {
                Ok(tls) => {
                    let cc = tls.get_callbacks(pe)?;
                    cc.iter().map(|x| x.0.into()).collect::<Vec<u64>>()
                }
                Err(e) => {
                    eprintln!("{e}");
                    vec![]
                }
            },
            exe::Arch::X64 => match ImageTLSDirectory64::parse(pe) {
                Ok(tls) => tls
                    .get_callbacks(pe)?
                    .iter()
                    .map(|x| x.0)
                    .collect::<Vec<u64>>(),
                Err(e) => {
                    eprintln!("{e}");
                    vec![]
                }
            },
        };
        Ok(TlsCallbacks { callbacks })
    }
}
