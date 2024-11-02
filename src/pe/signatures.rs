use authenticode::AuthenticodeSignature;
use cms::signed_data::SignerIdentifier;
use goblin::pe::PE;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub struct Identifier {
    pub issuer: String,
    pub serial_number: String,
}
#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub struct Cert {
    pub issuer: String,
    pub subject: String,
    pub serial_number: String,
}
#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub struct AuthenSig {
    // signature_index: u32,
    pub digest: String,
    pub issuer: Option<Identifier>,
    pub certificates: Vec<Cert>,
}
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub struct PeAuthenticodes {
    pub signatures: Vec<AuthenSig>,
}

impl PeAuthenticodes {
    pub fn parse(pe: (&PE, &[u8])) -> Result<PeAuthenticodes, crate::Error> {
        let signatures =
            pe.0.certificates
                .iter()
                .try_fold(vec![], |mut res, attribute_certificate| {
                    res.push(
                        authenticode::AttributeCertificate {
                            revision: attribute_certificate.revision as u16,
                            certificate_type: attribute_certificate.certificate_type as u16,
                            data: attribute_certificate.certificate,
                        }
                        .get_authenticode_signature()?
                        .into(),
                    );
                    Ok::<_, crate::Error>(res)
                })?;
        Ok(PeAuthenticodes { signatures })
    }
}

impl From<AuthenticodeSignature> for AuthenSig {
    fn from(value: AuthenticodeSignature) -> Self {
        let mut identifier: Option<Identifier> = None;
        if let SignerIdentifier::IssuerAndSerialNumber(sid) = &value.signer_info().sid {
            identifier = Some(Identifier {
                issuer: sid.issuer.to_string(),
                serial_number: sid.serial_number.to_string(),
            });
        }
        let mut certs = vec![];
        for cert in value.certificates() {
            certs.push(Cert {
                issuer: cert.tbs_certificate.issuer.to_string(),
                subject: cert.tbs_certificate.subject.to_string(),
                serial_number: cert.tbs_certificate.serial_number.to_string(),
            });
        }
        AuthenSig {
            digest: hex::encode(value.digest()),
            issuer: identifier,
            certificates: certs,
        }
    }
}
