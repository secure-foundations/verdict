//! Some (unverified) utility functions, such as decoding PEM to Base64

use std::io::BufRead;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PEMParseError {
    #[error("found BEGIN CERTIFICATE without matching END CERTIFICATE")]
    NoMatchingEndCertificate,

    #[error("found END CERTIFICATE without matching BEGIN CERTIFICATE")]
    NoMatchingBeginCertificate,

    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),
}

/// Decodes PEM format and returns an iterator over Base64-encoded strings
pub fn read_pem_as_base64<B: BufRead>(
    reader: B,
) -> impl Iterator<Item = Result<String, PEMParseError>> {
    const PREFIX: &'static str = "-----BEGIN CERTIFICATE-----";
    const SUFFIX: &'static str = "-----END CERTIFICATE-----";

    let mut cur_cert_base64 = None;

    reader.lines().filter_map(move |line| {
        let inner = || {
            let line = line?;
            let line_trimmed = line.trim();

            if line_trimmed == PREFIX {
                if cur_cert_base64.is_some() {
                    Err(PEMParseError::NoMatchingEndCertificate)
                } else {
                    cur_cert_base64 = Some(String::new());
                    Ok(None)
                }
            } else if line_trimmed == SUFFIX {
                match cur_cert_base64.take() {
                    // Found some base64 chunk
                    Some(cert_base64) => Ok(Some(cert_base64)),
                    None => Err(PEMParseError::NoMatchingBeginCertificate),
                }
            } else if let Some(cur_cert_base64) = cur_cert_base64.as_mut() {
                cur_cert_base64.push_str(line_trimmed);
                Ok(None)
            } else {
                // Ignore lines between SUFFIX and the next PREFIX
                Ok(None)
            }
        };

        match inner() {
            Ok(Some(cert_bytes)) => Some(Ok(cert_bytes)),
            Ok(None) => None,
            Err(err) => Some(Err(err)), // Eager return on error
        }
    })
}
