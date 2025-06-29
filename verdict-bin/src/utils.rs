use std::fs::File;
use std::io::{BufRead, BufReader};

use verdict::decode_base64;

use crate::error::Error;

pub fn read_pem_file_as_base64(path: &str) -> Result<Vec<String>, Error> {
    let file = BufReader::new(File::open(path)?);
    read_pem_as_base64(file).collect()
}

/// Read a PEM file (given as a BufRead) and return an iterator over the decoded certificates
pub fn read_pem_as_bytes<B: BufRead>(reader: B) -> impl Iterator<Item = Result<Vec<u8>, Error>> {
    read_pem_as_base64(reader).map(|res| match res {
        Ok(cert_base64) => Ok(decode_base64(cert_base64.as_bytes())?),
        Err(err) => Err(err),
    })
}

/// Read a PEM file and return an iterator over base64 encoded strings
pub fn read_pem_as_base64<B: BufRead>(reader: B) -> impl Iterator<Item = Result<String, Error>> {
    const PREFIX: &'static str = "-----BEGIN CERTIFICATE-----";
    const SUFFIX: &'static str = "-----END CERTIFICATE-----";

    let mut cur_cert_base64 = None;

    reader.lines().filter_map(move |line| {
        let inner = || {
            let line = line?;
            let line_trimmed = line.trim();

            if line_trimmed == PREFIX {
                if cur_cert_base64.is_some() {
                    Err(Error::NoMatchingEndCertificate)
                } else {
                    cur_cert_base64 = Some(String::new());
                    Ok(None)
                }
            } else if line_trimmed == SUFFIX {
                match cur_cert_base64.take() {
                    // Found some base64 chunk
                    Some(cert_base64) => Ok(Some(cert_base64)),
                    None => Err(Error::NoMatchingBeginCertificate),
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
