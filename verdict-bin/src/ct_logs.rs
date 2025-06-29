use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CTLogEntry {
    pub cert_base64: String,
    pub hash: String, // SHA-256 hash of the entire certificate
    pub domain: String,
    pub interm_certs: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CTLogResult {
    pub hash: String,
    pub domain: String,
    pub valid: bool,
    pub err: String,

    /// Samples of running time in microseconds
    /// TODO: this is currently serialized as a
    /// comma separated list, which is not ideal
    pub stats: Vec<u64>,
}

/// Workaround for an [issue](https://github.com/BurntSushi/rust-csv/issues/113) in rust-csv
#[derive(Debug, Deserialize, Serialize)]
pub struct CTLogResultLegacy {
    pub hash: String,
    pub domain: String,
    pub result: String,
}
