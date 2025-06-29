use std::collections::HashMap;
use std::fs::File;

use clap::Parser;
use csv::ReaderBuilder;

use verdict::{decode_base64, parse_x509_der};

use crate::ct_logs::*;
use crate::error::*;

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(num_args = 1..)]
    csv_files: Vec<String>,

    #[clap(short = 'e', long, default_value_t = false)]
    ignore_parse_errors: bool,
}

pub fn main(args: Args) -> Result<(), Error> {
    eprintln!("parsing {} CT log file(s)", args.csv_files.len());

    // Count the number of certificates using each subject key algo
    let mut signature_algs = HashMap::new();
    let mut subject_keys = HashMap::new();

    let mut num_parsed_total = 0;

    for path in args.csv_files {
        let mut num_parsed = 0;

        let file = File::open(&path)?;
        let mut reader = ReaderBuilder::new()
            .has_headers(false) // If your CSV has headers
            .from_reader(file);

        for result in reader.deserialize() {
            let result: CTLogEntry = result?;

            let cert_bytes = decode_base64(result.cert_base64.as_bytes())?;

            match parse_x509_der(&cert_bytes) {
                Ok(cert) => {
                    let alg_str = format!("{:?}", cert.get().cert.get().subject_key.alg);
                    *subject_keys.entry(alg_str).or_insert(0) += 1;

                    let sig_alg_str = format!("{:?}", cert.get().sig_alg);
                    *signature_algs.entry(sig_alg_str).or_insert(0) += 1;
                }
                Err(err) => {
                    if !args.ignore_parse_errors {
                        Err(err)?;
                    } else {
                        eprintln!("error parsing certificate in {}, ignored", path);
                    }
                }
            }

            num_parsed += 1;
            num_parsed_total += 1;
        }

        eprintln!(
            "parsed {} certificate(s) in {} (total {})",
            num_parsed, path, num_parsed_total
        );
        eprintln!("subject key algorithms found so far: {:?}", subject_keys);
        eprintln!("signature algorithms found so far: {:?}", signature_algs);
    }

    eprintln!("parsed {} certificate(s) in total", num_parsed_total);

    Ok(())
}
