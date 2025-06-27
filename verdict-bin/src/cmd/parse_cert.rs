use std::io;
use std::time::{Duration, Instant};

use clap::Parser;

use verdict::parse_x509_der;

use crate::error::*;
use crate::utils::*;

#[derive(Parser, Debug)]
pub struct Args {
    /// Ignore parse errors in X.509
    #[clap(short = 'e', long, default_value_t = false)]
    ignore_parse_errors: bool,
}

/// Read from stdin a sequence of PEM-encoded certificates, parse them, and print them to stdout
pub fn main(args: Args) -> Result<(), Error>
{
    let mut num_parsed = 0;
    let mut total_time = Duration::new(0, 0);

    for cert_bytes in read_pem_as_bytes(io::stdin().lock()) {
        let cert_bytes = cert_bytes?;

        let begin = Instant::now();
        let parsed = parse_x509_der(&cert_bytes);
        total_time += begin.elapsed();

        match parsed {
            Ok(cert) => {
                println!("{:?}", cert);
            }
            Err(err) => {
                if !args.ignore_parse_errors {
                    Err(err)?;
                } else {
                    eprintln!("error parsing certificate {}, ignored", num_parsed);
                }
            }
        }

        num_parsed += 1;
    }

    println!("time: {:.3}s", total_time.as_secs_f64());

    Ok(())
}
