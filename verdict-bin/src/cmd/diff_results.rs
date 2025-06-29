use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader};

use clap::Parser;
use csv::ReaderBuilder;
use regex::Regex;

use crate::error::*;

#[derive(Parser, Debug)]
pub struct Args {
    /// The main CSV file to compare against
    /// All entries in file2 should have a
    /// corresponding entry in file1, but
    /// not necessarily the other way around
    file1: String,

    /// The second CSV file to compare
    /// If this is optional, we read from stdin
    file2: Option<String>,

    #[clap(short = 'k', long = "key", default_value = "0")]
    key_column: usize,

    #[clap(short = 'v', long = "value", default_value = "2")]
    value_column: usize,

    /// Regex expressions specifying classes of results
    /// e.g. if file1 uses OK for success, while file2 uses true, then
    /// we can add a class r"OK|true" for both of them
    ///
    /// Result strings not belong to any class are considered as a singleton
    /// class of the string itself
    #[clap(short = 'c', long = "class", value_parser, num_args = 0..)]
    classes: Vec<String>,
}

/// Used for comparing results represented as different strings (e.g. OK vs true)
#[derive(PartialEq, Eq, Hash, Debug)]
enum DiffClass {
    Class(usize),
    Singleton(String),
}

impl DiffClass {
    fn get(classes: &[Regex], s: &str) -> DiffClass {
        // Match against each class
        for (i, class_regex) in classes.iter().enumerate() {
            if class_regex.is_match(&s) {
                return DiffClass::Class(i);
            }
        }

        return DiffClass::Singleton(s.to_string());
    }
}

pub fn main(args: Args) -> Result<(), Error> {
    let classes = args
        .classes
        .iter()
        .map(|pat| Regex::new(pat))
        .collect::<Result<Vec<_>, _>>()?;

    // Read CSV file1 into a HashMap
    let file1 = BufReader::new(File::open(&args.file1)?);
    let file1_results: HashMap<String, (String, DiffClass)> = ReaderBuilder::new()
        .has_headers(false)
        .from_reader(file1)
        .records()
        .map(|res| {
            let res = res?;
            let value = &res[args.value_column];
            let class = DiffClass::get(&classes, value);
            Ok::<_, csv::Error>((res[args.key_column].to_string(), (value.to_string(), class)))
        })
        .collect::<Result<_, _>>()?;

    // Create a reader on file2 or stdin
    let file2: Box<dyn io::Read> = if let Some(file2) = args.file2 {
        Box::new(BufReader::new(File::open(file2)?))
    } else {
        Box::new(std::io::stdin())
    };

    let mut file2_reader = ReaderBuilder::new().has_headers(false).from_reader(file2);

    let mut class_count = HashMap::new();

    // For each result entry in file2, check if the corresponding one exists in file1
    // Otherwise report
    for res in file2_reader.records() {
        let res = res?;
        let key = &res[args.key_column];
        let value = &res[args.value_column];

        if let Some((file1_result, file1_class)) = file1_results.get(key) {
            let file2_class = DiffClass::get(&classes, value);

            if file1_class != &file2_class {
                println!("mismatch at {}: {} vs {}", key, file1_result, value);
            } else {
                *class_count.entry(file1_class).or_insert(0) += 1;
            }
        } else {
            println!("{} does not exist in {}", key, &args.file1);
        }
    }

    for (class, count) in class_count {
        println!("matching class {:?}: {}", class, count);
    }

    Ok(())
}
