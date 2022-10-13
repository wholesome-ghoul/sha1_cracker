use sha1::Digest;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader};

use clap::Parser;

const SHA1_HEX_STRING_LENGTH: usize = 40;

#[derive(Debug, Parser)]
struct Opts {
    #[arg(short, long, help = "Path to wordlist with common passwords")]
    wordlist: String,

    #[arg(short, long, help = "Sha1 hash to crack")]
    target: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Opts::parse();

    if args.target.len() != SHA1_HEX_STRING_LENGTH {
        return Err("sha1 hash is not valid".into());
    }

    let wordlist_file = File::open(&args.wordlist)?;
    let reader = BufReader::new(&wordlist_file);

    for line in reader.lines() {
        let line = line?;
        let common_password = line.trim();
        let hash_to_crack = hex::encode(sha1::Sha1::digest(common_password.as_bytes()));
        if hash_to_crack == args.target {
            println!("Found password: {}", common_password);
            return Ok(());
        }
    }

    println!("No password found.");

    Ok(())
}
