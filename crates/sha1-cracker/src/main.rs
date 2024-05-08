use error::Result;
use sha1_smol::DIGEST_LENGTH;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};

mod error;

fn main() -> Result<()> {
    // read args
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage:");
        println!("sha1_cracker: <wordlist.txt> <sha1_hash>");
        println!("or hash a password with: hash <password>");
        return Err("CliUsage error".into());
    }

    // create Sha1 object
    let mut hasher = sha1_smol::Sha1::new();

    // hash a password with cmd "hash"
    if args[1] == "hash" {
        hasher.update(args[2].as_bytes());
        println!(
            "Password \"{}\" hashed = {}",
            args[2],
            hasher.digest().to_string()
        );
        return Ok(());
    }

    // validate sha1 hash length
    let hash_to_crack = args[2].trim();
    if hash_to_crack.len() != DIGEST_LENGTH * 2 {
        return Err("sha1 hash is not valid".into());
    }

    // open wordlist file
    let wordlist_file = File::open(&args[1])?;
    let reader = BufReader::new(&wordlist_file);

    for line in reader.lines() {
        // hash the potential pwd
        hasher.reset();
        let password_attempt = line?.trim().to_string();
        hasher.update(password_attempt.as_bytes());
        let password_attempt_hash = hasher.digest().to_string();

        // validate pwd hash
        if hash_to_crack == password_attempt_hash {
            println!("Password finded: {}", password_attempt);
            return Ok(());
        }
    }

    println!("Password not found in wordlist");

    Ok(())
}
