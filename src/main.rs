use clap::Parser;
use rand::{RngCore, thread_rng};


mod crypto;
use crypto::{AesCryptoEngine, SALT_LEN};
mod fs_engine;
use fs_engine::RecursiveFsEngine;
mod parser;
use parser::{Action, BANNER};
mod errors;


fn main() -> Result<(), Box<dyn std::error::Error>> {

    println!("{BANNER}");

    let args = parser::Args::parse();

    let config = rpassword::ConfigBuilder::new()
        .password_feedback_mask('*')
        .build();

    // Gather raw context configuration vector securely from TTY prompt stdin
    let passphrase = rpassword::prompt_password_with_config("Enter Master Passphrase: ", config)?;
    println!("");

    if passphrase.is_empty() {
        eprintln!("[-] Error: Master passphrase cannot be blank.");
        std::process::exit(1);
    }

    // Generate cryptographically safe operational salt block sequence initialization
    let mut salt = [0u8; SALT_LEN];

    match args.action {
        Action::Encrypt => thread_rng().fill_bytes(&mut salt),
        Action::Decrypt => {
            let file_salt = RecursiveFsEngine::read_salt_from_file(&args.target)?;
            salt.copy_from_slice(&file_salt);
        },
    };

    // Process key derivation via KDF Pipeline integration pipeline
    println!("[*] Deriving operational cryptokey parameters via Argon2id...");
    let derived_key = AesCryptoEngine::derive_key(passphrase.as_bytes(), &salt)?;

    // Initialize encryption suite interface framework setup.
    let crypto_engine = AesCryptoEngine::new(&derived_key);
    let fs_engine = RecursiveFsEngine::new(&crypto_engine, salt);

    // Execute recursive system payload iteration engine
    println!("[*] Commencing cryptographic sweep operations...");

    fs_engine.process_path(&args.target, args.action)?;
    
    println!("[+] Execution runtime lifecycle finished successfully.");
    Ok(())

}
