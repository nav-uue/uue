use std::fmt;
use std::io;


#[derive(Debug)]
pub enum AppError {
    Io(io::Error),
    Crypto(aes_gcm::Error),
    Argon(argon2::password_hash::Error),
    WalkDir(walkdir::Error),
    EncryptionFailed(String),
}


impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Io(err) => write!(f, "I/O Error: {}", err),
            AppError::Crypto(err) => write!(f, "AES-GCM Crypto Error: {}", err),
            AppError::Argon(err) => write!(f, "Argon2 KDF Error: {}", err),
            AppError::WalkDir(err) => write!(f, "Filesystem Traversal Error: {}", err),
            AppError::EncryptionFailed(msg) => write!(f, "Encryption Failure: {}", msg),
        }
    }
}


impl std::error::Error for AppError {}


// Implement boilerplate From traits for automatic conversion via the `?` operator
impl From<io::Error> for AppError { 
    fn from(err: io::Error) -> Self { AppError::Io(err) } 
}

impl From<aes_gcm::Error> for AppError { 
    fn from(err: aes_gcm::Error) -> Self { AppError::Crypto(err) } 
}

impl From<argon2::password_hash::Error> for AppError { 
    fn from(err: argon2::password_hash::Error) -> Self { AppError::Argon(err) } 
}

impl From<walkdir::Error> for AppError { 
    fn from(err: walkdir::Error) -> Self { AppError::WalkDir(err) } 
}
