use std::path::Path;
use std::fs::File;
use std::io::Read;
use walkdir::WalkDir;


use crate::crypto::{AesCryptoEngine, SALT_LEN};
use crate::errors::AppError;
use crate::parser::Action;


pub struct RecursiveFsEngine<'a> {
    crypto_engine: &'a AesCryptoEngine,
    salt: [u8; SALT_LEN],
}


impl<'a> RecursiveFsEngine<'a> {
    /// Instantiates the filesystem traversal orchestration suite
    pub fn new(crypto_engine: &'a AesCryptoEngine, salt: [u8; SALT_LEN]) -> Self {
        Self { crypto_engine, salt }
    }

    /// Iterates across nested structures and feeds standard files into the crypto runner.
    pub fn process_path(&self, target_path: &Path, option: Action) -> Result<(), AppError> {
        // Validate if path exists prior to initialization
        if !target_path.exists() {
            return Err(AppError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Target path does not exist: {:?}", target_path),
            )));
        }

        // Execute WalkDir traversal sequence
        for entry in WalkDir::new(target_path)
            .into_iter()
            .filter_map(|e| e.ok()) // Gracefully skip unreadable symbolic links or permission-denied metadata nodes
        {
            let path = entry.path();
            
            // Explicitly filter out directories, processing files exclusively
            if path.is_file() {

                let result = match option {
                    Action::Encrypt => self.crypto_engine.encrypt_file(path, &self.salt),
                    Action::Decrypt => self.crypto_engine.decrypt_file(path, &self.salt),
                };

                if let Err(e) = result {
                    eprintln!("[-] Failed to {:?} processing block {:?}: {}", option, path, e);
                }

            }
        }

        Ok(())
    }

    pub fn read_salt_from_file(path: &Path) -> Result<[u8; SALT_LEN], AppError> {

        let mut salt = [0u8; SALT_LEN];

        // Extract the salt from the file
        if path.is_file() {
            let mut file = File::open(path)?;
            file.read_exact(&mut salt).map_err(|_| {
                AppError::EncryptionFailed("Failed to read salt: file too short".to_string())
            })?;
            
            return Ok(salt);
        }

        // If the path points to a directory, look for a file to extract the salt from
        if path.is_dir() {
            for entry in WalkDir::new(path)
                .into_iter()
                .filter_map(|e| e.ok()) // Gracefully skip unreadable symbolic links or broken references
            {
                let entry_path = entry.path();

                if entry_path.is_file() {
                    let mut file = File::open(entry_path)?;
                    
                    file.read_exact(&mut salt).map_err(|_| {
                        AppError::EncryptionFailed("Failed to read salt from directory file".to_string())
                    })?;

                    return Ok(salt);
                }
            }
        }
        
        Err(AppError::EncryptionFailed("No files found in directory to extract salt".to_string()))
    }

}
