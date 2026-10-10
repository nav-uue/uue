use argon2::{Argon2, Params, Algorithm, Version};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce, Key
};
use rand::{RngCore, thread_rng};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;


use crate::errors::AppError;


// Constants defining binary layout allocation sizes
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32; // 256 bits for AES-256


pub struct AesCryptoEngine {
    cipher: Aes256Gcm,
}


impl AesCryptoEngine {
    /// Derives a secure 256-bit key from a raw passphrase using Argon2id.
    pub fn derive_key(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; KEY_LEN], AppError> {
        // Standard Argon2id profile setup with production parameters
        // m_cost = 65536 (64 MB RAM), t_cost = 3 iterations, p_cost = 4 parallel threads
        let params = Params::new(65536, 3, 4, Some(KEY_LEN))
            .map_err(|e| AppError::EncryptionFailed(format!("Invalid Argon2 params: {}", e)))?;
        
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            params
        );

        let mut key = [0u8; KEY_LEN];

        // Derive a secure encryption key from the user passphrase using the Argon2 KDF
        argon2.hash_password_into(passphrase, salt, &mut key)
            .map_err(|e| AppError::EncryptionFailed(format!("KDF execution failed: {}", e)))?;

        Ok(key)

    }
    
    /// Initializes the engine using an already derived key buffer
    pub fn new(key_bytes: &[u8; KEY_LEN]) -> Self {
        let key = Key::<Aes256Gcm>::from(*key_bytes);
        let cipher = Aes256Gcm::new(&key);
        Self { cipher }
    }

    /// Encrypts an individual file in-place or outputs a mutated state.
    /// Encrypted format layout: [16B Salt] + [12B Nonce] + [Encrypted Data Payload]
    pub fn encrypt_file(&self, path: &Path, salt: &[u8; SALT_LEN]) -> Result<(), AppError> {
        // Read entire contents of target file
        let mut file = File::open(path)?;
        let mut plaintext = Vec::new();
        file.read_to_end(&mut plaintext)?;

        // Generate a unique cryptographically secure cryptorandom Nonce
        let mut nonce_bytes = [0u8; NONCE_LEN];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        // Encrypt payload data using authenticated AES-GCM-256
        let ciphertext = self.cipher.encrypt(&nonce, plaintext.as_slice())?;

        // Overwrite file with standard binary header layout sequence
        // let mut out_file = OpenOptions::new()
        //     .write(true)
        //     .truncate(true)
        //     .open(path)?;

        // Create the encrypted file and remove the unencrypted original
        if let Some(file_name) = path.file_name() {

            let mut new_name = file_name.to_os_string();
            new_name.push(".uue");

            let new_path = path.with_file_name(new_name);

            match File::create(&new_path) {
                Ok(mut out_file) => {

                    out_file.write_all(salt)?;
                    out_file.write_all(&nonce_bytes)?;
                    out_file.write_all(&ciphertext)?;
                    out_file.flush()?;

                    match fs::read(&new_path) {
                        Ok(save_data) => {
                            let expected_len = salt.len() + nonce_bytes.len() + ciphertext.len();
                            if save_data.len() == expected_len {
                                fs::remove_file(path)?;
                            }
                            println!("[+] File encrypted successfully: {:?}", path);
                        },
                        Err(e) => eprintln!("Error: {}", e),
                    }
                }
                Err(e) => eprintln!("Error: {}", e)
            }

        }

        Ok(())
    }

    pub fn decrypt_file(&self, path: &Path, _salt: &[u8; SALT_LEN]) -> Result<(), AppError> {
        // Open encrypted file (.uue) for reading
        let mut file = File::open(path)?;
        let mut file_bytes = Vec::new();
        file.read_to_end(&mut file_bytes)?;

        // Expect a full header: SALT_LEN + NONCE_LEN bytes
        let header_len = SALT_LEN + NONCE_LEN;
        if file_bytes.len() < header_len {
            return Err(AppError::EncryptionFailed("File too short or corrupted".to_string()));
        }

        // Parse the file into cryptographic components using slices.
        // The salt is already provided in the function arguments, 
        // so we only extract the nonce and the ciphertext here.
        let nonce_bytes = &file_bytes[SALT_LEN..header_len];
        let ciphertext = &file_bytes[header_len..];

        // Restore the Nonce type from bytes
        let mut fixed_nonce = [0u8; NONCE_LEN];
        fixed_nonce.copy_from_slice(nonce_bytes);
        let nonce = Nonce::from(fixed_nonce);

        // Decryption
        let plaintext = self.cipher.decrypt(&nonce, ciphertext)?;

        // Save the original file and clean up
        if let Some(file_name) = path.file_name() {
            let file_name_str = file_name.to_string_lossy();
            
            // Check the extension and strip ".uue" (4 characters)
            if file_name_str.ends_with(".uue") {
                let original_name = &file_name_str[..file_name_str.len() - 4];
                let original_path = path.with_file_name(original_name);

                // Create the clean original file
                let mut out_file = File::create(&original_path)?;
                out_file.write_all(&plaintext)?;
                out_file.flush()?; // Ensure data is physically written to disk

                // Remove the encrypted file only after the original is successfully saved
                fs::remove_file(path)?;
                println!("[+] File decrypted successfully: {:?}", original_path);
            } else {
                return Err(AppError::EncryptionFailed("Invalid file extension. Expected .uue".to_string()));
            }
        }

        Ok(())
    }

}