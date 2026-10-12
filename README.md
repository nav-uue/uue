# uue

A CLI file encryption utility powered by **AES-GCM**.

`uue` is a simple, secure command-line tool designed for **Linux systems** to encrypt and decrypt individual files or entire directories. It leverages modern cryptographic standards to keep your data safe and private.

## Features

* **Authenticated Encryption:** Uses **AES-GCM** via the `aes-gcm` crate for confidentiality and tamper-proof security.
* **Strong Key Derivation:** Uses **Argon2** (`argon2`) for secure, memory-hard password hashing.
* **Flexible Targets:** Accepts both individual file paths and full directories.
* **Recursive Processing:** Automatically processes all files inside a directory tree using `walkdir`.
* **Secure Input:** Prompts for passwords securely without echoing characters to the terminal via `rpassword`.

## Usage

### Encrypting

To encrypt a specific file or an entire directory:
```bash
uue encrypt --target[-t] /path/to/target
```
*If a directory is provided, `uue` recursively scans and encrypts every file found inside.*

### Decrypting

To decrypt a previously encrypted file or directory:
```bash
uue decrypt -target[-t] /path/to/target
```

## License

This project is licensed under the **MIT License**.