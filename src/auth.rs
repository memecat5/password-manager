use argon2::{Argon2};
use rand::TryRngCore;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use rand::rngs::OsRng;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce, Key
};

const SALT_FILE: &str = "passwd_data/salt.bin";
const VERIFY_FILE: &str = "passwd_data/verify.bin";


/// Checks if salt file exists — i.e., if master password was set before
pub fn master_password_exists() -> bool {
    PathBuf::from(create_path(SALT_FILE)).exists() && PathBuf::from(create_path(VERIFY_FILE)).exists()
}

/// Generates a new random salt, stores it in a file and returns it
pub fn generate_and_store_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.try_fill_bytes(&mut salt).expect("Error when creating salt");

    let path = PathBuf::from(create_path(SALT_FILE));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("Unable to create salt directory");
    }

    let mut file = File::create(&path).expect("Unable to create salt file");
    file.write_all(&salt).expect("Unable to write salt to file");

    return salt;
}

/// Loads the salt from the file, returns None if file doesn't exist
pub fn load_salt() -> Option<[u8; 16]> {
    let path = PathBuf::from(create_path(SALT_FILE));
    if !path.exists() {
        return None;
    }

    let mut file = File::open(&path).ok()?;
    let mut salt = [0u8; 16];
    file.read_exact(&mut salt).ok()?;
    
    return Some(salt);
}

/// Derives a master key from the master password and salt using Argon2
pub fn derive_master_key(master_password: &str, salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::default();
    let mut output_key = [0u8; 32]; // 256-bit key
    argon2.hash_password_into(master_password.as_bytes(), salt, &mut output_key)
        .expect("Argon2 key derivation failed");
    
    return output_key;
}

/// Creates and stores a random verification token encrypted with master_key.
/// Call this on first master password setup.
pub fn create_verification_token(master_key: &[u8]) {
    // Wygeneruj losowy token 32 bajty
    let mut token = [0u8; 32];
    OsRng.try_fill_bytes(&mut token).expect("Error generating verification token");

    // Szyfrujemy token AES-GCM, klucz master_key, nonce losowy 12 bajtów
    let key = Key::<Aes256Gcm>::from_slice(master_key);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.try_fill_bytes(&mut nonce_bytes).expect("Error generating nonce");
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, token.as_ref())
        .expect("Encryption failed");

    // Zapisujemy nonce + ciphertext do pliku verify.bin
    let path = PathBuf::from(create_path(VERIFY_FILE));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("Unable to create verify directory");
    }
    let mut file = File::create(path).expect("Unable to create verify file");

    // Format: [nonce(12 bytes)] + [ciphertext]
    file.write_all(&nonce_bytes).expect("Write nonce failed");
    file.write_all(&ciphertext).expect("Write ciphertext failed");
}

/// Weryfikuje master_key poprzez próbę odszyfrowania verification token.
/// Zwraca true, jeśli odszyfrowanie się powiodło, false w przeciwnym razie.
pub fn verify_master_key(master_key: &[u8]) -> bool {
    let path = PathBuf::from(create_path(VERIFY_FILE));
    if !path.exists() {
        return false;
    }

    let mut file = File::open(path).expect("Unable to open verify file");
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).expect("Unable to read verify file");

    if contents.len() < 12 {
        panic!("Master key verification file was tampered with");
    }

    let (nonce_bytes, ciphertext) = contents.split_at(12);

    let key = Key::<Aes256Gcm>::from_slice(master_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, ciphertext).is_ok()
}

fn create_path(file_name: &str) -> PathBuf{
    let mut path = dirs::data_dir().expect("Couldn't find default data directory");
    path.push(file_name);
    return path;
}