use rand::{rngs::OsRng, Rng, TryRngCore};
use serde::{Serialize, Deserialize};
use std::{collections::HashMap, fs::{self, File}, io::{Read, Write}, path::PathBuf};
use aes_gcm::{Aes256Gcm, Key, Nonce,
aead::{Aead, KeyInit}};

const VAULT_FILE: &str = "passman_data/vault.json";

pub type Vault = HashMap<String, EncryptedPassword>;

#[derive(Serialize, Deserialize)]
pub struct EncryptedPassword{
    nonce: Vec<u8>,
    cipher: Vec<u8>
}

/// Load Vault HashMap from the vault file
pub fn load_vault() -> Vault{
    if !PathBuf::from(vault_path()).exists(){
        return HashMap::new();
    }

    let mut file = File::open(vault_path()).expect("File opening error");
    let mut data = String::new();
    file.read_to_string(&mut data).expect("File reading error");

    return serde_json::from_str::<Vault>(&data).expect("JSON parsing error"); 
}

/// Save vault HashMap to the vault file
pub fn save_vault(vault: &Vault){
    let json = serde_json::to_string_pretty(vault).expect("Error serializing passwords");
    
    let path = PathBuf::from(vault_path());
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("Unable to create vault directory");
    }

    let mut file = File::create(vault_path()).expect("Unable to create vault file");
    file.write_all(json.as_bytes()).expect("Unable to write vault file");
}

/// Encrypt a password with master_key and add it to the vault
fn add_password(vault: &mut Vault, label: &str, password: &str, master_key: &[u8]){
    let key = Key::<Aes256Gcm>::from_slice(master_key);

    let cipher = Aes256Gcm::new(key);

    let mut nonce = [0u8; 12];
    OsRng.try_fill_bytes(&mut nonce).expect("Nonce generation fail");

    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), password.as_bytes()).expect("Encryption fail");

    vault.insert(label.to_string(), EncryptedPassword { nonce: nonce.to_vec(), cipher: ciphertext.to_vec() });
}

/// Encrypt a password with master_key, add it to the vault and save vault in the vault file
pub fn add_and_save_password(vault: &mut Vault, label: &str, password: &str, master_key: &[u8]){
    add_password(vault, label, password, master_key);
    save_vault(vault);
}

/// Decrypts password with specified label and returns it or
/// none if there is no such label or it couldn't be decrypted.
pub fn get_password(label: &str, master_key: &[u8]) -> Option<String>{
    let vault = load_vault();

    let entry = vault.get(label)?;

    let key = Key::<Aes256Gcm>::from_slice(master_key);

    let cipher = Aes256Gcm::new(key);

    let password = cipher.decrypt(
        Nonce::from_slice(&entry.nonce),
    entry.cipher.as_ref()).ok()?;

    Some(String::from_utf8(password).expect("Decrypted password is not a valid UTF-8 string"))
}

/** 
 * Removes a password with specified label from the vault.
 * Panics if label doesn't exist.
*/ 
fn remove_password(vault: &mut Vault, label: &str){
    vault.remove(label).expect("Error removing password");
}

/**
 * Removes a password with specified label from the vault and
   saves it to the vault file.
 * Panics if label doesn't exist.
 */
pub fn remove_password_and_save(vault: &mut Vault, label: &str){
    remove_password(vault, label);
    save_vault(vault);
}

/// For switching master password, decrypts all passwords and encrypts them it new master password
pub fn change_encryption_to_new_master_password(vault: &mut Vault, old_master_key: &[u8], new_master_key: &[u8]){
    let keys: Vec<String> = vault.keys().cloned().collect();

    for label in keys{
        let password = get_password(&label, old_master_key).expect("Decrytion failed");
        
        // Modifying only HashMap, without saving to file
        remove_password(vault, &label);
        add_password(vault, &label, &password, new_master_key);
    }

    // Save new vault
    save_vault(vault);
}

pub fn generate_random_password() -> String{
    // Printable ASCII characters
    let characters: Vec<char> = (0x20u8..=0x7Eu8).map(|c| c as char).collect();
    let mut rng = rand::rng();

    // Every password will have fixed length (no point in allowing users to change this)
    let len = 32;

    return (0..len).map(|_| characters[rng.random_range(0..characters.len())]).collect();
}

fn vault_path() -> PathBuf{
    let mut path = dirs::data_dir().expect("Couldn't find data dir");
    path.push(VAULT_FILE);

    return path;
}
