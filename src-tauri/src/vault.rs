use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::crypto;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultEntry {
    pub id: String,
    pub entry_type: String,
    pub name: String,
    pub fields: HashMap<String, String>,
    pub notes: Option<String>,
    pub favorite: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Vault {
    pub entries: Vec<VaultEntry>,
    pub created_at: String,
    pub updated_at: String,
}

/// New encrypted vault format (no salt — key is provided directly)
#[derive(Serialize, Deserialize)]
struct EncryptedVault {
    nonce: String,
    data: String,
}

/// Legacy format (with salt — used for migration)
#[derive(Serialize, Deserialize)]
struct LegacyEncryptedVault {
    salt: String,
    nonce: String,
    data: String,
}

impl Vault {
    pub fn new() -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            entries: Vec::new(),
            created_at: now.clone(),
            updated_at: now,
        }
    }
}

pub fn generate_vault_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

pub fn save_vault(vault: &Vault, key: &[u8; 32], path: &Path) -> Result<(), String> {
    let json = serde_json::to_string(vault).map_err(|e| format!("Serialize error: {}", e))?;
    let (nonce, ciphertext) = crypto::encrypt(json.as_bytes(), key)?;

    let encrypted = EncryptedVault {
        nonce: BASE64.encode(&nonce),
        data: BASE64.encode(&ciphertext),
    };

    let content = serde_json::to_string_pretty(&encrypted)
        .map_err(|e| format!("Serialize error: {}", e))?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Dir create error: {}", e))?;
    }

    std::fs::write(path, content).map_err(|e| format!("File write error: {}", e))?;
    Ok(())
}

pub fn load_vault(path: &Path, key: &[u8; 32]) -> Result<Vault, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("File read error: {}", e))?;
    let encrypted: EncryptedVault =
        serde_json::from_str(&content).map_err(|e| format!("Parse error: {}", e))?;

    let nonce = BASE64
        .decode(&encrypted.nonce)
        .map_err(|e| format!("Base64 decode error: {}", e))?;
    let ciphertext = BASE64
        .decode(&encrypted.data)
        .map_err(|e| format!("Base64 decode error: {}", e))?;

    let plaintext = crypto::decrypt(&ciphertext, key, &nonce)?;

    let vault: Vault =
        serde_json::from_slice(&plaintext).map_err(|e| format!("Vault parse error: {}", e))?;
    Ok(vault)
}

/// Load a legacy vault file (with salt, password-derived key) — used for migration
pub fn load_legacy_vault(path: &Path, password: &str) -> Result<(Vault, [u8; 32], Vec<u8>), String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("File read error: {}", e))?;
    let encrypted: LegacyEncryptedVault =
        serde_json::from_str(&content).map_err(|e| format!("Parse error: {}", e))?;

    let salt = BASE64
        .decode(&encrypted.salt)
        .map_err(|e| format!("Base64 decode error: {}", e))?;
    let nonce = BASE64
        .decode(&encrypted.nonce)
        .map_err(|e| format!("Base64 decode error: {}", e))?;
    let ciphertext = BASE64
        .decode(&encrypted.data)
        .map_err(|e| format!("Base64 decode error: {}", e))?;

    let key = crypto::derive_key(password, &salt)?;
    let plaintext = crypto::decrypt(&ciphertext, &key, &nonce)?;

    let vault: Vault =
        serde_json::from_slice(&plaintext).map_err(|e| format!("Vault parse error: {}", e))?;
    Ok((vault, key, salt))
}

/// Encrypt vault data and return (nonce, ciphertext) as base64 strings — for cloud sync
pub fn encrypt_vault_for_cloud(vault: &Vault, key: &[u8; 32]) -> Result<(String, String), String> {
    let json = serde_json::to_string(vault).map_err(|e| format!("Serialize error: {}", e))?;
    let (nonce, ciphertext) = crypto::encrypt(json.as_bytes(), key)?;
    Ok((BASE64.encode(&nonce), BASE64.encode(&ciphertext)))
}

/// Decrypt vault data from cloud (base64 nonce + data)
pub fn decrypt_vault_from_cloud(
    data_b64: &str,
    nonce_b64: &str,
    key: &[u8; 32],
) -> Result<Vault, String> {
    let nonce = BASE64
        .decode(nonce_b64)
        .map_err(|e| format!("Base64 decode error: {}", e))?;
    let ciphertext = BASE64
        .decode(data_b64)
        .map_err(|e| format!("Base64 decode error: {}", e))?;

    let plaintext = crypto::decrypt(&ciphertext, key, &nonce)?;

    let vault: Vault =
        serde_json::from_slice(&plaintext).map_err(|e| format!("Vault parse error: {}", e))?;
    Ok(vault)
}
