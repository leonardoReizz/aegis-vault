use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::crypto;

/// Metadata about a single vault
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultMeta {
    pub id: String,
    pub name: String,
    pub cloud_sync: bool,
    pub role: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Per-vault key material (the vault's symmetric key encrypted with the master key)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultKeyEntry {
    pub vault_id: String,
    pub encrypted_key: String, // base64
    pub key_nonce: String,     // base64
}

/// The vault registry: list of all vaults + encrypted keys
/// Stored as an encrypted file per user
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultRegistry {
    pub vaults: Vec<VaultMeta>,
    pub keys: Vec<VaultKeyEntry>,
}

impl VaultRegistry {
    pub fn new() -> Self {
        Self {
            vaults: Vec::new(),
            keys: Vec::new(),
        }
    }

    /// Add a vault with its key encrypted by the master key
    pub fn add_vault(
        &mut self,
        meta: VaultMeta,
        vault_key: &[u8; 32],
        master_key: &[u8; 32],
    ) -> Result<(), String> {
        let (nonce, encrypted) = crypto::encrypt(vault_key, master_key)?;
        self.keys.push(VaultKeyEntry {
            vault_id: meta.id.clone(),
            encrypted_key: BASE64.encode(&encrypted),
            key_nonce: BASE64.encode(&nonce),
        });
        self.vaults.push(meta);
        Ok(())
    }

    /// Get the decrypted vault key for a given vault id
    pub fn get_vault_key(
        &self,
        vault_id: &str,
        master_key: &[u8; 32],
    ) -> Result<[u8; 32], String> {
        let key_entry = self
            .keys
            .iter()
            .find(|k| k.vault_id == vault_id)
            .ok_or("Vault key not found in registry")?;

        let encrypted = BASE64
            .decode(&key_entry.encrypted_key)
            .map_err(|e| format!("Base64 decode error: {}", e))?;
        let nonce = BASE64
            .decode(&key_entry.key_nonce)
            .map_err(|e| format!("Base64 decode error: {}", e))?;

        let decrypted = crypto::decrypt(&encrypted, master_key, &nonce)?;

        let mut key = [0u8; 32];
        if decrypted.len() != 32 {
            return Err("Invalid vault key length".to_string());
        }
        key.copy_from_slice(&decrypted);
        Ok(key)
    }

    /// Remove a vault and its key from the registry
    pub fn remove_vault(&mut self, vault_id: &str) {
        self.vaults.retain(|v| v.id != vault_id);
        self.keys.retain(|k| k.vault_id != vault_id);
    }
}

/// Encrypted registry file format
#[derive(Serialize, Deserialize)]
struct EncryptedRegistry {
    nonce: String,
    data: String,
}

pub fn save_registry(
    registry: &VaultRegistry,
    master_key: &[u8; 32],
    path: &Path,
) -> Result<(), String> {
    let json =
        serde_json::to_string(registry).map_err(|e| format!("Serialize error: {}", e))?;
    let (nonce, ciphertext) = crypto::encrypt(json.as_bytes(), master_key)?;

    let encrypted = EncryptedRegistry {
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

pub fn load_registry(path: &Path, master_key: &[u8; 32]) -> Result<VaultRegistry, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("File read error: {}", e))?;
    let encrypted: EncryptedRegistry =
        serde_json::from_str(&content).map_err(|e| format!("Parse error: {}", e))?;

    let nonce = BASE64
        .decode(&encrypted.nonce)
        .map_err(|e| format!("Base64 decode error: {}", e))?;
    let ciphertext = BASE64
        .decode(&encrypted.data)
        .map_err(|e| format!("Base64 decode error: {}", e))?;

    let plaintext = crypto::decrypt(&ciphertext, master_key, &nonce)?;

    let registry: VaultRegistry = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Registry parse error: {}", e))?;
    Ok(registry)
}
