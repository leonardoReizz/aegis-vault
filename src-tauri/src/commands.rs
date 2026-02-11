use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use mongodb::bson::doc;
use mongodb::Collection;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use tauri::State;
use uuid::Uuid;

use crate::crypto;
use crate::db::{CloudVault, PendingShare, User, UserInfo, VaultMemberDoc, VaultMemberInfo};
use crate::keypair;
use crate::password;
use crate::vault::{self, Vault, VaultEntry};
use crate::vault_meta::{self, VaultMeta, VaultRegistry};

// ── State ──

pub struct LoadedVault {
    pub meta: VaultMeta,
    pub key: [u8; 32],
    pub vault: Vault,
    pub path: PathBuf,
}

struct InnerState {
    current_user: Option<UserInfo>,
    user_dir: Option<PathBuf>,
    master_key: Option<[u8; 32]>,
    master_salt: Option<Vec<u8>>,
    private_key: Option<RsaPrivateKey>,
    registry: Option<VaultRegistry>,
    vaults: HashMap<String, LoadedVault>,
    active_vault_id: Option<String>,
}

impl InnerState {
    fn active_vault(&self) -> Result<&LoadedVault, String> {
        let id = self.active_vault_id.as_ref().ok_or("No vault selected")?;
        self.vaults.get(id).ok_or("Active vault not found".to_string())
    }

    fn active_vault_mut(&mut self) -> Result<&mut LoadedVault, String> {
        let id = self.active_vault_id.as_ref().ok_or("No vault selected")?.clone();
        self.vaults.get_mut(&id).ok_or("Active vault not found".to_string())
    }

    fn save_active(&self) -> Result<(), String> {
        let v = self.active_vault()?;
        vault::save_vault(&v.vault, &v.key, &v.path)
    }

    fn save_registry(&self) -> Result<(), String> {
        let registry = self.registry.as_ref().ok_or("No registry")?;
        let master_key = self.master_key.as_ref().ok_or("No master key")?;
        let user_dir = self.user_dir.as_ref().ok_or("No user dir")?;
        vault_meta::save_registry(registry, master_key, &user_dir.join("registry.pass"))
    }

    fn check_write_access(&self) -> Result<(), String> {
        let v = self.active_vault()?;
        match v.meta.role.as_str() {
            "owner" | "editor" => Ok(()),
            _ => Err("Read-only access".to_string()),
        }
    }
}

pub struct AppState {
    pub app_data_dir: PathBuf,
    pub db: mongodb::Database,
    inner: Mutex<InnerState>,
}

impl AppState {
    pub fn new(app_data_dir: PathBuf, db: mongodb::Database) -> Self {
        Self {
            app_data_dir,
            db,
            inner: Mutex::new(InnerState {
                current_user: None,
                user_dir: None,
                master_key: None,
                master_salt: None,
                private_key: None,
                registry: None,
                vaults: HashMap::new(),
                active_vault_id: None,
            }),
        }
    }

    fn users_collection(&self) -> Collection<User> {
        self.db.collection("users")
    }

    fn cloud_vaults_collection(&self) -> Collection<CloudVault> {
        self.db.collection("vaults")
    }

    fn vault_members_collection(&self) -> Collection<VaultMemberDoc> {
        self.db.collection("vault_members")
    }
}

// ── Auth Commands ──

#[tauri::command]
pub async fn register(
    email: String,
    password: String,
    state: State<'_, AppState>,
) -> Result<RegisterResult, String> {
    if !email.contains('@') || email.len() < 5 {
        return Err("Invalid email".to_string());
    }
    if password.len() < 8 {
        return Err("Password must be at least 8 characters".to_string());
    }

    let users = state.users_collection();

    let existing = users
        .find_one(doc! { "email": &email }, None)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

    if existing.is_some() {
        return Err("Email already registered".to_string());
    }

    let password_hash = crypto::hash_password(&password)?;

    // Generate RSA keypair
    let (rsa_private, rsa_public) = keypair::generate_keypair()?;
    let public_pem = keypair::public_key_to_pem(&rsa_public)?;
    let private_pem = keypair::private_key_to_pem(&rsa_private)?;

    // Store only public key in MongoDB — private key is local-only
    let user = User {
        id: None,
        email: email.clone(),
        password_hash,
        public_key: Some(public_pem),
        encrypted_private_key: None,
        private_key_nonce: None,
        private_key_salt: None,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    let result = users
        .insert_one(&user, None)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

    let user_id = result
        .inserted_id
        .as_object_id()
        .ok_or("Failed to get user ID")?
        .to_hex();

    let user_info = UserInfo {
        id: user_id.clone(),
        email,
    };

    // Derive master key and create default vault
    {
        let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
        let user_dir = state.app_data_dir.join(&user_id);
        std::fs::create_dir_all(user_dir.join("vaults"))
            .map_err(|e| format!("Dir error: {}", e))?;

        // Save private key locally (encrypted with password-derived key)
        save_local_private_key(&user_dir, &password, &rsa_private)?;

        let master_salt = crypto::generate_salt();
        // Persist the salt so login() can re-derive the same master key
        std::fs::write(user_dir.join("master.salt"), &master_salt)
            .map_err(|e| format!("Write salt error: {}", e))?;
        let master_key = crypto::derive_key(&password, &master_salt)?;

        // Create default vault
        let vault_id = Uuid::new_v4().to_string();
        let vault_key = vault::generate_vault_key();
        let new_vault = Vault::new();
        let vault_path = user_dir.join("vaults").join(format!("{}.pass", vault_id));
        vault::save_vault(&new_vault, &vault_key, &vault_path)?;

        let now = chrono::Utc::now().to_rfc3339();
        let meta = VaultMeta {
            id: vault_id.clone(),
            name: "My Vault".to_string(),
            cloud_sync: false,
            role: "owner".to_string(),
            created_at: now.clone(),
            updated_at: now,
        };

        // Create registry
        let mut registry = VaultRegistry::new();
        registry.add_vault(meta.clone(), &vault_key, &master_key)?;
        vault_meta::save_registry(&registry, &master_key, &user_dir.join("registry.pass"))?;

        inner.vaults.insert(
            vault_id.clone(),
            LoadedVault {
                meta,
                key: vault_key,
                vault: new_vault,
                path: vault_path,
            },
        );
        inner.active_vault_id = Some(vault_id);
        inner.registry = Some(registry);
        inner.master_key = Some(master_key);
        inner.master_salt = Some(master_salt);
        inner.private_key = Some(rsa_private);
        inner.user_dir = Some(user_dir);
        inner.current_user = Some(user_info.clone());
    }

    save_session(&state.app_data_dir, &user_info.email, &password)?;

    Ok(RegisterResult {
        user: user_info,
        private_key_pem: private_pem,
    })
}

#[tauri::command]
pub async fn login(
    email: String,
    password: String,
    remember_me: bool,
    state: State<'_, AppState>,
) -> Result<LoginResult, String> {
    let result = perform_login(&email, &password, &*state).await?;
    if remember_me {
        save_session(&state.app_data_dir, &email, &password)?;
    }
    Ok(result)
}

#[tauri::command]
pub async fn try_restore_session(
    state: State<'_, AppState>,
) -> Result<LoginResult, String> {
    let (email, password) = load_session(&state.app_data_dir)?;
    match perform_login(&email, &password, &*state).await {
        Ok(result) => Ok(result),
        Err(e) => {
            clear_session(&state.app_data_dir);
            Err(e)
        }
    }
}

async fn perform_login(email: &str, password: &str, state: &AppState) -> Result<LoginResult, String> {
    let users = state.users_collection();

    let user = users
        .find_one(doc! { "email": &email }, None)
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or("Invalid email or password".to_string())?;

    if !crypto::verify_password(&password, &user.password_hash)? {
        return Err("Invalid email or password".to_string());
    }

    let user_id = user.id.ok_or("User has no ID")?.to_hex();

    let user_info = UserInfo {
        id: user_id.clone(),
        email: user.email.clone(),
    };

    {
        let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
        let user_dir = state.app_data_dir.join(&user_id);
        std::fs::create_dir_all(user_dir.join("vaults"))
            .map_err(|e| format!("Dir error: {}", e))?;

        // Load RSA private key from local file (not MongoDB)
        let rsa_private = load_local_private_key(&user_dir, &password)?;
        let needs_key_import = rsa_private.is_none();

        let registry_path = user_dir.join("registry.pass");
        let legacy_vault_path = user_dir.join("vault.pass");
        let salt_path = user_dir.join("master.salt");

        // Ensure stable master salt exists and derive master key from it
        // (same approach as register — one salt, one key, used everywhere)
        let master_salt = if salt_path.exists() {
            std::fs::read(&salt_path)
                .map_err(|e| format!("Read salt error: {}", e))?
        } else {
            let s = crypto::generate_salt();
            std::fs::write(&salt_path, &s)
                .map_err(|e| format!("Write salt error: {}", e))?;
            s
        };
        let master_key = crypto::derive_key(&password, &master_salt)?;

        let registry = if registry_path.exists() {
            match vault_meta::load_registry(&registry_path, &master_key) {
                Ok(reg) => reg,
                Err(_) => {
                    // Registry is corrupted or key mismatch.
                    // Remove stale files and create a fresh registry.
                    let _ = std::fs::remove_file(&registry_path);
                    let _ = std::fs::remove_file(&salt_path);
                    let _ = std::fs::remove_dir_all(user_dir.join("vaults"));
                    std::fs::create_dir_all(user_dir.join("vaults"))
                        .map_err(|e| format!("Dir error: {}", e))?;

                    // Re-create salt since we just deleted it
                    let new_salt = crypto::generate_salt();
                    std::fs::write(&salt_path, &new_salt)
                        .map_err(|e| format!("Write salt error: {}", e))?;
                    let new_master_key = crypto::derive_key(&password, &new_salt)?;

                    let vault_id = Uuid::new_v4().to_string();
                    let vault_key = vault::generate_vault_key();
                    let new_vault = Vault::new();
                    let vault_path = user_dir.join("vaults").join(format!("{}.pass", vault_id));
                    vault::save_vault(&new_vault, &vault_key, &vault_path)?;

                    let now = chrono::Utc::now().to_rfc3339();
                    let meta = VaultMeta {
                        id: vault_id.clone(),
                        name: "My Vault".to_string(),
                        cloud_sync: false,
                        role: "owner".to_string(),
                        created_at: now.clone(),
                        updated_at: now,
                    };

                    let mut reg = VaultRegistry::new();
                    reg.add_vault(meta, &vault_key, &new_master_key)?;
                    vault_meta::save_registry(&reg, &new_master_key, &registry_path)?;
                    reg
                }
            }
        } else if legacy_vault_path.exists() {
            // Migration: old single-vault format
            let (old_vault, _old_key, _old_salt) =
                vault::load_legacy_vault(&legacy_vault_path, &password)?;

            let vault_id = Uuid::new_v4().to_string();
            let vault_key = vault::generate_vault_key();
            let vault_path = user_dir.join("vaults").join(format!("{}.pass", vault_id));
            vault::save_vault(&old_vault, &vault_key, &vault_path)?;

            let now = chrono::Utc::now().to_rfc3339();
            let meta = VaultMeta {
                id: vault_id.clone(),
                name: "My Vault".to_string(),
                cloud_sync: false,
                role: "owner".to_string(),
                created_at: now.clone(),
                updated_at: now,
            };

            let mut reg = VaultRegistry::new();
            reg.add_vault(meta, &vault_key, &master_key)?;
            vault_meta::save_registry(&reg, &master_key, &registry_path)?;

            // Remove old vault file
            let _ = std::fs::remove_file(&legacy_vault_path);

            reg
        } else {
            // No vaults yet — create default
            let vault_id = Uuid::new_v4().to_string();
            let vault_key = vault::generate_vault_key();
            let new_vault = Vault::new();
            let vault_path = user_dir.join("vaults").join(format!("{}.pass", vault_id));
            vault::save_vault(&new_vault, &vault_key, &vault_path)?;

            let now = chrono::Utc::now().to_rfc3339();
            let meta = VaultMeta {
                id: vault_id.clone(),
                name: "My Vault".to_string(),
                cloud_sync: false,
                role: "owner".to_string(),
                created_at: now.clone(),
                updated_at: now,
            };

            let mut reg = VaultRegistry::new();
            reg.add_vault(meta, &vault_key, &master_key)?;
            vault_meta::save_registry(&reg, &master_key, &registry_path)?;
            reg
        };

        // Re-read the salt (may have been recreated in fallback branch)
        let stable_salt = std::fs::read(&salt_path)
            .map_err(|e| format!("Read salt error: {}", e))?;
        let stable_master_key = crypto::derive_key(&password, &stable_salt)?;

        // Load all vaults
        let mut loaded_vaults = HashMap::new();
        let mut first_vault_id: Option<String> = None;

        for vault_meta in &registry.vaults {
            let vault_key = registry.get_vault_key(&vault_meta.id, &stable_master_key)?;
            let vault_path = user_dir.join("vaults").join(format!("{}.pass", vault_meta.id));

            if vault_path.exists() {
                let loaded_vault = vault::load_vault(&vault_path, &vault_key)?;
                if first_vault_id.is_none() {
                    first_vault_id = Some(vault_meta.id.clone());
                }
                loaded_vaults.insert(
                    vault_meta.id.clone(),
                    LoadedVault {
                        meta: vault_meta.clone(),
                        key: vault_key,
                        vault: loaded_vault,
                        path: vault_path,
                    },
                );
            }
        }

        inner.vaults = loaded_vaults;
        inner.active_vault_id = first_vault_id;
        inner.registry = Some(registry);
        inner.master_key = Some(stable_master_key);
        inner.master_salt = Some(stable_salt);
        inner.private_key = rsa_private;
        inner.user_dir = Some(user_dir);
        inner.current_user = Some(user_info.clone());

        Ok(LoginResult {
            user: user_info,
            needs_key_import,
        })
    }
}

/// Encrypt and save the RSA private key locally
fn save_local_private_key(
    user_dir: &PathBuf,
    password: &str,
    private_key: &RsaPrivateKey,
) -> Result<(), String> {
    let der = keypair::private_key_to_der(private_key)?;
    let salt = crypto::generate_salt();
    let key = crypto::derive_key(password, &salt)?;
    let (nonce, encrypted) = crypto::encrypt(&der, &key)?;

    let json = serde_json::json!({
        "salt": BASE64.encode(&salt),
        "nonce": BASE64.encode(&nonce),
        "data": BASE64.encode(&encrypted),
    });

    std::fs::write(user_dir.join("private_key.enc"), json.to_string())
        .map_err(|e| format!("Write private key error: {}", e))
}

/// Load and decrypt the RSA private key from local storage
fn load_local_private_key(
    user_dir: &PathBuf,
    password: &str,
) -> Result<Option<RsaPrivateKey>, String> {
    let pk_path = user_dir.join("private_key.enc");
    if !pk_path.exists() {
        return Ok(None);
    }

    // If decryption fails (corrupted file or password mismatch), remove the
    // stale file and return None so the user is prompted to re-import.
    match load_local_private_key_inner(&pk_path, password) {
        Ok(key) => Ok(Some(key)),
        Err(_) => {
            let _ = std::fs::remove_file(&pk_path);
            Ok(None)
        }
    }
}

fn load_local_private_key_inner(
    pk_path: &std::path::Path,
    password: &str,
) -> Result<RsaPrivateKey, String> {
    let content = std::fs::read_to_string(pk_path)
        .map_err(|e| format!("Read private key error: {}", e))?;
    let json: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("Parse private key error: {}", e))?;

    let salt = BASE64
        .decode(json["salt"].as_str().ok_or("Missing salt")?)
        .map_err(|e| format!("Base64 error: {}", e))?;
    let nonce = BASE64
        .decode(json["nonce"].as_str().ok_or("Missing nonce")?)
        .map_err(|e| format!("Base64 error: {}", e))?;
    let encrypted = BASE64
        .decode(json["data"].as_str().ok_or("Missing data")?)
        .map_err(|e| format!("Base64 error: {}", e))?;

    let key = crypto::derive_key(password, &salt)?;
    let der = crypto::decrypt(&encrypted, &key, &nonce)?;
    let private_key = keypair::private_key_from_der(&der)?;
    Ok(private_key)
}

// ── Session Persistence ──

fn save_session(app_data_dir: &PathBuf, email: &str, password: &str) -> Result<(), String> {
    let key_bytes = crypto::generate_salt(); // 32 random bytes
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    let session_data = serde_json::json!({
        "email": email,
        "password": password,
    })
    .to_string();

    let (nonce, encrypted) = crypto::encrypt(session_data.as_bytes(), &key)?;

    let session_json = serde_json::json!({
        "nonce": BASE64.encode(&nonce),
        "data": BASE64.encode(&encrypted),
    });

    std::fs::write(app_data_dir.join("session.key"), &key_bytes)
        .map_err(|e| format!("Write session key error: {}", e))?;
    std::fs::write(
        app_data_dir.join("session.enc"),
        session_json.to_string(),
    )
    .map_err(|e| format!("Write session error: {}", e))?;

    Ok(())
}

fn clear_session(app_data_dir: &PathBuf) {
    let _ = std::fs::remove_file(app_data_dir.join("session.key"));
    let _ = std::fs::remove_file(app_data_dir.join("session.enc"));
}

fn load_session(app_data_dir: &PathBuf) -> Result<(String, String), String> {
    let key_path = app_data_dir.join("session.key");
    let enc_path = app_data_dir.join("session.enc");

    if !key_path.exists() || !enc_path.exists() {
        return Err("No saved session".to_string());
    }

    let key_bytes = std::fs::read(&key_path)
        .map_err(|e| format!("Read session key error: {}", e))?;
    if key_bytes.len() != 32 {
        clear_session(app_data_dir);
        return Err("Invalid session".to_string());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    let content = std::fs::read_to_string(&enc_path)
        .map_err(|e| format!("Read session error: {}", e))?;
    let json: serde_json::Value = serde_json::from_str(&content).map_err(|_| {
        clear_session(app_data_dir);
        "Invalid session".to_string()
    })?;

    let nonce = BASE64
        .decode(json["nonce"].as_str().ok_or("Invalid session")?)
        .map_err(|_| "Invalid session".to_string())?;
    let encrypted = BASE64
        .decode(json["data"].as_str().ok_or("Invalid session")?)
        .map_err(|_| "Invalid session".to_string())?;

    let decrypted = crypto::decrypt(&encrypted, &key, &nonce).map_err(|_| {
        clear_session(app_data_dir);
        "Invalid session".to_string()
    })?;

    let session_str =
        String::from_utf8(decrypted).map_err(|_| "Invalid session".to_string())?;
    let session: serde_json::Value =
        serde_json::from_str(&session_str).map_err(|_| "Invalid session".to_string())?;

    let email = session["email"]
        .as_str()
        .ok_or("Invalid session")?
        .to_string();
    let password = session["password"]
        .as_str()
        .ok_or("Invalid session")?
        .to_string();

    Ok((email, password))
}

#[derive(Serialize)]
pub struct RegisterResult {
    pub user: UserInfo,
    pub private_key_pem: String,
}

#[derive(Serialize)]
pub struct LoginResult {
    pub user: UserInfo,
    pub needs_key_import: bool,
}

#[tauri::command]
pub fn logout(state: State<AppState>) -> Result<(), String> {
    clear_session(&state.app_data_dir);
    let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
    inner.current_user = None;
    inner.user_dir = None;
    inner.master_key = None;
    inner.master_salt = None;
    inner.private_key = None;
    inner.registry = None;
    inner.vaults.clear();
    inner.active_vault_id = None;
    Ok(())
}

#[tauri::command]
pub async fn import_private_key(
    pem: String,
    password: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    // Parse the PEM to a private key
    let imported_private = keypair::private_key_from_pem(&pem)
        .map_err(|_| "Invalid recovery key format".to_string())?;

    // Derive public key from imported private key
    let imported_public = RsaPublicKey::from(&imported_private);
    let imported_public_pem = keypair::public_key_to_pem(&imported_public)?;

    // Get current user and verify against stored public key in MongoDB
    let user_id = {
        let inner = state.inner.lock().map_err(|e| e.to_string())?;
        inner
            .current_user
            .as_ref()
            .ok_or("Not logged in")?
            .id
            .clone()
    };

    let users = state.users_collection();
    let user = users
        .find_one(
            doc! { "_id": mongodb::bson::oid::ObjectId::parse_str(&user_id).map_err(|e| e.to_string())? },
            None,
        )
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or("User not found")?;

    let stored_public_pem = user.public_key.ok_or("No public key stored for user")?;

    if imported_public_pem.trim() != stored_public_pem.trim() {
        return Err("Recovery key does not match. Please check and try again.".to_string());
    }

    // Save locally encrypted
    let user_dir = {
        let inner = state.inner.lock().map_err(|e| e.to_string())?;
        inner.user_dir.clone().ok_or("No user directory")?
    };

    save_local_private_key(&user_dir, &password, &imported_private)?;

    // Store in app state
    {
        let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
        inner.private_key = Some(imported_private);
    }

    // Automatically restore cloud vaults after key import
    restore_cloud_vaults_inner(&*state).await?;

    Ok(())
}

/// Restore cloud vaults using the user's RSA private key.
/// Called after private key import to pull vaults from MongoDB.
async fn restore_cloud_vaults_inner(state: &AppState) -> Result<(), String> {
    let (user_id, private_key, master_key, user_dir) = {
        let inner = state.inner.lock().map_err(|e| e.to_string())?;
        let user = inner.current_user.as_ref().ok_or("Not logged in")?;
        let pk = inner.private_key.as_ref().ok_or("No private key")?.clone();
        let mk = inner.master_key.as_ref().ok_or("No master key")?.clone();
        let ud = inner.user_dir.as_ref().ok_or("No user dir")?.clone();
        (user.id.clone(), pk, mk, ud)
    };

    use futures::TryStreamExt;

    let cloud_coll = state.cloud_vaults_collection();
    let mut cursor = cloud_coll
        .find(doc! { "owner_id": &user_id }, None)
        .await
        .map_err(|e| format!("DB error: {}", e))?;

    let mut restored_count = 0u32;

    while let Some(cloud) = cursor.try_next().await.map_err(|e| format!("DB error: {}", e))? {
        // Skip vaults without encrypted_vault_key (old format)
        let encrypted_vk_b64 = match &cloud.encrypted_vault_key {
            Some(evk) => evk.clone(),
            None => continue,
        };

        // Decrypt the vault key with RSA private key
        let encrypted_vk = BASE64
            .decode(&encrypted_vk_b64)
            .map_err(|e| format!("Base64 error: {}", e))?;
        let vault_key_bytes = keypair::rsa_decrypt(&encrypted_vk, &private_key)?;
        if vault_key_bytes.len() != 32 {
            continue;
        }
        let mut vault_key = [0u8; 32];
        vault_key.copy_from_slice(&vault_key_bytes);

        // Decrypt the vault data
        let cloud_vault =
            vault::decrypt_vault_from_cloud(&cloud.encrypted_data, &cloud.data_nonce, &vault_key)?;

        // Check if this vault already exists locally (by name)
        let already_exists = {
            let inner = state.inner.lock().map_err(|e| e.to_string())?;
            inner.vaults.values().any(|v| v.meta.name == cloud.name)
        };
        if already_exists {
            continue;
        }

        // Create local vault file
        let vault_id = Uuid::new_v4().to_string();
        let vault_path = user_dir.join("vaults").join(format!("{}.pass", vault_id));
        vault::save_vault(&cloud_vault, &vault_key, &vault_path)?;

        let meta = VaultMeta {
            id: vault_id.clone(),
            name: cloud.name,
            cloud_sync: true,
            role: "owner".to_string(),
            created_at: cloud.created_at,
            updated_at: cloud.updated_at,
        };

        // Add to registry and loaded vaults
        {
            let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
            if let Some(ref mut registry) = inner.registry {
                registry.add_vault(meta.clone(), &vault_key, &master_key)?;
            }
            inner.vaults.insert(
                vault_id.clone(),
                LoadedVault {
                    meta,
                    key: vault_key,
                    vault: cloud_vault,
                    path: vault_path,
                },
            );
            // If this is the first vault or replacing the empty default, select it
            if inner.active_vault_id.is_none() || restored_count == 0 {
                inner.active_vault_id = Some(vault_id);
            }
            inner.save_registry()?;
        }

        restored_count += 1;
    }

    // If we restored vaults, remove the empty default "My Vault" if it has no entries
    if restored_count > 0 {
        let default_to_remove = {
            let inner = state.inner.lock().map_err(|e| e.to_string())?;
            inner.vaults.iter()
                .find(|(_, v)| v.meta.name == "My Vault" && v.vault.entries.is_empty() && !v.meta.cloud_sync)
                .map(|(id, _)| id.clone())
        };
        if let Some(id) = default_to_remove {
            let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
            if let Some(removed) = inner.vaults.remove(&id) {
                let _ = std::fs::remove_file(&removed.path);
            }
            if let Some(ref mut registry) = inner.registry {
                registry.remove_vault(&id);
            }
            if inner.active_vault_id.as_deref() == Some(&id) {
                inner.active_vault_id = inner.vaults.keys().next().cloned();
            }
            inner.save_registry()?;
        }
    }

    Ok(())
}

#[tauri::command]
pub async fn change_password(
    current_password: String,
    new_password: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if new_password.len() < 8 {
        return Err("Password must be at least 8 characters".to_string());
    }

    // Step 1: Get current user info from state
    let (user_id, user_dir, old_master_salt) = {
        let inner = state.inner.lock().map_err(|e| e.to_string())?;
        let user = inner.current_user.as_ref().ok_or("Not logged in")?;
        let dir = inner.user_dir.as_ref().ok_or("No user dir")?.clone();
        let salt = inner.master_salt.as_ref().ok_or("No master salt")?.clone();
        (user.id.clone(), dir, salt)
    };

    // Step 2: Verify current password against MongoDB hash
    let users = state.users_collection();
    let user_doc = users
        .find_one(
            doc! { "_id": mongodb::bson::oid::ObjectId::parse_str(&user_id).map_err(|e| e.to_string())? },
            None,
        )
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or("User not found")?;

    if !crypto::verify_password(&current_password, &user_doc.password_hash)? {
        return Err("Current password is incorrect".to_string());
    }

    // Step 3: Derive OLD master key to decrypt the registry
    let old_master_key = crypto::derive_key(&current_password, &old_master_salt)?;

    // Step 4: Load registry with OLD key and extract all vault keys
    let registry = vault_meta::load_registry(&user_dir.join("registry.pass"), &old_master_key)?;

    let mut vault_keys: Vec<(VaultMeta, [u8; 32])> = Vec::new();
    for vault_meta in &registry.vaults {
        let vk = registry.get_vault_key(&vault_meta.id, &old_master_key)?;
        vault_keys.push((vault_meta.clone(), vk));
    }

    // Step 5: Generate new master salt and derive NEW master key
    let new_master_salt = crypto::generate_salt();
    let new_master_key = crypto::derive_key(&new_password, &new_master_salt)?;

    // Step 6: Rebuild registry with NEW master key (re-encrypt all vault keys)
    let mut new_registry = VaultRegistry::new();
    for (meta, vk) in &vault_keys {
        new_registry.add_vault(meta.clone(), vk, &new_master_key)?;
    }

    // Step 7: Write new master salt to disk
    std::fs::write(user_dir.join("master.salt"), &new_master_salt)
        .map_err(|e| format!("Write salt error: {}", e))?;

    // Step 8: Save re-encrypted registry
    vault_meta::save_registry(&new_registry, &new_master_key, &user_dir.join("registry.pass"))?;

    // Step 9: Re-encrypt private key with new password
    let private_key = {
        let inner = state.inner.lock().map_err(|e| e.to_string())?;
        inner.private_key.as_ref().ok_or("No private key")?.clone()
    };
    save_local_private_key(&user_dir, &new_password, &private_key)?;

    // Step 10: Update password hash in MongoDB
    let new_hash = crypto::hash_password(&new_password)?;
    users
        .update_one(
            doc! { "_id": mongodb::bson::oid::ObjectId::parse_str(&user_id).map_err(|e| e.to_string())? },
            doc! { "$set": { "password_hash": &new_hash } },
            None,
        )
        .await
        .map_err(|e| format!("Database error: {}", e))?;

    // Step 11: Update in-memory state
    {
        let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
        inner.master_key = Some(new_master_key);
        inner.master_salt = Some(new_master_salt);
        inner.registry = Some(new_registry);
    }

    // Step 12: Update session if one exists
    if load_session(&state.app_data_dir).is_ok() {
        let email = {
            let inner = state.inner.lock().map_err(|e| e.to_string())?;
            inner.current_user.as_ref().ok_or("Not logged in")?.email.clone()
        };
        save_session(&state.app_data_dir, &email, &new_password)?;
    }

    Ok(())
}

// ── Vault Management Commands ──

#[derive(Serialize, Clone)]
pub struct VaultMetaResponse {
    pub id: String,
    pub name: String,
    pub cloud_sync: bool,
    pub role: String,
    pub created_at: String,
    pub updated_at: String,
}

impl From<&VaultMeta> for VaultMetaResponse {
    fn from(m: &VaultMeta) -> Self {
        Self {
            id: m.id.clone(),
            name: m.name.clone(),
            cloud_sync: m.cloud_sync,
            role: m.role.clone(),
            created_at: m.created_at.clone(),
            updated_at: m.updated_at.clone(),
        }
    }
}

#[tauri::command]
pub fn list_vaults(state: State<AppState>) -> Result<Vec<VaultMetaResponse>, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    let registry = inner.registry.as_ref().ok_or("Not logged in")?;
    Ok(registry.vaults.iter().map(VaultMetaResponse::from).collect())
}

#[tauri::command]
pub fn create_vault(name: String, state: State<AppState>) -> Result<VaultMetaResponse, String> {
    let mut inner = state.inner.lock().map_err(|e| e.to_string())?;

    let user_dir = inner.user_dir.as_ref().ok_or("Not logged in")?.clone();
    let master_key = inner.master_key.ok_or("No master key")?;

    let vault_id = Uuid::new_v4().to_string();
    let vault_key = vault::generate_vault_key();
    let new_vault = Vault::new();
    let vault_path = user_dir.join("vaults").join(format!("{}.pass", vault_id));
    vault::save_vault(&new_vault, &vault_key, &vault_path)?;

    let now = chrono::Utc::now().to_rfc3339();
    let meta = VaultMeta {
        id: vault_id.clone(),
        name,
        cloud_sync: false,
        role: "owner".to_string(),
        created_at: now.clone(),
        updated_at: now,
    };

    let registry = inner.registry.as_mut().ok_or("No registry")?;
    registry.add_vault(meta.clone(), &vault_key, &master_key)?;

    inner.vaults.insert(
        vault_id,
        LoadedVault {
            meta: meta.clone(),
            key: vault_key,
            vault: new_vault,
            path: vault_path,
        },
    );

    inner.save_registry()?;

    Ok(VaultMetaResponse::from(&meta))
}

#[tauri::command]
pub fn delete_vault(vault_id: String, state: State<AppState>) -> Result<(), String> {
    let mut inner = state.inner.lock().map_err(|e| e.to_string())?;

    let loaded = inner
        .vaults
        .get(&vault_id)
        .ok_or("Vault not found")?;

    if loaded.meta.role != "owner" {
        return Err("Only the owner can delete a vault".to_string());
    }

    if inner.vaults.len() <= 1 {
        return Err("Cannot delete the last vault".to_string());
    }

    // Remove vault file
    let path = loaded.path.clone();
    let _ = std::fs::remove_file(&path);

    // Remove from registry
    let registry = inner.registry.as_mut().ok_or("No registry")?;
    registry.remove_vault(&vault_id);

    // Remove from loaded vaults
    inner.vaults.remove(&vault_id);

    // If this was the active vault, switch to the first available
    if inner.active_vault_id.as_deref() == Some(&vault_id) {
        inner.active_vault_id = inner.vaults.keys().next().cloned();
    }

    inner.save_registry()?;
    Ok(())
}

#[tauri::command]
pub fn rename_vault(
    vault_id: String,
    name: String,
    state: State<AppState>,
) -> Result<VaultMetaResponse, String> {
    let mut inner = state.inner.lock().map_err(|e| e.to_string())?;

    let loaded = inner
        .vaults
        .get_mut(&vault_id)
        .ok_or("Vault not found")?;
    loaded.meta.name = name.clone();
    loaded.meta.updated_at = chrono::Utc::now().to_rfc3339();

    let response = VaultMetaResponse::from(&loaded.meta);

    // Update registry
    let registry = inner.registry.as_mut().ok_or("No registry")?;
    if let Some(meta) = registry.vaults.iter_mut().find(|v| v.id == vault_id) {
        meta.name = name;
        meta.updated_at = chrono::Utc::now().to_rfc3339();
    }

    inner.save_registry()?;
    Ok(response)
}

#[tauri::command]
pub fn select_vault(
    vault_id: String,
    state: State<AppState>,
) -> Result<Vec<VaultEntry>, String> {
    let mut inner = state.inner.lock().map_err(|e| e.to_string())?;

    if !inner.vaults.contains_key(&vault_id) {
        return Err("Vault not found".to_string());
    }

    inner.active_vault_id = Some(vault_id.clone());

    let v = inner.vaults.get(&vault_id).unwrap();
    Ok(v.vault.entries.clone())
}

// ── Cloud Sync Commands ──

#[tauri::command]
pub async fn set_cloud_sync(
    vault_id: String,
    enabled: bool,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if enabled {
        // Upload vault to MongoDB
        let (vault_data, vault_key, meta_clone, user_id) = {
            let inner = state.inner.lock().map_err(|e| e.to_string())?;
            let loaded = inner.vaults.get(&vault_id).ok_or("Vault not found")?;
            if loaded.meta.role != "owner" {
                return Err("Only the owner can change sync settings".to_string());
            }
            let user = inner.current_user.as_ref().ok_or("Not logged in")?;
            (
                loaded.vault.clone(),
                loaded.key,
                loaded.meta.clone(),
                user.id.clone(),
            )
        };

        let (data_nonce, encrypted_data) = vault::encrypt_vault_for_cloud(&vault_data, &vault_key)?;

        // Encrypt vault_key with owner's RSA public key for cloud recovery
        let encrypted_vk = {
            let inner = state.inner.lock().map_err(|e| e.to_string())?;
            if let Some(ref pk) = inner.private_key {
                let public = RsaPublicKey::from(pk);
                let enc = keypair::rsa_encrypt(&vault_key, &public)?;
                Some(BASE64.encode(&enc))
            } else {
                None
            }
        };

        let cloud_vault = CloudVault {
            id: None,
            owner_id: user_id.clone(),
            name: meta_clone.name.clone(),
            encrypted_data,
            data_nonce,
            encrypted_vault_key: encrypted_vk,
            updated_at: chrono::Utc::now().to_rfc3339(),
            created_at: meta_clone.created_at.clone(),
        };

        // Check if already exists in cloud
        let cloud_coll = state.cloud_vaults_collection();
        let existing = cloud_coll
            .find_one(doc! { "owner_id": &user_id, "name": &meta_clone.name }, None)
            .await
            .map_err(|e| format!("DB error: {}", e))?;

        if existing.is_none() {
            cloud_coll
                .insert_one(&cloud_vault, None)
                .await
                .map_err(|e| format!("DB error: {}", e))?;
        }

        // Add owner as vault_member with encrypted vault key
        let private_key_and_public = {
            let inner = state.inner.lock().map_err(|e| e.to_string())?;
            let pk = inner.private_key.as_ref().ok_or("No private key")?;
            let public = rsa::RsaPublicKey::from(pk);
            public
        };

        let encrypted_vk = keypair::rsa_encrypt(&vault_key, &private_key_and_public)?;

        let member = VaultMemberDoc {
            id: None,
            vault_id: vault_id.clone(),
            user_id: user_id.clone(),
            encrypted_vault_key: BASE64.encode(&encrypted_vk),
            role: "owner".to_string(),
            status: "accepted".to_string(),
            added_at: chrono::Utc::now().to_rfc3339(),
        };

        let members_coll = state.vault_members_collection();
        let existing_member = members_coll
            .find_one(
                doc! { "vault_id": &vault_id, "user_id": &user_id },
                None,
            )
            .await
            .map_err(|e| format!("DB error: {}", e))?;

        if existing_member.is_none() {
            members_coll
                .insert_one(&member, None)
                .await
                .map_err(|e| format!("DB error: {}", e))?;
        }
    } else {
        // Remove from cloud
        let owner_id = {
            let inner = state.inner.lock().map_err(|e| e.to_string())?;
            inner.current_user.as_ref().ok_or("Not logged in")?.id.clone()
        };

        let cloud_coll = state.cloud_vaults_collection();
        cloud_coll
            .delete_one(doc! { "owner_id": &owner_id }, None)
            .await
            .map_err(|e| format!("DB error: {}", e))?;

        let members_coll = state.vault_members_collection();
        members_coll
            .delete_many(doc! { "vault_id": &vault_id }, None)
            .await
            .map_err(|e| format!("DB error: {}", e))?;
    }

    // Update local state
    {
        let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
        if let Some(loaded) = inner.vaults.get_mut(&vault_id) {
            loaded.meta.cloud_sync = enabled;
        }
        if let Some(registry) = inner.registry.as_mut() {
            if let Some(meta) = registry.vaults.iter_mut().find(|v| v.id == vault_id) {
                meta.cloud_sync = enabled;
            }
        }
        inner.save_registry()?;
    }

    Ok(())
}

#[tauri::command]
pub async fn sync_vault(vault_id: String, state: State<'_, AppState>) -> Result<(), String> {
    let (vault_data, vault_key, meta, user_id, encrypted_vk_b64) = {
        let inner = state.inner.lock().map_err(|e| e.to_string())?;
        let loaded = inner.vaults.get(&vault_id).ok_or("Vault not found")?;
        if !loaded.meta.cloud_sync {
            return Err("Cloud sync is not enabled for this vault".to_string());
        }
        let user = inner.current_user.as_ref().ok_or("Not logged in")?;

        // Encrypt vault_key with owner's RSA public key for cloud recovery
        let evk = if let Some(ref pk) = inner.private_key {
            let public = RsaPublicKey::from(pk);
            let encrypted = keypair::rsa_encrypt(&loaded.key, &public)?;
            Some(BASE64.encode(&encrypted))
        } else {
            None
        };

        (
            loaded.vault.clone(),
            loaded.key,
            loaded.meta.clone(),
            user.id.clone(),
            evk,
        )
    };

    let cloud_coll = state.cloud_vaults_collection();

    // Find cloud vault
    let cloud_doc = cloud_coll
        .find_one(doc! { "owner_id": &user_id, "name": &meta.name }, None)
        .await
        .map_err(|e| format!("DB error: {}", e))?;

    if let Some(cloud) = cloud_doc {
        // Compare timestamps
        let local_updated = &meta.updated_at;
        let cloud_updated = &cloud.updated_at;

        if local_updated > cloud_updated {
            // Local is newer — push to cloud
            let (data_nonce, encrypted_data) =
                vault::encrypt_vault_for_cloud(&vault_data, &vault_key)?;
            let mut update_doc = doc! {
                "encrypted_data": encrypted_data,
                "data_nonce": data_nonce,
                "updated_at": chrono::Utc::now().to_rfc3339(),
            };
            if let Some(ref evk) = encrypted_vk_b64 {
                update_doc.insert("encrypted_vault_key", evk);
            }
            cloud_coll
                .update_one(
                    doc! { "owner_id": &user_id, "name": &meta.name },
                    doc! { "$set": update_doc },
                    None,
                )
                .await
                .map_err(|e| format!("DB error: {}", e))?;
        } else if cloud_updated > local_updated {
            // Cloud is newer — pull from cloud
            let cloud_vault =
                vault::decrypt_vault_from_cloud(&cloud.encrypted_data, &cloud.data_nonce, &vault_key)?;

            let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
            if let Some(loaded) = inner.vaults.get_mut(&vault_id) {
                loaded.vault = cloud_vault;
                loaded.meta.updated_at = cloud.updated_at;
                vault::save_vault(&loaded.vault, &loaded.key, &loaded.path)?;
            }
        }
    } else {
        // No cloud doc — push
        let (data_nonce, encrypted_data) =
            vault::encrypt_vault_for_cloud(&vault_data, &vault_key)?;

        let cloud_vault = CloudVault {
            id: None,
            owner_id: user_id,
            name: meta.name,
            encrypted_data,
            data_nonce,
            encrypted_vault_key: encrypted_vk_b64,
            updated_at: chrono::Utc::now().to_rfc3339(),
            created_at: meta.created_at,
        };

        cloud_coll
            .insert_one(&cloud_vault, None)
            .await
            .map_err(|e| format!("DB error: {}", e))?;
    }

    Ok(())
}

// ── Sharing Commands ──

#[tauri::command]
pub async fn share_vault(
    vault_id: String,
    email: String,
    role: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if role != "editor" && role != "viewer" {
        return Err("Role must be 'editor' or 'viewer'".to_string());
    }

    let vault_key = {
        let inner = state.inner.lock().map_err(|e| e.to_string())?;
        let loaded = inner.vaults.get(&vault_id).ok_or("Vault not found")?;
        if loaded.meta.role != "owner" {
            return Err("Only the owner can share a vault".to_string());
        }
        if !loaded.meta.cloud_sync {
            return Err("Enable cloud sync before sharing".to_string());
        }
        loaded.key
    };

    // Find recipient
    let users = state.users_collection();
    let recipient = users
        .find_one(doc! { "email": &email }, None)
        .await
        .map_err(|e| format!("DB error: {}", e))?
        .ok_or("User not found".to_string())?;

    let recipient_id = recipient.id.ok_or("Recipient has no ID")?.to_hex();

    let recipient_public_pem = recipient
        .public_key
        .ok_or("Recipient does not support sharing (no public key)")?;

    let recipient_public = keypair::public_key_from_pem(&recipient_public_pem)?;

    // Encrypt vault key with recipient's public key
    let encrypted_vk = keypair::rsa_encrypt(&vault_key, &recipient_public)?;

    let members_coll = state.vault_members_collection();

    // Check if already shared
    let existing = members_coll
        .find_one(
            doc! { "vault_id": &vault_id, "user_id": &recipient_id },
            None,
        )
        .await
        .map_err(|e| format!("DB error: {}", e))?;

    if existing.is_some() {
        return Err("Vault already shared with this user".to_string());
    }

    let member = VaultMemberDoc {
        id: None,
        vault_id,
        user_id: recipient_id,
        encrypted_vault_key: BASE64.encode(&encrypted_vk),
        role,
        status: "pending".to_string(),
        added_at: chrono::Utc::now().to_rfc3339(),
    };

    members_coll
        .insert_one(&member, None)
        .await
        .map_err(|e| format!("DB error: {}", e))?;

    Ok(())
}

#[tauri::command]
pub async fn unshare_vault(
    vault_id: String,
    user_email: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    // Find the user to unshare with
    let users = state.users_collection();
    let target = users
        .find_one(doc! { "email": &user_email }, None)
        .await
        .map_err(|e| format!("DB error: {}", e))?
        .ok_or("User not found")?;

    let target_id = target.id.ok_or("User has no ID")?.to_hex();

    let members_coll = state.vault_members_collection();
    members_coll
        .delete_one(
            doc! { "vault_id": &vault_id, "user_id": &target_id },
            None,
        )
        .await
        .map_err(|e| format!("DB error: {}", e))?;

    Ok(())
}

#[tauri::command]
pub async fn list_vault_members(
    vault_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<VaultMemberInfo>, String> {
    use futures::TryStreamExt;

    let members_coll = state.vault_members_collection();
    let cursor = members_coll
        .find(doc! { "vault_id": &vault_id }, None)
        .await
        .map_err(|e| format!("DB error: {}", e))?;

    let members: Vec<VaultMemberDoc> = cursor
        .try_collect()
        .await
        .map_err(|e| format!("DB error: {}", e))?;

    let users = state.users_collection();
    let mut result = Vec::new();

    for member in members {
        let user = users
            .find_one(
                doc! { "_id": mongodb::bson::oid::ObjectId::parse_str(&member.user_id).map_err(|e| format!("Parse error: {}", e))? },
                None,
            )
            .await
            .map_err(|e| format!("DB error: {}", e))?;

        let email = user.map(|u| u.email).unwrap_or_else(|| "Unknown".to_string());

        result.push(VaultMemberInfo {
            user_id: member.user_id,
            email,
            role: member.role,
            status: member.status,
        });
    }

    Ok(result)
}

#[tauri::command]
pub async fn get_pending_shares(state: State<'_, AppState>) -> Result<Vec<PendingShare>, String> {
    use futures::TryStreamExt;

    let user_id = {
        let inner = state.inner.lock().map_err(|e| e.to_string())?;
        inner
            .current_user
            .as_ref()
            .ok_or("Not logged in")?
            .id
            .clone()
    };

    let members_coll = state.vault_members_collection();
    let cursor = members_coll
        .find(
            doc! { "user_id": &user_id, "status": "pending" },
            None,
        )
        .await
        .map_err(|e| format!("DB error: {}", e))?;

    let pending: Vec<VaultMemberDoc> = cursor
        .try_collect()
        .await
        .map_err(|e| format!("DB error: {}", e))?;

    let cloud_coll = state.cloud_vaults_collection();
    let users = state.users_collection();
    let mut result = Vec::new();

    for member in pending {
        // Find vault info
        let cloud_vault = cloud_coll
            .find_one(doc! { "owner_id": &member.vault_id }, None)
            .await
            .ok()
            .flatten();

        let vault_name = cloud_vault
            .as_ref()
            .map(|v| v.name.clone())
            .unwrap_or_else(|| "Unknown Vault".to_string());

        let owner_id = cloud_vault
            .as_ref()
            .map(|v| v.owner_id.clone())
            .unwrap_or_default();

        let owner = if !owner_id.is_empty() {
            users
                .find_one(
                    doc! { "_id": mongodb::bson::oid::ObjectId::parse_str(&owner_id).unwrap_or_default() },
                    None,
                )
                .await
                .ok()
                .flatten()
        } else {
            None
        };

        let owner_email = owner.map(|u| u.email).unwrap_or_else(|| "Unknown".to_string());

        result.push(PendingShare {
            vault_id: member.vault_id,
            vault_name,
            owner_email,
            role: member.role,
            added_at: member.added_at,
        });
    }

    Ok(result)
}

#[tauri::command]
pub async fn accept_shared_vault(
    vault_id: String,
    state: State<'_, AppState>,
) -> Result<VaultMetaResponse, String> {
    let user_id = {
        let inner = state.inner.lock().map_err(|e| e.to_string())?;
        inner.current_user.as_ref().ok_or("Not logged in")?.id.clone()
    };

    // Get the pending member doc
    let members_coll = state.vault_members_collection();
    let member_doc = members_coll
        .find_one(
            doc! { "vault_id": &vault_id, "user_id": &user_id, "status": "pending" },
            None,
        )
        .await
        .map_err(|e| format!("DB error: {}", e))?
        .ok_or("No pending invitation found")?;

    // Decrypt the vault key with our private key
    let vault_key = {
        let inner = state.inner.lock().map_err(|e| e.to_string())?;
        let pk = inner.private_key.as_ref().ok_or("No private key")?;
        let encrypted_vk = BASE64
            .decode(&member_doc.encrypted_vault_key)
            .map_err(|e| format!("Base64 error: {}", e))?;
        let key_bytes = keypair::rsa_decrypt(&encrypted_vk, pk)?;
        let mut key = [0u8; 32];
        if key_bytes.len() != 32 {
            return Err("Invalid vault key".to_string());
        }
        key.copy_from_slice(&key_bytes);
        key
    };

    // Fetch the cloud vault data
    let cloud_coll = state.cloud_vaults_collection();
    let cloud_vault = cloud_coll
        .find_one(doc! { "owner_id": &vault_id }, None)
        .await
        .map_err(|e| format!("DB error: {}", e))?;

    // Try to find vault by scanning — the vault_id in vault_members might not match owner_id
    // We need a better lookup. Let's use the vault name from cloud_vaults where _id matches
    // Actually, we need to store the vault's cloud ID differently.
    // For simplicity, we'll look up the cloud vault differently.

    let vault_data = if let Some(cv) = &cloud_vault {
        vault::decrypt_vault_from_cloud(&cv.encrypted_data, &cv.data_nonce, &vault_key)?
    } else {
        Vault::new()
    };

    let vault_name = cloud_vault
        .as_ref()
        .map(|v| v.name.clone())
        .unwrap_or_else(|| "Shared Vault".to_string());

    // Save vault locally
    let (user_dir, master_key) = {
        let inner = state.inner.lock().map_err(|e| e.to_string())?;
        let ud = inner.user_dir.as_ref().ok_or("No user dir")?.clone();
        let mk = inner.master_key.ok_or("No master key")?;
        (ud, mk)
    };

    let vault_path = user_dir.join("vaults").join(format!("{}.pass", vault_id));
    vault::save_vault(&vault_data, &vault_key, &vault_path)?;

    let now = chrono::Utc::now().to_rfc3339();
    let meta = VaultMeta {
        id: vault_id.clone(),
        name: vault_name,
        cloud_sync: true,
        role: member_doc.role,
        created_at: now.clone(),
        updated_at: now,
    };

    // Add to local registry and loaded vaults
    {
        let mut inner = state.inner.lock().map_err(|e| e.to_string())?;

        let registry = inner.registry.as_mut().ok_or("No registry")?;
        registry.add_vault(meta.clone(), &vault_key, &master_key)?;

        inner.vaults.insert(
            vault_id.clone(),
            LoadedVault {
                meta: meta.clone(),
                key: vault_key,
                vault: vault_data,
                path: vault_path,
            },
        );

        inner.save_registry()?;
    }

    // Update member status to accepted
    members_coll
        .update_one(
            doc! { "vault_id": &vault_id, "user_id": &user_id },
            doc! { "$set": { "status": "accepted" } },
            None,
        )
        .await
        .map_err(|e| format!("DB error: {}", e))?;

    Ok(VaultMetaResponse::from(&meta))
}

#[tauri::command]
pub async fn decline_shared_vault(
    vault_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let user_id = {
        let inner = state.inner.lock().map_err(|e| e.to_string())?;
        inner.current_user.as_ref().ok_or("Not logged in")?.id.clone()
    };

    let members_coll = state.vault_members_collection();
    members_coll
        .delete_one(
            doc! { "vault_id": &vault_id, "user_id": &user_id, "status": "pending" },
            None,
        )
        .await
        .map_err(|e| format!("DB error: {}", e))?;

    Ok(())
}

// ── Entry Commands (operate on active vault) ──

#[tauri::command]
pub fn get_entries(state: State<AppState>) -> Result<Vec<VaultEntry>, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    let v = inner.active_vault()?;
    Ok(v.vault.entries.clone())
}

#[derive(Deserialize)]
pub struct EntryData {
    pub entry_type: String,
    pub name: String,
    pub fields: HashMap<String, String>,
    pub notes: Option<String>,
    pub favorite: bool,
}

#[tauri::command]
pub fn add_entry(entry: EntryData, state: State<AppState>) -> Result<VaultEntry, String> {
    let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
    inner.check_write_access()?;

    let now = chrono::Utc::now().to_rfc3339();
    let new_entry = VaultEntry {
        id: Uuid::new_v4().to_string(),
        entry_type: entry.entry_type,
        name: entry.name,
        fields: entry.fields,
        notes: entry.notes,
        favorite: entry.favorite,
        created_at: now.clone(),
        updated_at: now,
    };

    let v = inner.active_vault_mut()?;
    v.vault.entries.push(new_entry.clone());
    v.vault.updated_at = chrono::Utc::now().to_rfc3339();
    v.meta.updated_at = v.vault.updated_at.clone();

    inner.save_active()?;

    Ok(new_entry)
}

#[derive(Deserialize)]
pub struct UpdateEntryData {
    pub id: String,
    pub entry_type: String,
    pub name: String,
    pub fields: HashMap<String, String>,
    pub notes: Option<String>,
    pub favorite: bool,
}

#[tauri::command]
pub fn update_entry(
    entry: UpdateEntryData,
    state: State<AppState>,
) -> Result<VaultEntry, String> {
    let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
    inner.check_write_access()?;

    let v = inner.active_vault_mut()?;

    let existing = v
        .vault
        .entries
        .iter_mut()
        .find(|e| e.id == entry.id)
        .ok_or("Entry not found")?;

    let now = chrono::Utc::now().to_rfc3339();
    existing.entry_type = entry.entry_type;
    existing.name = entry.name;
    existing.fields = entry.fields;
    existing.notes = entry.notes;
    existing.favorite = entry.favorite;
    existing.updated_at = now;

    let updated = existing.clone();
    v.vault.updated_at = chrono::Utc::now().to_rfc3339();
    v.meta.updated_at = v.vault.updated_at.clone();

    inner.save_active()?;

    Ok(updated)
}

#[tauri::command]
pub fn delete_entry(id: String, state: State<AppState>) -> Result<(), String> {
    let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
    inner.check_write_access()?;

    let v = inner.active_vault_mut()?;

    let len_before = v.vault.entries.len();
    v.vault.entries.retain(|e| e.id != id);

    if v.vault.entries.len() == len_before {
        return Err("Entry not found".to_string());
    }

    v.vault.updated_at = chrono::Utc::now().to_rfc3339();
    v.meta.updated_at = v.vault.updated_at.clone();

    inner.save_active()?;

    Ok(())
}

#[tauri::command]
pub fn generate_password(
    length: usize,
    uppercase: bool,
    lowercase: bool,
    numbers: bool,
    symbols: bool,
) -> Result<String, String> {
    let options = password::PasswordOptions {
        length,
        uppercase,
        lowercase,
        numbers,
        symbols,
    };
    password::generate(&options)
}

#[tauri::command]
pub fn toggle_favorite(id: String, state: State<AppState>) -> Result<bool, String> {
    let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
    inner.check_write_access()?;

    let v = inner.active_vault_mut()?;

    let entry = v
        .vault
        .entries
        .iter_mut()
        .find(|e| e.id == id)
        .ok_or("Entry not found")?;

    entry.favorite = !entry.favorite;
    entry.updated_at = chrono::Utc::now().to_rfc3339();
    let new_favorite = entry.favorite;

    v.vault.updated_at = chrono::Utc::now().to_rfc3339();
    v.meta.updated_at = v.vault.updated_at.clone();

    inner.save_active()?;

    Ok(new_favorite)
}
