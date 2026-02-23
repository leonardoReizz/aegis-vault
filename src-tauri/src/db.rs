use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub email: String,
    pub password_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_salt: Option<String>,
    pub created_at: String,
    // OAuth fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth_id: Option<String>,
    // TOTP 2FA fields
    #[serde(default)]
    pub totp_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_backup_codes: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
}

/// Vault document stored in MongoDB (for cloud-synced vaults)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CloudVault {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub owner_id: String,
    pub name: String,
    pub encrypted_data: String,
    pub data_nonce: String,
    /// Vault symmetric key encrypted with the owner's RSA public key (base64)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_vault_key: Option<String>,
    pub updated_at: String,
    pub created_at: String,
}

/// Vault member document in MongoDB (access control + key distribution)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultMemberDoc {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub vault_id: String,
    pub user_id: String,
    pub encrypted_vault_key: String,
    pub role: String,
    pub status: String,
    pub added_at: String,
}

/// Pending share info returned to frontend
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PendingShare {
    pub vault_id: String,
    pub vault_name: String,
    pub owner_email: String,
    pub role: String,
    pub added_at: String,
}

/// Vault member info returned to frontend
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultMemberInfo {
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub status: String,
}
