export type EntryType =
  | "login"
  | "credit_card"
  | "identity"
  | "ssh_key"
  | "database"
  | "crypto_wallet"
  | "server"
  | "software_license"
  | "secure_note"
  | "api_key"
  | "wifi"
  | "bank_account"
  | "email_account"
  | "passport"
  | "drivers_license";

export interface VaultEntry {
  id: string;
  entry_type: EntryType;
  name: string;
  fields: Record<string, string>;
  notes: string | null;
  favorite: boolean;
  created_at: string;
  updated_at: string;
}

export interface EntryFormData {
  entry_type: EntryType;
  name: string;
  fields: Record<string, string>;
  notes: string;
  favorite: boolean;
}

export interface UserInfo {
  id: string;
  email: string;
}

export interface RegisterResult {
  user: UserInfo;
  private_key_pem: string;
}

export interface LoginResult {
  user: UserInfo;
  needs_key_import: boolean;
  needs_totp: boolean;
}

export interface GoogleOAuthResult {
  email: string;
  is_new_user: boolean;
  google_oauth_id: string;
}

export interface TotpSetupResult {
  qr_code_base64: string;
  secret: string;
}

export interface TotpVerifySetupResult {
  backup_codes: string[];
}

export type VaultRole = "owner" | "editor" | "viewer";

export interface VaultMeta {
  id: string;
  name: string;
  cloud_sync: boolean;
  role: VaultRole;
  created_at: string;
  updated_at: string;
}

export interface VaultMemberInfo {
  user_id: string;
  email: string;
  role: VaultRole;
  status: "accepted" | "pending";
}

export interface PendingShare {
  vault_id: string;
  vault_name: string;
  owner_email: string;
  role: string;
  added_at: string;
}
