# Aegis Vault

> **[aegis-lp.cap.leonardo-reis.com](http://aegis-lp.cap.leonardo-reis.com/)**

A cross-platform desktop password manager built with Tauri 2, React, and Rust. All sensitive data is encrypted locally using AES-256-GCM, with RSA-2048 key pairs enabling secure vault sharing between users.

## Features

- **Zero-knowledge encryption** — Vault data is encrypted/decrypted entirely on-device. The server never sees plaintext passwords.
- **Multi-vault support** — Organize credentials into separate vaults (e.g. Personal, Work).
- **Vault sharing** — Share vaults with other users via RSA key exchange. Role-based access control (owner, editor, viewer).
- **Cloud sync** — Optional per-vault MongoDB sync for backup and cross-device access.
- **Local-first private key** — Your RSA private key never leaves your machine. Export it as a recovery key for use on new devices.
- **16 entry types** — Login, Credit Card, Identity, SSH Key, Database, Crypto Wallet, Server, Software License, Secure Note, API Key, Wi-Fi, Bank Account, Email Account, Passport, Driver's License, and more.
- **Password generator** — Configurable length with uppercase, lowercase, numbers, and symbols.
- **i18n** — English and Brazilian Portuguese.
- **Custom window chrome** — Frameless window with macOS-style traffic light controls.

## Security Architecture

```
Master Password
  |
  |-> Argon2id (65536 memory cost, 3 iterations, 4 parallelism)
  |     \-> 256-bit Master Key
  |           \-> AES-256-GCM encrypts Vault Registry
  |                 \-> Per-vault symmetric keys
  |                       \-> AES-256-GCM encrypts each entry
  |
  \-> Argon2id password hash (stored in MongoDB for auth)

RSA-2048 Key Pair (generated on registration)
  |-> Public key  -> stored in MongoDB (used by others to share vaults with you)
  \-> Private key -> encrypted with master key, stored ONLY on local disk
        \-> Used to decrypt vault keys shared by other users
```

**What's stored in the cloud (MongoDB):**
- Argon2 password hash
- RSA public key
- Encrypted vault data (AES-256-GCM ciphertext)

**What stays local only:**
- RSA private key (encrypted with your master password)
- Master key derivation salt

## Tech Stack

| Layer    | Technology                                        |
| -------- | ------------------------------------------------- |
| Frontend | React 19, TypeScript, Tailwind CSS 4, shadcn/ui   |
| Backend  | Rust, Tauri 2                                      |
| Database | MongoDB                                            |
| Crypto   | AES-256-GCM, Argon2id, RSA-2048 (OAEP + SHA-256)  |
| Build    | Vite 7, Cargo                                      |

## Prerequisites

- [Node.js](https://nodejs.org/) (v18+)
- [Rust](https://www.rust-lang.org/tools/install) (latest stable)
- [Tauri 2 prerequisites](https://v2.tauri.app/start/prerequisites/)
- [MongoDB](https://www.mongodb.com/docs/manual/installation/) (running locally or a remote URI)
- Yarn

## Getting Started

```bash
# Clone the repository
git clone https://github.com/leonardoreis/pass.git
cd pass

# Install frontend dependencies
yarn install

# Configure MongoDB connection (defaults to mongodb://localhost:27017)
echo "MONGODB_URI=mongodb://localhost:27017" > .env

# Run in development mode
yarn tauri dev
```

## Building

```bash
yarn tauri build
```

The compiled binary will be in `src-tauri/target/release/bundle/`.

## Project Structure

```
pass/
├── src/                          # Frontend (React + TypeScript)
│   ├── components/               # UI components
│   │   ├── ui/                   # shadcn/ui primitives
│   │   ├── auth-screen.tsx       # Login / Register
│   │   ├── vault-view.tsx        # Main vault interface
│   │   ├── entry-dialog.tsx      # Add / Edit entries
│   │   ├── entry-card.tsx        # Entry display card
│   │   ├── vault-selector.tsx    # Multi-vault switcher
│   │   ├── key-backup-screen.tsx # Recovery key export (post-register)
│   │   ├── key-import-screen.tsx # Recovery key import (new device)
│   │   └── ...
│   ├── contexts/                 # React contexts (auth, vault, vault-list)
│   ├── i18n/                     # Translations (en, pt-BR)
│   ├── lib/                      # Entry schemas, utilities
│   └── types/                    # TypeScript interfaces
│
├── src-tauri/                    # Backend (Rust)
│   └── src/
│       ├── commands.rs           # Tauri IPC commands
│       ├── crypto.rs             # AES-256-GCM, Argon2id
│       ├── keypair.rs            # RSA-2048 key pair operations
│       ├── vault.rs              # Vault encryption / persistence
│       ├── vault_meta.rs         # Vault registry management
│       ├── db.rs                 # MongoDB models
│       ├── password.rs           # Password strength evaluation
│       └── lib.rs                # Tauri app setup
│
└── package.json
```

## How Vault Sharing Works

1. Alice creates a vault and enables cloud sync.
2. Alice clicks **Share** and enters Bob's email.
3. The app fetches Bob's RSA public key from MongoDB.
4. The vault's symmetric key is encrypted with Bob's public key and stored alongside the share invitation.
5. Bob accepts the share. His local RSA private key decrypts the vault key.
6. Bob can now decrypt and (depending on his role) edit the shared vault.

## Recovery Key Flow

On **registration**, a RSA-2048 key pair is generated. The private key is saved encrypted on your local disk and displayed once as a recovery key. You should copy or download it and store it somewhere safe.

On **login from a new device** (where no local key file exists), the app prompts you to import your recovery key. Without it, shared vaults and previously encrypted data cannot be decrypted.

## Roadmap

- [ ] Google Authentication — Sign in with your Google account
- [ ] Two-Factor Authentication (2FA) — Extra security layer for account access
- [ ] Audit Log — Full change history tracking across vaults and entries
- [ ] Standalone Password Generator — Use the password generator without creating an entry
- [ ] Password History & Rollback — Version control for credentials with the ability to restore previous passwords

## License

MIT
