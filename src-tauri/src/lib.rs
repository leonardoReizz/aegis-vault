mod commands;
mod crypto;
mod db;
mod keypair;
mod password;
mod vault;
mod vault_meta;

use commands::AppState;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;

            let mongo_uri = option_env!("MONGODB_URI")
                .unwrap_or("mongodb://localhost:27017")
                .to_string();

            let client = tauri::async_runtime::block_on(async {
                mongodb::Client::with_uri_str(&mongo_uri).await
            })
            .map_err(|e| format!("MongoDB connection error: {}", e))?;

            let db = client.database("pass");

            app.manage(AppState::new(data_dir, db));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::register,
            commands::login,
            commands::try_restore_session,
            commands::logout,
            commands::import_private_key,
            commands::change_password,
            commands::google_oauth_identify,
            commands::register_with_google,
            commands::setup_totp,
            commands::verify_totp_setup,
            commands::verify_totp_login,
            commands::disable_totp,
            commands::get_totp_status,
            commands::list_vaults,
            commands::create_vault,
            commands::delete_vault,
            commands::rename_vault,
            commands::select_vault,
            commands::set_cloud_sync,
            commands::sync_vault,
            commands::share_vault,
            commands::unshare_vault,
            commands::list_vault_members,
            commands::get_pending_shares,
            commands::accept_shared_vault,
            commands::decline_shared_vault,
            commands::get_entries,
            commands::add_entry,
            commands::update_entry,
            commands::delete_entry,
            commands::generate_password,
            commands::toggle_favorite,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
