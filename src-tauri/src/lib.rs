mod adapters;
mod commands;
mod dns_chain;
mod domain;
mod error;
mod logging;
mod models;
mod redact;
mod service;
mod ssh;
mod storage;

use service::AppState;
use storage::Store;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let store = Store::open_default()
        .unwrap_or_else(|error| panic!("failed to initialize safe local storage: {error}"));
    let _log_guard = logging::init(store.data_dir());
    logging::safe_info("application_started", "route-assistant v0.4.0");
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::new(store))
        .invoke_handler(tauri::generate_handler![
            commands::list_router_profiles,
            commands::discover_router,
            commands::refresh_plugin_state,
            commands::select_plugin,
            commands::list_rules,
            commands::list_custom_rules,
            commands::list_policy_targets,
            commands::plan_rule_change,
            commands::plan_rule_update,
            commands::plan_rule_removal,
            commands::apply_rule_change,
            commands::verify_rule,
            commands::inspect_dns_protection,
            commands::plan_dns_protection,
            commands::apply_dns_protection,
            commands::rollback_dns_protection,
            commands::rollback_change,
            commands::list_operation_history,
            commands::export_redacted_diagnostics,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Route Assistant");
}
