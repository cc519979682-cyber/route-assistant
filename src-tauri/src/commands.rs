use crate::error::AppResult;
use crate::models::*;
use crate::service::{self, AppState};
use tauri::State;

#[tauri::command]
pub fn list_router_profiles(state: State<'_, AppState>) -> AppResult<Vec<RouterProfile>> {
    state.store.list_profiles()
}

#[tauri::command]
pub async fn discover_router(
    input: RouterProfileInput,
    state: State<'_, AppState>,
) -> AppResult<RouterSnapshot> {
    service::discover(&state, input).await
}

#[tauri::command]
pub fn select_plugin(
    profile_id: String,
    plugin: PluginKind,
    state: State<'_, AppState>,
) -> AppResult<()> {
    state.select_plugin(&profile_id, plugin)
}

#[tauri::command]
pub async fn list_rules(
    profile_id: String,
    state: State<'_, AppState>,
) -> AppResult<Vec<RuleSpec>> {
    service::list_managed_rules(&state, &profile_id).await
}

#[tauri::command]
pub async fn list_custom_rules(
    profile_id: String,
    state: State<'_, AppState>,
) -> AppResult<CustomRulesSnapshot> {
    service::list_custom_rules(&state, &profile_id).await
}

#[tauri::command]
pub async fn list_policy_targets(
    profile_id: String,
    state: State<'_, AppState>,
) -> AppResult<Vec<PolicyTarget>> {
    let (session, plugin) = service::with_session(&state, &profile_id).await?;
    let result = crate::adapters::policy_targets(&session, &plugin).await;
    session.disconnect().await;
    result
}

#[tauri::command]
pub async fn plan_rule_change(
    profile_id: String,
    draft: RuleDraft,
    state: State<'_, AppState>,
) -> AppResult<ChangePlan> {
    service::create_plan(&state, &profile_id, draft).await
}

#[tauri::command]
pub async fn plan_rule_update(
    profile_id: String,
    rule_id: String,
    draft: RuleDraft,
    state: State<'_, AppState>,
) -> AppResult<ChangePlan> {
    service::create_update_plan(&state, &profile_id, &rule_id, draft).await
}

#[tauri::command]
pub async fn plan_rule_removal(
    profile_id: String,
    rule_id: String,
    state: State<'_, AppState>,
) -> AppResult<ChangePlan> {
    service::create_delete_plan(&state, &profile_id, &rule_id).await
}

#[tauri::command]
pub async fn apply_rule_change(
    plan_id: String,
    allow_override: bool,
    state: State<'_, AppState>,
) -> AppResult<VerificationReport> {
    service::apply_plan(&state, &plan_id, allow_override).await
}

#[tauri::command]
pub async fn verify_rule(
    profile_id: String,
    rule_id: String,
    state: State<'_, AppState>,
) -> AppResult<VerificationReport> {
    service::verify(&state, &profile_id, &rule_id).await
}

#[tauri::command]
pub async fn rollback_change(
    profile_id: String,
    backup_id: String,
    state: State<'_, AppState>,
) -> AppResult<VerificationReport> {
    service::rollback(&state, &profile_id, &backup_id).await
}

#[tauri::command]
pub fn list_operation_history(
    profile_id: Option<String>,
    state: State<'_, AppState>,
) -> AppResult<Vec<OperationHistoryItem>> {
    state.store.list_history(profile_id.as_deref())
}

#[tauri::command]
pub async fn export_redacted_diagnostics(
    profile_id: String,
    state: State<'_, AppState>,
) -> AppResult<String> {
    service::export_diagnostics(&state, &profile_id)
        .await
        .map(|path| path.to_string_lossy().into_owned())
}
