use crate::adapters;
use crate::domain::normalize_domain;
use crate::error::{AppError, AppResult};
use crate::models::*;
use crate::redact::redact;
use crate::ssh::{SshSession, shell_quote};
use crate::storage::Store;
use chrono::Utc;
use regex::Regex;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;
use uuid::Uuid;

pub struct AppState {
    pub store: Store,
    selected_plugins: Mutex<HashMap<String, PluginKind>>,
    dns_plans: Mutex<HashMap<String, DnsProtectionPlan>>,
}

impl AppState {
    pub fn new(store: Store) -> Self {
        Self {
            store,
            selected_plugins: Mutex::new(HashMap::new()),
            dns_plans: Mutex::new(HashMap::new()),
        }
    }

    fn remember_manual_plugin(&self, profile_id: &str, plugin: PluginKind) -> AppResult<()> {
        if !plugin.is_managed() {
            return Err(AppError::Validation("不能选择不支持的插件".into()));
        }
        self.selected_plugins
            .lock()
            .map_err(|_| AppError::Other("插件选择状态不可用".into()))?
            .insert(profile_id.to_owned(), plugin);
        Ok(())
    }

    pub fn selected_plugin(&self, profile_id: &str) -> Option<PluginKind> {
        self.selected_plugins.lock().ok()?.get(profile_id).cloned()
    }

    fn save_dns_plan(&self, plan: DnsProtectionPlan) -> AppResult<()> {
        self.dns_plans
            .lock()
            .map_err(|_| AppError::Other("DNS 预览状态不可用".into()))?
            .insert(plan.id.clone(), plan);
        Ok(())
    }

    fn take_dns_plan(&self, plan_id: &str) -> AppResult<DnsProtectionPlan> {
        self.dns_plans
            .lock()
            .map_err(|_| AppError::Other("DNS 预览状态不可用".into()))?
            .remove(plan_id)
            .ok_or_else(|| AppError::Validation("DNS 变更预览已失效，请重新生成".into()))
    }
}

pub async fn discover(state: &AppState, input: RouterProfileInput) -> AppResult<RouterSnapshot> {
    crate::logging::safe_info(
        "router_discovery_started",
        &format!("profile={}", input.id.as_deref().unwrap_or("new")),
    );
    let effective = hydrate_input(state, input)?;
    let fingerprint = SshSession::probe_host_key(&effective).await?;
    if let Some(id) = effective.id.as_deref()
        && let Ok(saved) = state.store.get_profile(id)
        && let Some(expected) = saved.host_key_fingerprint
        && expected != fingerprint
    {
        return Err(AppError::HostKeyChanged(format!(
            "保存的是 {expected}，当前为 {fingerprint}"
        )));
    }

    if effective.id.is_none() && !effective.trust_host_key {
        return Ok(RouterSnapshot {
            profile: pending_profile(&effective),
            distribution: "OpenWrt（等待确认）".into(),
            release: None,
            plugin_state: resolve_plugin_state(Vec::new(), None),
            host_key_fingerprint: fingerprint,
            needs_host_key_trust: true,
        });
    }

    let session = SshSession::connect(&effective, &fingerprint).await?;
    let release_output = session
        .run_checked(
            r#". /etc/openwrt_release 2>/dev/null || true; printf '%s\n%s' "${DISTRIB_ID:-OpenWrt}" "${DISTRIB_RELEASE:-unknown}""#,
        )
        .await?;
    let mut release_lines = release_output.lines();
    let distribution = release_lines.next().unwrap_or("OpenWrt").trim().to_owned();
    let release = release_lines
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let profile = state.store.save_profile(&effective, &fingerprint)?;
    let plugins = detect_plugins(&session).await;
    let plugin_state = resolve_plugin_state(plugins, state.selected_plugin(&profile.id));
    session.disconnect().await;
    Ok(RouterSnapshot {
        profile,
        distribution,
        release,
        plugin_state,
        host_key_fingerprint: fingerprint,
        needs_host_key_trust: false,
    })
}

pub async fn detect_plugins(session: &SshSession) -> Vec<DetectedPlugin> {
    let package_output = session
        .run("if command -v apk >/dev/null 2>&1; then apk info -v 2>/dev/null; elif command -v opkg >/dev/null 2>&1; then opkg list-installed 2>/dev/null; fi | grep -Ei 'openclash|nikki|homeproxy|passwall2?' || true")
        .await
        .map(|value| value.stdout)
        .unwrap_or_default();
    let openclash_installed = plugin_installed(
        session,
        &package_output,
        &["openclash"],
        "test -x /etc/init.d/openclash || test -s /etc/config/openclash || pgrep -f '[o]penclash' >/dev/null",
    )
    .await;
    let nikki_installed = plugin_installed(
        session,
        &package_output,
        &["nikki"],
        "test -x /etc/init.d/nikki || test -s /etc/config/nikki || pgrep -f '[n]ikki' >/dev/null",
    )
    .await;
    let homeproxy_installed = plugin_installed(
        session,
        &package_output,
        &["homeproxy"],
        "test -x /etc/init.d/homeproxy",
    )
    .await;
    let passwall_installed = plugin_installed(
        session,
        &package_output,
        &["passwall", "passwall2"],
        "test -x /etc/init.d/passwall || test -x /etc/init.d/passwall2",
    )
    .await;
    let mut plugins = Vec::new();
    if openclash_installed {
        plugins.push(detect_plugin(session, PluginKind::OpenClash, &package_output).await);
    }
    if nikki_installed {
        plugins.push(detect_plugin(session, PluginKind::Nikki, &package_output).await);
    }
    if homeproxy_installed {
        plugins.push(detect_plugin(session, PluginKind::HomeProxy, &package_output).await);
    }
    if passwall_installed {
        plugins.push(detect_plugin(session, PluginKind::PassWall, &package_output).await);
    }
    if plugins.is_empty() {
        plugins.push(DetectedPlugin {
            kind: PluginKind::Unsupported,
            display_name: "未识别".into(),
            version: None,
            service_state: ServiceState::Unknown,
            core_version: None,
            capabilities: vec!["readOnlyDiagnostics".into()],
            support_level: PluginSupportLevel::DetectedOnly,
            can_select: false,
            can_read_custom_rules: false,
            read_only: true,
            reason: Some("没有发现可识别的代理插件；不会尝试写入未知配置。".into()),
        });
    }
    plugins
}

async fn detect_plugin(session: &SshSession, kind: PluginKind, packages: &str) -> DetectedPlugin {
    let passwall2 = packages.to_lowercase().contains("passwall2");
    let (name, needles, support_level) = match kind {
        PluginKind::OpenClash => ("OpenClash", &["openclash"][..], PluginSupportLevel::Managed),
        PluginKind::Nikki => ("Nikki", &["nikki"][..], PluginSupportLevel::Managed),
        PluginKind::HomeProxy => (
            "HomeProxy",
            &["homeproxy"][..],
            PluginSupportLevel::DetectedOnly,
        ),
        PluginKind::PassWall if passwall2 => (
            "PassWall2",
            &["passwall2", "passwall"][..],
            PluginSupportLevel::DetectedOnly,
        ),
        PluginKind::PassWall => (
            "PassWall",
            &["passwall", "passwall2"][..],
            PluginSupportLevel::DetectedOnly,
        ),
        PluginKind::Unsupported => (
            "未识别",
            &["__unsupported__"][..],
            PluginSupportLevel::DetectedOnly,
        ),
    };
    let state = adapters::service_state(session, &kind).await;
    let version = extract_package_version(packages, needles);
    let managed = support_level == PluginSupportLevel::Managed;
    let core_version = if managed && state == ServiceState::Running {
        if let Ok(api) = adapters::api_config(session, &kind).await {
            session
                .api_get(api.port, api.secret.as_deref(), "/version")
                .await
                .ok()
                .and_then(|value| {
                    value
                        .get("version")
                        .and_then(serde_json::Value::as_str)
                        .map(ToOwned::to_owned)
                })
        } else {
            None
        }
    } else {
        None
    };
    let api_ready = core_version.is_some();
    let version_known = version.is_some();
    let writable = managed && api_ready && version_known && state == ServiceState::Running;
    DetectedPlugin {
        kind,
        display_name: name.into(),
        version,
        service_state: state.clone(),
        core_version,
        capabilities: if writable {
            vec![
                "domainRules".into(),
                "policyGroups".into(),
                "runtimeVerification".into(),
                "rollback".into(),
            ]
        } else {
            vec!["readOnlyDiagnostics".into()]
        },
        support_level: support_level.clone(),
        can_select: managed,
        can_read_custom_rules: managed,
        read_only: !writable,
        reason: if !managed {
            Some(format!("已检测到 {name}，本版本尚未提供适配器。"))
        } else if !version_known {
            Some("无法确认插件版本，已进入只读诊断模式。".into())
        } else if !api_ready || state != ServiceState::Running {
            Some("服务未运行或无法通过 SSH 安全访问 Mihomo API".into())
        } else {
            None
        },
    }
}

fn extract_package_version(packages: &str, needles: &[&str]) -> Option<String> {
    for line in packages.lines() {
        let lower = line.to_lowercase();
        let Some(needle) = needles.iter().find(|needle| lower.contains(**needle)) else {
            continue;
        };
        let opkg_marker = " - ";
        if let Some((_, version)) = line.split_once(opkg_marker) {
            let value = version.split_whitespace().next().unwrap_or_default();
            if value
                .chars()
                .next()
                .is_some_and(|item| item.is_ascii_digit())
            {
                return Some(value.to_owned());
            }
        }
        if let Some(position) = lower.find(needle) {
            let suffix = line[(position + needle.len())..].trim_start_matches(['-', '_', ' ']);
            if let Some(value) = suffix.split_whitespace().next().filter(|value| {
                value
                    .chars()
                    .next()
                    .is_some_and(|item| item.is_ascii_digit())
            }) {
                return Some(value.to_owned());
            }
        }
        for value in line.split_whitespace() {
            let cleaned =
                value.trim_matches(|item: char| !item.is_ascii_alphanumeric() && item != '.');
            if cleaned
                .chars()
                .next()
                .is_some_and(|item| item.is_ascii_digit())
                && cleaned.contains('.')
            {
                return Some(cleaned.to_owned());
            }
        }
    }
    None
}

async fn plugin_installed(
    session: &SshSession,
    packages: &str,
    needles: &[&str],
    evidence_command: &str,
) -> bool {
    let packages = packages.to_lowercase();
    needles.iter().any(|needle| packages.contains(needle))
        || session
            .run(evidence_command)
            .await
            .map(|output| output.exit_status == 0)
            .unwrap_or(false)
}

fn plugin_state_token(plugins: &[DetectedPlugin], selected: &Option<PluginKind>) -> String {
    let mut hasher = Sha256::new();
    for plugin in plugins {
        hasher.update(format!(
            "{:?}|{:?}|{:?}|{}|{};",
            plugin.kind,
            plugin.service_state,
            plugin.support_level,
            plugin.version.as_deref().unwrap_or(""),
            plugin.core_version.as_deref().unwrap_or("")
        ));
    }
    hasher.update(format!("selected={selected:?}"));
    hex::encode(hasher.finalize())
}

fn resolve_plugin_state(
    plugins: Vec<DetectedPlugin>,
    manual_selection: Option<PluginKind>,
) -> RouterPluginState {
    let managed: Vec<&DetectedPlugin> = plugins
        .iter()
        .filter(|plugin| plugin.kind.is_managed())
        .collect();
    let running_managed: Vec<&DetectedPlugin> = managed
        .iter()
        .copied()
        .filter(|plugin| plugin.service_state == ServiceState::Running)
        .collect();
    let running_plugin_count = plugins
        .iter()
        .filter(|plugin| {
            plugin.kind != PluginKind::Unsupported && plugin.service_state == ServiceState::Running
        })
        .count();
    let running_detected_only: Vec<&DetectedPlugin> = plugins
        .iter()
        .filter(|plugin| {
            plugin.kind != PluginKind::Unsupported
                && plugin.support_level == PluginSupportLevel::DetectedOnly
                && plugin.service_state == ServiceState::Running
        })
        .collect();

    let (selected_plugin, selection_reason, requires_manual_selection) = match running_managed.len()
    {
        1 => (
            Some(running_managed[0].kind.clone()),
            Some(PluginSelectionReason::AutoRunning),
            false,
        ),
        count if count > 1 => {
            let selected = running_managed
                .iter()
                .find(|plugin| manual_selection.as_ref() == Some(&plugin.kind))
                .map(|plugin| plugin.kind.clone());
            let requires = selected.is_none();
            (
                selected,
                manual_selection
                    .as_ref()
                    .and_then(|_| (!requires).then_some(PluginSelectionReason::Manual)),
                requires,
            )
        }
        _ if managed.len() == 1 => (
            Some(managed[0].kind.clone()),
            Some(PluginSelectionReason::AutoOnlyManaged),
            false,
        ),
        _ => {
            let selected = managed
                .iter()
                .find(|plugin| manual_selection.as_ref() == Some(&plugin.kind))
                .map(|plugin| plugin.kind.clone());
            let requires = selected.is_none() && managed.len() > 1;
            (
                selected,
                manual_selection
                    .as_ref()
                    .and_then(|_| (!requires).then_some(PluginSelectionReason::Manual)),
                requires,
            )
        }
    };

    let write_block_reason = if requires_manual_selection {
        Some("检测到多个可管理插件，请先明确选择当前管理对象。".into())
    } else if let Some(selected) = selected_plugin.as_ref() {
        plugins
            .iter()
            .find(|plugin| &plugin.kind == selected)
            .and_then(|plugin| {
                if plugin.service_state != ServiceState::Running {
                    Some("当前管理对象没有运行，只能查看自定义规则。".into())
                } else if plugin.read_only {
                    Some(
                        plugin
                            .reason
                            .clone()
                            .unwrap_or_else(|| "当前管理对象处于只读状态。".into()),
                    )
                } else {
                    None
                }
            })
    } else {
        Some("没有选中可管理的 OpenClash 或 Nikki。".into())
    };
    let risk_warning = if !running_detected_only.is_empty() {
        Some(format!(
            "检测到其他代理插件同时运行（{}）。本次只修改当前管理对象；软件无法保证最终流量由哪个插件接管。",
            running_detected_only
                .iter()
                .map(|plugin| plugin.display_name.as_str())
                .collect::<Vec<_>>()
                .join("、")
        ))
    } else if running_managed.len() > 1 && !requires_manual_selection {
        Some("OpenClash 与 Nikki 同时运行；本次只修改你明确选择的管理对象。".into())
    } else {
        None
    };
    let can_write = write_block_reason.is_none();
    let state_token = plugin_state_token(&plugins, &selected_plugin);
    RouterPluginState {
        plugins,
        selected_plugin,
        selection_reason,
        requires_manual_selection,
        running_plugin_count,
        can_write,
        write_block_reason,
        risk_warning,
        state_token,
    }
}

async fn connect_profile(state: &AppState, profile_id: &str) -> AppResult<SshSession> {
    let profile = state.store.get_profile(profile_id)?;
    let input = state.store.profile_input_with_secret(&profile)?;
    let fingerprint = profile
        .host_key_fingerprint
        .as_deref()
        .ok_or_else(|| AppError::HostKeyUntrusted("档案没有保存主机指纹".into()))?;
    SshSession::connect(&input, fingerprint).await
}

pub async fn refresh_plugin_state(
    state: &AppState,
    profile_id: &str,
) -> AppResult<RouterPluginState> {
    let session = connect_profile(state, profile_id).await?;
    let plugins = detect_plugins(&session).await;
    let result = resolve_plugin_state(plugins, state.selected_plugin(profile_id));
    session.disconnect().await;
    Ok(result)
}

pub async fn select_plugin(
    state: &AppState,
    profile_id: &str,
    plugin: PluginKind,
) -> AppResult<RouterPluginState> {
    if !plugin.is_managed() {
        return Err(AppError::Validation(
            "只能选择 OpenClash 或 Nikki 作为管理对象。".into(),
        ));
    }
    let session = connect_profile(state, profile_id).await?;
    let plugins = detect_plugins(&session).await;
    if !plugins
        .iter()
        .any(|item| item.kind == plugin && item.can_select)
    {
        session.disconnect().await;
        return Err(AppError::Unsupported(
            "所选插件不存在或本版本尚不支持管理。".into(),
        ));
    }
    state.remember_manual_plugin(profile_id, plugin.clone())?;
    let result = resolve_plugin_state(plugins, Some(plugin));
    session.disconnect().await;
    Ok(result)
}

pub async fn with_session(
    state: &AppState,
    profile_id: &str,
) -> AppResult<(SshSession, PluginKind, RouterPluginState)> {
    let session = connect_profile(state, profile_id).await?;
    let plugin_state = resolve_plugin_state(
        detect_plugins(&session).await,
        state.selected_plugin(profile_id),
    );
    if let Some(reason) = plugin_state.write_block_reason.clone() {
        session.disconnect().await;
        return Err(AppError::Unsupported(reason));
    }
    let plugin = plugin_state
        .selected_plugin
        .clone()
        .ok_or_else(|| AppError::Conflict("请先选择当前管理对象。".into()))?;
    Ok((session, plugin, plugin_state))
}

pub async fn with_read_session(
    state: &AppState,
    profile_id: &str,
) -> AppResult<(SshSession, PluginKind)> {
    let session = connect_profile(state, profile_id).await?;
    let plugin_state = resolve_plugin_state(
        detect_plugins(&session).await,
        state.selected_plugin(profile_id),
    );
    let plugin = plugin_state
        .selected_plugin
        .filter(PluginKind::is_managed)
        .ok_or_else(|| AppError::Conflict("请先选择要查看的 OpenClash 或 Nikki。".into()))?;
    Ok((session, plugin))
}

pub async fn list_managed_rules(state: &AppState, profile_id: &str) -> AppResult<Vec<RuleSpec>> {
    let (session, plugin) = with_read_session(state, profile_id).await?;
    let result = match plugin {
        PluginKind::OpenClash => adapters::openclash::list_rules(&session).await,
        PluginKind::Nikki => adapters::nikki::list_rules(&session).await,
        PluginKind::HomeProxy | PluginKind::PassWall | PluginKind::Unsupported => {
            Err(AppError::Unsupported("不支持的插件".into()))
        }
    };
    session.disconnect().await;
    result
}

pub async fn list_custom_rules(
    state: &AppState,
    profile_id: &str,
) -> AppResult<CustomRulesSnapshot> {
    let (session, plugin) = with_read_session(state, profile_id).await?;
    let result = match plugin {
        PluginKind::OpenClash => adapters::openclash::list_custom_rules(&session).await,
        PluginKind::Nikki => adapters::nikki::list_custom_rules(&session).await,
        PluginKind::HomeProxy | PluginKind::PassWall | PluginKind::Unsupported => {
            Err(AppError::Unsupported("不支持的插件".into()))
        }
    };
    session.disconnect().await;
    result
}

fn conflict_rules_from_snapshot(snapshot: &CustomRulesSnapshot) -> Vec<RuleSpec> {
    snapshot
        .rules
        .iter()
        .filter(|record| record.enabled && record.parse_state == CustomRuleParseState::Structured)
        .filter_map(|record| {
            if let Some(rule) = &record.assistant_rule {
                return Some(rule.clone());
            }
            let draft = record.copy_draft.as_ref()?;
            let normalized = normalize_domain(&draft.domain, &draft.scope).ok()?;
            Some(RuleSpec {
                id: record.id.clone(),
                scope: draft.scope.clone(),
                domain: draft.domain.clone(),
                normalized_domain: normalized,
                action: draft.action.clone(),
                enabled: record.enabled,
                note: draft.note.clone(),
                managed: false,
                source: Some(record.source_location.clone()),
            })
        })
        .collect()
}

async fn custom_snapshot_for_session(
    session: &SshSession,
    plugin: &PluginKind,
) -> AppResult<CustomRulesSnapshot> {
    match plugin {
        PluginKind::OpenClash => adapters::openclash::list_custom_rules(session).await,
        PluginKind::Nikki => adapters::nikki::list_custom_rules(session).await,
        PluginKind::HomeProxy | PluginKind::PassWall | PluginKind::Unsupported => {
            Err(AppError::Unsupported("不支持的插件".into()))
        }
    }
}

pub async fn create_plan(
    state: &AppState,
    profile_id: &str,
    draft: RuleDraft,
) -> AppResult<ChangePlan> {
    let normalized = normalize_domain(&draft.domain, &draft.scope)?;
    let (session, plugin, plugin_state) = with_session(state, profile_id).await?;
    let snapshot = custom_snapshot_for_session(&session, &plugin).await?;
    let rules = conflict_rules_from_snapshot(&snapshot);
    let targets = adapters::policy_targets(&session, &plugin).await?;
    let rule = RuleSpec {
        id: Uuid::new_v4().to_string(),
        scope: draft.scope,
        domain: draft.domain.trim().to_owned(),
        normalized_domain: normalized,
        action: draft.action,
        enabled: true,
        note: draft
            .note
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.trim().chars().take(120).collect()),
        managed: true,
        source: None,
    };
    let conflicts = detect_rule_conflicts(&rules, &rule, &targets);
    let has_duplicate = conflicts.iter().any(|item| item.kind == "duplicate");
    let has_invalid = conflicts.iter().any(|item| item.kind == "invalidTarget");
    let plugin_name = if plugin == PluginKind::OpenClash {
        "OpenClash"
    } else {
        "Nikki"
    };
    let scope_text = if rule.scope == MatchScope::Suffix {
        "整个域名及其子域名"
    } else {
        "仅此域名"
    };
    let mut preview = format!(
        "将{scope_text}“{}”设为“{}”，对所有经过该软路由的设备生效。规则位于订阅规则之前；应用时 {plugin_name} 会短暂重载，预计不超过 20 秒。DNS 配置不会被修改。",
        rule.normalized_domain,
        rule.action.target()
    );
    if rule.scope == MatchScope::Exact {
        preview.push_str(
            " 注意：仅匹配完全相同的主机名；不会自动覆盖其他子域名（例如只拦 www.baidu.com 时，baidu.com / m.baidu.com 仍可能可访问）。拦截整个网站请改用“整个域名及子域名”。",
        );
        if rule.normalized_domain.starts_with("www.") {
            let bare = rule.normalized_domain.trim_start_matches("www.");
            preview.push_str(&format!(
                " 当前是精确匹配 {0}；若目标是拦截整个站点，建议改为域名后缀 {bare}。",
                rule.normalized_domain
            ));
        }
    }
    if matches!(rule.action, crate::models::RuleAction::Reject) {
        preview.push_str(
            " 拒绝规则会同时写入 OpenClash hosts 屏蔽（解析到 0.0.0.0）。因为若开启“绕过大陆 IP”且国内域名走真实 IP，仅靠 DOMAIN 规则往往拦不住百度等国内站点。",
        );
    }
    let plan = ChangePlan {
        id: Uuid::new_v4().to_string(),
        profile_id: profile_id.to_owned(),
        plugin,
        plugin_state_token: plugin_state.state_token,
        operation: "create".into(),
        rule,
        preview,
        conflicts,
        requires_reload: true,
        interruption_seconds: 20,
        can_apply: !has_duplicate && !has_invalid,
    };
    state.store.save_plan(&plan)?;
    session.disconnect().await;
    Ok(plan)
}

pub async fn create_update_plan(
    state: &AppState,
    profile_id: &str,
    rule_id: &str,
    draft: RuleDraft,
) -> AppResult<ChangePlan> {
    let normalized = normalize_domain(&draft.domain, &draft.scope)?;
    let (session, plugin, plugin_state) = with_session(state, profile_id).await?;
    let managed = match plugin {
        PluginKind::OpenClash => adapters::openclash::list_rules(&session).await?,
        PluginKind::Nikki => adapters::nikki::list_rules(&session).await?,
        PluginKind::HomeProxy | PluginKind::PassWall | PluginKind::Unsupported => {
            return Err(AppError::Unsupported("不支持的插件".into()));
        }
    };
    if !managed
        .iter()
        .any(|item| item.id == rule_id && item.managed)
    {
        session.disconnect().await;
        return Err(AppError::Validation(
            "只能编辑由本助手创建且仍然存在的规则。".into(),
        ));
    }
    let snapshot = custom_snapshot_for_session(&session, &plugin).await?;
    let rules = conflict_rules_from_snapshot(&snapshot);
    let targets = adapters::policy_targets(&session, &plugin).await?;
    let rule = RuleSpec {
        id: rule_id.to_owned(),
        scope: draft.scope,
        domain: draft.domain.trim().to_owned(),
        normalized_domain: normalized,
        action: draft.action,
        enabled: true,
        note: draft
            .note
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.trim().chars().take(120).collect()),
        managed: true,
        source: None,
    };
    let conflicts = detect_rule_conflicts(&rules, &rule, &targets);
    let has_duplicate = conflicts.iter().any(|item| item.kind == "duplicate");
    let has_invalid = conflicts.iter().any(|item| item.kind == "invalidTarget");
    let plugin_name = if plugin == PluginKind::OpenClash {
        "OpenClash"
    } else {
        "Nikki"
    };
    let scope_text = if rule.scope == MatchScope::Suffix {
        "整个域名及其子域名"
    } else {
        "仅此域名"
    };
    let plan = ChangePlan {
        id: Uuid::new_v4().to_string(),
        profile_id: profile_id.to_owned(),
        plugin,
        plugin_state_token: plugin_state.state_token,
        operation: "update".into(),
        preview: format!(
            "将本助手规则更新为：{scope_text}“{}” → “{}”。应用前会备份配置，{plugin_name} 会短暂重载；其他自定义规则不会被修改。",
            rule.normalized_domain,
            rule.action.target()
        ),
        rule,
        conflicts,
        requires_reload: true,
        interruption_seconds: 20,
        can_apply: !has_duplicate && !has_invalid,
    };
    state.store.save_plan(&plan)?;
    session.disconnect().await;
    Ok(plan)
}

fn detect_rule_conflicts(
    rules: &[RuleSpec],
    rule: &RuleSpec,
    targets: &[PolicyTarget],
) -> Vec<Conflict> {
    let mut conflicts = Vec::new();
    for existing in rules.iter().filter(|item| {
        item.enabled
            && item.id != rule.id
            && item.scope == rule.scope
            && item.normalized_domain == rule.normalized_domain
    }) {
        if existing.action == rule.action {
            conflicts.push(Conflict {
                kind: "duplicate".into(),
                message: "同一规则已经存在，不需要重复添加。".into(),
                existing_rule: Some(existing.clone()),
                requires_override: false,
            });
        } else {
            conflicts.push(Conflict {
                kind: "differentAction".into(),
                message: format!(
                    "同一域名当前指向 {}，新规则将以更高优先级覆盖。",
                    existing.action.target()
                ),
                existing_rule: Some(existing.clone()),
                requires_override: true,
            });
        }
    }
    if matches!(rule.action, RuleAction::PolicyGroup { .. })
        && !targets
            .iter()
            .any(|target| target.name == rule.action.target())
    {
        conflicts.push(Conflict {
            kind: "invalidTarget".into(),
            message: "当前运行配置中不存在这个策略组，请重新选择。".into(),
            existing_rule: None,
            requires_override: false,
        });
    }
    conflicts
}

pub async fn create_delete_plan(
    state: &AppState,
    profile_id: &str,
    rule_id: &str,
) -> AppResult<ChangePlan> {
    let (session, plugin, plugin_state) = with_session(state, profile_id).await?;
    let rules = match plugin {
        PluginKind::OpenClash => adapters::openclash::list_rules(&session).await?,
        PluginKind::Nikki => adapters::nikki::list_rules(&session).await?,
        PluginKind::HomeProxy | PluginKind::PassWall | PluginKind::Unsupported => {
            return Err(AppError::Unsupported("不支持的插件".into()));
        }
    };
    let rule = rules
        .into_iter()
        .find(|item| item.id == rule_id && item.managed)
        .ok_or_else(|| AppError::Validation("只能删除由本助手创建且仍然存在的规则。".into()))?;
    let plugin_name = if plugin == PluginKind::OpenClash {
        "OpenClash"
    } else {
        "Nikki"
    };
    let plan = ChangePlan {
        id: Uuid::new_v4().to_string(),
        profile_id: profile_id.to_owned(),
        plugin,
        plugin_state_token: plugin_state.state_token,
        operation: "delete".into(),
        preview: format!(
            "将删除本助手创建的规则“{} → {}”。应用前会备份配置，{} 会短暂重载；不会删除或改写其他规则。",
            rule.normalized_domain,
            rule.action.target(),
            plugin_name
        ),
        rule,
        conflicts: Vec::new(),
        requires_reload: true,
        interruption_seconds: 20,
        can_apply: true,
    };
    state.store.save_plan(&plan)?;
    session.disconnect().await;
    Ok(plan)
}

pub async fn apply_plan(
    state: &AppState,
    plan_id: &str,
    allow_override: bool,
) -> AppResult<VerificationReport> {
    let plan = state.store.get_plan(plan_id)?;
    if !plan.can_apply {
        return Err(AppError::Conflict(
            "当前变更预览不能应用，请修正规则后重试".into(),
        ));
    }
    if plan.conflicts.iter().any(|item| item.requires_override) && !allow_override {
        return Err(AppError::Conflict("需要明确确认高优先级覆盖".into()));
    }
    let (session, selected, plugin_state) = with_session(state, &plan.profile_id).await?;
    if selected != plan.plugin {
        session.disconnect().await;
        return Err(AppError::Conflict(
            "生成预览后当前代理插件发生变化，请重新预览".into(),
        ));
    }
    if plugin_state.state_token != plan.plugin_state_token {
        session.disconnect().await;
        return Err(AppError::Conflict(
            "生成预览后代理插件的运行状态、版本或核心状态发生变化，请重新生成预览。".into(),
        ));
    }
    let deleting = plan.operation == "delete";
    crate::logging::safe_info(
        "rule_change_started",
        &format!(
            "profile={} operation={} plugin={:?}",
            plan.profile_id, plan.operation, plan.plugin
        ),
    );
    let mut report = match (selected, deleting) {
        (PluginKind::OpenClash, false) => {
            adapters::openclash::apply_rule(&session, &plan.id, &plan.rule).await?
        }
        (PluginKind::Nikki, false) => {
            adapters::nikki::apply_rule(&session, &plan.id, &plan.rule).await?
        }
        (PluginKind::OpenClash, true) => {
            adapters::openclash::remove_rule(&session, &plan.id, &plan.rule).await?
        }
        (PluginKind::Nikki, true) => {
            adapters::nikki::remove_rule(&session, &plan.id, &plan.rule).await?
        }
        (PluginKind::HomeProxy | PluginKind::PassWall | PluginKind::Unsupported, _) => {
            return Err(AppError::Unsupported("不支持的插件".into()));
        }
    };
    if !deleting {
        report.dns_observation = diagnose_dns(&session, &plan.rule.normalized_domain)
            .await
            .ok();
    }
    let history = OperationHistoryItem {
        id: Uuid::new_v4().to_string(),
        profile_id: plan.profile_id.clone(),
        plugin: plan.plugin.clone(),
        operation: plan.operation.clone(),
        summary: if deleting {
            format!(
                "删除 {} → {}",
                plan.rule.normalized_domain,
                plan.rule.action.target()
            )
        } else {
            format!(
                "{} → {}",
                plan.rule.normalized_domain,
                plan.rule.action.target()
            )
        },
        backup_id: report.backup_id.clone(),
        success: report.success,
        created_at: Utc::now(),
    };
    state.store.add_history(&history)?;
    state.store.consume_plan(plan_id)?;
    crate::logging::safe_info(
        "rule_change_finished",
        &format!(
            "profile={} operation={} success={}",
            plan.profile_id, plan.operation, report.success
        ),
    );
    session.disconnect().await;
    Ok(report)
}

pub async fn verify(
    state: &AppState,
    profile_id: &str,
    rule_id: &str,
) -> AppResult<VerificationReport> {
    let (session, plugin, _) = with_session(state, profile_id).await?;
    let rules = match plugin {
        PluginKind::OpenClash => adapters::openclash::list_rules(&session).await?,
        PluginKind::Nikki => adapters::nikki::list_rules(&session).await?,
        PluginKind::HomeProxy | PluginKind::PassWall | PluginKind::Unsupported => {
            return Err(AppError::Unsupported("不支持的插件".into()));
        }
    };
    let rule = rules
        .into_iter()
        .find(|item| item.id == rule_id)
        .ok_or_else(|| AppError::Validation("找不到要验证的助手规则".into()))?;
    let report = match plugin {
        PluginKind::OpenClash => adapters::openclash::verify_rule(&session, rule_id, &rule).await,
        PluginKind::Nikki => adapters::nikki::verify_rule(&session, rule_id, &rule).await,
        PluginKind::HomeProxy | PluginKind::PassWall | PluginKind::Unsupported => unreachable!(),
    };
    session.disconnect().await;
    Ok(report)
}

pub async fn rollback(
    state: &AppState,
    profile_id: &str,
    backup_id: &str,
) -> AppResult<VerificationReport> {
    let (session, plugin, _) = with_session(state, profile_id).await?;
    match plugin {
        PluginKind::OpenClash => adapters::openclash::rollback(&session, backup_id).await?,
        PluginKind::Nikki => adapters::nikki::rollback(&session, backup_id).await?,
        PluginKind::HomeProxy | PluginKind::PassWall | PluginKind::Unsupported => {
            return Err(AppError::Unsupported("不支持的插件".into()));
        }
    }
    let state_after = adapters::service_state(&session, &plugin).await;
    session.disconnect().await;
    Ok(VerificationReport {
        change_id: format!("rollback:{backup_id}"),
        success: state_after == ServiceState::Running,
        service_state: state_after,
        core_api_reachable: false,
        rule_present: false,
        rule_index: None,
        hit_verified: false,
        verification_limited: true,
        dns_observation: None,
        rolled_back: true,
        backup_id: Some(backup_id.to_owned()),
        messages: vec!["已恢复指定备份并重新加载代理插件。".into()],
    })
}

pub async fn diagnose_dns(session: &SshSession, domain: &str) -> AppResult<DnsObservation> {
    let start = Instant::now();
    let command = format!(
        "resolver=$(uci -q get dhcp.@dnsmasq[0].server | tr '\\n' ',' | sed 's/,$//'); printf 'RESOLVER=%s\\n' \"${{resolver:-unknown}}\"; nslookup {} 127.0.0.1 2>/dev/null || true",
        shell_quote(domain)
    );
    let output = session.run_checked(&command).await?;
    let resolver = output
        .lines()
        .find_map(|line| line.strip_prefix("RESOLVER="))
        .unwrap_or("unknown")
        .to_owned();
    let address_regex = Regex::new(r"(?m)^Address(?: \d+)?:\s*([^#\s]+)")
        .map_err(|error| AppError::Other(error.to_string()))?;
    let mut addresses: Vec<String> = address_regex
        .captures_iter(&output)
        .filter_map(|capture| capture.get(1).map(|value| value.as_str().to_owned()))
        .filter(|value| value != "127.0.0.1")
        .collect();
    addresses.sort();
    addresses.dedup();
    Ok(DnsObservation {
        resolver,
        addresses,
        elapsed_ms: Some(start.elapsed().as_millis() as u64),
        note: "只读观察结果；直连不代表 DNS 或 CDN 一定在国内。".into(),
    })
}

fn unsupported_dns_snapshot(
    plugin: PluginKind,
    summary: impl Into<String>,
) -> DnsProtectionSnapshot {
    let summary = summary.into();
    DnsProtectionSnapshot {
        plugin,
        status: DnsProtectionStatus::Unsupported,
        summary: summary.clone(),
        supported: false,
        can_apply: false,
        dns_enabled: None,
        enhanced_mode: None,
        dnsmasq_to_openclash: None,
        encrypted_upstream_count: None,
        plaintext_upstream_count: None,
        local_upstreams: Vec::new(),
        respect_rules: None,
        managed_by_assistant: false,
        risks: vec![summary],
        checks: Vec::new(),
        chain: Default::default(),
    }
}

pub async fn inspect_dns_protection(
    state: &AppState,
    profile_id: &str,
) -> AppResult<DnsProtectionSnapshot> {
    let profile = state.store.get_profile(profile_id)?;
    let session = connect_profile(state, profile_id).await?;
    let plugin_state = resolve_plugin_state(
        detect_plugins(&session).await,
        state.selected_plugin(profile_id),
    );
    let selected = plugin_state
        .selected_plugin
        .clone()
        .unwrap_or(PluginKind::Unsupported);
    let mut snapshot = if selected == PluginKind::OpenClash {
        adapters::openclash_dns::inspect(&session).await?
    } else {
        unsupported_dns_snapshot(
            selected.clone(),
            "v0.4 的基础 DNS 防护目前只支持 OpenClash；其他插件只提供原有诊断。",
        )
    };
    if selected == PluginKind::OpenClash && !plugin_state.can_write {
        snapshot.can_apply = false;
        snapshot.risks.push(
            plugin_state
                .write_block_reason
                .unwrap_or_else(|| "当前 OpenClash 不能安全写入。".into()),
        );
    }
    snapshot.chain = crate::dns_chain::inspect(&session, &profile.host, &snapshot).await;
    session.disconnect().await;
    Ok(snapshot)
}

pub async fn plan_dns_protection(
    state: &AppState,
    profile_id: &str,
) -> AppResult<DnsProtectionPlan> {
    let session = connect_profile(state, profile_id).await?;
    let plugin_state = resolve_plugin_state(
        detect_plugins(&session).await,
        state.selected_plugin(profile_id),
    );
    if plugin_state.selected_plugin != Some(PluginKind::OpenClash) {
        session.disconnect().await;
        return Err(AppError::Unsupported(
            "基础 DNS 防护目前只支持当前管理对象为 OpenClash。".into(),
        ));
    }
    if let Some(reason) = plugin_state.write_block_reason.clone() {
        session.disconnect().await;
        return Err(AppError::Unsupported(reason));
    }
    let snapshot = adapters::openclash_dns::inspect(&session).await?;
    session.disconnect().await;
    if !snapshot.can_apply {
        return Err(AppError::Validation(
            if snapshot.status == DnsProtectionStatus::Protected {
                "当前 OpenClash 已满足基础 DNS 防护要求，无需重复修改。".into()
            } else {
                "当前 DNS 入口或配置条件不满足自动修复要求，请先查看风险说明。".into()
            },
        ));
    }
    let plan = DnsProtectionPlan {
        id: Uuid::new_v4().to_string(),
        profile_id: profile_id.to_owned(),
        plugin: PluginKind::OpenClash,
        plugin_state_token: plugin_state.state_token,
        preview: "将在 OpenClash 官方自定义覆写脚本中加入助手专属 DNS 块：国内使用阿里/腾讯加密 DoH，国外使用 Cloudflare/Google 加密 DoH并跟随现有分流规则；保留当前 Fake-IP或Redir-Host模式。应用前会备份，OpenClash将短暂重启；不会修改订阅、DHCP、防火墙、SmartDNS或AdGuard Home。".into(),
        can_apply: true,
        requires_reload: true,
        interruption_seconds: 20,
    };
    state.save_dns_plan(plan.clone())?;
    Ok(plan)
}

pub async fn apply_dns_protection(
    state: &AppState,
    plan_id: &str,
) -> AppResult<DnsProtectionReport> {
    let plan = state.take_dns_plan(plan_id)?;
    let profile = state.store.get_profile(&plan.profile_id)?;
    let session = connect_profile(state, &plan.profile_id).await?;
    let plugin_state = resolve_plugin_state(
        detect_plugins(&session).await,
        state.selected_plugin(&plan.profile_id),
    );
    if plugin_state.selected_plugin != Some(PluginKind::OpenClash) {
        session.disconnect().await;
        return Err(AppError::Conflict(
            "当前管理对象已经变化，请重新检测并生成预览。".into(),
        ));
    }
    if let Some(reason) = plugin_state.write_block_reason.clone() {
        session.disconnect().await;
        return Err(AppError::Unsupported(reason));
    }
    if plugin_state.state_token != plan.plugin_state_token {
        session.disconnect().await;
        return Err(AppError::Conflict(
            "插件状态在预览后发生变化，原 DNS 预览已作废。".into(),
        ));
    }
    let current_dns = adapters::openclash_dns::inspect(&session).await?;
    if !current_dns.can_apply {
        session.disconnect().await;
        return Err(AppError::Conflict(
            "DNS 状态在预览后发生变化，原预览已作废，请重新检测。".into(),
        ));
    }
    let (backup_id, mut snapshot, rolled_back, messages) =
        adapters::openclash_dns::apply(&session, &plan.id).await?;
    snapshot.chain = crate::dns_chain::inspect(&session, &profile.host, &snapshot).await;
    session.disconnect().await;
    let success = snapshot.status == DnsProtectionStatus::Protected && !rolled_back;
    state.store.add_history(&OperationHistoryItem {
        id: Uuid::new_v4().to_string(),
        profile_id: plan.profile_id,
        plugin: PluginKind::OpenClash,
        operation: "dnsProtection".into(),
        summary: if success {
            "启用 OpenClash 基础 DNS 防护".into()
        } else {
            "OpenClash DNS 防护验证失败并回滚".into()
        },
        backup_id: Some(backup_id.clone()),
        success,
        created_at: Utc::now(),
    })?;
    Ok(DnsProtectionReport {
        change_id: plan.id,
        success,
        rolled_back,
        backup_id: Some(backup_id),
        messages,
        snapshot,
    })
}

pub async fn rollback_dns_protection(
    state: &AppState,
    profile_id: &str,
    backup_id: &str,
) -> AppResult<DnsProtectionReport> {
    if !backup_id.starts_with("dns-") {
        return Err(AppError::Validation("这不是 DNS 防护备份编号。".into()));
    }
    let profile = state.store.get_profile(profile_id)?;
    let session = connect_profile(state, profile_id).await?;
    adapters::openclash_dns::rollback(&session, backup_id).await?;
    let mut snapshot = adapters::openclash_dns::inspect(&session).await?;
    snapshot.chain = crate::dns_chain::inspect(&session, &profile.host, &snapshot).await;
    session.disconnect().await;
    state.store.add_history(&OperationHistoryItem {
        id: Uuid::new_v4().to_string(),
        profile_id: profile_id.to_owned(),
        plugin: PluginKind::OpenClash,
        operation: "dnsRollback".into(),
        summary: "恢复 OpenClash DNS 防护备份".into(),
        backup_id: Some(backup_id.to_owned()),
        success: true,
        created_at: Utc::now(),
    })?;
    Ok(DnsProtectionReport {
        change_id: format!("dns-rollback:{backup_id}"),
        success: true,
        rolled_back: true,
        backup_id: Some(backup_id.to_owned()),
        messages: vec!["已恢复应用前的 OpenClash DNS 配置并重新检测。".into()],
        snapshot,
    })
}

pub async fn export_diagnostics(state: &AppState, profile_id: &str) -> AppResult<PathBuf> {
    let profile = state.store.get_profile(profile_id)?;
    let session = connect_profile(state, profile_id).await?;
    let plugins = detect_plugins(&session).await;
    let plugin_state = resolve_plugin_state(plugins.clone(), state.selected_plugin(profile_id));
    let selected = plugin_state.selected_plugin.clone();
    let release = session
        .run("cat /etc/openwrt_release 2>/dev/null")
        .await
        .unwrap_or(CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_status: 255,
        });
    let packages = session.run("(opkg list-installed 2>/dev/null || apk list --installed 2>/dev/null) | grep -Ei 'openclash|nikki|homeproxy|passwall2?|mihomo' || true").await.unwrap_or(CommandOutput { stdout: String::new(), stderr: String::new(), exit_status: 255 });
    session.disconnect().await;
    let document = json!({
        "schema": 1,
        "generatedAt": Utc::now(),
        "appVersion": env!("CARGO_PKG_VERSION"),
        "router": { "name": profile.name, "host": "[REDACTED]", "port": profile.port, "username": "[REDACTED]" },
        "selectedPlugin": selected,
        "plugins": plugins,
        "pluginState": plugin_state,
        "openwrtRelease": redact(&release.stdout),
        "relevantPackages": redact(&packages.stdout),
        "history": state.store.list_history(Some(profile_id))?,
        "privacy": "No passwords, private keys, subscription URLs, proxy nodes, or full configs are included."
    });
    let path = state.store.data_dir().join(format!(
        "route-assistant-diagnostics-{}.json",
        Utc::now().format("%Y%m%d-%H%M%S")
    ));
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&document).map_err(|error| AppError::Other(error.to_string()))?,
    )
    .map_err(|error| AppError::Other(error.to_string()))?;
    Ok(path)
}

fn hydrate_input(state: &AppState, input: RouterProfileInput) -> AppResult<RouterProfileInput> {
    let Some(id) = input.id.as_deref() else {
        return Ok(input);
    };
    let saved = state.store.get_profile(id)?;
    let mut hydrated = state.store.profile_input_with_secret(&saved)?;
    hydrated.name = input.name;
    hydrated.host = input.host;
    hydrated.port = input.port;
    hydrated.username = input.username;
    hydrated.trust_host_key = true;
    if input.password.is_some() {
        hydrated.password = input.password;
    }
    if input.private_key_path.is_some() {
        hydrated.private_key_path = input.private_key_path;
    }
    if input.private_key_passphrase.is_some() {
        hydrated.private_key_passphrase = input.private_key_passphrase;
    }
    Ok(hydrated)
}

fn pending_profile(input: &RouterProfileInput) -> RouterProfile {
    RouterProfile {
        id: input.id.clone().unwrap_or_else(|| "pending".into()),
        name: input.name.clone(),
        host: input.host.clone(),
        port: input.port,
        username: input.username.clone(),
        auth_kind: input.auth_kind.clone(),
        credential_ref: "pending".into(),
        host_key_fingerprint: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::MatchScope;

    #[test]
    fn diagnostic_filename_does_not_include_router_data() {
        let filename = format!(
            "route-assistant-diagnostics-{}.json",
            Utc::now().format("%Y%m%d-%H%M%S")
        );
        assert!(!filename.contains("192.168"));
    }

    #[test]
    fn extracts_opkg_and_apk_plugin_versions() {
        assert_eq!(
            extract_package_version("luci-app-openclash - 0.47.116-beta", &["openclash"]),
            Some("0.47.116-beta".into())
        );
        assert_eq!(
            extract_package_version(
                "luci-app-openclash-0.47.116-r1 x86_64 {luci-app-openclash}",
                &["openclash"]
            ),
            Some("0.47.116-r1".into())
        );
        assert_eq!(
            extract_package_version("luci-app-passwall2-25.7.1-r2", &["passwall2", "passwall"]),
            Some("25.7.1-r2".into())
        );
    }

    fn rule(action: RuleAction) -> RuleSpec {
        RuleSpec {
            id: Uuid::new_v4().to_string(),
            scope: MatchScope::Exact,
            domain: "www.baidu.com".into(),
            normalized_domain: "www.baidu.com".into(),
            action,
            enabled: true,
            note: None,
            managed: true,
            source: None,
        }
    }

    fn detected(
        kind: PluginKind,
        service_state: ServiceState,
        support_level: PluginSupportLevel,
        writable: bool,
    ) -> DetectedPlugin {
        let managed = support_level == PluginSupportLevel::Managed;
        DetectedPlugin {
            display_name: format!("{kind:?}"),
            kind,
            version: Some("1.0.0".into()),
            service_state,
            core_version: writable.then(|| "core-1".into()),
            capabilities: if writable {
                vec!["rollback".into()]
            } else {
                vec!["readOnlyDiagnostics".into()]
            },
            support_level,
            can_select: managed,
            can_read_custom_rules: managed,
            read_only: !writable,
            reason: (!writable).then(|| "只读".into()),
        }
    }

    #[test]
    fn auto_selects_unique_running_managed_plugin() {
        let state = resolve_plugin_state(
            vec![
                detected(
                    PluginKind::OpenClash,
                    ServiceState::Running,
                    PluginSupportLevel::Managed,
                    true,
                ),
                detected(
                    PluginKind::Nikki,
                    ServiceState::Stopped,
                    PluginSupportLevel::Managed,
                    false,
                ),
            ],
            None,
        );
        assert_eq!(state.selected_plugin, Some(PluginKind::OpenClash));
        assert_eq!(
            state.selection_reason,
            Some(PluginSelectionReason::AutoRunning)
        );
        assert!(state.can_write);
    }

    #[test]
    fn auto_selects_only_stopped_managed_plugin_for_reading() {
        let state = resolve_plugin_state(
            vec![detected(
                PluginKind::Nikki,
                ServiceState::Stopped,
                PluginSupportLevel::Managed,
                false,
            )],
            None,
        );
        assert_eq!(state.selected_plugin, Some(PluginKind::Nikki));
        assert_eq!(
            state.selection_reason,
            Some(PluginSelectionReason::AutoOnlyManaged)
        );
        assert!(!state.can_write);
        assert!(state.write_block_reason.unwrap().contains("没有运行"));
    }

    #[test]
    fn two_running_managed_plugins_require_and_remember_manual_selection() {
        let plugins = vec![
            detected(
                PluginKind::OpenClash,
                ServiceState::Running,
                PluginSupportLevel::Managed,
                true,
            ),
            detected(
                PluginKind::Nikki,
                ServiceState::Running,
                PluginSupportLevel::Managed,
                true,
            ),
        ];
        let unresolved = resolve_plugin_state(plugins.clone(), None);
        assert!(unresolved.requires_manual_selection);
        assert!(!unresolved.can_write);

        let selected = resolve_plugin_state(plugins, Some(PluginKind::Nikki));
        assert_eq!(selected.selected_plugin, Some(PluginKind::Nikki));
        assert_eq!(
            selected.selection_reason,
            Some(PluginSelectionReason::Manual)
        );
        assert!(!selected.requires_manual_selection);
        assert!(selected.can_write);
        assert_eq!(selected.running_plugin_count, 2);
    }

    #[test]
    fn running_detected_only_plugin_warns_without_blocking_selected_plugin() {
        let state = resolve_plugin_state(
            vec![
                detected(
                    PluginKind::OpenClash,
                    ServiceState::Running,
                    PluginSupportLevel::Managed,
                    true,
                ),
                detected(
                    PluginKind::HomeProxy,
                    ServiceState::Running,
                    PluginSupportLevel::DetectedOnly,
                    false,
                ),
            ],
            None,
        );
        assert_eq!(state.selected_plugin, Some(PluginKind::OpenClash));
        assert!(state.can_write);
        assert!(state.write_block_reason.is_none());
        assert!(state.risk_warning.unwrap().contains("HomeProxy"));
    }

    #[test]
    fn plugin_state_token_changes_when_runtime_state_changes() {
        let running = resolve_plugin_state(
            vec![detected(
                PluginKind::OpenClash,
                ServiceState::Running,
                PluginSupportLevel::Managed,
                true,
            )],
            None,
        );
        let stopped = resolve_plugin_state(
            vec![detected(
                PluginKind::OpenClash,
                ServiceState::Stopped,
                PluginSupportLevel::Managed,
                false,
            )],
            None,
        );
        assert_ne!(running.state_token, stopped.state_token);
    }

    #[test]
    fn detects_duplicate_override_and_missing_policy_target() {
        let existing = rule(RuleAction::Direct);
        let duplicate = detect_rule_conflicts(
            std::slice::from_ref(&existing),
            &rule(RuleAction::Direct),
            &[],
        );
        assert_eq!(duplicate[0].kind, "duplicate");
        assert!(!duplicate[0].requires_override);

        let override_conflict = detect_rule_conflicts(&[existing], &rule(RuleAction::Reject), &[]);
        assert_eq!(override_conflict[0].kind, "differentAction");
        assert!(override_conflict[0].requires_override);

        let missing = detect_rule_conflicts(
            &[],
            &rule(RuleAction::PolicyGroup {
                name: "不存在".into(),
            }),
            &[PolicyTarget {
                name: "节点选择".into(),
                kind: "group".into(),
            }],
        );
        assert_eq!(missing[0].kind, "invalidTarget");
    }

    #[test]
    fn conflict_detection_includes_existing_rules_but_ignores_disabled_and_same_id() {
        let mut existing = rule(RuleAction::Direct);
        existing.managed = false;
        existing.source = Some("/etc/openclash/custom/openclash_custom_rules.list:12".into());
        assert_eq!(
            detect_rule_conflicts(&[existing.clone()], &rule(RuleAction::Reject), &[])[0].kind,
            "differentAction"
        );

        existing.enabled = false;
        assert!(
            detect_rule_conflicts(&[existing.clone()], &rule(RuleAction::Reject), &[]).is_empty()
        );

        existing.enabled = true;
        let mut update = rule(RuleAction::Reject);
        update.id = existing.id.clone();
        assert!(detect_rule_conflicts(&[existing], &update, &[]).is_empty());
    }
}
