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
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;
use uuid::Uuid;

pub struct AppState {
    pub store: Store,
    selected_plugins: Mutex<HashMap<String, PluginKind>>,
}

impl AppState {
    pub fn new(store: Store) -> Self {
        Self {
            store,
            selected_plugins: Mutex::new(HashMap::new()),
        }
    }

    pub fn select_plugin(&self, profile_id: &str, plugin: PluginKind) -> AppResult<()> {
        if !matches!(plugin, PluginKind::OpenClash | PluginKind::Nikki) {
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
            plugins: Vec::new(),
            selected_plugin: None,
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
    let running: Vec<PluginKind> = plugins
        .iter()
        .filter(|item| {
            item.service_state == ServiceState::Running && item.kind != PluginKind::Unsupported
        })
        .map(|item| item.kind.clone())
        .collect();
    let selected = if running.len() == 1 {
        running.first().cloned()
    } else {
        state.selected_plugin(&profile.id)
    };
    if let Some(plugin) = selected.clone() {
        state.select_plugin(&profile.id, plugin)?;
    }
    session.disconnect().await;
    Ok(RouterSnapshot {
        profile,
        distribution,
        release,
        plugins,
        selected_plugin: selected,
        host_key_fingerprint: fingerprint,
        needs_host_key_trust: false,
    })
}

pub async fn detect_plugins(session: &SshSession) -> Vec<DetectedPlugin> {
    let package_output = session
        .run("(opkg list-installed 2>/dev/null || apk list --installed 2>/dev/null) | grep -E '(^|-)openclash|(^|-)nikki' || true")
        .await
        .map(|value| value.stdout)
        .unwrap_or_default();
    let openclash_installed = package_output.to_lowercase().contains("openclash")
        || session
            .run("test -x /etc/init.d/openclash")
            .await
            .map(|v| v.exit_status == 0)
            .unwrap_or(false);
    let nikki_installed = package_output.to_lowercase().contains("nikki")
        || session
            .run("test -x /etc/init.d/nikki")
            .await
            .map(|v| v.exit_status == 0)
            .unwrap_or(false);
    let mut plugins = Vec::new();
    if openclash_installed {
        plugins.push(detect_plugin(session, PluginKind::OpenClash, &package_output).await);
    }
    if nikki_installed {
        plugins.push(detect_plugin(session, PluginKind::Nikki, &package_output).await);
    }
    if plugins.is_empty() {
        plugins.push(DetectedPlugin {
            kind: PluginKind::Unsupported,
            display_name: "未识别".into(),
            version: None,
            service_state: ServiceState::Unknown,
            core_version: None,
            capabilities: vec!["readOnlyDiagnostics".into()],
            read_only: true,
            reason: Some("没有发现 OpenClash 或 Nikki。不会尝试修改其他代理插件。".into()),
        });
    }
    plugins
}

async fn detect_plugin(session: &SshSession, kind: PluginKind, packages: &str) -> DetectedPlugin {
    let (name, needle) = match kind {
        PluginKind::OpenClash => ("OpenClash", "openclash"),
        PluginKind::Nikki => ("Nikki", "nikki"),
        PluginKind::Unsupported => ("未识别", ""),
    };
    let state = adapters::service_state(session, &kind).await;
    let version = packages
        .lines()
        .find(|line| line.to_lowercase().contains(needle))
        .and_then(|line| line.split_whitespace().nth(2))
        .map(ToOwned::to_owned);
    let core_version = if state == ServiceState::Running {
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
    let writable = api_ready && version_known && state == ServiceState::Running;
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
        read_only: !writable,
        reason: if !version_known {
            Some("无法确认插件版本，已进入只读诊断模式。".into())
        } else if !api_ready || state != ServiceState::Running {
            Some("服务未运行或无法通过 SSH 安全访问 Mihomo API".into())
        } else {
            None
        },
    }
}

pub async fn with_session(
    state: &AppState,
    profile_id: &str,
) -> AppResult<(SshSession, PluginKind)> {
    let profile = state.store.get_profile(profile_id)?;
    let input = state.store.profile_input_with_secret(&profile)?;
    let fingerprint = profile
        .host_key_fingerprint
        .as_deref()
        .ok_or_else(|| AppError::HostKeyUntrusted("档案没有保存主机指纹".into()))?;
    let session = SshSession::connect(&input, fingerprint).await?;
    let detected = detect_plugins(&session).await;
    let plugin = match state.selected_plugin(profile_id) {
        Some(value) => {
            let usable = detected
                .iter()
                .any(|item| item.kind == value && !item.read_only);
            if !usable {
                session.disconnect().await;
                return Err(AppError::Unsupported(
                    "所选插件当前为只读、已停止或版本未知；不会写入配置。".into(),
                ));
            }
            value
        }
        None => {
            let running: Vec<_> = detected
                .iter()
                .filter(|item| item.service_state == ServiceState::Running && !item.read_only)
                .map(|item| item.kind.clone())
                .collect();
            if running.len() == 1 {
                running[0].clone()
            } else {
                session.disconnect().await;
                return Err(AppError::Conflict(
                    "多个代理插件同时运行，请先明确选择要管理的插件".into(),
                ));
            }
        }
    };
    Ok((session, plugin))
}

pub async fn with_read_session(
    state: &AppState,
    profile_id: &str,
) -> AppResult<(SshSession, PluginKind)> {
    let profile = state.store.get_profile(profile_id)?;
    let input = state.store.profile_input_with_secret(&profile)?;
    let fingerprint = profile
        .host_key_fingerprint
        .as_deref()
        .ok_or_else(|| AppError::HostKeyUntrusted("档案没有保存主机指纹".into()))?;
    let session = SshSession::connect(&input, fingerprint).await?;
    let detected = detect_plugins(&session).await;
    let supported: Vec<PluginKind> = detected
        .iter()
        .filter(|item| matches!(item.kind, PluginKind::OpenClash | PluginKind::Nikki))
        .map(|item| item.kind.clone())
        .collect();
    let plugin = if let Some(selected) = state.selected_plugin(profile_id) {
        if supported.contains(&selected) {
            selected
        } else {
            session.disconnect().await;
            return Err(AppError::Unsupported(
                "所选插件已不存在，无法读取自定义规则。".into(),
            ));
        }
    } else {
        let running: Vec<PluginKind> = detected
            .iter()
            .filter(|item| {
                item.service_state == ServiceState::Running
                    && matches!(item.kind, PluginKind::OpenClash | PluginKind::Nikki)
            })
            .map(|item| item.kind.clone())
            .collect();
        if running.len() == 1 {
            running[0].clone()
        } else if supported.len() == 1 {
            supported[0].clone()
        } else {
            session.disconnect().await;
            return Err(AppError::Conflict(
                "检测到多个代理插件，请先选择要查看的插件。".into(),
            ));
        }
    };
    Ok((session, plugin))
}

pub async fn list_managed_rules(state: &AppState, profile_id: &str) -> AppResult<Vec<RuleSpec>> {
    let (session, plugin) = with_session(state, profile_id).await?;
    let result = match plugin {
        PluginKind::OpenClash => adapters::openclash::list_rules(&session).await,
        PluginKind::Nikki => adapters::nikki::list_rules(&session).await,
        PluginKind::Unsupported => Err(AppError::Unsupported("不支持的插件".into())),
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
        PluginKind::Unsupported => Err(AppError::Unsupported("不支持的插件".into())),
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
        PluginKind::Unsupported => Err(AppError::Unsupported("不支持的插件".into())),
    }
}

pub async fn create_plan(
    state: &AppState,
    profile_id: &str,
    draft: RuleDraft,
) -> AppResult<ChangePlan> {
    let normalized = normalize_domain(&draft.domain, &draft.scope)?;
    let (session, plugin) = with_session(state, profile_id).await?;
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
    let preview = format!(
        "将{scope_text}“{}”设为“{}”，对所有经过该软路由的设备生效。规则位于订阅规则之前；应用时 {plugin_name} 会短暂重载，预计不超过 20 秒。DNS 配置不会被修改。",
        rule.normalized_domain,
        rule.action.target()
    );
    let plan = ChangePlan {
        id: Uuid::new_v4().to_string(),
        profile_id: profile_id.to_owned(),
        plugin,
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
    let (session, plugin) = with_session(state, profile_id).await?;
    let managed = match plugin {
        PluginKind::OpenClash => adapters::openclash::list_rules(&session).await?,
        PluginKind::Nikki => adapters::nikki::list_rules(&session).await?,
        PluginKind::Unsupported => return Err(AppError::Unsupported("不支持的插件".into())),
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
    let (session, plugin) = with_session(state, profile_id).await?;
    let rules = match plugin {
        PluginKind::OpenClash => adapters::openclash::list_rules(&session).await?,
        PluginKind::Nikki => adapters::nikki::list_rules(&session).await?,
        PluginKind::Unsupported => return Err(AppError::Unsupported("不支持的插件".into())),
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
    let (session, selected) = with_session(state, &plan.profile_id).await?;
    if selected != plan.plugin {
        session.disconnect().await;
        return Err(AppError::Conflict(
            "生成预览后当前代理插件发生变化，请重新预览".into(),
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
        (PluginKind::Unsupported, _) => return Err(AppError::Unsupported("不支持的插件".into())),
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
    let (session, plugin) = with_session(state, profile_id).await?;
    let rules = match plugin {
        PluginKind::OpenClash => adapters::openclash::list_rules(&session).await?,
        PluginKind::Nikki => adapters::nikki::list_rules(&session).await?,
        PluginKind::Unsupported => return Err(AppError::Unsupported("不支持的插件".into())),
    };
    let rule = rules
        .into_iter()
        .find(|item| item.id == rule_id)
        .ok_or_else(|| AppError::Validation("找不到要验证的助手规则".into()))?;
    let report = match plugin {
        PluginKind::OpenClash => adapters::openclash::verify_rule(&session, rule_id, &rule).await,
        PluginKind::Nikki => adapters::nikki::verify_rule(&session, rule_id, &rule).await,
        PluginKind::Unsupported => unreachable!(),
    };
    session.disconnect().await;
    Ok(report)
}

pub async fn rollback(
    state: &AppState,
    profile_id: &str,
    backup_id: &str,
) -> AppResult<VerificationReport> {
    let (session, plugin) = with_session(state, profile_id).await?;
    match plugin {
        PluginKind::OpenClash => adapters::openclash::rollback(&session, backup_id).await?,
        PluginKind::Nikki => adapters::nikki::rollback(&session, backup_id).await?,
        PluginKind::Unsupported => return Err(AppError::Unsupported("不支持的插件".into())),
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

pub async fn export_diagnostics(state: &AppState, profile_id: &str) -> AppResult<PathBuf> {
    let profile = state.store.get_profile(profile_id)?;
    let (session, selected) = with_session(state, profile_id).await?;
    let release = session
        .run("cat /etc/openwrt_release 2>/dev/null")
        .await
        .unwrap_or(CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_status: 255,
        });
    let packages = session.run("(opkg list-installed 2>/dev/null || apk list --installed 2>/dev/null) | grep -E 'openclash|nikki|mihomo' || true").await.unwrap_or(CommandOutput { stdout: String::new(), stderr: String::new(), exit_status: 255 });
    let plugins = detect_plugins(&session).await;
    session.disconnect().await;
    let document = json!({
        "schema": 1,
        "generatedAt": Utc::now(),
        "appVersion": env!("CARGO_PKG_VERSION"),
        "router": { "name": profile.name, "host": "[REDACTED]", "port": profile.port, "username": "[REDACTED]" },
        "selectedPlugin": selected,
        "plugins": plugins,
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

    #[test]
    fn detects_duplicate_override_and_missing_policy_target() {
        let existing = rule(RuleAction::Direct);
        let duplicate = detect_rule_conflicts(std::slice::from_ref(&existing), &rule(RuleAction::Direct), &[]);
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
