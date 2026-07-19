pub mod nikki;
pub mod openclash;

use crate::error::{AppError, AppResult};
use crate::models::{PluginKind, PolicyTarget, RuleSpec, ServiceState, VerificationReport};
use crate::ssh::SshSession;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub port: u16,
    pub secret: Option<String>,
}

pub async fn api_config(session: &SshSession, plugin: &PluginKind) -> AppResult<ApiConfig> {
    let output = match plugin {
        PluginKind::OpenClash => {
            session
                .run_checked(
                    r#"port=$(uci -q get openclash.config.cn_port); [ -n "$port" ] || port=9090; secret=$(uci -q get openclash.config.dashboard_password); printf '%s\n%s' "$port" "$secret""#,
                )
                .await?
        }
        PluginKind::Nikki => {
            session
                .run_checked(
                    r#"listen=$(uci -q get nikki.mixin.api_listen); port=${listen##*:}; [ -n "$port" ] || port=9090; secret=$(uci -q get nikki.mixin.api_secret); printf '%s\n%s' "$port" "$secret""#,
                )
                .await?
        }
        PluginKind::Unsupported => return Err(AppError::Unsupported("没有可用的 Mihomo 插件".into())),
    };
    let mut lines = output.lines();
    let port = lines
        .next()
        .and_then(|value| value.trim().parse::<u16>().ok())
        .ok_or_else(|| AppError::Unsupported("无法确定 Mihomo 控制端口".into()))?;
    let secret = lines.next().map(str::trim).filter(|value| !value.is_empty()).map(ToOwned::to_owned);
    Ok(ApiConfig { port, secret })
}

pub async fn policy_targets(session: &SshSession, plugin: &PluginKind) -> AppResult<Vec<PolicyTarget>> {
    let config = api_config(session, plugin).await?;
    let value = session
        .api_get(config.port, config.secret.as_deref(), "/proxies")
        .await?;
    let mut targets = vec![
        PolicyTarget { name: "DIRECT".into(), kind: "builtIn".into() },
        PolicyTarget { name: "REJECT".into(), kind: "builtIn".into() },
    ];
    if let Some(proxies) = value.get("proxies").and_then(Value::as_object) {
        for (name, item) in proxies {
            let kind = item.get("type").and_then(Value::as_str).unwrap_or_default();
            if matches!(kind, "Selector" | "URLTest" | "Fallback" | "LoadBalance") {
                targets.push(PolicyTarget { name: name.clone(), kind: "group".into() });
            }
        }
    }
    targets.sort_by(|left, right| left.kind.cmp(&right.kind).then_with(|| left.name.cmp(&right.name)));
    targets.dedup_by(|left, right| left.name == right.name);
    Ok(targets)
}

pub async fn verify_runtime_rule(
    session: &SshSession,
    plugin: &PluginKind,
    change_id: &str,
    rule: &RuleSpec,
    backup_id: Option<String>,
) -> VerificationReport {
    let service_state = service_state(session, plugin).await;
    let mut report = VerificationReport {
        change_id: change_id.to_owned(),
        success: false,
        service_state: service_state.clone(),
        core_api_reachable: false,
        rule_present: false,
        rule_index: None,
        hit_verified: false,
        verification_limited: true,
        dns_observation: None,
        rolled_back: false,
        backup_id,
        messages: Vec::new(),
    };
    if service_state != ServiceState::Running {
        report.messages.push("代理插件没有恢复运行".into());
        return report;
    }
    let config = match api_config(session, plugin).await {
        Ok(value) => value,
        Err(error) => {
            report.messages.push(error.to_string());
            return report;
        }
    };
    let runtime = match session.api_get(config.port, config.secret.as_deref(), "/rules").await {
        Ok(value) => value,
        Err(error) => {
            report.messages.push(error.to_string());
            return report;
        }
    };
    report.core_api_reachable = true;
    if let Some(rules) = runtime.get("rules").and_then(Value::as_array) {
        let expected_type = if matches!(rule.scope, crate::models::MatchScope::Exact) { "DOMAIN" } else { "DOMAIN-SUFFIX" };
        for (index, item) in rules.iter().enumerate() {
            if item.get("type").and_then(Value::as_str) == Some(expected_type)
                && item.get("payload").and_then(Value::as_str) == Some(rule.normalized_domain.as_str())
                && item.get("proxy").and_then(Value::as_str) == Some(rule.action.target())
            {
                report.rule_present = true;
                report.rule_index = Some(index);
                if let Some(hit_count) = item.pointer("/extra/hitCount").and_then(Value::as_u64) {
                    report.hit_verified = hit_count > 0;
                    report.verification_limited = false;
                }
                break;
            }
        }
    }
    report.success = report.core_api_reachable && report.rule_present;
    if report.success {
        report.messages.push(if report.hit_verified {
            "规则已生效，并检测到实际命中。".into()
        } else {
            "规则已写入运行配置；尚未观察到实际流量命中。".into()
        });
    } else {
        report.messages.push("运行配置中没有找到目标规则。".into());
    }
    report
}

pub async fn verify_runtime_ready_after_delete(
    session: &SshSession,
    plugin: &PluginKind,
    change_id: &str,
    backup_id: Option<String>,
) -> VerificationReport {
    let service_state = service_state(session, plugin).await;
    let mut report = VerificationReport {
        change_id: change_id.to_owned(),
        success: false,
        service_state: service_state.clone(),
        core_api_reachable: false,
        rule_present: false,
        rule_index: None,
        hit_verified: false,
        verification_limited: true,
        dns_observation: None,
        rolled_back: false,
        backup_id,
        messages: Vec::new(),
    };
    if service_state != ServiceState::Running {
        report.messages.push("删除后代理插件没有恢复运行。".into());
        return report;
    }
    if let Ok(config) = api_config(session, plugin).await {
        report.core_api_reachable = session
            .api_get(config.port, config.secret.as_deref(), "/version")
            .await
            .is_ok();
    }
    report.success = report.core_api_reachable;
    report.messages.push(if report.success {
        "助手规则已删除，代理服务与核心 API 均已恢复。".into()
    } else {
        "助手规则已删除，但核心 API 验证失败。".into()
    });
    report
}

pub async fn service_state(session: &SshSession, plugin: &PluginKind) -> ServiceState {
    let service = match plugin {
        PluginKind::OpenClash => "openclash",
        PluginKind::Nikki => "nikki",
        PluginKind::Unsupported => return ServiceState::Unknown,
    };
    let command = format!("/etc/init.d/{service} status >/dev/null 2>&1");
    match session.run(&command).await {
        Ok(output) if output.exit_status == 0 => ServiceState::Running,
        Ok(_) => ServiceState::Stopped,
        Err(_) => ServiceState::Unknown,
    }
}

pub fn validate_backup_id(backup_id: &str) -> AppResult<()> {
    if backup_id.is_empty()
        || backup_id.len() > 96
        || !backup_id.chars().all(|value| value.is_ascii_alphanumeric() || matches!(value, '-' | '_'))
    {
        return Err(AppError::Validation("备份编号无效".into()));
    }
    Ok(())
}
