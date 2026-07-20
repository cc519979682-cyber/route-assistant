pub mod nikki;
pub mod openclash;
pub mod openclash_dns;

use crate::error::{AppError, AppResult};
use crate::models::{PluginKind, PolicyTarget, RuleSpec, ServiceState, VerificationReport};
use crate::ssh::SshSession;
use serde_json::Value;
use tokio::time::{Duration, sleep};

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
        PluginKind::HomeProxy | PluginKind::PassWall | PluginKind::Unsupported => {
            return Err(AppError::Unsupported("当前插件没有可用的受支持 Mihomo 适配器".into()));
        }
    };
    let mut lines = output.lines();
    let port = lines
        .next()
        .and_then(|value| value.trim().parse::<u16>().ok())
        .ok_or_else(|| AppError::Unsupported("无法确定 Mihomo 控制端口".into()))?;
    let secret = lines
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    Ok(ApiConfig { port, secret })
}

pub async fn policy_targets(
    session: &SshSession,
    plugin: &PluginKind,
) -> AppResult<Vec<PolicyTarget>> {
    let config = api_config(session, plugin).await?;
    let value = session
        .api_get(config.port, config.secret.as_deref(), "/proxies")
        .await?;
    let mut targets = vec![
        PolicyTarget {
            name: "DIRECT".into(),
            kind: "builtIn".into(),
        },
        PolicyTarget {
            name: "REJECT".into(),
            kind: "builtIn".into(),
        },
    ];
    if let Some(proxies) = value.get("proxies").and_then(Value::as_object) {
        for (name, item) in proxies {
            let kind = item.get("type").and_then(Value::as_str).unwrap_or_default();
            if matches!(kind, "Selector" | "URLTest" | "Fallback" | "LoadBalance") {
                targets.push(PolicyTarget {
                    name: name.clone(),
                    kind: "group".into(),
                });
            }
        }
    }
    targets.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.name.cmp(&right.name))
    });
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

    // OpenClash restart can take longer than a single probe; Mihomo API type names also
    // differ from YAML tokens (DomainSuffix vs DOMAIN-SUFFIX).
    let expected_type = if matches!(rule.scope, crate::models::MatchScope::Exact) {
        "DOMAIN"
    } else {
        "DOMAIN-SUFFIX"
    };
    let expected_type_norm = normalize_rule_type_token(expected_type);
    let expected_payload = rule.normalized_domain.as_str();
    let expected_proxy = rule.action.target();

    for attempt in 0..6 {
        let runtime = match session
            .api_get(config.port, config.secret.as_deref(), "/rules")
            .await
        {
            Ok(value) => value,
            Err(error) => {
                if attempt + 1 == 6 {
                    report.messages.push(error.to_string());
                    return report;
                }
                sleep(Duration::from_secs(3)).await;
                continue;
            }
        };
        report.core_api_reachable = true;
        if let Some(rules) = runtime.get("rules").and_then(Value::as_array) {
            for (index, item) in rules.iter().enumerate() {
                let item_type = item.get("type").and_then(Value::as_str).unwrap_or_default();
                let item_payload = item.get("payload").and_then(Value::as_str).unwrap_or_default();
                let item_proxy = item.get("proxy").and_then(Value::as_str).unwrap_or_default();
                let type_ok = normalize_rule_type_token(item_type) == expected_type_norm;
                let payload_ok = item_payload.eq_ignore_ascii_case(expected_payload);
                let proxy_ok = item_proxy == expected_proxy
                    || (expected_proxy == "REJECT"
                        && matches!(item_proxy, "REJECT" | "REJECT-DROP" | "reject"));
                if type_ok && payload_ok && proxy_ok {
                    report.rule_present = true;
                    report.rule_index = Some(index);
                    if let Some(hit_count) = item.pointer("/extra/hitCount").and_then(Value::as_u64)
                    {
                        report.hit_verified = hit_count > 0;
                        report.verification_limited = false;
                    }
                    break;
                }
            }
        }
        if report.rule_present {
            break;
        }
        if attempt + 1 < 6 {
            sleep(Duration::from_secs(3)).await;
        }
    }

    report.success = report.core_api_reachable && report.rule_present;
    if report.success {
        report.messages.push(if report.hit_verified {
            "规则已生效，并检测到实际命中。".into()
        } else {
            "规则已写入运行配置；尚未观察到实际流量命中。".into()
        });
    } else if report.core_api_reachable {
        report.messages.push(format!(
            "运行配置中没有找到目标规则（期望 {expected_type},{expected_payload},{expected_proxy}）。请确认 OpenClash 已开启“自定义规则”，且助手规则已合并进运行配置。"
        ));
    } else {
        report.messages.push("运行配置中没有找到目标规则。".into());
    }
    report
}

/// Normalize YAML tokens (`DOMAIN-SUFFIX`) and Mihomo API tokens (`DomainSuffix`) for comparison.
pub fn normalize_rule_type_token(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
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
    let (services, process_pattern) = match plugin {
        PluginKind::OpenClash => (&["openclash"][..], "[o]penclash|[m]ihomo.*openclash"),
        PluginKind::Nikki => (&["nikki"][..], "[n]ikki|[m]ihomo.*nikki"),
        PluginKind::HomeProxy => (&["homeproxy"][..], ""),
        PluginKind::PassWall => (&["passwall", "passwall2"][..], ""),
        PluginKind::Unsupported => return ServiceState::Unknown,
    };
    let service_list = services.join(" ");
    let process_check = if process_pattern.is_empty() {
        String::new()
    } else {
        format!("pgrep -f '{process_pattern}' >/dev/null 2>&1 && exit 0;")
    };
    let command = format!(
        "found=0; for service in {service_list}; do if [ -x /etc/init.d/$service ]; then found=1; ubus call service list \"{{\\\"name\\\":\\\"$service\\\"}}\" 2>/dev/null | grep -Eq '\"running\"[[:space:]]*:[[:space:]]*true' && exit 0; /etc/init.d/$service status 2>/dev/null | grep -Eqi 'running|active' && exit 0; fi; done; {process_check} [ $found -eq 1 ] && exit 1; exit 2"
    );
    match session.run(&command).await {
        Ok(output) if output.exit_status == 0 => ServiceState::Running,
        Ok(output) if output.exit_status == 1 => ServiceState::Stopped,
        Ok(_) => ServiceState::Unknown,
        Err(_) => ServiceState::Unknown,
    }
}

pub fn validate_backup_id(backup_id: &str) -> AppResult<()> {
    if backup_id.is_empty()
        || backup_id.len() > 96
        || !backup_id
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, '-' | '_'))
    {
        return Err(AppError::Validation("备份编号无效".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::normalize_rule_type_token;

    #[test]
    fn normalizes_yaml_and_api_rule_type_tokens() {
        assert_eq!(normalize_rule_type_token("DOMAIN-SUFFIX"), "domainsuffix");
        assert_eq!(normalize_rule_type_token("DomainSuffix"), "domainsuffix");
        assert_eq!(normalize_rule_type_token("DOMAIN"), "domain");
        assert_eq!(normalize_rule_type_token("Domain"), "domain");
        assert_eq!(normalize_rule_type_token("domain-suffix"), "domainsuffix");
    }
}
