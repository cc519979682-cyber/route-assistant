use crate::adapters::{validate_backup_id, verify_runtime_ready_after_delete, verify_runtime_rule};
use crate::error::{AppError, AppResult};
use crate::models::{
    CustomRuleNotice, CustomRuleOwner, CustomRuleParseState, CustomRuleRecord, CustomRulesSnapshot,
    MatchScope, PluginKind, RuleAction, RuleDraft, RuleSpec, VerificationReport,
};
use crate::redact::redact;
use crate::ssh::{SshSession, shell_quote};
use base64::Engine;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tokio::time::{Duration, sleep};
use uuid::Uuid;

pub fn section_name(rule_id: &str) -> AppResult<String> {
    let compact: String = rule_id
        .chars()
        .filter(|value| value.is_ascii_hexdigit())
        .collect();
    if compact.len() < 16 {
        return Err(AppError::Validation("规则编号无效".into()));
    }
    Ok(format!("route_assistant_{compact}"))
}

fn parse_uci_sections(output: &str) -> (Vec<String>, HashMap<String, HashMap<String, String>>) {
    let mut order = Vec::new();
    let mut sections: HashMap<String, HashMap<String, String>> = HashMap::new();
    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("nikki."))
    {
        let Some((key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let Some(rest) = key.strip_prefix("nikki.") else {
            continue;
        };
        let mut parts = rest.splitn(2, '.');
        let section = parts.next().unwrap_or_default();
        let option = parts.next().unwrap_or("_type");
        if section.is_empty()
            || !matches!(
                option,
                "_type"
                    | "enabled"
                    | "type"
                    | "matcher"
                    | "node"
                    | "route_assistant_id"
                    | "route_assistant_note"
            )
        {
            continue;
        }
        let value = raw_value.trim_matches('\'').trim_matches('"').to_owned();
        if option == "_type" && value == "rule" && !order.iter().any(|item| item == section) {
            order.push(section.to_owned());
        }
        sections
            .entry(section.to_owned())
            .or_default()
            .insert(option.to_owned(), value);
    }
    (order, sections)
}

fn stable_record_id(source_location: &str, raw: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"nikki\0");
    digest.update(source_location.as_bytes());
    digest.update(b"\0");
    digest.update(raw.as_bytes());
    format!("nikki-{}", hex::encode(&digest.finalize()[..12]))
}

fn action_from_target(target: &str) -> RuleAction {
    match target {
        "DIRECT" => RuleAction::Direct,
        "REJECT" | "REJECT-DROP" => RuleAction::Reject,
        name => RuleAction::PolicyGroup {
            name: name.to_owned(),
        },
    }
}

pub fn parse_uci_custom_rules(output: &str, has_mixin_rules: bool) -> CustomRulesSnapshot {
    let (order, sections) = parse_uci_sections(output);
    let mut rules = Vec::new();
    for (index, section) in order.iter().enumerate() {
        let Some(values) = sections.get(section) else {
            continue;
        };
        let matcher = values.get("matcher").map(|value| redact(value));
        let kind = values
            .get("type")
            .cloned()
            .unwrap_or_else(|| "UNKNOWN".into())
            .to_ascii_uppercase();
        let target = values.get("node").map(|value| redact(value));
        let owner = if section.starts_with("route_assistant_") {
            CustomRuleOwner::Assistant
        } else {
            CustomRuleOwner::Existing
        };
        let enabled = values.get("enabled").map(String::as_str) != Some("0");
        let valid_shape = matcher.as_deref().is_some_and(|value| !value.is_empty())
            && target.as_deref().is_some_and(|value| !value.is_empty())
            && kind != "UNKNOWN";
        let supported_type = matches!(
            kind.as_str(),
            "DOMAIN"
                | "DOMAIN-SUFFIX"
                | "DOMAIN-KEYWORD"
                | "IP-CIDR"
                | "IP-CIDR6"
                | "SRC-IP-CIDR"
                | "DST-PORT"
                | "SRC-PORT"
                | "RULE-SET"
        );
        let note = values
            .get("route_assistant_note")
            .and_then(|value| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(value)
                    .ok()
            })
            .and_then(|value| String::from_utf8(value).ok())
            .map(|value| redact(&value));
        let assistant_id = values
            .get("route_assistant_id")
            .cloned()
            .unwrap_or_else(|| section.trim_start_matches("route_assistant_").to_owned());
        let valid_assistant_id = (16..=36).contains(&assistant_id.len())
            && assistant_id
                .chars()
                .all(|value| value.is_ascii_hexdigit() || value == '-');
        let assistant_rule = if owner == CustomRuleOwner::Assistant
            && valid_assistant_id
            && valid_shape
            && matches!(kind.as_str(), "DOMAIN" | "DOMAIN-SUFFIX")
        {
            let domain = matcher.clone().unwrap_or_default();
            Some(RuleSpec {
                id: assistant_id,
                scope: if kind == "DOMAIN-SUFFIX" {
                    MatchScope::Suffix
                } else {
                    MatchScope::Exact
                },
                domain: domain.clone(),
                normalized_domain: domain,
                action: action_from_target(target.as_deref().unwrap_or("DIRECT")),
                enabled,
                note: note.clone(),
                managed: true,
                source: Some(format!("/etc/config/nikki#{section}")),
            })
        } else {
            None
        };
        let copy_draft = if valid_shape && matches!(kind.as_str(), "DOMAIN" | "DOMAIN-SUFFIX") {
            Some(RuleDraft {
                scope: if kind == "DOMAIN-SUFFIX" {
                    MatchScope::Suffix
                } else {
                    MatchScope::Exact
                },
                domain: matcher.clone().unwrap_or_default(),
                action: action_from_target(target.as_deref().unwrap_or("DIRECT")),
                note: note.clone(),
            })
        } else {
            None
        };
        let raw_preview = [
            kind.clone(),
            matcher
                .clone()
                .unwrap_or_else(|| "<missing matcher>".into()),
            target.clone().unwrap_or_else(|| "<missing target>".into()),
        ]
        .join(",");
        let source_location = format!("/etc/config/nikki#{section}");
        let (parse_state, warning) = if !valid_shape {
            (
                CustomRuleParseState::Invalid,
                Some("规则缺少 type、matcher 或 node 字段，已禁止复制和编辑。".into()),
            )
        } else if !supported_type {
            (
                CustomRuleParseState::Raw,
                Some("当前版本不能识别此规则类型，已按原字段显示。".into()),
            )
        } else if owner == CustomRuleOwner::Assistant && assistant_rule.is_none() {
            (
                CustomRuleParseState::Invalid,
                Some("助手规则字段不完整，已禁止编辑和删除。".into()),
            )
        } else {
            (CustomRuleParseState::Structured, None)
        };
        rules.push(CustomRuleRecord {
            id: stable_record_id(&source_location, &raw_preview),
            source_location,
            position: index + 1,
            owner,
            enabled,
            rule_type: kind,
            matcher,
            target,
            note,
            raw_preview,
            parse_state,
            warning,
            copy_draft,
            assistant_rule,
        });
    }
    let notices = if has_mixin_rules {
        vec![CustomRuleNotice {
            code: "mixinRulesPresent".into(),
            level: "info".into(),
            message: "存在混入文件规则，本版本未展开。".into(),
        }]
    } else {
        Vec::new()
    };
    CustomRulesSnapshot {
        plugin: PluginKind::Nikki,
        rules,
        notices,
    }
}

pub fn parse_uci_managed_rules(output: &str) -> AppResult<Vec<RuleSpec>> {
    Ok(parse_uci_custom_rules(output, false)
        .rules
        .into_iter()
        .filter_map(|record| record.assistant_rule)
        .collect())
}

pub async fn list_rules(session: &SshSession) -> AppResult<Vec<RuleSpec>> {
    let output = session.run_checked(uci_rule_query()).await?;
    parse_uci_managed_rules(&output)
}

fn uci_rule_query() -> &'static str {
    r#"uci -q show nikki | sed -n 's/^nikki\.\([^.=]*\)=rule$/\1/p' | while IFS= read -r section; do printf '%s' "$section" | grep -Eq '^(@rule\[[0-9]+\]|[A-Za-z0-9_]+)$' || continue; uci -q show "nikki.$section" | sed -n -e '/=rule$/p' -e '/\.enabled=/p' -e '/\.type=/p' -e '/\.matcher=/p' -e '/\.node=/p' -e '/\.route_assistant_id=/p' -e '/\.route_assistant_note=/p'; done"#
}

fn mixin_rule_detection_query() -> &'static str {
    r#"if [ "$(uci -q get nikki.mixin.mixin_file_content)" = "1" ] && grep -qs '^[[:space:]]*nikki-rules[[:space:]]*:' /etc/nikki/mixin.yaml 2>/dev/null; then printf 1; else printf 0; fi"#
}

pub async fn list_custom_rules(session: &SshSession) -> AppResult<CustomRulesSnapshot> {
    let output = session.run_checked(uci_rule_query()).await?;
    let mixin = session
        .run(mixin_rule_detection_query())
        .await
        .map(|value| value.stdout.trim() == "1")
        .unwrap_or(false);
    Ok(parse_uci_custom_rules(&output, mixin))
}

pub async fn apply_rule(
    session: &SshSession,
    change_id: &str,
    rule: &RuleSpec,
) -> AppResult<VerificationReport> {
    let section = section_name(&rule.id)?;
    let backup_id = create_backup(session).await?;
    start_watchdog(session, &backup_id).await?;
    let kind = if matches!(rule.scope, MatchScope::Suffix) {
        "DOMAIN-SUFFIX"
    } else {
        "DOMAIN"
    };
    let note = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(rule.note.as_deref().unwrap_or_default());
    let batch = format!(
        "set nikki.{section}=rule\nset nikki.{section}.enabled='1'\nset nikki.{section}.type={kind}\nset nikki.{section}.matcher={matcher}\nset nikki.{section}.node={node}\nset nikki.{section}.route_assistant_id={id}\nset nikki.{section}.route_assistant_note={note}\nset nikki.mixin.rule='1'\n",
        matcher = shell_quote(&rule.normalized_domain),
        node = shell_quote(rule.action.target()),
        id = shell_quote(&rule.id),
        note = shell_quote(&note),
    );
    let command = format!(
        "printf %s {} | uci -q batch && uci -q commit nikki && /etc/init.d/nikki reload >/dev/null 2>&1",
        shell_quote(&batch)
    );
    if let Err(error) = session.run_checked(&command).await {
        rollback(session, &backup_id).await?;
        return Err(AppError::Verification(format!(
            "Nikki 写入失败并已回滚：{error}"
        )));
    }
    sleep(Duration::from_secs(6)).await;
    let mut report = verify_runtime_rule(
        session,
        &PluginKind::Nikki,
        change_id,
        rule,
        Some(backup_id.clone()),
    )
    .await;
    if report.success {
        commit_watchdog(session, &backup_id).await?;
    } else {
        rollback(session, &backup_id).await?;
        report.rolled_back = true;
        report
            .messages
            .push("验证失败，已恢复 Nikki 修改前配置。".into());
    }
    Ok(report)
}

pub async fn remove_rule(
    session: &SshSession,
    change_id: &str,
    rule: &RuleSpec,
) -> AppResult<VerificationReport> {
    let section = section_name(&rule.id)?;
    let existing = list_rules(session).await?;
    if !existing.iter().any(|item| item.id == rule.id) {
        return Err(AppError::Validation(
            "找不到要删除的助手规则；未修改 Nikki。".into(),
        ));
    }
    let backup_id = create_backup(session).await?;
    start_watchdog(session, &backup_id).await?;
    let command = format!(
        "uci -q delete nikki.{section} && uci -q commit nikki && /etc/init.d/nikki reload >/dev/null 2>&1"
    );
    if let Err(error) = session.run_checked(&command).await {
        rollback(session, &backup_id).await?;
        return Err(AppError::Verification(format!(
            "Nikki 删除失败并已回滚：{error}"
        )));
    }
    sleep(Duration::from_secs(6)).await;
    let absent = !list_rules(session)
        .await?
        .iter()
        .any(|item| item.id == rule.id);
    let mut report = verify_runtime_ready_after_delete(
        session,
        &PluginKind::Nikki,
        change_id,
        Some(backup_id.clone()),
    )
    .await;
    report.success &= absent;
    if report.success {
        commit_watchdog(session, &backup_id).await?;
    } else {
        rollback(session, &backup_id).await?;
        report.rolled_back = true;
        report
            .messages
            .push("删除验证失败，已恢复 Nikki 修改前配置。".into());
    }
    Ok(report)
}

pub async fn verify_rule(
    session: &SshSession,
    change_id: &str,
    rule: &RuleSpec,
) -> VerificationReport {
    verify_runtime_rule(session, &PluginKind::Nikki, change_id, rule, None).await
}

pub async fn rollback(session: &SshSession, backup_id: &str) -> AppResult<()> {
    validate_backup_id(backup_id)?;
    let directory = format!("/etc/route-assistant/backups/{backup_id}");
    let command = format!(
        "test -f {d}/nikki.config; cp -f {d}/nikki.config /etc/config/nikki; chmod 600 /etc/config/nikki; /etc/init.d/nikki reload >/dev/null 2>&1",
        d = shell_quote(&directory)
    );
    session.run_checked(&command).await.map(|_| ())
}

async fn create_backup(session: &SshSession) -> AppResult<String> {
    let id = format!(
        "{}-{}",
        Utc::now().format("%Y%m%d%H%M%S"),
        &Uuid::new_v4().simple().to_string()[..8]
    );
    let directory = format!("/etc/route-assistant/backups/{id}");
    let command = format!(
        "umask 077; mkdir -p {d}; chmod 700 /etc/route-assistant /etc/route-assistant/backups {d}; cp -p /etc/config/nikki {d}/nikki.config; /etc/init.d/nikki status > {d}/service.status 2>&1 || true; ls -1dt /etc/route-assistant/backups/* 2>/dev/null | tail -n +11 | while read old; do case \"$old\" in /etc/route-assistant/backups/*) rm -rf -- \"$old\";; esac; done",
        d = shell_quote(&directory)
    );
    session.run_checked(&command).await?;
    Ok(id)
}

async fn start_watchdog(session: &SshSession, backup_id: &str) -> AppResult<()> {
    validate_backup_id(backup_id)?;
    let directory = format!("/etc/route-assistant/backups/{backup_id}");
    let marker = format!("/tmp/route-assistant-{backup_id}.commit");
    let script = format!("/tmp/route-assistant-{backup_id}.rollback.sh");
    let body = format!(
        "#!/bin/sh\nsleep 120\n[ -f {marker} ] && exit 0\ncp -f {dir}/nikki.config /etc/config/nikki\nchmod 600 /etc/config/nikki\n/etc/init.d/nikki reload >/dev/null 2>&1\n",
        marker = shell_quote(&marker),
        dir = shell_quote(&directory)
    );
    session.write_file(&script, body.as_bytes(), 0o700).await?;
    session
        .run_checked(&format!(
            "rm -f {}; nohup {} >/dev/null 2>&1 &",
            shell_quote(&marker),
            shell_quote(&script)
        ))
        .await?;
    Ok(())
}

async fn commit_watchdog(session: &SshSession, backup_id: &str) -> AppResult<()> {
    validate_backup_id(backup_id)?;
    let marker = format!("/tmp/route-assistant-{backup_id}.commit");
    session
        .run_checked(&format!("umask 077; : > {}", shell_quote(&marker)))
        .await
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_named_managed_sections() {
        let output = r#"nikki.route_assistant_e62f3a7d45544b20bc493af6eea5d650=rule
nikki.route_assistant_e62f3a7d45544b20bc493af6eea5d650.enabled='1'
nikki.route_assistant_e62f3a7d45544b20bc493af6eea5d650.type='DOMAIN'
nikki.route_assistant_e62f3a7d45544b20bc493af6eea5d650.matcher='www.baidu.com'
nikki.route_assistant_e62f3a7d45544b20bc493af6eea5d650.node='DIRECT'
nikki.route_assistant_e62f3a7d45544b20bc493af6eea5d650.route_assistant_id='e62f3a7d-4554-4b20-bc49-3af6eea5d650'
nikki.unmanaged=rule
"#;
        let rules = parse_uci_managed_rules(output).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].normalized_domain, "www.baidu.com");
        assert_eq!(rules[0].action, RuleAction::Direct);
    }

    #[test]
    fn lists_named_anonymous_disabled_and_invalid_rules_in_original_order() {
        let output = r#"nikki.route_assistant_e62f3a7d45544b20bc493af6eea5d650=rule
nikki.route_assistant_e62f3a7d45544b20bc493af6eea5d650.enabled='1'
nikki.route_assistant_e62f3a7d45544b20bc493af6eea5d650.type='DOMAIN'
nikki.route_assistant_e62f3a7d45544b20bc493af6eea5d650.matcher='www.baidu.com'
nikki.route_assistant_e62f3a7d45544b20bc493af6eea5d650.node='DIRECT'
nikki.route_assistant_e62f3a7d45544b20bc493af6eea5d650.route_assistant_id='e62f3a7d-4554-4b20-bc49-3af6eea5d650'
nikki.user_rule=rule
nikki.user_rule.enabled='0'
nikki.user_rule.type='DOMAIN-SUFFIX'
nikki.user_rule.matcher='example.com'
nikki.user_rule.node='REJECT'
nikki.@rule[0]=rule
nikki.@rule[0].type='IP-CIDR'
nikki.@rule[0].matcher='192.0.2.0/24'
nikki.@rule[0].node='DIRECT'
nikki.broken=rule
nikki.broken.type='DOMAIN'
nikki.broken.matcher='missing-target.example'
nikki.config.password='should-never-appear'
nikki.config.api_key='should-never-appear'
nikki.config.subscription='https://secret.example/sub'
"#;
        let snapshot = parse_uci_custom_rules(output, true);
        assert_eq!(snapshot.rules.len(), 4);
        assert_eq!(snapshot.rules[0].owner, CustomRuleOwner::Assistant);
        assert_eq!(snapshot.rules[1].owner, CustomRuleOwner::Existing);
        assert!(!snapshot.rules[1].enabled);
        assert!(snapshot.rules[1].copy_draft.is_some());
        assert_eq!(snapshot.rules[2].rule_type, "IP-CIDR");
        assert_eq!(snapshot.rules[3].parse_state, CustomRuleParseState::Invalid);
        assert_eq!(snapshot.notices[0].code, "mixinRulesPresent");
        let serialized = serde_json::to_string(&snapshot).unwrap();
        assert!(!serialized.contains("should-never-appear"));
        assert!(!serialized.contains("secret.example"));
    }

    #[test]
    fn remote_query_only_emits_rule_sections_and_whitelisted_fields() {
        let query = uci_rule_query();
        assert!(query.contains("=rule"));
        assert!(query.contains("route_assistant_note"));
        assert!(!query.contains("password"));
        assert!(!query.contains("api_key"));
        assert!(!query.contains("subscription"));

        let mixin_query = mixin_rule_detection_query();
        assert!(mixin_query.contains("nikki.mixin.mixin_file_content"));
        assert!(mixin_query.contains("/etc/nikki/mixin.yaml"));
        assert!(!mixin_query.contains("grep -R"));
        assert!(!mixin_query.contains("subscriptions"));
    }

    #[test]
    fn redacts_urls_even_when_they_appear_in_whitelisted_rule_fields() {
        let output = "nikki.bad=rule\nnikki.bad.type='RULE-SET'\nnikki.bad.matcher='https://secret.example/sub'\nnikki.bad.node='DIRECT'\n";
        let serialized = serde_json::to_string(&parse_uci_custom_rules(output, false)).unwrap();
        assert!(!serialized.contains("secret.example"));
        assert!(serialized.contains("REDACTED"));
    }
}
