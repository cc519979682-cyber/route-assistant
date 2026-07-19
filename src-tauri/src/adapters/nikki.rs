use crate::adapters::{validate_backup_id, verify_runtime_ready_after_delete, verify_runtime_rule};
use crate::error::{AppError, AppResult};
use crate::models::{MatchScope, PluginKind, RuleAction, RuleSpec, VerificationReport};
use crate::ssh::{SshSession, shell_quote};
use base64::Engine;
use chrono::Utc;
use std::collections::BTreeMap;
use tokio::time::{Duration, sleep};
use uuid::Uuid;

pub fn section_name(rule_id: &str) -> AppResult<String> {
    let compact: String = rule_id.chars().filter(|value| value.is_ascii_hexdigit()).collect();
    if compact.len() < 16 {
        return Err(AppError::Validation("规则编号无效".into()));
    }
    Ok(format!("route_assistant_{compact}"))
}

pub fn parse_uci_managed_rules(output: &str) -> AppResult<Vec<RuleSpec>> {
    let mut sections: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for line in output.lines().map(str::trim).filter(|line| line.starts_with("nikki.route_assistant_")) {
        let Some((key, raw_value)) = line.split_once('=') else { continue };
        let Some(rest) = key.strip_prefix("nikki.") else { continue };
        let mut parts = rest.splitn(2, '.');
        let section = parts.next().unwrap_or_default();
        let option = parts.next().unwrap_or("_type");
        let value = raw_value.trim_matches('\'').trim_matches('"').to_owned();
        sections.entry(section.to_owned()).or_default().insert(option.to_owned(), value);
    }
    let mut rules = Vec::new();
    for (section, values) in sections {
        if values.get("_type").map(String::as_str) != Some("rule") {
            continue;
        }
        let matcher = values.get("matcher").cloned().unwrap_or_default();
        let kind = values.get("type").map(String::as_str).unwrap_or("DOMAIN");
        let target = values.get("node").map(String::as_str).unwrap_or("DIRECT");
        if matcher.is_empty() || !matches!(kind, "DOMAIN" | "DOMAIN-SUFFIX") {
            continue;
        }
        let action = match target {
            "DIRECT" => RuleAction::Direct,
            "REJECT" => RuleAction::Reject,
            name => RuleAction::PolicyGroup { name: name.to_owned() },
        };
        let note = values
            .get("route_assistant_note")
            .and_then(|value| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value).ok())
            .and_then(|value| String::from_utf8(value).ok());
        let id = values
            .get("route_assistant_id")
            .cloned()
            .unwrap_or_else(|| section.trim_start_matches("route_assistant_").to_owned());
        rules.push(RuleSpec {
            id,
            scope: if kind == "DOMAIN-SUFFIX" { MatchScope::Suffix } else { MatchScope::Exact },
            domain: matcher.clone(),
            normalized_domain: matcher,
            action,
            enabled: values.get("enabled").map(String::as_str) != Some("0"),
            note,
            managed: true,
            source: Some(format!("/etc/config/nikki#{section}")),
        });
    }
    Ok(rules)
}

pub async fn list_rules(session: &SshSession) -> AppResult<Vec<RuleSpec>> {
    let output = session
        .run_checked("uci -q show nikki | sed -n '/^nikki\\.route_assistant_/p'")
        .await?;
    parse_uci_managed_rules(&output)
}

pub async fn apply_rule(
    session: &SshSession,
    change_id: &str,
    rule: &RuleSpec,
) -> AppResult<VerificationReport> {
    let section = section_name(&rule.id)?;
    let backup_id = create_backup(session).await?;
    start_watchdog(session, &backup_id).await?;
    let kind = if matches!(rule.scope, MatchScope::Suffix) { "DOMAIN-SUFFIX" } else { "DOMAIN" };
    let note = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rule.note.as_deref().unwrap_or_default());
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
        return Err(AppError::Verification(format!("Nikki 写入失败并已回滚：{error}")));
    }
    sleep(Duration::from_secs(6)).await;
    let mut report = verify_runtime_rule(session, &PluginKind::Nikki, change_id, rule, Some(backup_id.clone())).await;
    if report.success {
        commit_watchdog(session, &backup_id).await?;
    } else {
        rollback(session, &backup_id).await?;
        report.rolled_back = true;
        report.messages.push("验证失败，已恢复 Nikki 修改前配置。".into());
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
        return Err(AppError::Validation("找不到要删除的助手规则；未修改 Nikki。".into()));
    }
    let backup_id = create_backup(session).await?;
    start_watchdog(session, &backup_id).await?;
    let command = format!(
        "uci -q delete nikki.{section} && uci -q commit nikki && /etc/init.d/nikki reload >/dev/null 2>&1"
    );
    if let Err(error) = session.run_checked(&command).await {
        rollback(session, &backup_id).await?;
        return Err(AppError::Verification(format!("Nikki 删除失败并已回滚：{error}")));
    }
    sleep(Duration::from_secs(6)).await;
    let absent = !list_rules(session).await?.iter().any(|item| item.id == rule.id);
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
        report.messages.push("删除验证失败，已恢复 Nikki 修改前配置。".into());
    }
    Ok(report)
}

pub async fn verify_rule(session: &SshSession, change_id: &str, rule: &RuleSpec) -> VerificationReport {
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
    let id = format!("{}-{}", Utc::now().format("%Y%m%d%H%M%S"), &Uuid::new_v4().simple().to_string()[..8]);
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
        marker = shell_quote(&marker), dir = shell_quote(&directory)
    );
    session.write_file(&script, body.as_bytes(), 0o700).await?;
    session.run_checked(&format!("rm -f {}; nohup {} >/dev/null 2>&1 &", shell_quote(&marker), shell_quote(&script))).await?;
    Ok(())
}

async fn commit_watchdog(session: &SshSession, backup_id: &str) -> AppResult<()> {
    validate_backup_id(backup_id)?;
    let marker = format!("/tmp/route-assistant-{backup_id}.commit");
    session.run_checked(&format!("umask 077; : > {}", shell_quote(&marker))).await.map(|_| ())
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
}
