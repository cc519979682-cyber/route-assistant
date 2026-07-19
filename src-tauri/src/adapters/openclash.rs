use crate::adapters::{validate_backup_id, verify_runtime_ready_after_delete, verify_runtime_rule};
use crate::error::{AppError, AppResult};
use crate::models::{PluginKind, RuleAction, RuleSpec, VerificationReport};
use crate::ssh::{SshSession, shell_quote};
use base64::Engine;
use chrono::Utc;
use regex::Regex;
use std::sync::OnceLock;
use tokio::time::{Duration, sleep};
use uuid::Uuid;

pub const CUSTOM_RULES_PATH: &str = "/etc/openclash/custom/openclash_custom_rules.list";
const BEGIN_MARKER: &str = "## ROUTE-ASSISTANT-BEGIN (managed, do not edit)";
const END_MARKER: &str = "## ROUTE-ASSISTANT-END";

fn managed_rule_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^-\s*(DOMAIN|DOMAIN-SUFFIX),([^,]+),([^\s#]+)\s*#\s*route-assistant:([0-9a-fA-F-]{32,36})(?::([A-Za-z0-9_-]*))?$")
            .expect("managed rule regex is static and valid")
    })
}

pub fn parse_managed_rules(content: &str) -> AppResult<Vec<RuleSpec>> {
    let begin = content.lines().position(|line| line.trim() == BEGIN_MARKER);
    let end = content.lines().position(|line| line.trim() == END_MARKER);
    match (begin, end) {
        (None, None) => return Ok(Vec::new()),
        (Some(begin), Some(end)) if begin < end => {
            let mut rules = Vec::new();
            for line in content.lines().skip(begin + 1).take(end - begin - 1) {
                if let Some(captures) = managed_rule_regex().captures(line.trim()) {
                    let target = captures.get(3).map(|value| value.as_str()).unwrap_or("DIRECT");
                    let action = match target {
                        "DIRECT" => RuleAction::Direct,
                        "REJECT" => RuleAction::Reject,
                        name => RuleAction::PolicyGroup { name: name.to_owned() },
                    };
                    let note = captures
                        .get(5)
                        .filter(|value| !value.as_str().is_empty())
                        .and_then(|value| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value.as_str()).ok())
                        .and_then(|value| String::from_utf8(value).ok());
                    rules.push(RuleSpec {
                        id: captures.get(4).map(|value| value.as_str().to_owned()).unwrap_or_default(),
                        scope: if captures.get(1).map(|value| value.as_str()) == Some("DOMAIN-SUFFIX") {
                            crate::models::MatchScope::Suffix
                        } else {
                            crate::models::MatchScope::Exact
                        },
                        domain: captures.get(2).map(|value| value.as_str().to_owned()).unwrap_or_default(),
                        normalized_domain: captures.get(2).map(|value| value.as_str().to_owned()).unwrap_or_default(),
                        action,
                        enabled: true,
                        note,
                        managed: true,
                        source: Some(CUSTOM_RULES_PATH.into()),
                    });
                }
            }
            Ok(rules)
        }
        _ => Err(AppError::Conflict("OpenClash 自定义规则中的助手标记不完整，已进入只读保护".into())),
    }
}

pub fn render_managed_rules(content: &str, rules: &[RuleSpec]) -> AppResult<String> {
    let mut block = vec![BEGIN_MARKER.to_owned()];
    for rule in rules {
        let note = rule.note.as_deref().unwrap_or_default();
        let encoded_note = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(note.as_bytes());
        let suffix = if encoded_note.is_empty() { String::new() } else { format!(":{encoded_note}") };
        block.push(format!("- {} # route-assistant:{}{}", rule.mihomo_line(), rule.id, suffix));
    }
    block.push(END_MARKER.to_owned());
    let block = block.join("\n");

    let mut lines: Vec<String> = content.replace("\r\n", "\n").lines().map(ToOwned::to_owned).collect();
    let begin = lines.iter().position(|line| line.trim() == BEGIN_MARKER);
    let end = lines.iter().position(|line| line.trim() == END_MARKER);
    match (begin, end) {
        (Some(begin), Some(end)) if begin < end => {
            lines.splice(begin..=end, block.lines().map(ToOwned::to_owned));
        }
        (None, None) => {
            if let Some(rules_index) = lines.iter().position(|line| line.trim() == "rules:") {
                lines.splice((rules_index + 1)..(rules_index + 1), block.lines().map(ToOwned::to_owned));
            } else if lines.iter().all(|line| line.trim().is_empty()) {
                lines = vec!["rules:".into()];
                lines.extend(block.lines().map(ToOwned::to_owned));
            } else {
                return Err(AppError::Conflict("OpenClash 自定义规则文件缺少顶级 rules:，不会自动重写".into()));
            }
        }
        _ => return Err(AppError::Conflict("OpenClash 自定义规则中的助手标记不完整，已停止修改".into())),
    }
    Ok(format!("{}\n", lines.join("\n")))
}

pub async fn list_rules(session: &SshSession) -> AppResult<Vec<RuleSpec>> {
    let output = session.run(&format!("cat -- {} 2>/dev/null", shell_quote(CUSTOM_RULES_PATH))).await?;
    if output.exit_status != 0 && output.stdout.is_empty() {
        return Ok(Vec::new());
    }
    parse_managed_rules(&output.stdout)
}

pub async fn apply_rule(
    session: &SshSession,
    change_id: &str,
    rule: &RuleSpec,
) -> AppResult<VerificationReport> {
    let current = session.run(&format!("cat -- {} 2>/dev/null", shell_quote(CUSTOM_RULES_PATH))).await?.stdout;
    let mut rules = parse_managed_rules(&current)?;
    rules.retain(|item| item.id != rule.id && !(item.scope == rule.scope && item.normalized_domain == rule.normalized_domain));
    rules.insert(0, rule.clone());
    let rendered = render_managed_rules(&current, &rules)?;
    let backup_id = create_backup(session).await?;
    let candidate = format!("{CUSTOM_RULES_PATH}.route-assistant-candidate");
    session.write_file(&candidate, rendered.as_bytes(), 0o600).await?;
    session
        .run_checked(&format!(
            "ruby -ryaml -e {} -- {} >/dev/null 2>&1",
            shell_quote("YAML.load_file(ARGV[0])"),
            shell_quote(&candidate)
        ))
        .await
        .map_err(|error| AppError::Validation(format!("OpenClash 自定义规则语法检查失败：{error}")))?;
    start_watchdog(session, &backup_id).await?;
    let apply = format!(
        "mv -f {} {}; chmod 600 {}; uci -q set openclash.config.enable_custom_clash_rules=1; uci -q commit openclash; /etc/init.d/openclash restart >/dev/null 2>&1",
        shell_quote(&candidate), shell_quote(CUSTOM_RULES_PATH), shell_quote(CUSTOM_RULES_PATH)
    );
    session.run_checked(&apply).await?;
    sleep(Duration::from_secs(8)).await;
    let mut report = verify_runtime_rule(session, &PluginKind::OpenClash, change_id, rule, Some(backup_id.clone())).await;
    if report.success {
        commit_watchdog(session, &backup_id).await?;
    } else {
        rollback(session, &backup_id).await?;
        report.rolled_back = true;
        report.messages.push("验证失败，已恢复 OpenClash 修改前配置。".into());
    }
    Ok(report)
}

pub async fn remove_rule(
    session: &SshSession,
    change_id: &str,
    rule: &RuleSpec,
) -> AppResult<VerificationReport> {
    let current = session.run(&format!("cat -- {} 2>/dev/null", shell_quote(CUSTOM_RULES_PATH))).await?.stdout;
    let mut rules = parse_managed_rules(&current)?;
    let before = rules.len();
    rules.retain(|item| item.id != rule.id);
    if rules.len() == before {
        return Err(AppError::Validation("找不到要删除的助手规则；未修改 OpenClash。".into()));
    }
    let rendered = render_managed_rules(&current, &rules)?;
    let backup_id = create_backup(session).await?;
    let candidate = format!("{CUSTOM_RULES_PATH}.route-assistant-candidate");
    session.write_file(&candidate, rendered.as_bytes(), 0o600).await?;
    session
        .run_checked(&format!(
            "ruby -ryaml -e {} -- {} >/dev/null 2>&1",
            shell_quote("YAML.load_file(ARGV[0])"),
            shell_quote(&candidate)
        ))
        .await
        .map_err(|error| AppError::Validation(format!("OpenClash 自定义规则语法检查失败：{error}")))?;
    start_watchdog(session, &backup_id).await?;
    session
        .run_checked(&format!(
            "mv -f {} {}; chmod 600 {}; /etc/init.d/openclash restart >/dev/null 2>&1",
            shell_quote(&candidate), shell_quote(CUSTOM_RULES_PATH), shell_quote(CUSTOM_RULES_PATH)
        ))
        .await?;
    sleep(Duration::from_secs(8)).await;
    let absent = !list_rules(session).await?.iter().any(|item| item.id == rule.id);
    let mut report = verify_runtime_ready_after_delete(
        session,
        &PluginKind::OpenClash,
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
        report.messages.push("删除验证失败，已恢复 OpenClash 修改前配置。".into());
    }
    Ok(report)
}

pub async fn verify_rule(session: &SshSession, change_id: &str, rule: &RuleSpec) -> VerificationReport {
    verify_runtime_rule(session, &PluginKind::OpenClash, change_id, rule, None).await
}

pub async fn rollback(session: &SshSession, backup_id: &str) -> AppResult<()> {
    validate_backup_id(backup_id)?;
    let directory = format!("/etc/route-assistant/backups/{backup_id}");
    let command = format!(
        "test -d {d}; if test -f {d}/custom_rules.existed; then cp -f {d}/openclash_custom_rules.list {target}; else rm -f {target}; fi; uci -q import openclash < {d}/openclash.uci; uci -q commit openclash; /etc/init.d/openclash restart >/dev/null 2>&1",
        d = shell_quote(&directory), target = shell_quote(CUSTOM_RULES_PATH)
    );
    session.run_checked(&command).await.map(|_| ())
}

async fn create_backup(session: &SshSession) -> AppResult<String> {
    let id = format!("{}-{}", Utc::now().format("%Y%m%d%H%M%S"), &Uuid::new_v4().simple().to_string()[..8]);
    let directory = format!("/etc/route-assistant/backups/{id}");
    let command = format!(
        r#"umask 077; mkdir -p {d}; chmod 700 /etc/route-assistant /etc/route-assistant/backups {d}; if test -f {target}; then cp -p {target} {d}/openclash_custom_rules.list; touch {d}/custom_rules.existed; fi; uci -q export openclash > {d}/openclash.uci; /etc/init.d/openclash status > {d}/service.status 2>&1 || true; ls -1dt /etc/route-assistant/backups/* 2>/dev/null | tail -n +11 | while read old; do case "$old" in /etc/route-assistant/backups/*) rm -rf -- "$old";; esac; done"#,
        d = shell_quote(&directory), target = shell_quote(CUSTOM_RULES_PATH)
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
        "#!/bin/sh\nsleep 120\n[ -f {marker} ] && exit 0\nif [ -f {dir}/custom_rules.existed ]; then cp -f {dir}/openclash_custom_rules.list {target}; else rm -f {target}; fi\nuci -q import openclash < {dir}/openclash.uci\nuci -q commit openclash\n/etc/init.d/openclash restart >/dev/null 2>&1\n",
        marker = shell_quote(&marker), dir = shell_quote(&directory), target = shell_quote(CUSTOM_RULES_PATH)
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
    use crate::models::MatchScope;

    fn sample_rule() -> RuleSpec {
        RuleSpec {
            id: "e62f3a7d-4554-4b20-bc49-3af6eea5d650".into(),
            scope: MatchScope::Exact,
            domain: "www.baidu.com".into(),
            normalized_domain: "www.baidu.com".into(),
            action: RuleAction::Direct,
            enabled: true,
            note: Some("测试".into()),
            managed: true,
            source: Some(CUSTOM_RULES_PATH.into()),
        }
    }

    #[test]
    fn inserts_after_rules_key_and_preserves_user_content() {
        let source = "rule-providers:\n  sample: {}\nrules:\n##- DOMAIN,existing.example,DIRECT\n";
        let rendered = render_managed_rules(source, &[sample_rule()]).unwrap();
        assert!(rendered.contains("rules:\n## ROUTE-ASSISTANT-BEGIN"));
        assert!(rendered.contains("##- DOMAIN,existing.example,DIRECT"));
        assert_eq!(parse_managed_rules(&rendered).unwrap(), vec![sample_rule()]);
    }

    #[test]
    fn refuses_broken_markers() {
        assert!(render_managed_rules("rules:\n## ROUTE-ASSISTANT-BEGIN (managed, do not edit)\n", &[]).is_err());
    }

    #[test]
    fn deleting_managed_rule_preserves_unmanaged_lines() {
        let source = "rules:\n## ROUTE-ASSISTANT-BEGIN (managed, do not edit)\n- DOMAIN,www.baidu.com,DIRECT # route-assistant:e62f3a7d-4554-4b20-bc49-3af6eea5d650\n## ROUTE-ASSISTANT-END\n##- DOMAIN,manual.example,DIRECT\n";
        let rendered = render_managed_rules(source, &[]).unwrap();
        assert!(rendered.contains("##- DOMAIN,manual.example,DIRECT"));
        assert!(!rendered.contains("www.baidu.com"));
        assert!(parse_managed_rules(&rendered).unwrap().is_empty());
    }
}
