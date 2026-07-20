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
use regex::Regex;
use sha2::{Digest, Sha256};
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
        (None, None) => Ok(Vec::new()),
        (Some(begin), Some(end)) if begin < end => {
            let mut rules = Vec::new();
            for line in content.lines().skip(begin + 1).take(end - begin - 1) {
                if let Some(captures) = managed_rule_regex().captures(line.trim()) {
                    let target = captures
                        .get(3)
                        .map(|value| value.as_str())
                        .unwrap_or("DIRECT");
                    let action = match target {
                        "DIRECT" => RuleAction::Direct,
                        "REJECT" => RuleAction::Reject,
                        name => RuleAction::PolicyGroup {
                            name: name.to_owned(),
                        },
                    };
                    let note = captures
                        .get(5)
                        .filter(|value| !value.as_str().is_empty())
                        .and_then(|value| {
                            base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(value.as_str())
                                .ok()
                        })
                        .and_then(|value| String::from_utf8(value).ok());
                    rules.push(RuleSpec {
                        id: captures
                            .get(4)
                            .map(|value| value.as_str().to_owned())
                            .unwrap_or_default(),
                        scope: if captures.get(1).map(|value| value.as_str())
                            == Some("DOMAIN-SUFFIX")
                        {
                            crate::models::MatchScope::Suffix
                        } else {
                            crate::models::MatchScope::Exact
                        },
                        domain: captures
                            .get(2)
                            .map(|value| value.as_str().to_owned())
                            .unwrap_or_default(),
                        normalized_domain: captures
                            .get(2)
                            .map(|value| value.as_str().to_owned())
                            .unwrap_or_default(),
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
        _ => Err(AppError::Conflict(
            "OpenClash 自定义规则中的助手标记不完整，已进入只读保护".into(),
        )),
    }
}

fn stable_record_id(source_location: &str, raw: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"openclash\0");
    digest.update(source_location.as_bytes());
    digest.update(b"\0");
    digest.update(raw.as_bytes());
    format!("openclash-{}", hex::encode(&digest.finalize()[..12]))
}

fn is_known_rule_type(value: &str) -> bool {
    matches!(
        value,
        "DOMAIN"
            | "DOMAIN-SUFFIX"
            | "DOMAIN-KEYWORD"
            | "DOMAIN-REGEX"
            | "GEOSITE"
            | "IP-CIDR"
            | "IP-CIDR6"
            | "IP-SUFFIX"
            | "IP-ASN"
            | "GEOIP"
            | "SRC-GEOIP"
            | "SRC-IP-ASN"
            | "SRC-IP-CIDR"
            | "SRC-IP-SUFFIX"
            | "DST-PORT"
            | "SRC-PORT"
            | "IN-PORT"
            | "IN-TYPE"
            | "IN-USER"
            | "IN-NAME"
            | "PROCESS-PATH"
            | "PROCESS-PATH-REGEX"
            | "PROCESS-NAME"
            | "PROCESS-NAME-REGEX"
            | "NETWORK"
            | "UID"
            | "RULE-SET"
            | "SUB-RULE"
            | "MATCH"
    )
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

fn parse_custom_line(
    raw_line: &str,
    line_number: usize,
    owner: CustomRuleOwner,
    enabled: bool,
) -> CustomRuleRecord {
    let source_location = format!("{CUSTOM_RULES_PATH}:{line_number}");
    let trimmed = raw_line.trim();
    let payload = if enabled {
        trimmed.strip_prefix('-').unwrap_or(trimmed).trim()
    } else {
        trimmed.strip_prefix("##-").unwrap_or(trimmed).trim()
    };
    let rule_text = payload
        .split_once(" # ")
        .map(|(rule, _)| rule)
        .unwrap_or(payload)
        .trim();
    let parts: Vec<&str> = rule_text.split(',').map(str::trim).collect();
    let rule_type = parts
        .first()
        .copied()
        .unwrap_or("UNKNOWN")
        .to_ascii_uppercase();
    let known = is_known_rule_type(&rule_type);
    let minimum = if rule_type == "MATCH" { 2 } else { 3 };
    let valid_shape =
        parts.len() >= minimum && parts.iter().take(minimum).all(|value| !value.is_empty());
    let matcher = if rule_type == "MATCH" {
        None
    } else {
        parts.get(1).map(|value| redact(value))
    };
    let target_index = if rule_type == "MATCH" { 1 } else { 2 };
    let target = parts.get(target_index).map(|value| redact(value));

    let assistant_rule = if owner == CustomRuleOwner::Assistant {
        managed_rule_regex().captures(trimmed).map(|captures| {
            let target = captures
                .get(3)
                .map(|value| value.as_str())
                .unwrap_or("DIRECT");
            let note = captures
                .get(5)
                .filter(|value| !value.as_str().is_empty())
                .and_then(|value| {
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(value.as_str())
                        .ok()
                })
                .and_then(|value| String::from_utf8(value).ok())
                .map(|value| redact(&value));
            let domain = captures
                .get(2)
                .map(|value| redact(value.as_str()))
                .unwrap_or_default();
            let safe_target = redact(target);
            RuleSpec {
                id: captures
                    .get(4)
                    .map(|value| value.as_str().to_owned())
                    .unwrap_or_default(),
                scope: if captures.get(1).map(|value| value.as_str()) == Some("DOMAIN-SUFFIX") {
                    MatchScope::Suffix
                } else {
                    MatchScope::Exact
                },
                domain: domain.clone(),
                normalized_domain: domain,
                action: action_from_target(&safe_target),
                enabled,
                note,
                managed: true,
                source: Some(CUSTOM_RULES_PATH.into()),
            }
        })
    } else {
        None
    };
    let note = assistant_rule
        .as_ref()
        .and_then(|rule| rule.note.as_deref().map(redact));
    let copy_draft = if valid_shape && matches!(rule_type.as_str(), "DOMAIN" | "DOMAIN-SUFFIX") {
        Some(RuleDraft {
            scope: if rule_type == "DOMAIN-SUFFIX" {
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
    let (parse_state, warning) = if !valid_shape {
        (
            CustomRuleParseState::Invalid,
            Some("规则字段缺失或格式不完整，已按原文显示。".into()),
        )
    } else if !known {
        (
            CustomRuleParseState::Raw,
            Some("当前版本不能识别此规则类型，已按原文显示。".into()),
        )
    } else if owner == CustomRuleOwner::Assistant && assistant_rule.is_none() {
        (
            CustomRuleParseState::Invalid,
            Some("助手规则标识损坏，已禁止编辑和删除。".into()),
        )
    } else {
        (CustomRuleParseState::Structured, None)
    };

    CustomRuleRecord {
        id: stable_record_id(&source_location, trimmed),
        source_location,
        position: line_number,
        owner,
        enabled,
        rule_type,
        matcher,
        target,
        note,
        raw_preview: redact(trimmed),
        parse_state,
        warning,
        copy_draft,
        assistant_rule,
    }
}

pub fn parse_custom_rules(content: &str) -> CustomRulesSnapshot {
    let mut rules = Vec::new();
    let mut notices = Vec::new();
    let mut in_assistant_block = false;
    let mut saw_begin = false;
    let mut saw_end = false;
    for (index, line) in content.replace("\r\n", "\n").lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim();
        if trimmed == BEGIN_MARKER {
            in_assistant_block = true;
            saw_begin = true;
            continue;
        }
        if trimmed == END_MARKER {
            in_assistant_block = false;
            saw_end = true;
            continue;
        }
        let (enabled, is_rule) = if trimmed.starts_with("##-") {
            (false, true)
        } else if trimmed.starts_with('-') {
            (true, true)
        } else {
            (true, false)
        };
        if !is_rule {
            continue;
        }
        let owner = if in_assistant_block {
            CustomRuleOwner::Assistant
        } else {
            CustomRuleOwner::Existing
        };
        rules.push(parse_custom_line(line, line_number, owner, enabled));
    }
    if saw_begin != saw_end || in_assistant_block {
        notices.push(CustomRuleNotice {
            code: "brokenAssistantMarkers".into(),
            level: "warning".into(),
            message: "助手规则标记不完整；当前内容仅供查看，写入仍会被安全保护阻止。".into(),
        });
    }
    CustomRulesSnapshot {
        plugin: PluginKind::OpenClash,
        rules,
        notices,
    }
}

pub fn render_managed_rules(content: &str, rules: &[RuleSpec]) -> AppResult<String> {
    let mut block = vec![BEGIN_MARKER.to_owned()];
    for rule in rules {
        let note = rule.note.as_deref().unwrap_or_default();
        let encoded_note = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(note.as_bytes());
        let suffix = if encoded_note.is_empty() {
            String::new()
        } else {
            format!(":{encoded_note}")
        };
        block.push(format!(
            "- {} # route-assistant:{}{}",
            rule.mihomo_line(),
            rule.id,
            suffix
        ));
    }
    block.push(END_MARKER.to_owned());
    let block = block.join("\n");

    let mut lines: Vec<String> = content
        .replace("\r\n", "\n")
        .lines()
        .map(ToOwned::to_owned)
        .collect();
    let begin = lines.iter().position(|line| line.trim() == BEGIN_MARKER);
    let end = lines.iter().position(|line| line.trim() == END_MARKER);
    match (begin, end) {
        (Some(begin), Some(end)) if begin < end => {
            lines.splice(begin..=end, block.lines().map(ToOwned::to_owned));
        }
        (None, None) => {
            if let Some(rules_index) = lines.iter().position(|line| line.trim() == "rules:") {
                lines.splice(
                    (rules_index + 1)..(rules_index + 1),
                    block.lines().map(ToOwned::to_owned),
                );
            } else if lines.iter().all(|line| line.trim().is_empty()) {
                lines = vec!["rules:".into()];
                lines.extend(block.lines().map(ToOwned::to_owned));
            } else {
                return Err(AppError::Conflict(
                    "OpenClash 自定义规则文件缺少顶级 rules:，不会自动重写".into(),
                ));
            }
        }
        _ => {
            return Err(AppError::Conflict(
                "OpenClash 自定义规则中的助手标记不完整，已停止修改".into(),
            ));
        }
    }
    Ok(format!("{}\n", lines.join("\n")))
}

pub async fn list_rules(session: &SshSession) -> AppResult<Vec<RuleSpec>> {
    let output = session
        .run(&format!(
            "cat -- {} 2>/dev/null",
            shell_quote(CUSTOM_RULES_PATH)
        ))
        .await?;
    if output.exit_status != 0 && output.stdout.is_empty() {
        return Ok(Vec::new());
    }
    parse_managed_rules(&output.stdout)
}

pub async fn list_custom_rules(session: &SshSession) -> AppResult<CustomRulesSnapshot> {
    let output = session
        .run(&format!(
            "cat -- {} 2>/dev/null",
            shell_quote(CUSTOM_RULES_PATH)
        ))
        .await?;
    if output.exit_status != 0 && output.stdout.is_empty() {
        return Ok(CustomRulesSnapshot {
            plugin: PluginKind::OpenClash,
            rules: Vec::new(),
            notices: Vec::new(),
        });
    }
    Ok(parse_custom_rules(&output.stdout))
}

pub async fn apply_rule(
    session: &SshSession,
    change_id: &str,
    rule: &RuleSpec,
) -> AppResult<VerificationReport> {
    let current = session
        .run(&format!(
            "cat -- {} 2>/dev/null",
            shell_quote(CUSTOM_RULES_PATH)
        ))
        .await?
        .stdout;
    let mut rules = parse_managed_rules(&current)?;
    rules.retain(|item| {
        item.id != rule.id
            && !(item.scope == rule.scope && item.normalized_domain == rule.normalized_domain)
    });
    rules.insert(0, rule.clone());
    let rendered = render_managed_rules(&current, &rules)?;
    let backup_id = create_backup(session).await?;
    let candidate = format!("{CUSTOM_RULES_PATH}.route-assistant-candidate");
    session
        .write_file(&candidate, rendered.as_bytes(), 0o600)
        .await?;
    session
        .run_checked(&format!(
            "ruby -ryaml -e {} -- {} >/dev/null 2>&1",
            shell_quote("YAML.load_file(ARGV[0])"),
            shell_quote(&candidate)
        ))
        .await
        .map_err(|error| {
            AppError::Validation(format!("OpenClash 自定义规则语法检查失败：{error}"))
        })?;
    start_watchdog(session, &backup_id).await?;
    let apply = format!(
        "mv -f {} {}; chmod 600 {}; uci -q set openclash.config.enable_custom_clash_rules=1; uci -q commit openclash; /etc/init.d/openclash restart >/dev/null 2>&1",
        shell_quote(&candidate),
        shell_quote(CUSTOM_RULES_PATH),
        shell_quote(CUSTOM_RULES_PATH)
    );
    session.run_checked(&apply).await?;
    sleep(Duration::from_secs(8)).await;
    let mut report = verify_runtime_rule(
        session,
        &PluginKind::OpenClash,
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
            .push("验证失败，已恢复 OpenClash 修改前配置。".into());
    }
    Ok(report)
}

pub async fn remove_rule(
    session: &SshSession,
    change_id: &str,
    rule: &RuleSpec,
) -> AppResult<VerificationReport> {
    let current = session
        .run(&format!(
            "cat -- {} 2>/dev/null",
            shell_quote(CUSTOM_RULES_PATH)
        ))
        .await?
        .stdout;
    let mut rules = parse_managed_rules(&current)?;
    let before = rules.len();
    rules.retain(|item| item.id != rule.id);
    if rules.len() == before {
        return Err(AppError::Validation(
            "找不到要删除的助手规则；未修改 OpenClash。".into(),
        ));
    }
    let rendered = render_managed_rules(&current, &rules)?;
    let backup_id = create_backup(session).await?;
    let candidate = format!("{CUSTOM_RULES_PATH}.route-assistant-candidate");
    session
        .write_file(&candidate, rendered.as_bytes(), 0o600)
        .await?;
    session
        .run_checked(&format!(
            "ruby -ryaml -e {} -- {} >/dev/null 2>&1",
            shell_quote("YAML.load_file(ARGV[0])"),
            shell_quote(&candidate)
        ))
        .await
        .map_err(|error| {
            AppError::Validation(format!("OpenClash 自定义规则语法检查失败：{error}"))
        })?;
    start_watchdog(session, &backup_id).await?;
    session
        .run_checked(&format!(
            "mv -f {} {}; chmod 600 {}; /etc/init.d/openclash restart >/dev/null 2>&1",
            shell_quote(&candidate),
            shell_quote(CUSTOM_RULES_PATH),
            shell_quote(CUSTOM_RULES_PATH)
        ))
        .await?;
    sleep(Duration::from_secs(8)).await;
    let absent = !list_rules(session)
        .await?
        .iter()
        .any(|item| item.id == rule.id);
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
        report
            .messages
            .push("删除验证失败，已恢复 OpenClash 修改前配置。".into());
    }
    Ok(report)
}

pub async fn verify_rule(
    session: &SshSession,
    change_id: &str,
    rule: &RuleSpec,
) -> VerificationReport {
    verify_runtime_rule(session, &PluginKind::OpenClash, change_id, rule, None).await
}

pub async fn rollback(session: &SshSession, backup_id: &str) -> AppResult<()> {
    validate_backup_id(backup_id)?;
    let directory = format!("/etc/route-assistant/backups/{backup_id}");
    let command = format!(
        "test -d {d}; if test -f {d}/custom_rules.existed; then cp -f {d}/openclash_custom_rules.list {target}; else rm -f {target}; fi; uci -q import openclash < {d}/openclash.uci; uci -q commit openclash; /etc/init.d/openclash restart >/dev/null 2>&1",
        d = shell_quote(&directory),
        target = shell_quote(CUSTOM_RULES_PATH)
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
        r#"umask 077; mkdir -p {d}; chmod 700 /etc/route-assistant /etc/route-assistant/backups {d}; if test -f {target}; then cp -p {target} {d}/openclash_custom_rules.list; touch {d}/custom_rules.existed; fi; uci -q export openclash > {d}/openclash.uci; /etc/init.d/openclash status > {d}/service.status 2>&1 || true; ls -1dt /etc/route-assistant/backups/* 2>/dev/null | tail -n +11 | while read old; do case "$old" in /etc/route-assistant/backups/*) rm -rf -- "$old";; esac; done"#,
        d = shell_quote(&directory),
        target = shell_quote(CUSTOM_RULES_PATH)
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
        marker = shell_quote(&marker),
        dir = shell_quote(&directory),
        target = shell_quote(CUSTOM_RULES_PATH)
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
        assert!(
            render_managed_rules(
                "rules:\n## ROUTE-ASSISTANT-BEGIN (managed, do not edit)\n",
                &[]
            )
            .is_err()
        );
    }

    #[test]
    fn deleting_managed_rule_preserves_unmanaged_lines() {
        let source = "rules:\n## ROUTE-ASSISTANT-BEGIN (managed, do not edit)\n- DOMAIN,www.baidu.com,DIRECT # route-assistant:e62f3a7d-4554-4b20-bc49-3af6eea5d650\n## ROUTE-ASSISTANT-END\n##- DOMAIN,manual.example,DIRECT\n";
        let rendered = render_managed_rules(source, &[]).unwrap();
        assert!(rendered.contains("##- DOMAIN,manual.example,DIRECT"));
        assert!(!rendered.contains("www.baidu.com"));
        assert!(parse_managed_rules(&rendered).unwrap().is_empty());
    }

    #[test]
    fn lists_all_custom_rules_in_file_order_without_expanding_other_content() {
        let source = r#"rule-providers:
  private-provider: {}
rules:
##- DOMAIN,disabled.example,DIRECT
- DOMAIN-SUFFIX,existing.example,REJECT
## comment
- IP-CIDR,192.0.2.0/24,DIRECT,no-resolve
- FUTURE-RULE,something,GROUP
- DOMAIN,broken.example
## ROUTE-ASSISTANT-BEGIN (managed, do not edit)
- DOMAIN,www.baidu.com,DIRECT # route-assistant:e62f3a7d-4554-4b20-bc49-3af6eea5d650
## ROUTE-ASSISTANT-END
"#;
        let snapshot = parse_custom_rules(source);
        assert_eq!(snapshot.rules.len(), 6);
        assert_eq!(snapshot.rules[0].position, 4);
        assert!(!snapshot.rules[0].enabled);
        assert_eq!(snapshot.rules[1].owner, CustomRuleOwner::Existing);
        assert!(snapshot.rules[1].copy_draft.is_some());
        assert_eq!(snapshot.rules[2].rule_type, "IP-CIDR");
        assert!(snapshot.rules[2].copy_draft.is_none());
        assert_eq!(snapshot.rules[3].parse_state, CustomRuleParseState::Raw);
        assert_eq!(snapshot.rules[4].parse_state, CustomRuleParseState::Invalid);
        assert_eq!(snapshot.rules[5].owner, CustomRuleOwner::Assistant);
        assert!(snapshot.rules[5].assistant_rule.is_some());
    }

    #[test]
    fn reports_broken_markers_but_keeps_read_only_listing_available() {
        let snapshot = parse_custom_rules(
            "rules:\n## ROUTE-ASSISTANT-BEGIN (managed, do not edit)\n- DOMAIN,example.com,DIRECT\n",
        );
        assert_eq!(snapshot.rules.len(), 1);
        assert_eq!(snapshot.notices[0].code, "brokenAssistantMarkers");
        assert_eq!(snapshot.rules[0].parse_state, CustomRuleParseState::Invalid);
    }

    #[test]
    fn redacts_urls_from_raw_custom_rule_records() {
        let snapshot = parse_custom_rules("rules:\n- RULE-SET,https://secret.example/sub,DIRECT\n");
        let serialized = serde_json::to_string(&snapshot).unwrap();
        assert!(!serialized.contains("secret.example"));
        assert!(serialized.contains("REDACTED"));
    }
}
