use crate::adapters::validate_backup_id;
use crate::error::{AppError, AppResult};
use crate::models::{DnsChainSnapshot, DnsProtectionSnapshot, DnsProtectionStatus, PluginKind};
use crate::ssh::{SshSession, shell_quote};
use chrono::Utc;
use tokio::time::{Duration, sleep};
use uuid::Uuid;

pub const CUSTOM_OVERWRITE_PATH: &str = "/etc/openclash/custom/openclash_custom_overwrite.sh";
const BEGIN_MARKER: &str = "# ROUTE-ASSISTANT-DNS-BEGIN (managed, do not edit)";
const END_MARKER: &str = "# ROUTE-ASSISTANT-DNS-END";

const MANAGED_COMMANDS: &[&str] = &[
    ". /usr/share/openclash/ruby.sh",
    "ruby_edit \"$CONFIG_FILE\" \"['dns']['enable']\" \"true\"",
    "ruby_edit \"$CONFIG_FILE\" \"['dns']['respect-rules']\" \"true\"",
    "ruby_edit \"$CONFIG_FILE\" \"['dns']['default-nameserver']\" \"['https://223.5.5.5/dns-query','https://1.1.1.1/dns-query']\"",
    "ruby_edit \"$CONFIG_FILE\" \"['dns']['nameserver']\" \"['https://223.5.5.5/dns-query','https://120.53.53.53/dns-query']\"",
    "ruby_edit \"$CONFIG_FILE\" \"['dns']['fallback']\" \"['https://1.1.1.1/dns-query#RULES','https://8.8.8.8/dns-query#RULES']\"",
    "ruby_edit \"$CONFIG_FILE\" \"['dns']['proxy-server-nameserver']\" \"['https://223.5.5.5/dns-query','https://120.53.53.53/dns-query']\"",
    "ruby_edit \"$CONFIG_FILE\" \"['dns']['direct-nameserver']\" \"['https://223.5.5.5/dns-query','https://120.53.53.53/dns-query']\"",
    "ruby_edit \"$CONFIG_FILE\" \"['dns']['direct-nameserver-follow-policy']\" \"false\"",
    "ruby_edit \"$CONFIG_FILE\" \"['dns']['fallback-filter']\" \"{'geoip'=>true,'geoip-code'=>'CN','ipcidr'=>['240.0.0.0/4','0.0.0.0/32','127.0.0.1/32','100.64.0.0/10']}\"",
];

fn managed_block() -> String {
    let mut lines = vec![BEGIN_MARKER.to_owned()];
    lines.push("if [ -n \"$CONFIG_FILE\" ] && [ -f \"$CONFIG_FILE\" ]; then".into());
    lines.extend(MANAGED_COMMANDS.iter().map(|line| format!("  {line}")));
    lines.push("fi".into());
    lines.push(END_MARKER.into());
    lines.join("\n")
}

fn test_script() -> String {
    let mut lines = vec!["#!/bin/sh".to_owned(), "set -e".into()];
    lines.push("CONFIG_FILE=\"$1\"".into());
    lines.extend(MANAGED_COMMANDS.iter().map(|line| (*line).to_owned()));
    lines.push("exit 0".into());
    format!("{}\n", lines.join("\n"))
}

pub fn render_managed_overwrite(content: &str) -> AppResult<String> {
    let normalized = content.replace("\r\n", "\n");
    let mut lines: Vec<String> = if normalized.trim().is_empty() {
        vec![
            "#!/bin/sh".into(),
            ". /usr/share/openclash/ruby.sh".into(),
            ". /usr/share/openclash/log.sh".into(),
            ". /lib/functions.sh".into(),
            "CONFIG_FILE=\"$1\"".into(),
            "exit 0".into(),
        ]
    } else {
        normalized.lines().map(ToOwned::to_owned).collect()
    };
    let begin_positions: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| (line.trim() == BEGIN_MARKER).then_some(index))
        .collect();
    let end_positions: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| (line.trim() == END_MARKER).then_some(index))
        .collect();
    let block: Vec<String> = managed_block().lines().map(ToOwned::to_owned).collect();
    match (begin_positions.as_slice(), end_positions.as_slice()) {
        ([begin], [end]) if begin < end => {
            lines.splice(begin..=end, block);
        }
        ([], []) => {
            let insert_at = lines
                .iter()
                .rposition(|line| line.trim() == "exit 0")
                .unwrap_or(lines.len());
            lines.splice(insert_at..insert_at, block);
        }
        _ => {
            return Err(AppError::Conflict(
                "OpenClash DNS 助手标记不完整，已停止修改".into(),
            ));
        }
    }
    Ok(format!("{}\n", lines.join("\n")))
}

fn value<'a>(content: &'a str, key: &str) -> Option<&'a str> {
    content
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")))
        .map(str::trim)
}

fn parse_bool(value: Option<&str>) -> Option<bool> {
    match value {
        Some("1" | "true" | "TRUE") => Some(true),
        Some("0" | "false" | "FALSE") => Some(false),
        _ => None,
    }
}

pub fn parse_snapshot(content: &str) -> DnsProtectionSnapshot {
    let config_ok = parse_bool(value(content, "CONFIG_OK")).unwrap_or(false);
    let dns_enabled = parse_bool(value(content, "DNS_ENABLED"));
    let respect_rules = parse_bool(value(content, "RESPECT_RULES"));
    let dnsmasq_to_openclash = parse_bool(value(content, "DNSMASQ_TO_OPENCLASH"));
    let encrypted_upstream_count = config_ok
        .then(|| value(content, "ENCRYPTED").and_then(|item| item.parse().ok()))
        .flatten();
    let plaintext_upstream_count = config_ok
        .then(|| value(content, "PLAINTEXT").and_then(|item| item.parse().ok()))
        .flatten();
    let local_upstreams: Vec<String> = value(content, "LOCAL_UPSTREAMS")
        .map(|items| {
            items
                .split(',')
                .filter(|item| item.starts_with("127.0.0.1:") || item.starts_with("::1:"))
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let enhanced_mode = value(content, "ENHANCED_MODE")
        .filter(|item| !item.is_empty() && *item != "unknown")
        .map(ToOwned::to_owned);
    let managed_by_assistant = parse_bool(value(content, "MANAGED")).unwrap_or(false);
    let markers_broken = parse_bool(value(content, "MARKERS_BROKEN")).unwrap_or(false);
    let overwrite_ready = parse_bool(value(content, "OVERWRITE_READY")).unwrap_or(false);
    let baidu_ok = parse_bool(value(content, "BAIDU_OK")).unwrap_or(false);
    let google_ok = parse_bool(value(content, "GOOGLE_OK")).unwrap_or(false);

    let mut risks = Vec::new();
    if !config_ok {
        risks.push("无法安全读取 OpenClash 当前运行配置。".into());
    }
    if dns_enabled == Some(false) {
        risks.push("OpenClash 内置 DNS 当前未启用。".into());
    }
    if let Some(plaintext_upstream_count) = plaintext_upstream_count.filter(|count| *count > 0) {
        risks.push(format!(
            "发现 {plaintext_upstream_count} 个明文或系统 DNS 上游，可能被污染或泄漏。"
        ));
    }
    if encrypted_upstream_count.is_some_and(|count| count < 2) {
        if local_upstreams.is_empty() {
            risks.push("OpenClash 自身的加密 DNS 上游不足，异常时可能无法可靠解析。".into());
        } else {
            risks.push(
                "OpenClash 将 DNS 转发到路由器本机的其他服务；助手只诊断这条组合链路，不会用基础方案覆盖它。"
                    .into(),
            );
        }
    }
    if respect_rules != Some(true) {
        risks.push("DNS 连接没有明确跟随分流规则。".into());
    }
    if dnsmasq_to_openclash == Some(false) {
        risks.push(
            "没有确认局域网 DNS 已进入 OpenClash；本版本不会自动修改防火墙或 DNS 劫持。".into(),
        );
    }
    if markers_broken {
        risks.push("助手 DNS 标记不完整，必须人工检查后才能写入。".into());
    }

    let protected = config_ok
        && dns_enabled == Some(true)
        && plaintext_upstream_count == Some(0)
        && encrypted_upstream_count.is_some_and(|count| count >= 2)
        && respect_rules == Some(true)
        && dnsmasq_to_openclash == Some(true);
    let complex_local_chain = !local_upstreams.is_empty() && !protected;
    let supported = config_ok && overwrite_ready && !markers_broken;
    let status = if protected {
        DnsProtectionStatus::Protected
    } else if complex_local_chain {
        DnsProtectionStatus::Unsupported
    } else if supported {
        DnsProtectionStatus::NeedsAttention
    } else if markers_broken || !overwrite_ready {
        DnsProtectionStatus::Unsupported
    } else {
        DnsProtectionStatus::Unknown
    };
    let can_apply =
        supported && !protected && !complex_local_chain && dnsmasq_to_openclash == Some(true);
    let summary = match status {
        DnsProtectionStatus::Protected => "当前 OpenClash 已使用加密 DNS，未发现明文上游。",
        DnsProtectionStatus::NeedsAttention => "发现可以安全修复的 OpenClash DNS 风险。",
        DnsProtectionStatus::Unsupported => "当前配置暂不满足自动修改条件，只提供诊断。",
        DnsProtectionStatus::Unknown => "无法确认当前 DNS 防护状态。",
    }
    .into();
    let mut checks = Vec::new();
    checks.push(if baidu_ok {
        "百度解析测试通过（仅表示解析可用，不证明使用加密 DNS）。".into()
    } else {
        "尚未确认百度解析。".into()
    });
    checks.push(if google_ok {
        "Google 解析测试通过（仅表示解析可用，不证明使用加密 DNS）。".into()
    } else {
        "尚未确认 Google 解析。".into()
    });

    DnsProtectionSnapshot {
        plugin: PluginKind::OpenClash,
        status,
        summary,
        supported,
        can_apply,
        dns_enabled,
        enhanced_mode,
        dnsmasq_to_openclash,
        encrypted_upstream_count,
        plaintext_upstream_count,
        local_upstreams,
        respect_rules,
        managed_by_assistant,
        risks,
        checks,
        chain: DnsChainSnapshot::default(),
    }
}

pub async fn inspect(session: &SshSession) -> AppResult<DnsProtectionSnapshot> {
    let ruby = r###"begin; v=YAML.load_file(ARGV[0]) || {}; d=v['dns'] || {}; keys=%w[default-nameserver nameserver fallback proxy-server-nameserver direct-nameserver]; a=keys.flat_map{|k| x=d[k]; x.is_a?(Array) ? x : (x.nil? ? [] : [x])}.map(&:to_s); loopback=/\A(?:(?:udp|tcp|tls|https|quic|h3):\/\/)?(127\.0\.0\.1|\[::1\])(?::|#)(\d+)/; local=a.filter_map{|x| m=x.match(loopback); m ? "#{m[1].tr('[]','')}:#{m[2]}" : nil}.uniq; encrypted=a.count{|x| x =~ /\A(https|tls|quic|h3):\/\// && x !~ loopback}; plaintext=a.count{|x| x !~ /\A(https|tls|quic|h3):\/\// && x !~ loopback}; puts "CONFIG_OK=1"; puts "DNS_ENABLED=#{d['enable'] ? 1 : 0}"; puts "RESPECT_RULES=#{d['respect-rules'] ? 1 : 0}"; puts "ENHANCED_MODE=#{d['enhanced-mode'] || 'unknown'}"; puts "ENCRYPTED=#{encrypted}"; puts "PLAINTEXT=#{plaintext}"; puts "LOCAL_UPSTREAMS=#{local.join(',')}"; rescue Exception; puts 'CONFIG_OK=0'; end"###;
    let command = format!(
        r#"cfg=$(ps w 2>/dev/null | awk '/[c]lash/ && /-d[[:space:]]+\/etc\/openclash/ {{for(i=1;i<=NF;i++) if($i=="-f" && (i+1)<=NF){{print $(i+1); exit}}}}'); if [ ! -f "$cfg" ]; then raw=$(uci -q get openclash.config.config_path); [ -n "$raw" ] && cfg="/etc/openclash/${{raw##*/}}"; fi; dns_port=$(uci -q get openclash.config.dns_port); [ -n "$dns_port" ] || dns_port=7874; redirect=$(uci -q get openclash.config.enable_redirect_dns); dnsmasq=0; case "$redirect" in 1|2) dnsmasq=1;; esac; uci -q get dhcp.@dnsmasq[0].server 2>/dev/null | grep -q "127.0.0.1#$dns_port" && dnsmasq=1; printf 'DNSMASQ_TO_OPENCLASH=%s\n' "$dnsmasq"; test -f {path} && test -f /usr/share/openclash/ruby.sh && echo OVERWRITE_READY=1 || echo OVERWRITE_READY=0; b=$(grep -cF {begin} {path} 2>/dev/null || true); e=$(grep -cF {end} {path} 2>/dev/null || true); [ "$b" = 1 ] && [ "$e" = 1 ] && echo MANAGED=1 || echo MANAGED=0; if {{ [ "$b" = 0 ] && [ "$e" = 0 ]; }} || {{ [ "$b" = 1 ] && [ "$e" = 1 ]; }}; then echo MARKERS_BROKEN=0; else echo MARKERS_BROKEN=1; fi; [ -f "$cfg" ] && ruby -ryaml -e {ruby} -- "$cfg" || echo CONFIG_OK=0; nslookup www.baidu.com "127.0.0.1:$dns_port" >/dev/null 2>&1 && echo BAIDU_OK=1 || echo BAIDU_OK=0; nslookup www.google.com "127.0.0.1:$dns_port" >/dev/null 2>&1 && echo GOOGLE_OK=1 || echo GOOGLE_OK=0"#,
        path = shell_quote(CUSTOM_OVERWRITE_PATH),
        begin = shell_quote(BEGIN_MARKER),
        end = shell_quote(END_MARKER),
        ruby = shell_quote(ruby),
    );
    let output = session.run_checked(&command).await?;
    Ok(parse_snapshot(&output))
}

async fn create_backup(session: &SshSession) -> AppResult<String> {
    let id = format!(
        "dns-{}-{}",
        Utc::now().format("%Y%m%d%H%M%S"),
        &Uuid::new_v4().simple().to_string()[..8]
    );
    let directory = format!("/etc/route-assistant/backups/{id}");
    let command = format!(
        r#"umask 077; mkdir -p {d}; chmod 700 /etc/route-assistant /etc/route-assistant/backups {d}; if test -f {target}; then cp -p {target} {d}/openclash_custom_overwrite.sh; touch {d}/overwrite.existed; fi; uci -q export openclash > {d}/openclash.uci; /etc/init.d/openclash status > {d}/service.status 2>&1 || true; ls -1dt /etc/route-assistant/backups/* 2>/dev/null | tail -n +11 | while read old; do case "$old" in /etc/route-assistant/backups/*) rm -rf -- "$old";; esac; done"#,
        d = shell_quote(&directory),
        target = shell_quote(CUSTOM_OVERWRITE_PATH),
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
        "#!/bin/sh\nsleep 120\n[ -f {marker} ] && exit 0\nif [ -f {dir}/overwrite.existed ]; then cp -f {dir}/openclash_custom_overwrite.sh {target}; else rm -f {target}; fi\nuci -q import openclash < {dir}/openclash.uci\nuci -q commit openclash\n/etc/init.d/openclash restart >/dev/null 2>&1\n",
        marker = shell_quote(&marker),
        dir = shell_quote(&directory),
        target = shell_quote(CUSTOM_OVERWRITE_PATH),
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
    let marker = format!("/tmp/route-assistant-{backup_id}.commit");
    session
        .run_checked(&format!("umask 077; : > {}", shell_quote(&marker)))
        .await
        .map(|_| ())
}

pub async fn rollback(session: &SshSession, backup_id: &str) -> AppResult<()> {
    validate_backup_id(backup_id)?;
    let directory = format!("/etc/route-assistant/backups/{backup_id}");
    let command = format!(
        "test -d {d}; if test -f {d}/overwrite.existed; then cp -f {d}/openclash_custom_overwrite.sh {target}; else rm -f {target}; fi; chmod 755 {target} 2>/dev/null || true; uci -q import openclash < {d}/openclash.uci; uci -q commit openclash; /etc/init.d/openclash restart >/dev/null 2>&1",
        d = shell_quote(&directory),
        target = shell_quote(CUSTOM_OVERWRITE_PATH),
    );
    session.run_checked(&command).await.map(|_| ())
}

pub async fn apply(
    session: &SshSession,
    change_id: &str,
) -> AppResult<(String, DnsProtectionSnapshot, bool, Vec<String>)> {
    let current = session
        .run(&format!(
            "cat -- {} 2>/dev/null",
            shell_quote(CUSTOM_OVERWRITE_PATH)
        ))
        .await?
        .stdout;
    let rendered = render_managed_overwrite(&current)?;
    let backup_id = create_backup(session).await?;
    let candidate = format!("{CUSTOM_OVERWRITE_PATH}.route-assistant-candidate");
    let test_path = format!("/tmp/route-assistant-dns-{change_id}.sh");
    session
        .write_file(&candidate, rendered.as_bytes(), 0o755)
        .await?;
    session
        .write_file(&test_path, test_script().as_bytes(), 0o700)
        .await?;
    let validate = format!(
        r#"set -e; sh -n {candidate}; cfg=$(ps w 2>/dev/null | awk '/[c]lash/ && /-d[[:space:]]+\/etc\/openclash/ {{for(i=1;i<=NF;i++) if($i=="-f" && (i+1)<=NF){{print $(i+1); exit}}}}'); if [ ! -f "$cfg" ]; then raw=$(uci -q get openclash.config.config_path); [ -n "$raw" ] && cfg="/etc/openclash/${{raw##*/}}"; fi; [ -f "$cfg" ]; tmp=/tmp/route-assistant-dns-test.yaml; cp -f "$cfg" "$tmp"; {test_script} "$tmp"; /etc/openclash/clash -t -d /etc/openclash -f "$tmp" >/dev/null 2>&1; rm -f "$tmp" {test_script}"#,
        candidate = shell_quote(&candidate),
        test_script = shell_quote(&test_path),
    );
    if let Err(error) = session.run_checked(&validate).await {
        let _ = session
            .run(&format!(
                "rm -f {} {}",
                shell_quote(&candidate),
                shell_quote(&test_path)
            ))
            .await;
        return Err(AppError::Validation(format!(
            "OpenClash DNS 候选配置检查失败：{error}"
        )));
    }
    start_watchdog(session, &backup_id).await?;
    session
        .run_checked(&format!(
            "mv -f {} {}; chmod 755 {}; /etc/init.d/openclash restart >/dev/null 2>&1",
            shell_quote(&candidate),
            shell_quote(CUSTOM_OVERWRITE_PATH),
            shell_quote(CUSTOM_OVERWRITE_PATH),
        ))
        .await?;
    sleep(Duration::from_secs(10)).await;
    let snapshot = inspect(session).await?;
    let success = snapshot.status == DnsProtectionStatus::Protected
        && snapshot.checks.iter().all(|item| item.contains("通过"));
    let mut messages = if success {
        vec![
            "OpenClash 已启用基础 DNS 防护，当前上游均为加密 DNS。".into(),
            "国外加密 DNS 会按现有分流规则连接；本次未修改防火墙、DHCP或订阅。".into(),
        ]
    } else {
        vec!["DNS 验证没有全部通过。".into()]
    };
    let rolled_back = if success {
        commit_watchdog(session, &backup_id).await?;
        false
    } else {
        rollback(session, &backup_id).await?;
        messages.push("已自动恢复应用前的 OpenClash DNS 配置。".into());
        true
    };
    Ok((backup_id, snapshot, rolled_back, messages))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inserts_managed_block_before_exit_and_preserves_user_content() {
        let source = "#!/bin/sh\nCONFIG_FILE=\"$1\"\necho user-code\nexit 0\n";
        let rendered = render_managed_overwrite(source).unwrap();
        assert!(rendered.contains("echo user-code"));
        assert!(rendered.find(BEGIN_MARKER).unwrap() < rendered.rfind("exit 0").unwrap());
        assert_eq!(rendered.matches(BEGIN_MARKER).count(), 1);
    }

    #[test]
    fn replaces_existing_block_without_duplication() {
        let first = render_managed_overwrite("#!/bin/sh\nexit 0\n").unwrap();
        let second = render_managed_overwrite(&first).unwrap();
        assert_eq!(second.matches(BEGIN_MARKER).count(), 1);
        assert_eq!(second.matches(END_MARKER).count(), 1);
    }

    #[test]
    fn refuses_broken_markers() {
        assert!(render_managed_overwrite(&format!("#!/bin/sh\n{BEGIN_MARKER}\nexit 0\n")).is_err());
    }

    #[test]
    fn refuses_duplicate_managed_blocks() {
        let block = managed_block();
        let duplicate = format!("#!/bin/sh\n{block}\n{block}\nexit 0\n");
        assert!(render_managed_overwrite(&duplicate).is_err());
    }

    #[test]
    fn classifies_protected_and_risky_snapshots() {
        let protected = parse_snapshot(
            "CONFIG_OK=1\nDNS_ENABLED=1\nRESPECT_RULES=1\nENHANCED_MODE=fake-ip\nENCRYPTED=8\nPLAINTEXT=0\nDNSMASQ_TO_OPENCLASH=1\nOVERWRITE_READY=1\nMANAGED=1\nMARKERS_BROKEN=0\nBAIDU_OK=1\nGOOGLE_OK=1\n",
        );
        assert_eq!(protected.status, DnsProtectionStatus::Protected);
        assert!(!protected.can_apply);

        let risky = parse_snapshot(
            "CONFIG_OK=1\nDNS_ENABLED=1\nRESPECT_RULES=0\nENCRYPTED=1\nPLAINTEXT=2\nDNSMASQ_TO_OPENCLASH=1\nOVERWRITE_READY=1\nMANAGED=0\nMARKERS_BROKEN=0\n",
        );
        assert_eq!(risky.status, DnsProtectionStatus::NeedsAttention);
        assert!(risky.can_apply);
        assert!(!risky.risks.is_empty());

        let broken = parse_snapshot(
            "CONFIG_OK=1\nDNS_ENABLED=1\nRESPECT_RULES=1\nENCRYPTED=4\nPLAINTEXT=0\nDNSMASQ_TO_OPENCLASH=1\nOVERWRITE_READY=1\nMANAGED=0\nMARKERS_BROKEN=1\n",
        );
        assert_eq!(broken.status, DnsProtectionStatus::Protected);
        assert!(!broken.supported);
        assert!(!broken.can_apply);

        let unreadable = parse_snapshot(
            "CONFIG_OK=0\nDNSMASQ_TO_OPENCLASH=1\nOVERWRITE_READY=1\nMANAGED=0\nMARKERS_BROKEN=0\n",
        );
        assert_eq!(unreadable.encrypted_upstream_count, None);
        assert_eq!(unreadable.plaintext_upstream_count, None);
        assert!(
            !unreadable
                .risks
                .iter()
                .any(|risk| risk.contains("上游不足"))
        );

        let local_chain = parse_snapshot(
            "CONFIG_OK=1\nDNS_ENABLED=1\nRESPECT_RULES=1\nENCRYPTED=0\nPLAINTEXT=0\nLOCAL_UPSTREAMS=127.0.0.1:5353\nDNSMASQ_TO_OPENCLASH=1\nOVERWRITE_READY=1\nMANAGED=0\nMARKERS_BROKEN=0\n",
        );
        assert_eq!(local_chain.status, DnsProtectionStatus::Unsupported);
        assert!(!local_chain.can_apply);
        assert_eq!(local_chain.local_upstreams, vec!["127.0.0.1:5353"]);
    }
}
