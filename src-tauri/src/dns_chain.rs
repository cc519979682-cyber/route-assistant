use crate::models::{
    DnsChainConfidence, DnsChainNode, DnsChainSnapshot, DnsProtectionSnapshot,
    DnsResolutionObservation,
};
use crate::ssh::SshSession;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::ptr::{null, null_mut};
use std::time::Instant;
use tokio::time::{Duration, timeout};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses,
    IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS,
};

const ERROR_BUFFER_OVERFLOW: u32 = 111;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct LocalAdapter {
    name: String,
    dns_servers: Vec<IpAddr>,
    gateways: Vec<IpAddr>,
    is_tunnel: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RouterDnsEvidence {
    dnsmasq_running: bool,
    dnsmasq_port: Option<u16>,
    dnsmasq_upstreams: Vec<String>,
    openclash_running: bool,
    openclash_port: Option<u16>,
    adguard_running: bool,
    adguard_port: Option<u16>,
    adguard_upstreams: Vec<String>,
    smartdns_running: bool,
    smartdns_ports: Vec<u16>,
    smartdns_encrypted_count: Option<usize>,
    mosdns_running: bool,
    mosdns_ports: Vec<u16>,
    baidu_ok: Option<bool>,
    google_ok: Option<bool>,
}

fn parse_bool(value: Option<&str>) -> Option<bool> {
    match value.map(str::trim) {
        Some("1" | "true" | "TRUE") => Some(true),
        Some("0" | "false" | "FALSE") => Some(false),
        _ => None,
    }
}

fn metadata_value<'a>(content: &'a str, key: &str) -> Option<&'a str> {
    content
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")))
        .map(str::trim)
}

fn parse_ports(value: Option<&str>) -> Vec<u16> {
    let mut ports: Vec<u16> = value
        .unwrap_or_default()
        .split(',')
        .filter_map(|value| value.trim().parse().ok())
        .filter(|port| *port > 0)
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn safe_loopback_endpoints(value: Option<&str>) -> Vec<String> {
    let mut endpoints: Vec<String> = value
        .unwrap_or_default()
        .split(',')
        .filter_map(|item| {
            let normalized = item.trim().replace('#', ":");
            let (host, port) = normalized.rsplit_once(':')?;
            let host = host.trim_matches(['[', ']']);
            let port: u16 = port.parse().ok()?;
            if (host == "127.0.0.1" || host == "::1") && port > 0 {
                Some(format!("{host}:{port}"))
            } else {
                None
            }
        })
        .collect();
    endpoints.sort();
    endpoints.dedup();
    endpoints
}

fn parse_router_evidence(content: &str) -> RouterDnsEvidence {
    RouterDnsEvidence {
        dnsmasq_running: parse_bool(metadata_value(content, "DNSMASQ_RUNNING")).unwrap_or(false),
        dnsmasq_port: metadata_value(content, "DNSMASQ_PORT").and_then(|v| v.parse().ok()),
        dnsmasq_upstreams: safe_loopback_endpoints(metadata_value(content, "DNSMASQ_UPSTREAMS")),
        openclash_running: parse_bool(metadata_value(content, "OPENCLASH_RUNNING"))
            .unwrap_or(false),
        openclash_port: metadata_value(content, "OPENCLASH_PORT").and_then(|v| v.parse().ok()),
        adguard_running: parse_bool(metadata_value(content, "ADGUARD_RUNNING")).unwrap_or(false),
        adguard_port: metadata_value(content, "ADGUARD_PORT").and_then(|v| v.parse().ok()),
        adguard_upstreams: safe_loopback_endpoints(metadata_value(content, "ADGUARD_UPSTREAMS")),
        smartdns_running: parse_bool(metadata_value(content, "SMARTDNS_RUNNING")).unwrap_or(false),
        smartdns_ports: parse_ports(metadata_value(content, "SMARTDNS_PORTS")),
        smartdns_encrypted_count: metadata_value(content, "SMARTDNS_ENCRYPTED")
            .and_then(|v| v.parse().ok()),
        mosdns_running: parse_bool(metadata_value(content, "MOSDNS_RUNNING")).unwrap_or(false),
        mosdns_ports: parse_ports(metadata_value(content, "MOSDNS_PORTS")),
        baidu_ok: parse_bool(metadata_value(content, "ROUTER_BAIDU_OK")),
        google_ok: parse_bool(metadata_value(content, "ROUTER_GOOGLE_OK")),
    }
}

fn router_probe_command() -> &'static str {
    r#"is_running() { pidof "$1" >/dev/null 2>&1 || pgrep -f "$1" >/dev/null 2>&1; }
is_running dnsmasq && echo DNSMASQ_RUNNING=1 || echo DNSMASQ_RUNNING=0
dm_port=$(uci -q get dhcp.@dnsmasq[0].port); [ -n "$dm_port" ] || dm_port=53; printf 'DNSMASQ_PORT=%s\n' "$dm_port"
dm_servers=$(uci -q get dhcp.@dnsmasq[0].server 2>/dev/null | tr ' ' '\n' | sed -n -e 's#.*127\.0\.0\.1[#:]\([0-9][0-9]*\).*#127.0.0.1:\1#p' -e 's#.*::1[#:]\([0-9][0-9]*\).*#::1:\1#p' | paste -sd, -); printf 'DNSMASQ_UPSTREAMS=%s\n' "$dm_servers"
is_running openclash && oc_run=1 || { pgrep -f '[m]ihomo.*openclash\|[c]lash.*openclash' >/dev/null 2>&1 && oc_run=1 || oc_run=0; }; printf 'OPENCLASH_RUNNING=%s\n' "$oc_run"
oc_port=$(uci -q get openclash.config.dns_port); [ -n "$oc_port" ] || oc_port=7874; printf 'OPENCLASH_PORT=%s\n' "$oc_port"
is_running AdGuardHome && agh_run=1 || agh_run=0; printf 'ADGUARD_RUNNING=%s\n' "$agh_run"
agh_cfg=''; for f in /etc/AdGuardHome.yaml /etc/adguardhome.yaml /etc/AdGuardHome/AdGuardHome.yaml; do [ -f "$f" ] && { agh_cfg="$f"; break; }; done
agh_port=''; agh_up=''; if [ -n "$agh_cfg" ]; then agh_port=$(awk '/^dns:/{d=1;next} d&&/^[^[:space:]]/{exit} d&&/^[[:space:]]*port:/{gsub(/[^0-9]/,"");print;exit}' "$agh_cfg"); agh_up=$(awk '/^dns:/{d=1;next} d&&/^[^[:space:]]/{exit} d&&/127\.0\.0\.1:[0-9]+|::1:[0-9]+/{if(match($0,/127\.0\.0\.1:[0-9]+|::1:[0-9]+/)) print substr($0,RSTART,RLENGTH)}' "$agh_cfg" | paste -sd, -); fi; printf 'ADGUARD_PORT=%s\nADGUARD_UPSTREAMS=%s\n' "$agh_port" "$agh_up"
is_running smartdns && sd_run=1 || sd_run=0; printf 'SMARTDNS_RUNNING=%s\n' "$sd_run"
sd_ports=$(uci -q show smartdns 2>/dev/null | sed -n "s/.*\.port='\([0-9][0-9]*\)'.*/\1/p" | sort -nu | paste -sd, -); printf 'SMARTDNS_PORTS=%s\n' "$sd_ports"
sd_enc=$(uci -q show smartdns 2>/dev/null | grep -Ec "server_(https|tls)|type='(https|tls)'" || true); printf 'SMARTDNS_ENCRYPTED=%s\n' "$sd_enc"
is_running mosdns && md_run=1 || md_run=0; printf 'MOSDNS_RUNNING=%s\n' "$md_run"
md_ports=$(uci -q show mosdns 2>/dev/null | sed -n "s/.*listen.*[:#]\([0-9][0-9]*\)'.*/\1/p" | sort -nu | paste -sd, -); printf 'MOSDNS_PORTS=%s\n' "$md_ports"
nslookup www.baidu.com 127.0.0.1 >/dev/null 2>&1 && echo ROUTER_BAIDU_OK=1 || echo ROUTER_BAIDU_OK=0
nslookup www.google.com 127.0.0.1 >/dev/null 2>&1 && echo ROUTER_GOOGLE_OK=1 || echo ROUTER_GOOGLE_OK=0"#
}

unsafe fn wide_string(pointer: *const u16) -> String {
    if pointer.is_null() {
        return String::new();
    }
    let mut length = 0usize;
    while unsafe { *pointer.add(length) } != 0 && length < 1024 {
        length += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(pointer, length) })
}

unsafe fn socket_ip(address: &SOCKET_ADDRESS) -> Option<IpAddr> {
    if address.lpSockaddr.is_null() || address.iSockaddrLength < size_of::<SOCKADDR>() as i32 {
        return None;
    }
    let family = unsafe { (*address.lpSockaddr).sa_family };
    if family == AF_INET {
        let address = unsafe { &*(address.lpSockaddr as *const SOCKADDR_IN) };
        let bytes = unsafe { address.sin_addr.S_un.S_addr }.to_ne_bytes();
        Some(IpAddr::V4(Ipv4Addr::from(bytes)))
    } else if family == AF_INET6 {
        let address = unsafe { &*(address.lpSockaddr as *const SOCKADDR_IN6) };
        Some(IpAddr::V6(Ipv6Addr::from(unsafe {
            address.sin6_addr.u.Byte
        })))
    } else {
        None
    }
}

fn is_tunnel_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ["vpn", "tailscale", "wireguard", "zerotier", " tap", " tun"]
        .iter()
        .any(|marker| lower.contains(marker))
}

fn inspect_windows_adapters() -> Result<Vec<LocalAdapter>, String> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    let mut size = 0u32;
    let first =
        unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, flags, null(), null_mut(), &mut size) };
    if first != ERROR_BUFFER_OVERFLOW || size == 0 {
        return Err(format!("GetAdaptersAddresses size query failed: {first}"));
    }
    let mut buffer = vec![0u8; size as usize];
    let head = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
    let result = unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, flags, null(), head, &mut size) };
    if result != 0 {
        return Err(format!("GetAdaptersAddresses failed: {result}"));
    }

    let mut adapters = Vec::new();
    let mut current = head;
    while !current.is_null() {
        let adapter = unsafe { &*current };
        if adapter.OperStatus == IfOperStatusUp && adapter.IfType != IF_TYPE_SOFTWARE_LOOPBACK {
            let name = unsafe { wide_string(adapter.FriendlyName) };
            let mut dns_servers = Vec::new();
            let mut dns = adapter.FirstDnsServerAddress;
            while !dns.is_null() {
                if let Some(ip) = unsafe { socket_ip(&(*dns).Address) } {
                    dns_servers.push(ip);
                }
                dns = unsafe { (*dns).Next };
            }
            let mut gateways = Vec::new();
            let mut gateway = adapter.FirstGatewayAddress;
            while !gateway.is_null() {
                if let Some(ip) = unsafe { socket_ip(&(*gateway).Address) } {
                    gateways.push(ip);
                }
                gateway = unsafe { (*gateway).Next };
            }
            dns_servers.sort();
            dns_servers.dedup();
            gateways.sort();
            gateways.dedup();
            if !dns_servers.is_empty() || !gateways.is_empty() {
                adapters.push(LocalAdapter {
                    is_tunnel: is_tunnel_name(&name),
                    name,
                    dns_servers,
                    gateways,
                });
            }
        }
        current = adapter.Next;
    }
    adapters.sort_by_key(|adapter| (adapter.gateways.is_empty(), adapter.is_tunnel));
    Ok(adapters)
}

fn host_ip(router_host: &str) -> Option<IpAddr> {
    router_host.parse().ok().or_else(|| {
        (router_host, 22)
            .to_socket_addrs()
            .ok()?
            .map(|address| address.ip())
            .next()
    })
}

fn node(
    id: impl Into<String>,
    label: impl Into<String>,
    detail: Option<String>,
    confidence: DnsChainConfidence,
    evidence: impl Into<String>,
) -> DnsChainNode {
    DnsChainNode {
        id: id.into(),
        label: label.into(),
        detail,
        confidence,
        evidence: evidence.into(),
    }
}

fn endpoint_port(endpoint: &str) -> Option<u16> {
    endpoint.rsplit_once(':')?.1.parse().ok()
}

fn service_for_port(port: u16, evidence: &RouterDnsEvidence) -> (&'static str, bool) {
    if evidence.openclash_port == Some(port) {
        ("OpenClash DNS", evidence.openclash_running)
    } else if evidence.adguard_port == Some(port) {
        ("AdGuard Home", evidence.adguard_running)
    } else if evidence.smartdns_ports.contains(&port) {
        ("SmartDNS", evidence.smartdns_running)
    } else if evidence.mosdns_ports.contains(&port) {
        ("mosdns", evidence.mosdns_running)
    } else {
        ("本机 DNS 服务", false)
    }
}

fn append_endpoint_nodes(
    nodes: &mut Vec<DnsChainNode>,
    endpoints: &[String],
    evidence: &RouterDnsEvidence,
    seen: &mut HashSet<String>,
) {
    for endpoint in endpoints {
        let Some(port) = endpoint_port(endpoint) else {
            continue;
        };
        let (label, running) = service_for_port(port, evidence);
        let key = format!("{label}:{port}");
        if seen.insert(key.clone()) {
            nodes.push(node(
                key,
                label,
                Some(format!("127.0.0.1:{port}")),
                if running {
                    DnsChainConfidence::Confirmed
                } else {
                    DnsChainConfidence::Inferred
                },
                if running {
                    "配置指向该端口，且检测到对应服务正在运行"
                } else {
                    "配置指向该本机端口，但未确认对应进程"
                },
            ));
        }
    }
}

fn build_router_nodes(
    evidence: &RouterDnsEvidence,
    protection: &DnsProtectionSnapshot,
) -> Vec<DnsChainNode> {
    let mut nodes = Vec::new();
    let mut seen = HashSet::new();
    if evidence.dnsmasq_running {
        nodes.push(node(
            "dnsmasq",
            "dnsmasq",
            evidence
                .dnsmasq_port
                .map(|port| format!("局域网入口 :{port}")),
            DnsChainConfidence::Confirmed,
            "路由器进程与配置共同确认",
        ));
        seen.insert("dnsmasq".to_string());
    } else {
        nodes.push(node(
            "router-entry-unknown",
            "路由器 DNS 入口",
            None,
            DnsChainConfidence::Unknown,
            "未确认 dnsmasq 是否正在接收局域网请求",
        ));
    }
    append_endpoint_nodes(&mut nodes, &evidence.dnsmasq_upstreams, evidence, &mut seen);

    if evidence.dnsmasq_upstreams.is_empty()
        && protection.dnsmasq_to_openclash == Some(true)
        && let Some(port) = evidence.openclash_port
    {
        append_endpoint_nodes(
            &mut nodes,
            &[format!("127.0.0.1:{port}")],
            evidence,
            &mut seen,
        );
    }
    append_endpoint_nodes(&mut nodes, &protection.local_upstreams, evidence, &mut seen);
    append_endpoint_nodes(&mut nodes, &evidence.adguard_upstreams, evidence, &mut seen);

    let encrypted = protection.encrypted_upstream_count.unwrap_or(0)
        + evidence.smartdns_encrypted_count.unwrap_or(0);
    if encrypted > 0 {
        nodes.push(node(
            "encrypted-upstream",
            "加密 DNS 上游",
            Some(format!("检测到 {encrypted} 项 DoH / DoT / DoQ 配置")),
            DnsChainConfidence::Inferred,
            "根据脱敏配置统计推断，未进行全程抓包",
        ));
    } else {
        nodes.push(node(
            "upstream-unknown",
            "最终上游",
            None,
            DnsChainConfidence::Unknown,
            "没有足够证据确认最终上游及加密方式",
        ));
    }
    nodes
}

fn build_client_nodes(
    adapters: &[LocalAdapter],
    router_host: &str,
) -> (Vec<DnsChainNode>, Vec<String>, Vec<String>) {
    let mut nodes = Vec::new();
    let mut warnings = Vec::new();
    let router_ip = host_ip(router_host);
    let mut active_names = Vec::new();
    for (index, adapter) in adapters.iter().enumerate() {
        active_names.push(adapter.name.clone());
        nodes.push(node(
            format!("adapter-{index}"),
            format!("本机：{}", adapter.name),
            if adapter.gateways.is_empty() {
                None
            } else {
                Some(format!(
                    "网关 {}",
                    adapter
                        .gateways
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("、")
                ))
            },
            DnsChainConfidence::Confirmed,
            "由当前 Windows 网卡 API 读取",
        ));
        if adapter.is_tunnel {
            warnings.push(format!(
                "检测到可能的 VPN/隧道网卡“{}”，DNS 可能绕过软路由。",
                adapter.name
            ));
        }
        for dns in &adapter.dns_servers {
            let reaches_router = router_ip == Some(*dns) || adapter.gateways.contains(dns);
            nodes.push(node(
                format!("adapter-{index}-dns-{dns}"),
                if reaches_router {
                    "软路由 DNS"
                } else {
                    "其他 DNS"
                },
                Some(format!("{dns}:53")),
                if reaches_router {
                    DnsChainConfidence::Confirmed
                } else {
                    DnsChainConfidence::PossibleBypass
                },
                if reaches_router {
                    "Windows 将该地址配置为 DNS，且与软路由地址或网关匹配"
                } else {
                    "Windows 正在使用不等于软路由地址的 DNS；也可能被防火墙重定向"
                },
            ));
            if !reaches_router {
                warnings.push(format!(
                    "网卡“{}”使用 DNS {dns}，可能绕过软路由 DNS。",
                    adapter.name
                ));
            }
        }
    }
    if adapters.is_empty() {
        nodes.push(node(
            "windows-network-unknown",
            "当前 Windows 网络",
            None,
            DnsChainConfidence::Unknown,
            "未读取到处于连接状态且带 DNS 信息的网卡",
        ));
        warnings.push("无法读取当前 Windows 网卡 DNS，客户端链路标记为未知。".into());
    } else if adapters.len() > 1 {
        warnings.push("检测到多个活动网卡；Windows 会按接口优先级选择实际解析出口。".into());
    }
    (nodes, active_names, warnings)
}

async fn local_resolution(target: &'static str) -> DnsResolutionObservation {
    let started = Instant::now();
    let result = timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || {
            (target, 0)
                .to_socket_addrs()
                .map(|mut a| a.next().is_some())
        }),
    )
    .await;
    let success = match result {
        Ok(Ok(Ok(value))) => Some(value),
        Ok(Ok(Err(_))) => Some(false),
        _ => None,
    };
    DnsResolutionObservation {
        source: "当前 Windows 系统解析器".into(),
        target: target.into(),
        success,
        elapsed_ms: Some(started.elapsed().as_millis() as u64),
        detail: "只证明当前系统解析成功或失败，不能据此证明请求使用了加密 DNS。".into(),
    }
}

fn router_observation(target: &str, success: Option<bool>) -> DnsResolutionObservation {
    DnsResolutionObservation {
        source: "软路由默认解析器".into(),
        target: target.into(),
        success,
        elapsed_ms: None,
        detail: "在软路由上进行只读解析测试；结果不等于完整数据包路径。".into(),
    }
}

pub async fn inspect(
    session: &SshSession,
    router_host: &str,
    protection: &DnsProtectionSnapshot,
) -> DnsChainSnapshot {
    let router_output = session.run(router_probe_command()).await.ok();
    let evidence = router_output
        .as_ref()
        .map(|output| parse_router_evidence(&output.stdout))
        .unwrap_or_default();

    let adapters = tokio::task::spawn_blocking(inspect_windows_adapters)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    let (client_nodes, active_adapters, mut warnings) = build_client_nodes(&adapters, router_host);
    if router_output.is_none() {
        warnings.push("软路由 DNS 组件读取失败，路由器链路只能显示为未知。".into());
    }

    let (baidu, google) = tokio::join!(
        local_resolution("www.baidu.com"),
        local_resolution("www.google.com")
    );
    let observations = vec![
        baidu,
        google,
        router_observation("www.baidu.com", evidence.baidu_ok),
        router_observation("www.google.com", evidence.google_ok),
    ];

    DnsChainSnapshot {
        active_adapters,
        client_nodes,
        router_nodes: build_router_nodes(&evidence, protection),
        observations,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DnsProtectionStatus, PluginKind};

    fn protection(local_upstreams: Vec<String>) -> DnsProtectionSnapshot {
        DnsProtectionSnapshot {
            plugin: PluginKind::OpenClash,
            status: DnsProtectionStatus::Protected,
            summary: String::new(),
            supported: true,
            can_apply: false,
            dns_enabled: Some(true),
            enhanced_mode: Some("fake-ip".into()),
            dnsmasq_to_openclash: Some(true),
            encrypted_upstream_count: Some(2),
            plaintext_upstream_count: Some(0),
            local_upstreams,
            respect_rules: Some(true),
            managed_by_assistant: false,
            risks: Vec::new(),
            checks: Vec::new(),
            chain: DnsChainSnapshot::default(),
        }
    }

    #[test]
    fn parses_only_sanitized_router_metadata() {
        let evidence = parse_router_evidence(
            "DNSMASQ_RUNNING=1\nDNSMASQ_PORT=53\nDNSMASQ_UPSTREAMS=127.0.0.1:7874,8.8.8.8:53\nOPENCLASH_RUNNING=1\nOPENCLASH_PORT=7874\nADGUARD_RUNNING=1\nADGUARD_PORT=5353\nADGUARD_UPSTREAMS=127.0.0.1:6053\nSMARTDNS_RUNNING=1\nSMARTDNS_PORTS=6053,6053\nSMARTDNS_ENCRYPTED=4\nMOSDNS_RUNNING=0\nROUTER_BAIDU_OK=1\nROUTER_GOOGLE_OK=0\nAPI_KEY=must-not-appear",
        );
        assert_eq!(evidence.dnsmasq_upstreams, vec!["127.0.0.1:7874"]);
        assert_eq!(evidence.smartdns_ports, vec![6053]);
        assert_eq!(evidence.baidu_ok, Some(true));
        assert_eq!(evidence.google_ok, Some(false));
    }

    #[test]
    fn builds_realistic_multi_component_router_chain() {
        let evidence = RouterDnsEvidence {
            dnsmasq_running: true,
            dnsmasq_port: Some(53),
            dnsmasq_upstreams: vec!["127.0.0.1:7874".into()],
            openclash_running: true,
            openclash_port: Some(7874),
            adguard_running: true,
            adguard_port: Some(5353),
            adguard_upstreams: vec!["127.0.0.1:6053".into()],
            smartdns_running: true,
            smartdns_ports: vec![6053],
            smartdns_encrypted_count: Some(2),
            ..Default::default()
        };
        let labels: Vec<String> =
            build_router_nodes(&evidence, &protection(vec!["127.0.0.1:5353".into()]))
                .into_iter()
                .map(|node| node.label)
                .collect();
        assert_eq!(
            labels,
            vec![
                "dnsmasq",
                "OpenClash DNS",
                "AdGuard Home",
                "SmartDNS",
                "加密 DNS 上游"
            ]
        );
    }

    #[test]
    fn marks_external_windows_dns_as_possible_bypass() {
        let adapters = vec![LocalAdapter {
            name: "Ethernet".into(),
            dns_servers: vec!["8.8.8.8".parse().unwrap()],
            gateways: vec!["192.168.1.1".parse().unwrap()],
            is_tunnel: false,
        }];
        let (nodes, _, warnings) = build_client_nodes(&adapters, "192.168.1.1");
        assert_eq!(nodes[1].confidence, DnsChainConfidence::PossibleBypass);
        assert!(!warnings.is_empty());
    }

    #[test]
    fn keeps_ipv6_dns_visible() {
        let adapters = vec![LocalAdapter {
            name: "Wi-Fi".into(),
            dns_servers: vec!["2001:4860:4860::8888".parse().unwrap()],
            gateways: vec!["fe80::1".parse().unwrap()],
            is_tunnel: false,
        }];
        let (nodes, _, _) = build_client_nodes(&adapters, "192.168.1.1");
        assert!(nodes[1].detail.as_deref().unwrap().contains("2001:4860"));
        assert_eq!(nodes[1].confidence, DnsChainConfidence::PossibleBypass);
    }
}
