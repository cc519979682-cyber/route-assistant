import { invoke } from "@tauri-apps/api/core";
import type {
  ChangePlan,
  CustomRuleRecord,
  CustomRulesSnapshot,
  DnsChainSnapshot,
  DnsProtectionPlan,
  DnsProtectionReport,
  DnsProtectionSnapshot,
  OperationHistoryItem,
  PolicyTarget,
  RouterProfile,
  RouterProfileInput,
  RouterPluginState,
  RouterSnapshot,
  RuleDraft,
  RuleSpec,
  VerificationReport,
} from "./types";

const isTauri = () => typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

const demoProfile: RouterProfile = {
  id: "demo-router",
  name: "演示软路由",
  host: "192.168.1.1",
  port: 22,
  username: "root",
  authKind: "password",
  credentialRef: "demo",
  hostKeyFingerprint: "SHA256:demo-fingerprint",
};

const demoRules: RuleSpec[] = [];
const demoExistingRules: CustomRuleRecord[] = [
  {
    id: "demo-existing-domain",
    sourceLocation: "/etc/openclash/custom/openclash_custom_rules.list:8",
    position: 8,
    owner: "existing",
    enabled: true,
    ruleType: "DOMAIN-SUFFIX",
    matcher: "example.com",
    target: "DIRECT",
    rawPreview: "- DOMAIN-SUFFIX,example.com,DIRECT",
    parseState: "structured",
    copyDraft: { scope: "suffix", domain: "example.com", action: { type: "direct" } },
  },
  {
    id: "demo-existing-ip",
    sourceLocation: "/etc/openclash/custom/openclash_custom_rules.list:9",
    position: 9,
    owner: "existing",
    enabled: false,
    ruleType: "IP-CIDR",
    matcher: "192.0.2.0/24",
    target: "REJECT",
    rawPreview: "##- IP-CIDR,192.0.2.0/24,REJECT",
    parseState: "structured",
    warning: "当前版本尚不能创建 IP 规则。",
  },
];
const demoPlans = new Map<string, ChangePlan>();
const demoDnsPlans = new Map<string, DnsProtectionPlan>();
let demoDnsProtected = false;

const demoPlugins: RouterPluginState["plugins"] = [
  {
    kind: "openClash",
    displayName: "OpenClash",
    version: "0.47.028-beta",
    serviceState: "running",
    coreVersion: "Mihomo demo",
    capabilities: ["domainRules", "policyGroups", "runtimeVerification", "rollback"],
    supportLevel: "managed",
    canSelect: true,
    canReadCustomRules: true,
    readOnly: false,
  },
  {
    kind: "nikki",
    displayName: "Nikki",
    version: "1.23.0",
    serviceState: "stopped",
    capabilities: ["readOnlyDiagnostics"],
    supportLevel: "managed",
    canSelect: true,
    canReadCustomRules: true,
    readOnly: true,
    reason: "服务未运行，只能查看自定义规则。",
  },
  {
    kind: "homeProxy",
    displayName: "HomeProxy",
    version: "0.9.11",
    serviceState: "stopped",
    capabilities: ["readOnlyDiagnostics"],
    supportLevel: "detectedOnly",
    canSelect: false,
    canReadCustomRules: false,
    readOnly: true,
    reason: "已检测到 HomeProxy，本版本尚未提供适配器。",
  },
  {
    kind: "passWall",
    displayName: "PassWall2",
    version: "25.7.1",
    serviceState: "stopped",
    capabilities: ["readOnlyDiagnostics"],
    supportLevel: "detectedOnly",
    canSelect: false,
    canReadCustomRules: false,
    readOnly: true,
    reason: "已检测到 PassWall2，本版本尚未提供适配器。",
  },
];

let demoPluginState: RouterPluginState = {
  plugins: demoPlugins,
  selectedPlugin: "openClash",
  selectionReason: "autoRunning",
  requiresManualSelection: false,
  runningPluginCount: 1,
  canWrite: true,
  stateToken: "demo-openclash-running",
};

function demoNormalizeDomain(input: string, suffix: boolean) {
  const candidate = input.includes("://") ? input : `https://${input}`;
  const host = new URL(candidate).hostname.toLowerCase().replace(/\.$/, "");
  return suffix && host.startsWith("www.") ? host.slice(4) : host;
}

export async function listProfiles(): Promise<RouterProfile[]> {
  if (!isTauri()) return [];
  return invoke("list_router_profiles");
}

export async function discoverRouter(input: RouterProfileInput): Promise<RouterSnapshot> {
  if (!isTauri()) {
    await new Promise((resolve) => setTimeout(resolve, 450));
    return {
      profile: { ...demoProfile, name: input.name, host: input.host },
      distribution: "OpenWrt",
      release: "24.10 (演示模式)",
      hostKeyFingerprint: "SHA256:demo-fingerprint",
      needsHostKeyTrust: !input.trustHostKey,
      pluginState: demoPluginState,
    };
  }
  return invoke("discover_router", { input });
}

export async function listCustomRules(profileId: string): Promise<CustomRulesSnapshot> {
  if (!isTauri()) {
    const assistant = demoRules.map<CustomRuleRecord>((rule, index) => ({
      id: `demo-assistant-${rule.id}`,
      sourceLocation: `/etc/openclash/custom/openclash_custom_rules.list:${index + 3}`,
      position: index + 3,
      owner: "assistant",
      enabled: rule.enabled,
      ruleType: rule.scope === "suffix" ? "DOMAIN-SUFFIX" : "DOMAIN",
      matcher: rule.normalizedDomain,
      target: rule.action.type === "direct" ? "DIRECT" : rule.action.type === "reject" ? "REJECT" : rule.action.name,
      note: rule.note,
      rawPreview: rule.normalizedDomain,
      parseState: "structured",
      copyDraft: { scope: rule.scope, domain: rule.normalizedDomain, action: rule.action, note: rule.note },
      assistantRule: rule,
    }));
    return { plugin: "openClash", rules: [...assistant, ...demoExistingRules], notices: [] };
  }
  return invoke("list_custom_rules", { profileId });
}

export async function refreshPluginState(profileId: string): Promise<RouterPluginState> {
  if (!isTauri()) return demoPluginState;
  return invoke("refresh_plugin_state", { profileId });
}

export async function selectPlugin(profileId: string, plugin: "openClash" | "nikki"): Promise<RouterPluginState> {
  if (!isTauri()) {
    const selected = demoPlugins.find((item) => item.kind === plugin)!;
    demoPluginState = {
      ...demoPluginState,
      selectedPlugin: plugin,
      selectionReason: "manual",
      requiresManualSelection: false,
      canWrite: selected.serviceState === "running" && !selected.readOnly,
      writeBlockReason: selected.serviceState === "running" && !selected.readOnly ? undefined : selected.reason,
      stateToken: `demo-${plugin}-${selected.serviceState}`,
    };
    return demoPluginState;
  }
  return invoke("select_plugin", { profileId, plugin });
}

export async function listPolicyTargets(profileId: string): Promise<PolicyTarget[]> {
  if (!isTauri()) {
    return [
      { name: "DIRECT", kind: "builtIn" },
      { name: "REJECT", kind: "builtIn" },
      { name: "节点选择", kind: "group" },
    ];
  }
  return invoke("list_policy_targets", { profileId });
}

export async function planRuleChange(profileId: string, draft: RuleDraft): Promise<ChangePlan> {
  if (!isTauri()) {
    const normalizedDomain = demoNormalizeDomain(draft.domain, draft.scope === "suffix");
    const plan: ChangePlan = {
      id: crypto.randomUUID(),
      profileId,
      plugin: "openClash",
      pluginStateToken: demoPluginState.stateToken,
      operation: "create",
      rule: {
        id: crypto.randomUUID(),
        scope: draft.scope,
        domain: draft.domain,
        normalizedDomain,
        action: draft.action,
        enabled: true,
        note: draft.note,
        managed: true,
      },
      preview: `将${draft.scope === "suffix" ? "整个域名及其子域名" : "仅此域名"}“${normalizedDomain}”设为“${draft.action.type === "direct" ? "直连（不经过代理）" : draft.action.type === "reject" ? "拒绝" : draft.action.name}”。规则位于订阅规则之前；应用时 OpenClash 会短暂重载。`,
      conflicts: [],
      requiresReload: true,
      interruptionSeconds: 20,
      canApply: true,
    };
    demoPlans.set(plan.id, plan);
    return plan;
  }
  return invoke("plan_rule_change", { profileId, draft });
}

export async function planRuleUpdate(profileId: string, ruleId: string, draft: RuleDraft): Promise<ChangePlan> {
  if (!isTauri()) {
    const plan = await planRuleChange(profileId, draft);
    plan.operation = "update";
    plan.rule.id = ruleId;
    plan.preview = `将本助手规则更新为“${plan.rule.normalizedDomain} → ${plan.rule.action.type === "direct" ? "DIRECT" : plan.rule.action.type === "reject" ? "REJECT" : plan.rule.action.name}”。`;
    demoPlans.set(plan.id, plan);
    return plan;
  }
  return invoke("plan_rule_update", { profileId, ruleId, draft });
}

export async function planRuleRemoval(profileId: string, rule: RuleSpec): Promise<ChangePlan> {
  if (!isTauri()) {
    const plan: ChangePlan = {
      id: crypto.randomUUID(),
      profileId,
      plugin: "openClash",
      pluginStateToken: demoPluginState.stateToken,
      operation: "delete",
      rule,
      preview: `将删除本助手创建的规则“${rule.normalizedDomain} → ${rule.action.type === "direct" ? "DIRECT" : rule.action.type === "reject" ? "REJECT" : rule.action.name}”。应用前会备份配置，不会修改其他规则。`,
      conflicts: [],
      requiresReload: true,
      interruptionSeconds: 20,
      canApply: true,
    };
    demoPlans.set(plan.id, plan);
    return plan;
  }
  return invoke("plan_rule_removal", { profileId, ruleId: rule.id });
}

export async function applyRuleChange(planId: string, allowOverride: boolean): Promise<VerificationReport> {
  if (!isTauri()) {
    await new Promise((resolve) => setTimeout(resolve, 700));
    const plan = demoPlans.get(planId);
    if (plan?.operation === "delete") {
      const index = demoRules.findIndex((item) => item.id === plan.rule.id);
      if (index >= 0) demoRules.splice(index, 1);
    } else if (plan) {
      const index = demoRules.findIndex((item) => item.id === plan.rule.id || (item.scope === plan.rule.scope && item.normalizedDomain === plan.rule.normalizedDomain));
      if (index >= 0) demoRules.splice(index, 1);
      demoRules.unshift(plan.rule);
    }
    demoPlans.delete(planId);
    return {
      changeId: planId,
      success: true,
      serviceState: "running",
      coreApiReachable: true,
      rulePresent: plan?.operation !== "delete",
      ruleIndex: 0,
      hitVerified: false,
      verificationLimited: true,
      rolledBack: false,
      backupId: "demo-backup",
      messages: ["演示模式：规则配置验证成功。"],
    };
  }
  return invoke("apply_rule_change", { planId, allowOverride });
}

export async function verifyRule(profileId: string, ruleId: string): Promise<VerificationReport> {
  return invoke("verify_rule", { profileId, ruleId });
}

export async function rollbackChange(profileId: string, backupId: string): Promise<VerificationReport> {
  return invoke("rollback_change", { profileId, backupId });
}

function emptyDnsChain(): DnsChainSnapshot {
  return {
    activeAdapters: [],
    clientNodes: [],
    routerNodes: [],
    observations: [],
    warnings: [],
  };
}

function demoDnsChain(): DnsChainSnapshot {
  return {
    activeAdapters: ["以太网"],
    clientNodes: [
      { id: "demo-adapter", label: "本机：以太网", detail: "网关 192.168.1.1", confidence: "confirmed", evidence: "由当前 Windows 网卡 API 读取" },
      { id: "demo-router-dns", label: "软路由 DNS", detail: "192.168.1.1:53", confidence: "confirmed", evidence: "Windows DNS 与软路由地址匹配" },
    ],
    routerNodes: [
      { id: "demo-dnsmasq", label: "dnsmasq", detail: "局域网入口 :53", confidence: "confirmed", evidence: "路由器进程与配置共同确认" },
      { id: "demo-openclash", label: "OpenClash DNS", detail: "127.0.0.1:7874", confidence: "confirmed", evidence: "配置指向该端口，且服务正在运行" },
      { id: "demo-upstream", label: "加密 DNS 上游", detail: "检测到 DoH 配置", confidence: "inferred", evidence: "根据脱敏配置推断，未进行全程抓包" },
    ],
    observations: [
      { source: "当前 Windows 系统解析器", target: "www.baidu.com", success: true, elapsedMs: 18, detail: "只证明解析成功，不能据此证明使用了加密 DNS。" },
      { source: "软路由默认解析器", target: "www.google.com", success: true, detail: "只读解析测试，不等于完整数据包路径。" },
    ],
    warnings: [],
  };
}

/** Backend/frontend version skew or partial payloads must not crash the DNS page. */
function normalizeDnsSnapshot(snapshot: DnsProtectionSnapshot): DnsProtectionSnapshot {
  const chain = snapshot.chain ?? emptyDnsChain();
  return {
    ...snapshot,
    localUpstreams: snapshot.localUpstreams ?? [],
    risks: snapshot.risks ?? [],
    checks: snapshot.checks ?? [],
    chain: {
      activeAdapters: chain.activeAdapters ?? [],
      clientNodes: chain.clientNodes ?? [],
      routerNodes: chain.routerNodes ?? [],
      observations: chain.observations ?? [],
      warnings: chain.warnings ?? [],
    },
  };
}

function normalizeDnsReport(report: DnsProtectionReport): DnsProtectionReport {
  return {
    ...report,
    messages: report.messages ?? [],
    snapshot: normalizeDnsSnapshot(report.snapshot),
  };
}

function demoDnsSnapshot(): DnsProtectionSnapshot {
  return demoDnsProtected
    ? {
        plugin: "openClash",
        status: "protected",
        summary: "当前 OpenClash 已使用加密 DNS，未发现明文上游。",
        supported: true,
        canApply: false,
        dnsEnabled: true,
        enhancedMode: "fake-ip",
        dnsmasqToOpenclash: true,
        encryptedUpstreamCount: 8,
        plaintextUpstreamCount: 0,
        localUpstreams: [],
        respectRules: true,
        managedByAssistant: true,
        risks: [],
        checks: ["百度解析测试通过（仅表示解析可用，不证明使用加密 DNS）。", "Google 解析测试通过（仅表示解析可用，不证明使用加密 DNS）。"],
        chain: demoDnsChain(),
      }
    : {
        plugin: "openClash",
        status: "needsAttention",
        summary: "发现可以安全修复的 OpenClash DNS 风险。",
        supported: true,
        canApply: true,
        dnsEnabled: true,
        enhancedMode: "fake-ip",
        dnsmasqToOpenclash: true,
        encryptedUpstreamCount: 1,
        plaintextUpstreamCount: 2,
        localUpstreams: [],
        respectRules: false,
        managedByAssistant: false,
        risks: ["发现 2 个明文或系统 DNS 上游，可能被污染或泄漏。", "DNS 连接没有明确跟随分流规则。"],
        checks: ["百度解析测试通过（仅表示解析可用，不证明使用加密 DNS）。", "Google 解析测试通过（仅表示解析可用，不证明使用加密 DNS）。"],
        chain: demoDnsChain(),
      };
}

export async function inspectDnsProtection(profileId: string): Promise<DnsProtectionSnapshot> {
  if (!isTauri()) return demoDnsSnapshot();
  return normalizeDnsSnapshot(await invoke("inspect_dns_protection", { profileId }));
}

export async function planDnsProtection(profileId: string): Promise<DnsProtectionPlan> {
  if (!isTauri()) {
    const plan: DnsProtectionPlan = {
      id: crypto.randomUUID(),
      profileId,
      plugin: "openClash",
      pluginStateToken: demoPluginState.stateToken,
      preview: "将在 OpenClash 官方自定义覆写脚本中加入助手专属 DNS 块：国内使用阿里/腾讯加密 DoH，国外使用 Cloudflare/Google 加密 DoH并跟随现有分流规则；不会修改订阅、DHCP或防火墙。",
      canApply: true,
      requiresReload: true,
      interruptionSeconds: 20,
    };
    demoDnsPlans.set(plan.id, plan);
    return plan;
  }
  return invoke("plan_dns_protection", { profileId });
}

export async function applyDnsProtection(planId: string): Promise<DnsProtectionReport> {
  if (!isTauri()) {
    demoDnsPlans.delete(planId);
    demoDnsProtected = true;
    return {
      changeId: planId,
      success: true,
      rolledBack: false,
      backupId: "dns-demo-backup",
      messages: ["演示模式：OpenClash 基础 DNS 防护已通过验证。"],
      snapshot: demoDnsSnapshot(),
    };
  }
  return normalizeDnsReport(await invoke("apply_dns_protection", { planId }));
}

export async function rollbackDnsProtection(profileId: string, backupId: string): Promise<DnsProtectionReport> {
  if (!isTauri()) {
    demoDnsProtected = false;
    return {
      changeId: `dns-rollback:${backupId}`,
      success: true,
      rolledBack: true,
      backupId,
      messages: ["演示模式：已恢复应用前的 DNS 配置。"],
      snapshot: demoDnsSnapshot(),
    };
  }
  return normalizeDnsReport(await invoke("rollback_dns_protection", { profileId, backupId }));
}

export async function listHistory(profileId?: string): Promise<OperationHistoryItem[]> {
  if (!isTauri()) return [];
  return invoke("list_operation_history", { profileId });
}

export async function exportDiagnostics(profileId: string): Promise<string> {
  if (!isTauri()) return "演示模式不会生成诊断文件。";
  return invoke("export_redacted_diagnostics", { profileId });
}
