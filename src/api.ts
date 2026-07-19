import { invoke } from "@tauri-apps/api/core";
import type {
  ChangePlan,
  OperationHistoryItem,
  PolicyTarget,
  RouterProfile,
  RouterProfileInput,
  RouterSnapshot,
  RuleDraft,
  RuleSpec,
  VerificationReport,
} from "./types";

const isTauri = () => "__TAURI_INTERNALS__" in window;

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
const demoPlans = new Map<string, ChangePlan>();

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
      selectedPlugin: "openClash",
      plugins: [
        {
          kind: "openClash",
          displayName: "OpenClash",
          version: "0.47.028-beta",
          serviceState: "running",
          coreVersion: "Mihomo demo",
          capabilities: ["domainRules", "policyGroups", "runtimeVerification", "rollback"],
          readOnly: false,
        },
      ],
    };
  }
  return invoke("discover_router", { input });
}

export async function listRules(profileId: string): Promise<RuleSpec[]> {
  if (!isTauri()) return [...demoRules];
  return invoke("list_rules", { profileId });
}

export async function selectPlugin(profileId: string, plugin: "openClash" | "nikki"): Promise<void> {
  if (!isTauri()) return;
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

export async function planRuleRemoval(profileId: string, rule: RuleSpec): Promise<ChangePlan> {
  if (!isTauri()) {
    const plan: ChangePlan = {
      id: crypto.randomUUID(),
      profileId,
      plugin: "openClash",
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
      const index = demoRules.findIndex((item) => item.scope === plan.rule.scope && item.normalizedDomain === plan.rule.normalizedDomain);
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

export async function listHistory(profileId?: string): Promise<OperationHistoryItem[]> {
  if (!isTauri()) return [];
  return invoke("list_operation_history", { profileId });
}

export async function exportDiagnostics(profileId: string): Promise<string> {
  if (!isTauri()) return "演示模式不会生成诊断文件。";
  return invoke("export_redacted_diagnostics", { profileId });
}
