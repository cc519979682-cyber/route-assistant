export type Locale = "zh-CN" | "en";
export type AuthKind = "password" | "privateKey";
export type PluginKind = "openClash" | "nikki" | "unsupported";
export type ServiceState = "running" | "stopped" | "unknown";
export type MatchScope = "exact" | "suffix";
export type RuleAction =
  | { type: "direct" }
  | { type: "reject" }
  | { type: "policyGroup"; name: string };

export interface RouterProfileInput {
  id?: string;
  name: string;
  host: string;
  port: number;
  username: string;
  authKind: AuthKind;
  password?: string;
  privateKeyPath?: string;
  privateKeyPassphrase?: string;
  trustHostKey?: boolean;
}

export interface RouterProfile {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  authKind: AuthKind;
  credentialRef: string;
  hostKeyFingerprint?: string;
}

export interface DetectedPlugin {
  kind: PluginKind;
  displayName: string;
  version?: string;
  serviceState: ServiceState;
  coreVersion?: string;
  capabilities: string[];
  readOnly: boolean;
  reason?: string;
}

export interface RouterSnapshot {
  profile: RouterProfile;
  distribution: string;
  release?: string;
  plugins: DetectedPlugin[];
  selectedPlugin?: PluginKind;
  hostKeyFingerprint: string;
  needsHostKeyTrust: boolean;
}

export interface RuleSpec {
  id: string;
  scope: MatchScope;
  domain: string;
  normalizedDomain: string;
  action: RuleAction;
  enabled: boolean;
  note?: string;
  managed: boolean;
  source?: string;
}

export interface RuleDraft {
  scope: MatchScope;
  domain: string;
  action: RuleAction;
  note?: string;
}

export type CustomRuleOwner = "assistant" | "existing";
export type CustomRuleParseState = "structured" | "raw" | "invalid";

export interface CustomRuleRecord {
  id: string;
  sourceLocation: string;
  position: number;
  owner: CustomRuleOwner;
  enabled: boolean;
  ruleType: string;
  matcher?: string;
  target?: string;
  note?: string;
  rawPreview: string;
  parseState: CustomRuleParseState;
  warning?: string;
  copyDraft?: RuleDraft;
  assistantRule?: RuleSpec;
}

export interface CustomRuleNotice {
  code: string;
  level: "info" | "warning" | "error";
  message: string;
}

export interface CustomRulesSnapshot {
  plugin: PluginKind;
  rules: CustomRuleRecord[];
  notices: CustomRuleNotice[];
}

export interface PolicyTarget {
  name: string;
  kind: "builtIn" | "group";
}

export interface Conflict {
  kind: "duplicate" | "differentAction" | "invalidTarget" | "unmanaged";
  message: string;
  existingRule?: RuleSpec;
  requiresOverride: boolean;
}

export interface ChangePlan {
  id: string;
  profileId: string;
  plugin: PluginKind;
  operation: "create" | "update" | "delete";
  rule: RuleSpec;
  preview: string;
  conflicts: Conflict[];
  requiresReload: boolean;
  interruptionSeconds: number;
  canApply: boolean;
}

export interface DnsObservation {
  resolver: string;
  addresses: string[];
  elapsedMs?: number;
  note: string;
}

export interface VerificationReport {
  changeId: string;
  success: boolean;
  serviceState: ServiceState;
  coreApiReachable: boolean;
  rulePresent: boolean;
  ruleIndex?: number;
  hitVerified: boolean;
  verificationLimited: boolean;
  dnsObservation?: DnsObservation;
  rolledBack: boolean;
  backupId?: string;
  messages: string[];
}

export interface OperationHistoryItem {
  id: string;
  profileId: string;
  plugin: PluginKind;
  operation: string;
  summary: string;
  backupId?: string;
  success: boolean;
  createdAt: string;
}
