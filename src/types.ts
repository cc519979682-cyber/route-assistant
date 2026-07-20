export type Locale = "zh-CN" | "en";
export type AuthKind = "password" | "privateKey";
export type PluginKind = "openClash" | "nikki" | "homeProxy" | "passWall" | "unsupported";
export type PluginSupportLevel = "managed" | "detectedOnly";
export type PluginSelectionReason = "autoRunning" | "autoOnlyManaged" | "manual";
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
  supportLevel: PluginSupportLevel;
  canSelect: boolean;
  canReadCustomRules: boolean;
  readOnly: boolean;
  reason?: string;
}

export interface RouterPluginState {
  plugins: DetectedPlugin[];
  selectedPlugin?: PluginKind;
  selectionReason?: PluginSelectionReason;
  requiresManualSelection: boolean;
  runningPluginCount: number;
  canWrite: boolean;
  writeBlockReason?: string;
  riskWarning?: string;
  stateToken: string;
}

export interface RouterSnapshot {
  profile: RouterProfile;
  distribution: string;
  release?: string;
  pluginState: RouterPluginState;
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
  pluginStateToken: string;
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

export type DnsProtectionStatus = "protected" | "needsAttention" | "unsupported" | "unknown";

export type DnsChainConfidence = "confirmed" | "inferred" | "unknown" | "possibleBypass";

export interface DnsChainNode {
  id: string;
  label: string;
  detail?: string;
  confidence: DnsChainConfidence;
  evidence: string;
}

export interface DnsResolutionObservation {
  source: string;
  target: string;
  success?: boolean;
  elapsedMs?: number;
  detail: string;
}

export interface DnsChainSnapshot {
  activeAdapters: string[];
  clientNodes: DnsChainNode[];
  routerNodes: DnsChainNode[];
  observations: DnsResolutionObservation[];
  warnings: string[];
}

export interface DnsProtectionSnapshot {
  plugin: PluginKind;
  status: DnsProtectionStatus;
  summary: string;
  supported: boolean;
  canApply: boolean;
  dnsEnabled?: boolean;
  enhancedMode?: string;
  dnsmasqToOpenclash?: boolean;
  encryptedUpstreamCount?: number;
  plaintextUpstreamCount?: number;
  localUpstreams?: string[];
  respectRules?: boolean;
  managedByAssistant: boolean;
  risks: string[];
  checks: string[];
  /** Older backends may omit this field; UI/api normalize to empty chain. */
  chain?: DnsChainSnapshot;
}

export interface DnsProtectionPlan {
  id: string;
  profileId: string;
  plugin: PluginKind;
  pluginStateToken: string;
  preview: string;
  canApply: boolean;
  requiresReload: boolean;
  interruptionSeconds: number;
}

export interface DnsProtectionReport {
  changeId: string;
  success: boolean;
  rolledBack: boolean;
  backupId?: string;
  messages: string[];
  snapshot: DnsProtectionSnapshot;
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
