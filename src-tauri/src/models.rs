use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AuthKind {
    Password,
    PrivateKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterProfileInput {
    pub id: Option<String>,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_kind: AuthKind,
    pub password: Option<String>,
    pub private_key_path: Option<String>,
    pub private_key_passphrase: Option<String>,
    #[serde(default)]
    pub trust_host_key: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterProfile {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_kind: AuthKind,
    pub credential_ref: String,
    pub host_key_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PluginKind {
    OpenClash,
    Nikki,
    HomeProxy,
    PassWall,
    Unsupported,
}

impl PluginKind {
    pub fn is_managed(&self) -> bool {
        matches!(self, Self::OpenClash | Self::Nikki)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PluginSupportLevel {
    Managed,
    DetectedOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PluginSelectionReason {
    AutoRunning,
    AutoOnlyManaged,
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ServiceState {
    Running,
    Stopped,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectedPlugin {
    pub kind: PluginKind,
    pub display_name: String,
    pub version: Option<String>,
    pub service_state: ServiceState,
    pub core_version: Option<String>,
    pub capabilities: Vec<String>,
    pub support_level: PluginSupportLevel,
    pub can_select: bool,
    pub can_read_custom_rules: bool,
    pub read_only: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterPluginState {
    pub plugins: Vec<DetectedPlugin>,
    pub selected_plugin: Option<PluginKind>,
    pub selection_reason: Option<PluginSelectionReason>,
    pub requires_manual_selection: bool,
    pub running_plugin_count: usize,
    pub can_write: bool,
    pub write_block_reason: Option<String>,
    pub risk_warning: Option<String>,
    pub state_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterSnapshot {
    pub profile: RouterProfile,
    pub distribution: String,
    pub release: Option<String>,
    pub plugin_state: RouterPluginState,
    pub host_key_fingerprint: String,
    pub needs_host_key_trust: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum MatchScope {
    Exact,
    Suffix,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum RuleAction {
    Direct,
    Reject,
    PolicyGroup { name: String },
}

impl RuleAction {
    pub fn target(&self) -> &str {
        match self {
            Self::Direct => "DIRECT",
            Self::Reject => "REJECT",
            Self::PolicyGroup { name } => name,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleDraft {
    pub scope: MatchScope,
    pub domain: String,
    pub action: RuleAction,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuleSpec {
    pub id: String,
    pub scope: MatchScope,
    pub domain: String,
    pub normalized_domain: String,
    pub action: RuleAction,
    pub enabled: bool,
    pub note: Option<String>,
    pub managed: bool,
    pub source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CustomRuleOwner {
    Assistant,
    Existing,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CustomRuleParseState {
    Structured,
    Raw,
    Invalid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomRuleRecord {
    pub id: String,
    pub source_location: String,
    pub position: usize,
    pub owner: CustomRuleOwner,
    pub enabled: bool,
    pub rule_type: String,
    pub matcher: Option<String>,
    pub target: Option<String>,
    pub note: Option<String>,
    pub raw_preview: String,
    pub parse_state: CustomRuleParseState,
    pub warning: Option<String>,
    pub copy_draft: Option<RuleDraft>,
    pub assistant_rule: Option<RuleSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomRuleNotice {
    pub code: String,
    pub level: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomRulesSnapshot {
    pub plugin: PluginKind,
    pub rules: Vec<CustomRuleRecord>,
    pub notices: Vec<CustomRuleNotice>,
}

impl RuleSpec {
    pub fn mihomo_line(&self) -> String {
        let kind = match self.scope {
            MatchScope::Exact => "DOMAIN",
            MatchScope::Suffix => "DOMAIN-SUFFIX",
        };
        format!("{kind},{},{}", self.normalized_domain, self.action.target())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyTarget {
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Conflict {
    pub kind: String,
    pub message: String,
    pub existing_rule: Option<RuleSpec>,
    pub requires_override: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePlan {
    pub id: String,
    pub profile_id: String,
    pub plugin: PluginKind,
    #[serde(default)]
    pub plugin_state_token: String,
    pub operation: String,
    pub rule: RuleSpec,
    pub preview: String,
    pub conflicts: Vec<Conflict>,
    pub requires_reload: bool,
    pub interruption_seconds: u32,
    pub can_apply: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsObservation {
    pub resolver: String,
    pub addresses: Vec<String>,
    pub elapsed_ms: Option<u64>,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DnsProtectionStatus {
    Protected,
    NeedsAttention,
    Unsupported,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DnsChainConfidence {
    Confirmed,
    Inferred,
    Unknown,
    PossibleBypass,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsChainNode {
    pub id: String,
    pub label: String,
    pub detail: Option<String>,
    pub confidence: DnsChainConfidence,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsResolutionObservation {
    pub source: String,
    pub target: String,
    pub success: Option<bool>,
    pub elapsed_ms: Option<u64>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DnsChainSnapshot {
    pub active_adapters: Vec<String>,
    pub client_nodes: Vec<DnsChainNode>,
    pub router_nodes: Vec<DnsChainNode>,
    pub observations: Vec<DnsResolutionObservation>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsProtectionSnapshot {
    pub plugin: PluginKind,
    pub status: DnsProtectionStatus,
    pub summary: String,
    pub supported: bool,
    pub can_apply: bool,
    pub dns_enabled: Option<bool>,
    pub enhanced_mode: Option<String>,
    pub dnsmasq_to_openclash: Option<bool>,
    pub encrypted_upstream_count: Option<usize>,
    pub plaintext_upstream_count: Option<usize>,
    pub local_upstreams: Vec<String>,
    pub respect_rules: Option<bool>,
    pub managed_by_assistant: bool,
    pub risks: Vec<String>,
    pub checks: Vec<String>,
    pub chain: DnsChainSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsProtectionPlan {
    pub id: String,
    pub profile_id: String,
    pub plugin: PluginKind,
    pub plugin_state_token: String,
    pub preview: String,
    pub can_apply: bool,
    pub requires_reload: bool,
    pub interruption_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsProtectionReport {
    pub change_id: String,
    pub success: bool,
    pub rolled_back: bool,
    pub backup_id: Option<String>,
    pub messages: Vec<String>,
    pub snapshot: DnsProtectionSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub change_id: String,
    pub success: bool,
    pub service_state: ServiceState,
    pub core_api_reachable: bool,
    pub rule_present: bool,
    pub rule_index: Option<usize>,
    pub hit_verified: bool,
    pub verification_limited: bool,
    pub dns_observation: Option<DnsObservation>,
    pub rolled_back: bool,
    pub backup_id: Option<String>,
    pub messages: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationHistoryItem {
    pub id: String,
    pub profile_id: String,
    pub plugin: PluginKind,
    pub operation: String,
    pub summary: String,
    pub backup_id: Option<String>,
    pub success: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_status: u32,
}
