import { useEffect, useMemo, useState } from "react";
import {
  applyRuleChange,
  discoverRouter,
  exportDiagnostics,
  listHistory,
  listCustomRules,
  listPolicyTargets,
  listProfiles,
  planRuleChange,
  planRuleRemoval,
  planRuleUpdate,
  selectPlugin,
} from "./api";
import { createTranslator } from "./i18n";
import { filterCustomRules } from "./customRules";
import type {
  ChangePlan,
  CustomRuleOwner,
  CustomRuleRecord,
  CustomRulesSnapshot,
  Locale,
  OperationHistoryItem,
  PolicyTarget,
  RouterProfile,
  RouterProfileInput,
  RouterSnapshot,
  RuleDraft,
  RuleSpec,
  VerificationReport,
} from "./types";

type Screen = "connect" | "dashboard";
type Tab = "overview" | "rules" | "diagnostics" | "history";

const initialConnection: RouterProfileInput = {
  name: "办公室软路由",
  host: "192.168.1.1",
  port: 22,
  username: "root",
  authKind: "password",
  password: "",
};

const initialDraft: RuleDraft = {
  domain: "",
  scope: "exact",
  action: { type: "direct" },
  note: "",
};

function App() {
  const [locale, setLocale] = useState<Locale>("zh-CN");
  const t = useMemo(() => createTranslator(locale), [locale]);
  const [screen, setScreen] = useState<Screen>("connect");
  const [tab, setTab] = useState<Tab>("overview");
  const [profiles, setProfiles] = useState<RouterProfile[]>([]);
  const [connection, setConnection] = useState<RouterProfileInput>(initialConnection);
  const [snapshot, setSnapshot] = useState<RouterSnapshot>();
  const [customRules, setCustomRules] = useState<CustomRulesSnapshot>();
  const [targets, setTargets] = useState<PolicyTarget[]>([]);
  const [history, setHistory] = useState<OperationHistoryItem[]>([]);
  const [draft, setDraft] = useState<RuleDraft>(initialDraft);
  const [plan, setPlan] = useState<ChangePlan>();
  const [report, setReport] = useState<VerificationReport>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [showRuleForm, setShowRuleForm] = useState(false);
  const [ruleOwnerFilter, setRuleOwnerFilter] = useState<"all" | CustomRuleOwner>("all");
  const [ruleSearch, setRuleSearch] = useState("");
  const [modalMode, setModalMode] = useState<"create" | "copy" | "edit" | "delete">("create");
  const [editingRuleId, setEditingRuleId] = useState<string>();

  const visibleRules = useMemo(() => {
    return filterCustomRules(customRules?.rules ?? [], ruleOwnerFilter, ruleSearch);
  }, [customRules, ruleOwnerFilter, ruleSearch]);

  useEffect(() => {
    listProfiles().then(setProfiles).catch(() => setProfiles([]));
  }, []);

  async function refreshRouterData(profileId: string) {
    const [nextRules, nextTargets, nextHistory] = await Promise.all([
      listCustomRules(profileId),
      listPolicyTargets(profileId).catch(() => []),
      listHistory(profileId),
    ]);
    setCustomRules(nextRules);
    setTargets(nextTargets);
    setHistory(nextHistory);
  }

  async function connect(trustHostKey = false) {
    setBusy(true);
    setError(undefined);
    try {
      const nextSnapshot = await discoverRouter({ ...connection, trustHostKey });
      setSnapshot(nextSnapshot);
      if (nextSnapshot.needsHostKeyTrust && !trustHostKey) return;
      if (nextSnapshot.selectedPlugin) {
        await refreshRouterData(nextSnapshot.profile.id);
      } else {
        setCustomRules(undefined);
        setTargets([]);
        setHistory(await listHistory(nextSnapshot.profile.id));
      }
      setScreen("dashboard");
    } catch (cause) {
      setError(String(cause));
    } finally {
      setBusy(false);
    }
  }

  async function createPlan() {
    if (!snapshot || !draft.domain.trim()) return;
    setBusy(true);
    setError(undefined);
    setReport(undefined);
    try {
      setPlan(editingRuleId
        ? await planRuleUpdate(snapshot.profile.id, editingRuleId, draft)
        : await planRuleChange(snapshot.profile.id, draft));
    } catch (cause) {
      setError(String(cause));
    } finally {
      setBusy(false);
    }
  }

  async function applyPlan() {
    if (!plan || !snapshot) return;
    setBusy(true);
    setError(undefined);
    try {
      const nextReport = await applyRuleChange(
        plan.id,
        plan.conflicts.some((conflict) => conflict.requiresOverride),
      );
      setReport(nextReport);
      if (nextReport.success) {
        await refreshRouterData(snapshot.profile.id);
        setShowRuleForm(false);
        setPlan(undefined);
        setDraft(initialDraft);
        setEditingRuleId(undefined);
        setModalMode("create");
      }
    } catch (cause) {
      setError(String(cause));
    } finally {
      setBusy(false);
    }
  }

  async function prepareDelete(rule: RuleSpec) {
    if (!snapshot) return;
    setBusy(true);
    setError(undefined);
    setReport(undefined);
    try {
      setPlan(await planRuleRemoval(snapshot.profile.id, rule));
      setModalMode("delete");
      setEditingRuleId(undefined);
      setShowRuleForm(true);
    } catch (cause) {
      setError(String(cause));
    } finally {
      setBusy(false);
    }
  }

  function openCreate() {
    setDraft(initialDraft);
    setPlan(undefined);
    setReport(undefined);
    setEditingRuleId(undefined);
    setModalMode("create");
    setShowRuleForm(true);
  }

  function prepareCopy(rule: CustomRuleRecord) {
    if (!rule.copyDraft) return;
    setDraft({ ...rule.copyDraft, note: rule.copyDraft.note ?? "" });
    setPlan(undefined);
    setReport(undefined);
    setEditingRuleId(undefined);
    setModalMode("copy");
    setShowRuleForm(true);
  }

  function prepareEdit(rule: CustomRuleRecord) {
    if (!rule.assistantRule) return;
    setDraft({
      domain: rule.assistantRule.normalizedDomain,
      scope: rule.assistantRule.scope,
      action: rule.assistantRule.action,
      note: rule.assistantRule.note ?? "",
    });
    setPlan(undefined);
    setReport(undefined);
    setEditingRuleId(rule.assistantRule.id);
    setModalMode("edit");
    setShowRuleForm(true);
  }

  if (screen === "connect") {
    return (
      <main className="connect-shell">
        <header className="topbar">
          <div className="brand-mark">路</div>
          <div>
            <strong>{t("appName")}</strong>
            <span>{t("appTagline")}</span>
          </div>
          <button className="locale-button" onClick={() => setLocale(locale === "zh-CN" ? "en" : "zh-CN")}>
            {locale === "zh-CN" ? "EN" : "中文"}
          </button>
        </header>

        <section className="connect-card">
          <div className="eyebrow">ROUTE ASSISTANT · 0.2</div>
          <h1>{t("connectTitle")}</h1>
          <p className="lead">只需提供 SSH 登录信息，软件会在不暴露控制端口的情况下识别代理插件。</p>

          {profiles.length > 0 && (
            <label>
              已保存的软路由
              <select
                value=""
                onChange={(event) => {
                  const profile = profiles.find((item) => item.id === event.target.value);
                  if (profile) {
                    setConnection({
                      ...connection,
                      id: profile.id,
                      name: profile.name,
                      host: profile.host,
                      port: profile.port,
                      username: profile.username,
                      authKind: profile.authKind,
                    });
                  }
                }}
              >
                <option value="">选择已保存的软路由…</option>
                {profiles.map((profile) => (
                  <option key={profile.id} value={profile.id}>
                    {profile.name} · {profile.host}
                  </option>
                ))}
              </select>
            </label>
          )}

          <div className="form-grid">
            <label>
              {t("routerName")}
              <input value={connection.name} onChange={(e) => setConnection({ ...connection, name: e.target.value })} />
            </label>
            <label className="wide">
              {t("host")}
              <input value={connection.host} onChange={(e) => setConnection({ ...connection, host: e.target.value })} />
            </label>
            <label>
              {t("port")}
              <input
                type="number"
                min={1}
                max={65535}
                value={connection.port}
                onChange={(e) => setConnection({ ...connection, port: Number(e.target.value) })}
              />
            </label>
            <label>
              {t("username")}
              <input value={connection.username} onChange={(e) => setConnection({ ...connection, username: e.target.value })} />
            </label>
            <label className="wide segmented-label">
              登录方式
              <span className="segmented">
                <button
                  className={connection.authKind === "password" ? "active" : ""}
                  onClick={() => setConnection({ ...connection, authKind: "password" })}
                  type="button"
                >
                  密码
                </button>
                <button
                  className={connection.authKind === "privateKey" ? "active" : ""}
                  onClick={() => setConnection({ ...connection, authKind: "privateKey" })}
                  type="button"
                >
                  SSH 私钥
                </button>
              </span>
            </label>
            {connection.authKind === "password" ? (
              <label className="wide">
                {t("password")}
                <input
                  type="password"
                  autoComplete="current-password"
                  value={connection.password ?? ""}
                  onChange={(e) => setConnection({ ...connection, password: e.target.value })}
                />
              </label>
            ) : (
              <label className="wide">
                {t("privateKey")}
                <input
                  placeholder="C:\\Users\\you\\.ssh\\id_ed25519"
                  value={connection.privateKeyPath ?? ""}
                  onChange={(e) => setConnection({ ...connection, privateKeyPath: e.target.value })}
                />
              </label>
            )}
          </div>

          {error && <div className="alert error">{error}</div>}
          {snapshot?.needsHostKeyTrust && (
            <div className="host-key-box">
              <strong>{t("hostKeyTitle")}</strong>
              <p>{t("hostKeyMessage")}</p>
              <code>{snapshot.hostKeyFingerprint}</code>
              <button className="primary" disabled={busy} onClick={() => connect(true)}>
                {t("trustAndContinue")}
              </button>
            </div>
          )}

          {!snapshot?.needsHostKeyTrust && (
            <button className="primary large" disabled={busy || !connection.host || !connection.username} onClick={() => connect()}>
              {busy ? t("connecting") : t("connect")}
            </button>
          )}
          <footer className="privacy-note">✓ {t("noTelemetry")}</footer>
        </section>
      </main>
    );
  }

  const selectedPlugin = snapshot?.plugins.find((plugin) => plugin.kind === snapshot.selectedPlugin);
  const runningPlugins = snapshot?.plugins.filter((plugin) => plugin.serviceState === "running" && plugin.kind !== "unsupported") ?? [];

  async function choosePlugin(kind: "openClash" | "nikki") {
    if (!snapshot) return;
    setBusy(true);
    setError(undefined);
    try {
      await selectPlugin(snapshot.profile.id, kind);
      setSnapshot({ ...snapshot, selectedPlugin: kind });
      await refreshRouterData(snapshot.profile.id);
    } catch (cause) {
      setError(String(cause));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-mark">路</div>
          <div><strong>{t("appName")}</strong><span>v0.2.0</span></div>
        </div>
        <nav>
          {(["overview", "rules", "diagnostics", "history"] as Tab[]).map((item) => (
            <button key={item} className={tab === item ? "active" : ""} onClick={() => setTab(item)}>
              <span className="nav-dot" />{t(item)}
            </button>
          ))}
        </nav>
        <div className="router-chip">
          <span className={`status-dot ${selectedPlugin?.serviceState}`} />
          <div><strong>{snapshot?.profile.name}</strong><span>{snapshot?.profile.host}</span></div>
          <button onClick={() => { setScreen("connect"); setSnapshot(undefined); }}>切换</button>
        </div>
      </aside>

      <main className="workspace">
        <header className="workspace-header">
          <div>
            <div className="eyebrow">{snapshot?.distribution} {snapshot?.release}</div>
            <h1>{t(tab)}</h1>
          </div>
          <div className="header-actions">
            {selectedPlugin?.readOnly && <span className="pill warning">{t("readOnly")}</span>}
            <button className="ghost" onClick={() => setLocale(locale === "zh-CN" ? "en" : "zh-CN")}>{locale === "zh-CN" ? "EN" : "中文"}</button>
          </div>
        </header>

        {error && <div className="alert error">{error}</div>}

        {!snapshot?.selectedPlugin && runningPlugins.length > 1 && (
          <div className="plugin-choice alert">
            <strong>检测到多个代理插件同时运行</strong>
            <span>一次只会修改一个插件，请选择本次要管理的对象。</span>
            <div>
              {runningPlugins.map((plugin) => (
                <button
                  key={plugin.kind}
                  className="secondary"
                  disabled={busy || plugin.kind === "unsupported"}
                  onClick={() => choosePlugin(plugin.kind as "openClash" | "nikki")}
                >
                  {plugin.displayName}
                </button>
              ))}
            </div>
          </div>
        )}

        {tab === "overview" && (
          <section className="dashboard-grid">
            <article className="status-card hero-card">
              <div>
                <span className="card-label">当前代理工具</span>
                <h2>{selectedPlugin?.displayName ?? "未识别"}</h2>
                <p>{selectedPlugin?.coreVersion ?? selectedPlugin?.reason ?? t("pluginUnsupported")}</p>
              </div>
              <span className={`service-badge ${selectedPlugin?.serviceState}`}>
                {selectedPlugin?.serviceState === "running" ? "运行正常" : "需要检查"}
              </span>
            </article>
            <article className="metric-card"><span>插件版本</span><strong>{selectedPlugin?.version ?? "未知"}</strong></article>
            <article className="metric-card"><span>{t("customRuleTotal")}</span><strong>{customRules?.rules.length ?? 0}</strong><small>{t("assistantRules")} {customRules?.rules.filter((rule) => rule.owner === "assistant").length ?? 0} · {t("existingRules")} {customRules?.rules.filter((rule) => rule.owner === "existing").length ?? 0}</small></article>
            <article className="metric-card"><span>安全能力</span><strong>{selectedPlugin?.capabilities.includes("rollback") ? "自动回滚" : "只读"}</strong><small>变更看门狗 120 秒</small></article>
            <article className="status-card full-card">
              <div className="section-heading"><div><span className="card-label">连接检查</span><h3>安全边界</h3></div></div>
              <ul className="check-list">
                <li><span>✓</span> SSH 主机指纹已记录</li>
                <li><span>✓</span> Mihomo 控制接口不暴露到局域网</li>
                <li><span>✓</span> 只修改带助手标记的规则</li>
                <li><span>✓</span> DNS、DHCP 和防火墙保持只读</li>
              </ul>
            </article>
          </section>
        )}

        {tab === "rules" && (
          <section>
            <div className="section-heading">
              <div><p>{t("managedOnly")}</p></div>
              <button className="primary" disabled={selectedPlugin?.readOnly} onClick={openCreate}>
                + {t("addRule")}
              </button>
            </div>
            <div className="rule-summary">
              <article><span>{t("customRuleTotal")}</span><strong>{customRules?.rules.length ?? 0}</strong></article>
              <article><span>{t("assistantRules")}</span><strong>{customRules?.rules.filter((rule) => rule.owner === "assistant").length ?? 0}</strong></article>
              <article><span>{t("existingRules")}</span><strong>{customRules?.rules.filter((rule) => rule.owner === "existing").length ?? 0}</strong></article>
            </div>
            {customRules?.notices.map((notice) => (
              <div key={notice.code} className={`alert ${notice.level === "error" ? "error" : "info"}`}>{notice.message}</div>
            ))}
            <div className="rule-toolbar">
              <div className="segmented rule-filters">
                {(["all", "assistant", "existing"] as const).map((owner) => (
                  <button key={owner} type="button" className={ruleOwnerFilter === owner ? "active" : ""} onClick={() => setRuleOwnerFilter(owner)}>
                    {owner === "all" ? t("allRules") : owner === "assistant" ? t("assistantRules") : t("existingRules")}
                  </button>
                ))}
              </div>
              <label className="rule-search">
                <span>{t("searchRules")}</span>
                <input value={ruleSearch} placeholder={t("searchPlaceholder")} onChange={(event) => setRuleSearch(event.target.value)} />
              </label>
            </div>
            {visibleRules.length === 0 ? (
              <div className="empty-state"><div className="empty-icon">↗</div><h3>{customRules?.rules.length ? t("emptySearch") : t("noRules")}</h3><p>{customRules?.rules.length ? "" : t("emptySearch")} {t("addFirstRule")}</p></div>
            ) : (
              <div className="rule-list">
                {visibleRules.map((rule) => (
                  <article key={rule.id} className="rule-row">
                    <div className="rule-type">{rule.ruleType}</div>
                    <div className="rule-main"><strong>{rule.matcher || rule.rawPreview}</strong><span>{rule.note || rule.rawPreview}</span>{rule.warning && <small>{rule.warning}</small>}<code>{t("source")}：{rule.sourceLocation}</code></div>
                    <div className="route-arrow">→</div>
                    <div className="rule-badges"><span className={`pill ${rule.enabled ? "direct" : "warning"}`}>{rule.enabled ? t("enabled") : t("disabled")}</span><span className="pill">{rule.owner === "assistant" ? t("assistantRules") : t("existingReadOnly")}</span><span className="pill policyGroup">{rule.target ?? "—"}</span></div>
                    <div className="rule-actions">
                      {rule.owner === "assistant" && rule.assistantRule ? <>
                        <button className="secondary compact" disabled={busy} onClick={() => prepareEdit(rule)}>{t("editRule")}</button>
                        <button className="delete-rule" disabled={busy} onClick={() => prepareDelete(rule.assistantRule!)}>{t("deleteRule")}</button>
                      </> : <button className="secondary compact" disabled={busy || rule.owner !== "existing" || !rule.copyDraft} title={rule.owner === "existing" && rule.copyDraft ? t("copyAsAssistant") : t("copyUnsupported")} onClick={() => prepareCopy(rule)}>{t("copyAsAssistant")}</button>}
                    </div>
                  </article>
                ))}
              </div>
            )}
          </section>
        )}

        {tab === "diagnostics" && (
          <section className="diagnostics-card">
            <div className="dns-banner"><div>DNS</div><p><strong>只读诊断</strong><span>{t("dnsReadOnly")}</span></p></div>
            <div className="diagnostic-steps">
              <div><span>1</span><p><strong>识别入口</strong><small>读取 dnsmasq 与插件监听信息</small></p></div>
              <div><span>2</span><p><strong>解析测试</strong><small>显示返回地址和耗时，不判断地理位置</small></p></div>
              <div><span>3</span><p><strong>分开结论</strong><small>代理直连与 DNS/CDN 分别报告</small></p></div>
            </div>
            <button className="secondary" onClick={async () => snapshot && alert(await exportDiagnostics(snapshot.profile.id))}>{t("exportDiagnostics")}</button>
          </section>
        )}

        {tab === "history" && (
          <section className="history-list">
            {history.length === 0 ? <div className="empty-state"><h3>还没有操作记录</h3><p>每次变更只保存脱敏摘要、备份编号和验证结果。</p></div> : history.map((item) => (
              <article key={item.id}><span className={`status-dot ${item.success ? "running" : "stopped"}`} /><div><strong>{item.summary}</strong><small>{new Date(item.createdAt).toLocaleString()}</small></div><code>{item.backupId ?? "无备份"}</code></article>
            ))}
          </section>
        )}
      </main>

      {showRuleForm && (
        <div className="modal-backdrop" onMouseDown={(event) => event.currentTarget === event.target && setShowRuleForm(false)}>
          <section className="modal">
            <header><div><span className="eyebrow">安全变更</span><h2>{modalMode === "delete" ? "删除助手规则" : modalMode === "edit" ? t("editRuleTitle") : modalMode === "copy" ? t("copyRuleTitle") : t("addRule")}</h2></div><button className="close" onClick={() => setShowRuleForm(false)}>×</button></header>
            {modalMode !== "delete" && <>
              <label>{t("domain")}<input autoFocus placeholder="例如：www.baidu.com" value={draft.domain} onChange={(e) => { setDraft({ ...draft, domain: e.target.value }); setPlan(undefined); }} /></label>
              <label>{t("scope")}<select value={draft.scope} onChange={(e) => { setDraft({ ...draft, scope: e.target.value as RuleDraft["scope"] }); setPlan(undefined); }}><option value="exact">{t("exactDomain")}</option><option value="suffix">{t("suffixDomain")}</option></select></label>
              <label>{t("destination")}<select value={draft.action.type === "policyGroup" ? `group:${draft.action.name}` : draft.action.type} onChange={(e) => { const value = e.target.value; setDraft({ ...draft, action: value === "direct" ? { type: "direct" } : value === "reject" ? { type: "reject" } : { type: "policyGroup", name: value.slice(6) } }); setPlan(undefined); }}><option value="direct">{t("direct")}</option><option value="reject">{t("reject")}</option>{targets.filter((item) => item.kind === "group").map((target) => <option key={target.name} value={`group:${target.name}`}>{target.name}</option>)}</select></label>
              <label>{t("note")}<input value={draft.note} onChange={(e) => setDraft({ ...draft, note: e.target.value })} /></label>
            </>}
            {plan && <div className="preview-box"><span>{t("preview")}</span><p>{plan.preview}</p>{plan.conflicts.map((conflict) => <div key={conflict.message} className="conflict">⚠ {conflict.message}</div>)}<small>应用前创建备份；验证失败或连接中断时自动回滚。</small></div>}
            {report && <div className={`alert ${report.success ? "success" : "error"}`}>{report.messages.join(" ")}</div>}
            <footer><button className="ghost" onClick={() => setShowRuleForm(false)}>{t("cancel")}</button>{!plan ? <button className="primary" disabled={busy || !draft.domain.trim()} onClick={createPlan}>{busy ? "处理中…" : t("preparePreview")}</button> : <button className={plan.operation === "delete" ? "danger" : "primary"} disabled={busy || !plan.canApply} onClick={applyPlan}>{busy ? "正在安全应用…" : plan.operation === "delete" ? "确认删除" : plan.conflicts.some((item) => item.requiresOverride) ? t("overrideApply") : t("confirmApply")}</button>}</footer>
          </section>
        </div>
      )}
    </div>
  );
}

export default App;
