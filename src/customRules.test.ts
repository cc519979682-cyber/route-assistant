import { describe, expect, it } from "vitest";
import { canCopyCustomRule, canMutateCustomRule, filterCustomRules } from "./customRules";
import type { CustomRuleRecord, RuleSpec } from "./types";

const assistantRule: RuleSpec = {
  id: "assistant-id",
  scope: "exact",
  domain: "www.baidu.com",
  normalizedDomain: "www.baidu.com",
  action: { type: "direct" },
  enabled: true,
  managed: true,
};

const records: CustomRuleRecord[] = [
  {
    id: "assistant-record",
    sourceLocation: "/custom:3",
    position: 3,
    owner: "assistant",
    enabled: true,
    ruleType: "DOMAIN",
    matcher: "www.baidu.com",
    target: "DIRECT",
    rawPreview: "- DOMAIN,www.baidu.com,DIRECT",
    parseState: "structured",
    assistantRule,
  },
  {
    id: "existing-record",
    sourceLocation: "/custom:9",
    position: 9,
    owner: "existing",
    enabled: true,
    ruleType: "DOMAIN-SUFFIX",
    matcher: "example.com",
    target: "REJECT",
    rawPreview: "- DOMAIN-SUFFIX,example.com,REJECT",
    parseState: "structured",
    copyDraft: { scope: "suffix", domain: "example.com", action: { type: "reject" } },
  },
];

describe("custom rule UI safety", () => {
  it("keeps original custom rules read-only while allowing a copy", () => {
    expect(canMutateCustomRule(records[1])).toBe(false);
    expect(canCopyCustomRule(records[1])).toBe(true);
    expect(canMutateCustomRule(records[0])).toBe(true);
  });

  it("filters by owner and searches raw content", () => {
    expect(filterCustomRules(records, "assistant", "")).toEqual([records[0]]);
    expect(filterCustomRules(records, "all", "REJECT")).toEqual([records[1]]);
    expect(filterCustomRules(records, "existing", "baidu")).toEqual([]);
  });
});
