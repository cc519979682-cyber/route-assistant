import type { CustomRuleOwner, CustomRuleRecord } from "./types";

export function filterCustomRules(
  rules: CustomRuleRecord[],
  owner: "all" | CustomRuleOwner,
  search: string,
) {
  const query = search.trim().toLocaleLowerCase();
  return rules.filter((rule) => {
    if (owner !== "all" && rule.owner !== owner) return false;
    if (!query) return true;
    return [rule.matcher, rule.target, rule.ruleType, rule.note, rule.rawPreview, rule.sourceLocation]
      .filter(Boolean)
      .some((value) => value!.toLocaleLowerCase().includes(query));
  });
}

export function canMutateCustomRule(rule: CustomRuleRecord) {
  return rule.owner === "assistant" && Boolean(rule.assistantRule);
}

export function canCopyCustomRule(rule: CustomRuleRecord) {
  return rule.owner === "existing" && Boolean(rule.copyDraft);
}
