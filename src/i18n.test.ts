import { describe, expect, it } from "vitest";
import { createTranslator } from "./i18n";

describe("translations", () => {
  it("uses Simplified Chinese as the complete default interface", () => {
    const t = createTranslator("zh-CN");
    expect(t("appName")).toBe("软路由分流助手");
    expect(t("direct")).toContain("不经过代理");
    expect(t("dnsReadOnly")).toContain("不会修改");
  });

  it("provides an English public-release translation", () => {
    const t = createTranslator("en");
    expect(t("appName")).toBe("Route Assistant");
    expect(t("readOnly")).toBe("Read-only");
  });
});

