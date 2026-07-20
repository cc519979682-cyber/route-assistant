import { describe, expect, it } from "vitest";
import { createTranslator } from "./i18n";

describe("translations", () => {
  it("uses Simplified Chinese as the complete default interface", () => {
    const t = createTranslator("zh-CN");
    expect(t("appName")).toBe("软路由分流助手");
    expect(t("direct")).toContain("不经过代理");
    expect(t("dnsReadOnly")).toContain("不会修改");
    expect(t("rules")).toBe("自定义规则");
    expect(t("managedOnly")).toContain("订阅规则不会读取或展开");
    expect(t("currentManagedObject")).toBe("当前管理对象");
    expect(t("notSupportedYet")).toBe("暂不支持");
    expect(t("writeBlockedTitle")).toContain("只读");
    expect(t("dnsProtection")).toBe("DNS 防污染");
    expect(t("dnsBoundary")).toContain("防火墙");
  });

  it("provides an English public-release translation", () => {
    const t = createTranslator("en");
    expect(t("appName")).toBe("Route Assistant");
    expect(t("readOnly")).toBe("Read-only");
    expect(t("rules")).toBe("Custom rules");
    expect(t("existingReadOnly")).toContain("read-only");
    expect(t("switchPlugin")).toBe("Switch plugin");
    expect(t("detectedOnlyNote")).toContain("no adapter");
    expect(t("dnsProtection")).toBe("DNS protection");
    expect(t("dnsBoundary")).toContain("firewall");
  });
});
