import { describe, expect, it } from "vitest";
import {
  applyDnsProtection,
  inspectDnsProtection,
  planDnsProtection,
  rollbackDnsProtection,
} from "./api";

describe("DNS protection demo flow", () => {
  it("previews, applies, verifies, and restores without a router", async () => {
    const before = await inspectDnsProtection("demo-router");
    expect(before.status).toBe("needsAttention");
    expect(before.canApply).toBe(true);

    const plan = await planDnsProtection("demo-router");
    expect(plan.preview).toContain("OpenClash");
    expect(plan.preview).toContain("不会修改订阅");

    const applied = await applyDnsProtection(plan.id);
    expect(applied.success).toBe(true);
    expect(applied.snapshot.status).toBe("protected");
    expect(applied.snapshot.plaintextUpstreamCount).toBe(0);

    const restored = await rollbackDnsProtection("demo-router", applied.backupId!);
    expect(restored.rolledBack).toBe(true);
    expect(restored.snapshot.status).toBe("needsAttention");
  });
});
