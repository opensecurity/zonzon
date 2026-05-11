import { describe, it } from "node:test";
import assert from "node:assert";
import { getContext, contextStorage } from "./context.js";

describe("AsyncLocalStorage Context Boundary", () => {
  it("throws error when accessing context outside of storage run", () => {
    assert.throws(
      () => getContext(),
      /Security Exception: Context missing/
    );
  });

  it("successfully retrieves injected context payload", () => {
    const mockContext = {
      tenantId: "test-tenant-001",
      deviceHash: "deadbeef"
    };

    contextStorage.run(mockContext, () => {
      const ctx = getContext();
      assert.strictEqual(ctx.tenantId, "test-tenant-001");
      assert.strictEqual(ctx.deviceHash, "deadbeef");
    });
  });

  it("maintains isolation across asynchronous boundaries", async () => {
    const contextA = { tenantId: "tenant-A", deviceHash: "hash-A" };
    const contextB = { tenantId: "tenant-B", deviceHash: "hash-B" };

    const promiseA = contextStorage.run(contextA, async () => {
      await new Promise(resolve => setTimeout(resolve, 10));
      const ctx = getContext();
      assert.strictEqual(ctx.tenantId, "tenant-A");
    });

    const promiseB = contextStorage.run(contextB, async () => {
      await new Promise(resolve => setTimeout(resolve, 5));
      const ctx = getContext();
      assert.strictEqual(ctx.tenantId, "tenant-B");
    });

    await Promise.all([promiseA, promiseB]);
  });
});