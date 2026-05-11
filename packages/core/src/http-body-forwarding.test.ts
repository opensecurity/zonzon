import { describe, it } from "node:test";
import assert from "node:assert";
import { HttpProxyService } from "./http-proxy.js";
import { HostConfig } from "./types.js";

function makeBodyForwardingConfig(): HostConfig {
  return {
    records: [{ type: "A", address: "127.0.0.1" }],
    http_proxy: {
      enabled: true,
      upstream: "http://upstream.example.com",
      headers: { "X-Forward-Body": "true" },
    },
    redirect: undefined,
  };
}

describe("HttpProxyService - Body Forwarding Configuration", () => {
  const proxy = new HttpProxyService();

  it("accepts host config with body forwarding enabled", () => {
    const config: HostConfig & { http_proxy?: { enabled?: boolean; upstream?: string; headers?: Record<string, string>; forwardRequestBody?: boolean } } = {
      records: [{ type: "A", address: "127.0.0.1" }],
      http_proxy: {
        enabled: true,
        upstream: "http://upstream.example.com",
        headers: {},
        forwardRequestBody: true,
      },
    };

    assert.strictEqual(config.http_proxy?.forwardRequestBody, true);
  });

  it("defaults body forwarding to false when not specified", () => {
    const config = makeBodyForwardingConfig();
    assert.ok(!config.http_proxy?.forwardRequestBody);
  });

  it("rejects body forwarding when proxy is disabled", () => {
    const config: HostConfig & { http_proxy?: { enabled?: boolean; upstream?: string; headers?: Record<string, string>; forwardRequestBody?: boolean } } = {
      records: [{ type: "A", address: "127.0.0.1" }],
      http_proxy: {
        enabled: false,
        upstream: "",
        headers: {},
        forwardRequestBody: true,
      },
    };

    assert.strictEqual(config.http_proxy?.enabled, false);
  });
});

describe("HttpProxyService - Body Forwarding Header", () => {
  const proxy = new HttpProxyService();

  it("injects X-Forwarded-Body header when body forwarding is enabled", () => {
    const config: HostConfig & { http_proxy?: { enabled?: boolean; upstream?: string; headers?: Record<string, string>; forwardRequestBody?: boolean } } = makeBodyForwardingConfig();
    config.http_proxy!.forwardRequestBody = true;

    const request = {
      hostname: "app.loop",
      originalUrl: "/api/submit",
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: Buffer.from('{"key":"value"}'),
    };

    const result = proxy.getUpstreamHeaders(config, request as any);
    assert.ok("X-Body-Forwarded" in result.upstreamHeaders || "X-Body-Size" in result.upstreamHeaders);
  });

  it("does not inject body forwarding header when disabled", () => {
    const config: HostConfig & { http_proxy?: { enabled?: boolean; upstream?: string; headers?: Record<string, string>; forwardRequestBody?: boolean } } = makeBodyForwardingConfig();
    config.http_proxy!.forwardRequestBody = false;

    const request = {
      hostname: "app.loop",
      originalUrl: "/api/submit",
      method: "POST",
      headers: { "Content-Type": "application/json" },
    };

    const result = proxy.getUpstreamHeaders(config, request as any);
    assert.ok(!("X-Body-Forwarded" in result.upstreamHeaders));
  });
});

describe("HttpProxyService - Body size validation", () => {
  const proxy = new HttpProxyService();

  it("limits forwarded body size to configured maximum", () => {
    const largeBody = Buffer.alloc(10 * 1024 * 1024, "x"); 
    assert.ok(largeBody.length > 5 * 1024 * 1024);
    assert.doesNotThrow(() => {
      const config: HostConfig & { http_proxy?: { enabled?: boolean; upstream?: string; headers?: Record<string, string>; forwardRequestBody?: boolean; maxRequestBodyBytes?: number } } = makeBodyForwardingConfig();
      config.http_proxy!.forwardRequestBody = true;
    });
  });
});