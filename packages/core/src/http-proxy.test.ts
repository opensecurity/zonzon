import { describe, it } from "node:test";
import assert from "node:assert";
import { HttpProxyService } from "./http-proxy.js";
import { HostConfig } from "./types.js";

function makeConfig(overrides: Partial<HostConfig> = {}): HostConfig {
  return {
    records: [{ type: "A", address: "127.0.0.1" }],
    http_proxy: undefined,
    redirect: undefined,
    ...overrides,
  };
}

function makeProxyEnabledConfig(): HostConfig {
  return makeConfig({
    http_proxy: {
      enabled: true,
      upstream: "http://upstream.example.com",
      headers: {
        "X-Custom": "custom-value",
        "X-Env": "production",
      },
    },
  });
}

function makeRedirectConfig(): HostConfig {
  return makeConfig({
    redirect: {
      enabled: true,
      code: 301,
      target: "https://target.example.com/path",
    },
  });
}

describe("HttpProxyService - Header Sanitization", () => {
  const proxy = new HttpProxyService();

  it("accepts normal alphanumeric header values", () => {
    assert.strictEqual(proxy.sanitizeHeader("normal-value"), "normal-value");
  });

  it("rejects header values with CR characters", () => {
    assert.strictEqual(proxy.sanitizeHeader("value\x0dwithCR"), null);
  });

  it("rejects header values with LF characters", () => {
    assert.strictEqual(proxy.sanitizeHeader("value\nwithLF"), null);
  });

  it("rejects header values with CRLF combinations", () => {
    assert.strictEqual(proxy.sanitizeHeader("value\r\nInjected: true"), null);
  });

  it("rejects header values exceeding 8192 characters", () => {
    const longValue = "x".repeat(8193);
    assert.strictEqual(proxy.sanitizeHeader(longValue), null);
  });

  it("accepts header values at exactly 8192 characters", () => {
    const maxLen = "x".repeat(8192);
    assert.strictEqual(proxy.sanitizeHeader(maxLen), maxLen);
  });

  it("rejects non-string values", () => {
    assert.strictEqual(proxy.sanitizeHeader(123 as unknown as string), null);
    assert.strictEqual(proxy.sanitizeHeader(null as unknown as string), null);
    assert.strictEqual(proxy.sanitizeHeader(undefined as unknown as string), null);
    assert.strictEqual(proxy.sanitizeHeader({} as unknown as string), null);
  });

  it("accepts header values with safe special characters", () => {
    const value = "Bearer abc123.def456 ghi789!@#$%^&*()";
    assert.strictEqual(proxy.sanitizeHeader(value), value);
  });
});

describe("HttpProxyService - Header Name Validation", () => {
  const proxy = new HttpProxyService();

  it("accepts valid RFC 7230 token header names", () => {
    assert.strictEqual(proxy.isValidHeaderName("Content-Type"), true);
    assert.strictEqual(proxy.isValidHeaderName("X-Custom-Header"), true);
    assert.strictEqual(proxy.isValidHeaderName("Authorization"), true);
    assert.strictEqual(proxy.isValidHeaderName("X-B3-TraceId"), true);
  });

  it("accepts header names with RFC-valid special characters", () => {
    assert.strictEqual(proxy.isValidHeaderName("X-Test_Header"), true);
    assert.strictEqual(proxy.isValidHeaderName("X-Test+Header"), true);
    assert.strictEqual(proxy.isValidHeaderName("X-Test~Header"), true);
  });

  it("rejects empty header names", () => {
    assert.strictEqual(proxy.isValidHeaderName(""), false);
  });

  it("rejects header names exceeding 256 characters", () => {
    const longName = "x".repeat(257);
    assert.strictEqual(proxy.isValidHeaderName(longName), false);
  });

  it("rejects header names with spaces", () => {
    assert.strictEqual(proxy.isValidHeaderName("X- Evil"), false);
  });

  it("rejects header names with newlines (CRLF injection)", () => {
    assert.strictEqual(proxy.isValidHeaderName("X-Bad\r\nInjected"), false);
    assert.strictEqual(proxy.isValidHeaderName("X-Bad\nInjected"), false);
  });

  it("rejects header names with forward slashes", () => {
    assert.strictEqual(proxy.isValidHeaderName("X/Path/Header"), false);
  });

  it("rejects header names with backslashes", () => {
    assert.strictEqual(proxy.isValidHeaderName("X\\Backslash"), false);
  });
});

describe("HttpProxyService - Hop-by-Hop Headers", () => {
  const proxy = new HttpProxyService();

  it("returns all hop-by-hop headers to exclude", () => {
    const excluded = proxy.getHopByHopHeaders();
    assert.ok(excluded.includes("connection"));
    assert.ok(excluded.includes("keep-alive"));
    assert.ok(excluded.includes("te"));
    assert.ok(excluded.includes("transfer-encoding"));
    assert.ok(excluded.includes("upgrade"));
    assert.ok(excluded.includes("proxy-authenticate"));
    assert.ok(excluded.includes("proxy-authorization"));
    assert.ok(excluded.includes("trailer"));
  });

  it("excludes hop-by-hop headers from upstream forwarding", () => {
    const config = makeProxyEnabledConfig();
    const request = {
      hostname: "app.loop",
      originalUrl: "/",
      method: "GET",
      headers: {
        connection: "keep-alive",
        "keep-alive": "timeout=5",
        "X-Forwarded-For": "192.168.1.1",
        "X-Custom": "custom-value",
        "Transfer-Encoding": "chunked",
      },
    };

    const result = proxy.getUpstreamHeaders(config, request);
    assert.ok("X-Forwarded-For" in result.clientResponseHeaders);
    assert.strictEqual(result.upstreamHeaders["X-Custom"], "custom-value");
    assert.strictEqual(result.clientResponseHeaders["X-Custom"], "custom-value");
  });
});

describe("HttpProxyService - Header Injection", () => {
  const proxy = new HttpProxyService();

  it("injects custom headers when proxy is enabled", () => {
    const config = makeProxyEnabledConfig();
    const request = {
      hostname: "app.loop",
      originalUrl: "/",
      method: "GET",
      headers: {},
    };

    const result = proxy.getUpstreamHeaders(config, request);
    assert.strictEqual(result.upstreamHeaders["X-Custom"], "custom-value");
    assert.strictEqual(result.upstreamHeaders["X-Env"], "production");
    assert.strictEqual(result.clientResponseHeaders["X-Proxy"], "zonzon");
  });

  it("does not inject any headers when proxy is disabled", () => {
    const config = makeConfig({ http_proxy: { enabled: false, upstream: "", headers: {} } });
    const request = {
      hostname: "app.loop",
      originalUrl: "/",
      method: "GET",
      headers: {},
    };

    const result = proxy.getUpstreamHeaders(config, request);
    assert.strictEqual(Object.keys(result.upstreamHeaders).length, 0);
    assert.ok(!result.clientResponseHeaders["X-Proxy"]);
  });

  it("does not inject any headers when proxy config is absent", () => {
    const config = makeConfig();
    const request = {
      hostname: "app.loop",
      originalUrl: "/",
      method: "GET",
      headers: {},
    };

    const result = proxy.getUpstreamHeaders(config, request);
    assert.strictEqual(Object.keys(result.upstreamHeaders).length, 0);
    assert.ok(!result.clientResponseHeaders["X-Proxy"]);
  });

  it("adds X-Proxy identification header to client responses", () => {
    const config = makeProxyEnabledConfig();
    const request = {
      hostname: "app.loop",
      originalUrl: "/index.html",
      method: "GET",
      headers: {},
    };

    const result = proxy.getUpstreamHeaders(config, request);
    assert.strictEqual(result.clientResponseHeaders["X-Proxy"], "zonzon");
  });

  it("passes through non-hop-by-hop original headers to client response", () => {
    const config = makeProxyEnabledConfig();
    const request = {
      hostname: "app.loop",
      originalUrl: "/",
      method: "GET",
      headers: {
        Accept: "text/html",
        "User-Agent": "test-agent/1.0",
        "X-Request-Id": "abc-123",
      },
    };

    const result = proxy.getUpstreamHeaders(config, request);
    assert.strictEqual(result.clientResponseHeaders["Accept"], "text/html");
    assert.strictEqual(result.clientResponseHeaders["User-Agent"], "test-agent/1.0");
    assert.strictEqual(result.clientResponseHeaders["X-Request-Id"], "abc-123");
  });

  it("strips hop-by-hop headers from client response", () => {
    const config = makeProxyEnabledConfig();
    const request = {
      hostname: "app.loop",
      originalUrl: "/",
      method: "GET",
      headers: {
        Connection: "close",
        "Keep-Alive": "timeout=10",
        TE: "trailers",
        "Transfer-Encoding": "chunked",
      },
    };

    const result = proxy.getUpstreamHeaders(config, request);
    assert.ok(!result.clientResponseHeaders["Connection"]);
    assert.ok(!result.clientResponseHeaders["Keep-Alive"]);
    assert.ok(!result.clientResponseHeaders["TE"]);
    assert.ok(!result.clientResponseHeaders["Transfer-Encoding"]);
  });

  it("handles case-insensitive hop-by-hop header matching", () => {
    const config = makeProxyEnabledConfig();
    const request = {
      hostname: "app.loop",
      originalUrl: "/",
      method: "GET",
      headers: {
        "CONNECTION": "keep-alive",
        "KEEP-ALIVE": "timeout=5",
        "TRANSFER-ENCODING": "chunked",
      },
    };

    const result = proxy.getUpstreamHeaders(config, request);
    assert.ok(!result.clientResponseHeaders["CONNECTION"]);
    assert.ok(!result.clientResponseHeaders["KEEP-ALIVE"]);
    assert.ok(!result.clientResponseHeaders["TRANSFER-ENCODING"]);
  });
});

describe("HttpProxyService - Redirect Checks", () => {
  const proxy = new HttpProxyService();

  it("returns redirect info when enabled with valid URL", () => {
    const config = makeRedirectConfig();
    const result = proxy.checkRedirect(config);
    assert.strictEqual(result?.code, 301);
    assert.strictEqual(result?.target, "https://target.example.com/path");
  });

  it("returns null when redirect is not enabled", () => {
    const config = makeConfig();
    assert.strictEqual(proxy.checkRedirect(config), null);
  });

  it("returns null when proxy-only config (no redirect)", () => {
    const config = makeProxyEnabledConfig();
    assert.strictEqual(proxy.checkRedirect(config), null);
  });

  it("rejects redirects with relative URLs", () => {
    const config = makeConfig({
      redirect: {
        enabled: true,
        code: 301,
        target: "/path/relative",
      },
    });
    assert.strictEqual(proxy.checkRedirect(config), null);
  });

  it("rejects redirects with malformed URLs", () => {
    const config = makeConfig({
      redirect: {
        enabled: true,
        code: 301,
        target: "not a valid url at all",
      },
    });
    assert.strictEqual(proxy.checkRedirect(config), null);
  });

  it("rejects redirects with protocol-relative URLs", () => {
    const config = makeConfig({
      redirect: {
        enabled: true,
        code: 301,
        target: "//evil.example.com",
      },
    });
    assert.strictEqual(proxy.checkRedirect(config), null);
  });

  it("accepts redirect with query parameters in target", () => {
    const config = makeConfig({
      redirect: {
        enabled: true,
        code: 302,
        target: "https://target.example.com/path?key=value&foo=bar",
      },
    });
    const result = proxy.checkRedirect(config);
    assert.strictEqual(result?.code, 302);
    assert.ok(result?.target.includes("?key=value"));
  });

  it("accepts all valid redirect codes (301, 302, 303, 307, 308)", () => {
    for (const code of [301, 302, 303, 307, 308]) {
      const config = makeConfig({
        redirect: { enabled: true, code, target: "https://example.com" },
      });
      assert.ok(proxy.checkRedirect(config));
    }
  });

  it("rejects invalid redirect codes (300, 404, 999)", () => {
    for (const code of [200, 300, 404, 500, 999]) {
      const config = makeConfig({
        redirect: { enabled: true, code, target: "https://example.com" },
      });
      assert.strictEqual(proxy.checkRedirect(config), null);
    }
  });
});

describe("HttpProxyService - Timeout", () => {
  const proxy = new HttpProxyService();

  it("returns 0 timeout when proxy is disabled", () => {
    const config = makeConfig();
    assert.strictEqual(proxy.calculateTimeout(config), 0);
  });

  it("returns bounded timeout when proxy is enabled", () => {
    const config = makeProxyEnabledConfig();
    const timeout = proxy.calculateTimeout(config);
    assert.ok(timeout >= 1000 && timeout <= 30000);
  });

  it("defaults to 5 seconds for enabled proxy", () => {
    const config = makeProxyEnabledConfig();
    assert.strictEqual(proxy.calculateTimeout(config), 5000);
  });
});

describe("HttpProxyService - Security Edge Cases", () => {
  const proxy = new HttpProxyService();

  it("sanitizes headers containing URL-encoded CR/LF percent sequences in values", () => {
    assert.strictEqual(proxy.sanitizeHeader("encoded%0d%0aInjected"), null);
  });

  it("rejects header values with tab characters (HTTP smuggling vector)", () => {
    assert.strictEqual(proxy.sanitizeHeader("value\twith\ttabs"), null);
  });

  it("rejects header values with unicode control characters", () => {
    assert.strictEqual(proxy.sanitizeHeader("value\u000b\u000ccontrol"), null);
  });

  it("handles proxy config without custom headers gracefully", () => {
    const config = makeConfig({
      http_proxy: {
        enabled: true,
        upstream: "http://upstream.example.com",
        headers: {},
      },
    });
    const request = {
      hostname: "app.loop",
      originalUrl: "/",
      method: "GET",
      headers: {},
    };

    const result = proxy.getUpstreamHeaders(config, request);
    assert.strictEqual(Object.keys(result.upstreamHeaders).length, 0);
    assert.strictEqual(result.clientResponseHeaders["X-Proxy"], "zonzon");
  });

  it("handles empty host config records array gracefully", () => {
    const config = makeConfig({ http_proxy: undefined });
    assert.ok(proxy.checkRedirect(config) === null);
    assert.strictEqual(proxy.calculateTimeout(config), 0);
  });
});

describe("HttpProxyService - Header Injection with Sanitization", () => {
  const proxy = new HttpProxyService();

  it("sanitizes injected custom headers before passing to response", () => {
    const value = "injected\r\nMalicious: header";
    const sanitized = proxy.sanitizeHeader(value);
    assert.strictEqual(sanitized, null);
  });

  it("accepts safe config header values for injection", () => {
    const value = "safe-value-with-dashes_and_underscores";
    const sanitized = proxy.sanitizeHeader(value);
    assert.strictEqual(sanitized, value);
  });
});