import test from "node:test";
import assert from "node:assert/strict";

import {
  ConfigurationError,
  createSubscriptionService,
  deriveRecordStorageKey,
  resolveRuntimeOptions,
} from "../src/shared/subscription-core.js";

function createMemoryStorage({
  legacy = {},
  records = [],
} = {}) {
  const recordState = new Map(records.map((record) => [record.ruleName, structuredClone(record)]));
  const legacyState = new Map(Object.entries(legacy));

  return {
    legacyState,
    recordState,
    async deleteRecord(ruleName) {
      recordState.delete(ruleName);
    },
    async getLegacySubscription(subtype) {
      return legacyState.get(subtype) ?? null;
    },
    async getRecord(ruleName) {
      return structuredClone(recordState.get(ruleName) ?? null);
    },
    async listRecords() {
      return Array.from(recordState.values()).map((record) => structuredClone(record));
    },
    async putRecord(ruleName, record) {
      recordState.set(ruleName, structuredClone(record));
    },
  };
}

function createService(overrides = {}) {
  return createSubscriptionService({
    defaultSubscriptionFormat: "clash",
    readToken: "read-token",
    sessionSecret: "session-secret",
    storage: createMemoryStorage(),
    writeToken: "write-token",
    ...overrides,
  });
}

function extractSetCookie(response) {
  return response.headers["Set-Cookie"] ?? response.headers["set-cookie"] ?? "";
}

test("stores multi-node records and preserves root compatibility output", async () => {
  const storage = createMemoryStorage();
  const service = createSubscriptionService({
    defaultSubscriptionFormat: "clash",
    readToken: "read-token",
    storage,
    writeToken: "write-token",
  });

  const ssUpdateResponse = await service.handleRequest({
    body: JSON.stringify({
      ipAddr: "[2001:db8::1]:8388",
      method: "chacha20-ietf-poly1305",
      password: "密码123",
      ruleName: "alpha",
    }),
    headers: {
      Authorization: "Bearer write-token",
    },
    method: "POST",
    path: "/webhook",
  });

  assert.equal(ssUpdateResponse.statusCode, 200);
  assert.equal(
    deriveRecordStorageKey("alpha"),
    "record:v2:YWxwaGE",
  );

  const siteUpdateResponse = await service.handleRequest({
    body: JSON.stringify({
      host: "status.example.com",
      port: 443,
      ruleName: "status",
      type: "site",
    }),
    headers: {
      Authorization: "Bearer write-token",
    },
    method: "POST",
    path: "/webhook",
  });

  assert.equal(siteUpdateResponse.statusCode, 200);
  assert.equal(storage.recordState.size, 2);

  const explicitSsResponse = await service.handleRequest({
    headers: {
      Authorization: "Bearer read-token",
    },
    method: "GET",
    path: "/subscription",
    query: {
      subtype: "ss",
    },
  });

  assert.equal(explicitSsResponse.statusCode, 200);
  assert.equal(
    Buffer.from(explicitSsResponse.body, "base64").toString("utf8"),
    "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTrlr4bnoIExMjNAWzIwMDE6ZGI4OjoxXTo4Mzg4#alpha",
  );

  const explicitClashResponse = await service.handleRequest({
    headers: {
      Authorization: "Bearer read-token",
    },
    method: "GET",
    path: "/subscription",
    query: {
      subtype: "clash",
    },
  });

  assert.equal(explicitClashResponse.statusCode, 200);
  assert.equal(
    explicitClashResponse.body,
    'proxies:\n  - name: "alpha"\n    type: ss\n    server: "2001:db8::1"\n    port: 8388\n    cipher: "chacha20-ietf-poly1305"\n    password: "密码123"\n    udp: true\n',
  );

  const rootCompatibilityResponse = await service.handleRequest({
    method: "GET",
    path: "/",
    query: {
      api_key: "read-token",
    },
  });

  assert.equal(rootCompatibilityResponse.statusCode, 200);
  assert.equal(rootCompatibilityResponse.body, explicitClashResponse.body);
});

test("validates ruleName and type semantics", async () => {
  const service = createService();

  const missingRuleNameResponse = await service.handleRequest({
    body: JSON.stringify({
      ip: "1.2.3.4",
      method: "aes-256-gcm",
      password: "secret",
      port: 8388,
    }),
    headers: {
      Authorization: "Bearer write-token",
    },
    method: "POST",
    path: "/webhook",
  });

  assert.equal(missingRuleNameResponse.statusCode, 400);
  assert.match(missingRuleNameResponse.body, /ruleName/);

  const siteWithPasswordResponse = await service.handleRequest({
    body: JSON.stringify({
      host: "example.com",
      method: "aes-256-gcm",
      password: "secret",
      port: 443,
      ruleName: "site-record",
      type: "site",
    }),
    headers: {
      Authorization: "Bearer write-token",
    },
    method: "POST",
    path: "/webhook",
  });

  assert.equal(siteWithPasswordResponse.statusCode, 400);
  assert.match(siteWithPasswordResponse.body, /type=site/);

  const missingPasswordResponse = await service.handleRequest({
    body: JSON.stringify({
      ip: "1.2.3.4",
      method: "aes-256-gcm",
      port: 8388,
      ruleName: "broken-ss",
    }),
    headers: {
      Authorization: "Bearer write-token",
    },
    method: "POST",
    path: "/webhook",
  });

  assert.equal(missingPasswordResponse.statusCode, 400);
  assert.match(missingPasswordResponse.body, /password/);
});

test("uses address precedence without fallback after invalid higher-priority fields", async () => {
  const service = createService();

  const invalidPriorityResponse = await service.handleRequest({
    body: JSON.stringify({
      host: "good.example.com",
      ip: "bad host",
      method: "aes-256-gcm",
      password: "secret",
      port: 8388,
      ruleName: "broken",
    }),
    headers: {
      Authorization: "Bearer write-token",
    },
    method: "POST",
    path: "/webhook",
  });

  assert.equal(invalidPriorityResponse.statusCode, 400);
  assert.match(invalidPriorityResponse.body, /ip must be a valid/);

  const ipAddrResponse = await service.handleRequest({
    body: JSON.stringify({
      ipAddr: "edge.example.com:9443",
      method: "aes-256-gcm",
      password: "secret",
      ruleName: "edge",
    }),
    headers: {
      Authorization: "Bearer write-token",
    },
    method: "POST",
    path: "/webhook",
  });

  assert.equal(ipAddrResponse.statusCode, 200);

  const record = await service.handleRequest({
    headers: {
      Authorization: "Bearer read-token",
    },
    method: "GET",
    path: "/subscription",
  });

  assert.equal(record.statusCode, 200);
  assert.equal(
    Buffer.from(record.body, "base64").toString("utf8"),
    "ss://YWVzLTI1Ni1nY206c2VjcmV0QGVkZ2UuZXhhbXBsZS5jb206OTQ0Mw==#edge",
  );
});

test("falls back to legacy subscription until a v2 ss record exists", async () => {
  const legacyShadowsocksUri =
    "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzQGVkZ2UuZXhhbXBsZS5jb206ODM4OA==#legacy";
  const service = createSubscriptionService({
    defaultSubscriptionFormat: "ss",
    readToken: "read-token",
    sessionSecret: "session-secret",
    storage: createMemoryStorage({
      legacy: {
        clash: "legacy-clash",
        ss: legacyShadowsocksUri,
      },
    }),
    writeToken: "write-token",
  });

  const legacyResponse = await service.handleRequest({
    method: "GET",
    path: "/subscription",
    query: {
      api_key: "read-token",
      subtype: "ss",
    },
  });

  assert.equal(legacyResponse.statusCode, 200);
  assert.equal(
    Buffer.from(legacyResponse.body, "base64").toString("utf8"),
    legacyShadowsocksUri,
  );

  const loginResponse = await service.handleRequest({
    method: "GET",
    origin: "https://example.com",
    path: "/dashboard",
    query: {
      api_key: "read-token",
    },
    requestUrl: "https://example.com/dashboard?api_key=read-token",
  });

  assert.equal(loginResponse.statusCode, 302);
  const cookie = extractSetCookie(loginResponse);
  assert.match(cookie, /ghe_session=/);

  const recordsResponse = await service.handleRequest({
    headers: {
      Cookie: cookie,
    },
    method: "GET",
    origin: "https://example.com",
    path: "/api/records",
  });

  assert.equal(recordsResponse.statusCode, 200);
  const payload = JSON.parse(recordsResponse.body);
  assert.equal(payload.legacyFallbackActive, true);
  assert.equal(payload.mode, "read");
});

test("dashboard session cookie authorizes records api and delete requires same-origin write access", async () => {
  const storage = createMemoryStorage({
    records: [
      {
        host: "example.com",
        method: "aes-256-gcm",
        password: "secret",
        port: 443,
        ruleName: "alpha",
        sourceTime: "2026-06-26T00:00:00Z",
        type: "ss",
        updatedAt: "2026-06-26T00:00:00.000Z",
      },
      {
        host: "status.example.com",
        method: null,
        password: null,
        port: 8443,
        ruleName: "site-a",
        sourceTime: null,
        type: "site",
        updatedAt: "2026-06-26T00:00:01.000Z",
      },
    ],
  });
  const service = createSubscriptionService({
    defaultSubscriptionFormat: "ss",
    readToken: "read-token",
    sessionSecret: "session-secret",
    storage,
    writeToken: "write-token",
  });

  const dashboardLoginResponse = await service.handleRequest({
    method: "GET",
    origin: "https://panel.example.com",
    path: "/dashboard",
    query: {
      api_key: "write-token",
    },
    requestUrl: "https://panel.example.com/dashboard?api_key=write-token",
  });

  assert.equal(dashboardLoginResponse.statusCode, 302);
  const cookie = extractSetCookie(dashboardLoginResponse);
  assert.match(cookie, /HttpOnly/);

  const recordsResponse = await service.handleRequest({
    headers: {
      Cookie: cookie,
    },
    method: "GET",
    origin: "https://panel.example.com",
    path: "/api/records",
  });

  assert.equal(recordsResponse.statusCode, 200);
  const recordsPayload = JSON.parse(recordsResponse.body);
  assert.equal(recordsPayload.mode, "write");
  assert.equal(recordsPayload.records.length, 2);
  assert.equal(
    recordsPayload.subscriptionUrls.ss,
    "https://panel.example.com/subscription?subtype=ss&api_key=read-token",
  );

  const forbiddenDeleteResponse = await service.handleRequest({
    body: JSON.stringify({ ruleName: "alpha" }),
    headers: {
      Cookie: cookie,
    },
    method: "POST",
    origin: "https://panel.example.com",
    path: "/api/delete",
  });

  assert.equal(forbiddenDeleteResponse.statusCode, 403);

  const successfulDeleteResponse = await service.handleRequest({
    body: JSON.stringify({ ruleName: "alpha" }),
    headers: {
      Cookie: cookie,
      Origin: "https://panel.example.com",
    },
    method: "POST",
    origin: "https://panel.example.com",
    path: "/api/delete",
  });

  assert.equal(successfulDeleteResponse.statusCode, 204);
  assert.equal(storage.recordState.has("alpha"), false);
});

test("records api ignores query tokens and supports authorization headers", async () => {
  const storage = createMemoryStorage({
    records: [
      {
        host: "example.com",
        method: "aes-256-gcm",
        password: "secret",
        port: 443,
        ruleName: "alpha",
        sourceTime: null,
        type: "ss",
        updatedAt: "2026-06-26T00:00:00.000Z",
      },
    ],
  });
  const service = createSubscriptionService({
    defaultSubscriptionFormat: "ss",
    readToken: "read-token",
    sessionSecret: "session-secret",
    storage,
    writeToken: "write-token",
  });

  const queryTokenResponse = await service.handleRequest({
    method: "GET",
    origin: "https://example.com",
    path: "/api/records",
    query: {
      api_key: "read-token",
    },
  });

  assert.equal(queryTokenResponse.statusCode, 401);

  const headerAuthResponse = await service.handleRequest({
    headers: {
      Authorization: "Bearer read-token",
    },
    method: "GET",
    origin: "https://example.com",
    path: "/api/records",
  });

  assert.equal(headerAuthResponse.statusCode, 200);
  const payload = JSON.parse(headerAuthResponse.body);
  assert.equal(payload.mode, "read");
});

test("resolveRuntimeOptions fails closed when required tokens are missing", () => {
  assert.throws(
    () =>
      resolveRuntimeOptions({
        SUBSCRIPTION_FORMAT: "ss",
      }),
    ConfigurationError,
  );
});
