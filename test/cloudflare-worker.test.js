import test from "node:test";
import assert from "node:assert/strict";

import { createCloudflareWorker } from "../src/platform/cloudflare-worker.js";

function createKvNamespace(pageSize = 1000) {
  const values = new Map();

  return {
    async delete(key) {
      values.delete(key);
    },
    async get(key) {
      return values.get(key) ?? null;
    },
    async list({ cursor, prefix } = {}) {
      const startIndex = cursor ? Number(cursor) : 0;
      const keys = Array.from(values.keys())
        .filter((key) => !prefix || key.startsWith(prefix))
        .sort();
      const slice = keys.slice(startIndex, startIndex + pageSize);
      const nextIndex = startIndex + slice.length;

      return {
        cursor: nextIndex >= keys.length ? undefined : String(nextIndex),
        keys: slice.map((name) => ({ name })),
        list_complete: nextIndex >= keys.length,
      };
    },
    async put(key, value) {
      values.set(key, value);
    },
    values,
  };
}

test("cloudflare worker handles paginated KV records, root compatibility, and api auth rules", async () => {
  const worker = createCloudflareWorker();
  const kvNamespace = createKvNamespace(1);
  const env = {
    KV_NAMESPACE: kvNamespace,
    READ_TOKEN: "read-token",
    SESSION_SECRET: "session-secret",
    SUBSCRIPTION_FORMAT: "clash",
    WRITE_TOKEN: "write-token",
  };

  const ssRequest = new Request("https://example.com/webhook", {
    body: JSON.stringify({
      host: "edge.example.com",
      method: "aes-256-gcm",
      password: "secret",
      port: 443,
      ruleName: "edge",
    }),
    headers: {
      Authorization: "Bearer write-token",
      "Content-Type": "application/json",
    },
    method: "POST",
  });

  const siteRequest = new Request("https://example.com/webhook", {
    body: JSON.stringify({
      host: "portal.example.com",
      port: 8443,
      ruleName: "portal",
      type: "site",
    }),
    headers: {
      Authorization: "Bearer write-token",
      "Content-Type": "application/json",
    },
    method: "POST",
  });

  assert.equal((await worker.fetch(ssRequest, env)).status, 200);
  assert.equal((await worker.fetch(siteRequest, env)).status, 200);

  const rootCompatibilityResponse = await worker.fetch(
    new Request("https://example.com/?api_key=read-token"),
    env,
  );

  assert.equal(rootCompatibilityResponse.status, 200);
  assert.match(await rootCompatibilityResponse.text(), /proxies:\n  - name: "edge"/);

  const explicitSubscriptionResponse = await worker.fetch(
    new Request("https://example.com/subscription?subtype=ss&api_key=read-token"),
    env,
  );

  assert.equal(explicitSubscriptionResponse.status, 200);
  assert.match(await explicitSubscriptionResponse.text(), /^c3M6Ly9/);

  const recordsQueryTokenResponse = await worker.fetch(
    new Request("https://example.com/api/records?api_key=read-token"),
    env,
  );

  assert.equal(recordsQueryTokenResponse.status, 401);

  const recordsHeaderResponse = await worker.fetch(
    new Request("https://example.com/api/records", {
      headers: {
        Authorization: "Bearer read-token",
      },
    }),
    env,
  );

  assert.equal(recordsHeaderResponse.status, 200);
  const payload = await recordsHeaderResponse.json();
  assert.equal(payload.records.length, 2);
  assert.equal(payload.mode, "read");
});

test("cloudflare worker fails closed when required secrets are missing", async () => {
  const worker = createCloudflareWorker();
  const originalConsoleError = console.error;

  console.error = () => {};

  try {
    const response = await worker.fetch(
      new Request("https://example.com/?api_key=anything"),
      {
        KV_NAMESPACE: createKvNamespace(),
        SUBSCRIPTION_FORMAT: "ss",
      },
    );

    assert.equal(response.status, 500);
    assert.equal(await response.text(), '{"error":"Server misconfigured."}');
  } finally {
    console.error = originalConsoleError;
  }
});
