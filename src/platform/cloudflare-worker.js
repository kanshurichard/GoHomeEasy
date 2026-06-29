import {
  ConfigurationError,
  createSubscriptionService,
  defaultStorageKeyForFormat,
  deriveRecordStorageKey,
  resolveRuntimeOptions,
  toErrorResponse,
} from "../shared/subscription-core.js";

const RECORD_KEY_PREFIX = "record:v2:";

export function createCloudflareWorker(overrides = {}) {
  return {
    async fetch(request, env) {
      try {
        const options = resolveRuntimeOptions(env, overrides);
        const storage = createKvStorage(env?.KV_NAMESPACE);
        const service = createSubscriptionService({ ...options, storage });
        const url = new URL(request.url);

        const response = await service.handleRequest({
          body: request.method === "POST" ? await request.text() : "",
          headers: request.headers,
          method: request.method,
          origin: url.origin,
          path: url.pathname,
          query: Object.fromEntries(url.searchParams.entries()),
          requestUrl: request.url,
        });

        return toWorkerResponse(response);
      } catch (error) {
        logError(error);
        return toWorkerResponse(toErrorResponse(error));
      }
    },
  };
}

export function createKvStorage(kvNamespace) {
  if (
    !kvNamespace ||
    typeof kvNamespace.delete !== "function" ||
    typeof kvNamespace.get !== "function" ||
    typeof kvNamespace.list !== "function" ||
    typeof kvNamespace.put !== "function"
  ) {
    throw new ConfigurationError("Missing required configuration: KV_NAMESPACE");
  }

  return {
    async deleteRecord(ruleName) {
      await kvNamespace.delete(deriveRecordStorageKey(ruleName));
    },

    async getLegacySubscription(subtype) {
      return await kvNamespace.get(defaultStorageKeyForFormat(subtype));
    },

    async getRecord(ruleName) {
      const value = await kvNamespace.get(deriveRecordStorageKey(ruleName));

      if (!value) {
        return null;
      }

      return parseStoredRecord(value);
    },

    async listRecords() {
      const keys = [];
      let cursor;
      let completed = false;

      while (!completed) {
        const page = await kvNamespace.list({
          cursor,
          prefix: RECORD_KEY_PREFIX,
        });

        keys.push(...page.keys.map((entry) => entry.name));
        completed = page.list_complete;
        cursor = page.cursor;
      }

      const values = await Promise.all(keys.map((key) => kvNamespace.get(key)));

      return values.filter(Boolean).map(parseStoredRecord);
    },

    async putRecord(ruleName, record) {
      await kvNamespace.put(deriveRecordStorageKey(ruleName), JSON.stringify(record));
    },
  };
}

function parseStoredRecord(value) {
  const record = JSON.parse(value);

  if (!record || typeof record !== "object") {
    throw new ConfigurationError("Stored record is invalid.");
  }

  return record;
}

function toWorkerResponse(response) {
  return new Response(response.body, {
    headers: response.headers,
    status: response.statusCode,
  });
}

function logError(error) {
  if (error instanceof ConfigurationError) {
    console.error("Configuration error:", error.message);
    return;
  }

  console.error("Unhandled error:", error);
}
