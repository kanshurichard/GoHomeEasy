import test from "node:test";
import assert from "node:assert/strict";

import { DeleteCommand, GetCommand, PutCommand, QueryCommand } from "@aws-sdk/lib-dynamodb";

import { createAwsHandler } from "../src/platform/aws-handler.js";

function createInMemoryDynamoClient(pageSize = 1000) {
  const items = new Map();

  return {
    items,
    async send(command) {
      if (command instanceof DeleteCommand) {
        items.delete(command.input.Key.id);
        return {};
      }

      if (command instanceof GetCommand) {
        const item = items.get(command.input.Key.id);
        return item ? { Item: structuredClone(item) } : {};
      }

      if (command instanceof PutCommand) {
        items.set(command.input.Item.id, structuredClone(command.input.Item));
        return {};
      }

      if (command instanceof QueryCommand) {
        const recordItems = Array.from(items.values())
          .filter((item) => item.gsi1pk === "record")
          .sort((left, right) => left.gsi1sk.localeCompare(right.gsi1sk));
        const startId = command.input.ExclusiveStartKey?.id;
        const startIndex = startId
          ? recordItems.findIndex((item) => item.id === startId) + 1
          : 0;
        const page = recordItems.slice(startIndex, startIndex + pageSize);
        const lastItem = page.at(-1);

        return {
          Items: structuredClone(page),
          LastEvaluatedKey:
            startIndex + page.length >= recordItems.length || !lastItem
              ? undefined
              : { id: lastItem.id },
        };
      }

      throw new Error(`Unsupported command: ${command.constructor.name}`);
    },
  };
}

function createLambdaEvent({
  body = "",
  headers = {},
  isBase64Encoded = false,
  method = "GET",
  path = "/",
  query = {},
} = {}) {
  return {
    body,
    headers: {
      "x-forwarded-host": "api.example.com",
      "x-forwarded-proto": "https",
      ...headers,
    },
    isBase64Encoded,
    queryStringParameters: query,
    rawPath: path,
    requestContext: {
      http: {
        method,
      },
    },
  };
}

async function withEnv(nextEnv, callback) {
  const previous = new Map();

  for (const [key, value] of Object.entries(nextEnv)) {
    previous.set(key, process.env[key]);
    process.env[key] = value;
  }

  try {
    return await callback();
  } finally {
    for (const [key, value] of previous.entries()) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
}

function extractSetCookie(response) {
  return response.headers["Set-Cookie"] ?? response.headers["set-cookie"] ?? "";
}

test("aws handler processes webhook, subscription, dashboard, and delete flows", async () => {
  await withEnv(
    {
      READ_TOKEN: "read-token",
      SESSION_SECRET: "session-secret",
      WRITE_TOKEN: "write-token",
    },
    async () => {
      const handler = createAwsHandler({
        defaultSubscriptionFormat: "clash",
        documentClient: createInMemoryDynamoClient(1),
        indexName: "RecordIndex",
        tableName: "Subscription",
      });

      const ssCreateResponse = await handler(
        createLambdaEvent({
          body: Buffer.from(
            JSON.stringify({
              host: "edge.example.com",
              method: "aes-256-gcm",
              password: "secret",
              port: 443,
              ruleName: "edge",
            }),
          ).toString("base64"),
          headers: {
            Authorization: "Bearer write-token",
          },
          isBase64Encoded: true,
          method: "POST",
          path: "/webhook",
        }),
      );

      assert.equal(ssCreateResponse.statusCode, 200);

      const siteCreateResponse = await handler(
        createLambdaEvent({
          body: JSON.stringify({
            host: "portal.example.com",
            port: 8443,
            ruleName: "portal",
            type: "site",
          }),
          headers: {
            Authorization: "Bearer write-token",
          },
          method: "POST",
          path: "/webhook",
        }),
      );

      assert.equal(siteCreateResponse.statusCode, 200);

      const rootResponse = await handler(
        createLambdaEvent({
          path: "/",
          query: {
            api_key: "read-token",
          },
        }),
      );

      assert.equal(rootResponse.statusCode, 200);
      assert.match(rootResponse.body, /proxies:\n  - name: "edge"/);

      const explicitSubscriptionResponse = await handler(
        createLambdaEvent({
          headers: {
            Authorization: "Bearer read-token",
          },
          path: "/subscription",
          query: {
            subtype: "ss",
          },
        }),
      );

      assert.equal(explicitSubscriptionResponse.statusCode, 200);
      assert.equal(
        Buffer.from(explicitSubscriptionResponse.body, "base64").toString("utf8"),
        "ss://YWVzLTI1Ni1nY206c2VjcmV0QGVkZ2UuZXhhbXBsZS5jb206NDQz#edge",
      );

      const dashboardLoginResponse = await handler(
        createLambdaEvent({
          path: "/dashboard",
          query: {
            api_key: "write-token",
          },
        }),
      );

      assert.equal(dashboardLoginResponse.statusCode, 302);
      const sessionCookie = extractSetCookie(dashboardLoginResponse);
      assert.match(sessionCookie, /ghe_session=/);
      assert.match(sessionCookie, /Secure/);

      const queryOnlyRecordsResponse = await handler(
        createLambdaEvent({
          path: "/api/records",
          query: {
            api_key: "read-token",
          },
        }),
      );

      assert.equal(queryOnlyRecordsResponse.statusCode, 401);

      const recordsResponse = await handler(
        createLambdaEvent({
          headers: {
            Cookie: sessionCookie,
          },
          path: "/api/records",
        }),
      );

      assert.equal(recordsResponse.statusCode, 200);
      const recordsPayload = JSON.parse(recordsResponse.body);
      assert.equal(recordsPayload.mode, "write");
      assert.equal(recordsPayload.records.length, 2);
      assert.equal(
        recordsPayload.subscriptionUrls.ss,
        "https://api.example.com/subscription?subtype=ss&api_key=read-token",
      );

      const deleteWithoutOriginResponse = await handler(
        createLambdaEvent({
          body: JSON.stringify({ ruleName: "edge" }),
          headers: {
            Cookie: sessionCookie,
          },
          method: "POST",
          path: "/api/delete",
        }),
      );

      assert.equal(deleteWithoutOriginResponse.statusCode, 403);

      const deleteWithOriginResponse = await handler(
        createLambdaEvent({
          body: JSON.stringify({ ruleName: "edge" }),
          headers: {
            Cookie: sessionCookie,
            Origin: "https://api.example.com",
          },
          method: "POST",
          path: "/api/delete",
        }),
      );

      assert.equal(deleteWithOriginResponse.statusCode, 204);
    },
  );
});

test("aws handler override controls legacy root subscription format", async () => {
  await withEnv(
    {
      READ_TOKEN: "read-token",
      WRITE_TOKEN: "write-token",
    },
    async () => {
      const handler = createAwsHandler({
        defaultSubscriptionFormat: "ss",
        documentClient: createInMemoryDynamoClient(),
        indexName: "RecordIndex",
        tableName: "Subscription",
      });

      await handler(
        createLambdaEvent({
          body: JSON.stringify({
            host: "edge.example.com",
            method: "aes-256-gcm",
            password: "secret",
            port: 443,
            ruleName: "edge",
          }),
          headers: {
            Authorization: "Bearer write-token",
          },
          method: "POST",
          path: "/webhook",
        }),
      );

      const rootResponse = await handler(
        createLambdaEvent({
          path: "/",
          query: {
            api_key: "read-token",
          },
        }),
      );

      assert.equal(rootResponse.statusCode, 200);
      assert.match(rootResponse.body, /^c3M6Ly9/);
    },
  );
});
