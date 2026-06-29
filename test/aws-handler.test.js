import test from "node:test";
import assert from "node:assert/strict";

import { DeleteCommand, GetCommand, PutCommand, QueryCommand } from "@aws-sdk/lib-dynamodb";

import { createDynamoStorage } from "../src/platform/aws-handler.js";

function createMockClient(responses) {
  const sentCommands = [];

  return {
    sentCommands,
    async send(command) {
      sentCommands.push(command);
      const response = responses.shift();

      if (response instanceof Error) {
        throw response;
      }

      return response ?? {};
    },
  };
}

test("dynamo storage paginates Query results and preserves legacy keys", async () => {
  const legacyShadowsocksUri =
    "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzQGVkZ2UuZXhhbXBsZS5jb206ODM4OA==#legacy";
  const client = createMockClient([
    {
      Items: [
        {
          gsi1pk: "record",
          gsi1sk: "YWxwaGE",
          host: "edge.example.com",
          id: "record:v2:YWxwaGE",
          method: "aes-256-gcm",
          password: "secret",
          port: 443,
          ruleName: "alpha",
          type: "ss",
          updatedAt: "2026-06-26T00:00:00.000Z",
        },
      ],
      LastEvaluatedKey: { id: "record:v2:YWxwaGE" },
    },
    {
      Items: [
        {
          gsi1pk: "record",
          gsi1sk: "YmV0YQ",
          host: "portal.example.com",
          id: "record:v2:YmV0YQ",
          port: 8443,
          ruleName: "beta",
          type: "site",
          updatedAt: "2026-06-26T00:00:01.000Z",
        },
      ],
    },
    {
      Item: {
        id: "latest_subscription",
        value: legacyShadowsocksUri,
      },
    },
    {},
    {},
  ]);

  const storage = createDynamoStorage({
    documentClient: client,
    indexName: "RecordIndex",
    tableName: "Subscription",
  });

  const records = await storage.listRecords();

  assert.equal(records.length, 2);
  assert.equal(records[0].ruleName, "alpha");
  assert.equal(records[1].ruleName, "beta");
  assert.ok(client.sentCommands[0] instanceof QueryCommand);
  assert.ok(client.sentCommands[1] instanceof QueryCommand);

  const legacySubscription = await storage.getLegacySubscription("ss");
  assert.equal(legacySubscription, legacyShadowsocksUri);
  assert.ok(client.sentCommands[2] instanceof GetCommand);

  await storage.putRecord("alpha", {
    host: "edge.example.com",
    method: "aes-256-gcm",
    password: "secret",
    port: 443,
    ruleName: "alpha",
    sourceTime: null,
    type: "ss",
    updatedAt: "2026-06-26T00:00:02.000Z",
  });
  assert.ok(client.sentCommands[3] instanceof PutCommand);

  await storage.deleteRecord("alpha");
  assert.ok(client.sentCommands[4] instanceof DeleteCommand);
});
