import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DeleteCommand,
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  QueryCommand,
} from "@aws-sdk/lib-dynamodb";

import {
  ConfigurationError,
  createSubscriptionService,
  defaultStorageKeyForFormat,
  deriveRecordStorageKey,
  resolveRuntimeOptions,
  toErrorResponse,
} from "../shared/subscription-core.js";

const DEFAULT_RECORD_INDEX_NAME = "RecordIndex";

const dynamoClient = new DynamoDBClient({});
const documentClient = DynamoDBDocumentClient.from(dynamoClient);

export function createAwsHandler(overrides = {}) {
  return async function handler(event = {}) {
    try {
      const options = resolveRuntimeOptions(process.env, overrides);
      const tableName = overrides.tableName ?? readRequiredEnv("TABLE_NAME");
      const indexName =
        overrides.indexName ??
        readOptionalEnv("RECORD_INDEX_NAME") ??
        DEFAULT_RECORD_INDEX_NAME;
      const storage = createDynamoStorage({
        documentClient: overrides.documentClient ?? documentClient,
        indexName,
        tableName,
      });
      const service = createSubscriptionService({ ...options, storage });

      return await service.handleRequest({
        body: decodeLambdaBody(event.body, event.isBase64Encoded),
        headers: event.headers ?? {},
        method: event.requestContext?.http?.method ?? event.httpMethod,
        origin: resolveEventOrigin(event),
        path: resolveEventPath(event),
        query: event.queryStringParameters ?? {},
        requestUrl: resolveEventUrl(event),
      });
    } catch (error) {
      logError(error);
      return toErrorResponse(error);
    }
  };
}

export function createDynamoStorage({ documentClient: client, indexName, tableName }) {
  if (!client) {
    throw new ConfigurationError("Missing required configuration: DynamoDBDocumentClient");
  }

  if (!tableName) {
    throw new ConfigurationError("Missing required configuration: TABLE_NAME");
  }

  if (!indexName) {
    throw new ConfigurationError("Missing required configuration: RECORD_INDEX_NAME");
  }

  return {
    async deleteRecord(ruleName) {
      await client.send(
        new DeleteCommand({
          Key: { id: deriveRecordStorageKey(ruleName) },
          TableName: tableName,
        }),
      );
    },

    async getLegacySubscription(subtype) {
      const result = await client.send(
        new GetCommand({
          Key: { id: defaultStorageKeyForFormat(subtype) },
          TableName: tableName,
        }),
      );

      return typeof result.Item?.value === "string" ? result.Item.value : null;
    },

    async getRecord(ruleName) {
      const result = await client.send(
        new GetCommand({
          Key: { id: deriveRecordStorageKey(ruleName) },
          TableName: tableName,
        }),
      );

      return result.Item ? fromRecordItem(result.Item) : null;
    },

    async listRecords() {
      const records = [];
      let exclusiveStartKey;

      do {
        const result = await client.send(
          new QueryCommand({
            ExclusiveStartKey: exclusiveStartKey,
            ExpressionAttributeValues: {
              ":record": "record",
            },
            IndexName: indexName,
            KeyConditionExpression: "gsi1pk = :record",
            TableName: tableName,
          }),
        );

        records.push(...(result.Items ?? []).map(fromRecordItem));
        exclusiveStartKey = result.LastEvaluatedKey;
      } while (exclusiveStartKey);

      return records;
    },

    async putRecord(ruleName, record) {
      await client.send(
        new PutCommand({
          Item: {
            ...record,
            gsi1pk: "record",
            gsi1sk: base64UrlRecordName(ruleName),
            id: deriveRecordStorageKey(ruleName),
          },
          TableName: tableName,
        }),
      );
    },
  };
}

function fromRecordItem(item) {
  return {
    host: item.host,
    method: item.method ?? null,
    password: item.password ?? null,
    port: item.port,
    ruleName: item.ruleName,
    sourceTime: item.sourceTime ?? null,
    type: item.type,
    updatedAt: item.updatedAt,
  };
}

function base64UrlRecordName(ruleName) {
  return deriveRecordStorageKey(ruleName).replace(/^record:v2:/, "");
}

function decodeLambdaBody(body, isBase64Encoded) {
  if (!body) {
    return "";
  }

  if (!isBase64Encoded) {
    return typeof body === "string" ? body : String(body);
  }

  return Buffer.from(String(body), "base64").toString("utf8");
}

function resolveEventPath(event) {
  return event.rawPath ?? event.path ?? "/";
}

function resolveEventOrigin(event) {
  const headers = normalizeEventHeaders(event.headers);
  const host = headers["x-forwarded-host"] ?? headers.host;

  if (!host) {
    return "";
  }

  const protocol = headers["x-forwarded-proto"] === "https" ? "https" : "http";
  return `${protocol}://${host}`;
}

function resolveEventUrl(event) {
  const origin = resolveEventOrigin(event);
  const path = resolveEventPath(event);

  if (!origin) {
    return "";
  }

  const query = new URLSearchParams(event.queryStringParameters ?? {}).toString();
  return query ? `${origin}${path}?${query}` : `${origin}${path}`;
}

function normalizeEventHeaders(headers) {
  const normalized = {};

  for (const [key, value] of Object.entries(headers ?? {})) {
    if (value !== undefined && value !== null) {
      normalized[String(key).toLowerCase()] = String(value);
    }
  }

  return normalized;
}

function readRequiredEnv(key) {
  const value = process.env[key]?.trim();

  if (!value) {
    throw new ConfigurationError(`Missing required configuration: ${key}`);
  }

  return value;
}

function readOptionalEnv(key) {
  const value = process.env[key]?.trim();
  return value || undefined;
}

function logError(error) {
  if (error instanceof ConfigurationError) {
    console.error("Configuration error:", error.message);
    return;
  }

  console.error("Unhandled error:", error);
}
