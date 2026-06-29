import { renderDashboardHtml } from "./dashboard-template.js";

const DEFAULT_ALLOWED_METHODS = new Set([
  "aes-128-cfb",
  "aes-192-cfb",
  "aes-256-cfb",
  "aes-128-gcm",
  "aes-192-gcm",
  "aes-256-gcm",
  "chacha20-ietf",
  "chacha20-ietf-poly1305",
  "xchacha20-ietf-poly1305",
  "2022-blake3-aes-128-gcm",
  "2022-blake3-aes-256-gcm",
  "2022-blake3-chacha20-poly1305",
]);

const LEGACY_STORAGE_KEYS = {
  clash: "latest_clash_subscription",
  ss: "latest_subscription",
};

const SESSION_COOKIE_NAME = "ghe_session";
const DEFAULT_SESSION_TTL_SECONDS = 86400;
const RULE_NAME_CONTROL_CHARACTER_PATTERN = /[\u0000-\u001F\u007F]/;
const IPV6_BRACKETED_AUTHORITY_PATTERN = /^\[([^[\]]+)\]:(\d+)$/;
const HOST_PORT_PATTERN = /^([^:]+):(\d+)$/;

export class ConfigurationError extends Error {
  constructor(message) {
    super(message);
    this.name = "ConfigurationError";
  }
}

export class ValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "ValidationError";
  }
}

export function createSubscriptionService({
  allowedMethods = DEFAULT_ALLOWED_METHODS,
  defaultSubscriptionFormat,
  readToken,
  sessionSecret,
  sessionTtlSeconds = DEFAULT_SESSION_TTL_SECONDS,
  storage,
  writeToken,
}) {
  const normalizedDefaultSubscriptionFormat = normalizeSubtype(defaultSubscriptionFormat ?? "ss");
  const normalizedReadToken = requireConfiguredString(readToken, "READ_TOKEN");
  const normalizedWriteToken = requireConfiguredString(writeToken, "WRITE_TOKEN");
  const normalizedSessionSecret =
    typeof sessionSecret === "string" && sessionSecret.trim() !== "" ? sessionSecret : null;
  const normalizedSessionTtlSeconds = normalizeSessionTtlSeconds(sessionTtlSeconds);
  const methodSet = normalizeAllowedMethods(allowedMethods);

  validateStorageAdapter(storage);

  return {
    async handleRequest({
      body = "",
      headers = {},
      method,
      origin = "",
      path = "/",
      query = {},
      requestUrl = "",
    }) {
      try {
        const normalizedMethod = String(method || "").toUpperCase();
        const normalizedPath = normalizePath(path);
        const normalizedHeaders = normalizeHeaders(headers);
        const resolvedOrigin = resolveOrigin({
          explicitOrigin: origin,
          headers: normalizedHeaders,
          requestUrl,
        });

        if (normalizedMethod === "OPTIONS") {
          return createResponse(204, "", {
            Allow: "GET, POST, OPTIONS",
          });
        }

        if (normalizedPath === "/healthz") {
          if (normalizedMethod !== "GET") {
            return textResponse(405, "Method Not Allowed", { Allow: "GET" });
          }

          return textResponse(200, "ok");
        }

        if (normalizedPath === "/" || normalizedPath === "/subscription") {
          if (normalizedMethod !== "GET") {
            if (normalizedPath === "/" && normalizedMethod === "POST") {
              return await handleWebhookRequest({
                allowedMethods: methodSet,
                body,
                headers: normalizedHeaders,
                storage,
                writeToken: normalizedWriteToken,
              });
            }

            return textResponse(405, "Method Not Allowed", {
              Allow: normalizedPath === "/" ? "GET, POST, OPTIONS" : "GET, OPTIONS",
            });
          }

          const fallbackSubtype =
            normalizedPath === "/" ? normalizedDefaultSubscriptionFormat : "ss";

          return await handleSubscriptionRequest({
            fallbackSubtype,
            headers: normalizedHeaders,
            query,
            readToken: normalizedReadToken,
            storage,
          });
        }

        if (normalizedPath === "/webhook") {
          if (normalizedMethod !== "POST") {
            return textResponse(405, "Method Not Allowed", {
              Allow: "POST, OPTIONS",
            });
          }

          return await handleWebhookRequest({
            allowedMethods: methodSet,
            body,
            headers: normalizedHeaders,
            storage,
            writeToken: normalizedWriteToken,
          });
        }

        if (normalizedPath === "/dashboard") {
          return await handleDashboardRequest({
            headers: normalizedHeaders,
            origin: resolvedOrigin,
            query,
            readToken: normalizedReadToken,
            requestUrl,
            sessionSecret: normalizedSessionSecret,
            sessionTtlSeconds: normalizedSessionTtlSeconds,
            writeToken: normalizedWriteToken,
          });
        }

        if (normalizedPath === "/api/records") {
          if (normalizedMethod !== "GET") {
            return textResponse(405, "Method Not Allowed", { Allow: "GET, OPTIONS" });
          }

          return await handleRecordsApiRequest({
            headers: normalizedHeaders,
            origin: resolvedOrigin,
            readToken: normalizedReadToken,
            sessionSecret: normalizedSessionSecret,
            sessionTtlSeconds: normalizedSessionTtlSeconds,
            storage,
            writeToken: normalizedWriteToken,
          });
        }

        if (normalizedPath === "/api/delete") {
          if (normalizedMethod !== "POST") {
            return textResponse(405, "Method Not Allowed", { Allow: "POST, OPTIONS" });
          }

          return await handleDeleteRequest({
            body,
            headers: normalizedHeaders,
            origin: resolvedOrigin,
            sessionSecret: normalizedSessionSecret,
            storage,
            writeToken: normalizedWriteToken,
          });
        }

        return textResponse(404, "Not Found");
      } catch (error) {
        return toErrorResponse(error);
      }
    },
  };
}

export function defaultStorageKeyForFormat(format) {
  return LEGACY_STORAGE_KEYS[normalizeSubtype(format)];
}

export function deriveRecordStorageKey(ruleName) {
  return `record:v2:${base64UrlEncodeUtf8(ruleName)}`;
}

export function resolveRuntimeOptions(envSource, overrides = {}) {
  const defaultSubscriptionFormat = normalizeSubtype(
    overrides.defaultSubscriptionFormat ??
      readOptionalString(envSource, "SUBSCRIPTION_FORMAT") ??
      "ss",
  );

  return {
    allowedMethods: overrides.allowedMethods ?? readOptionalString(envSource, "ALLOWED_METHODS"),
    defaultSubscriptionFormat,
    readToken: readRequiredString(envSource, "READ_TOKEN"),
    sessionSecret: overrides.sessionSecret ?? readOptionalString(envSource, "SESSION_SECRET"),
    sessionTtlSeconds:
      overrides.sessionTtlSeconds ?? readOptionalString(envSource, "SESSION_TTL_SECONDS"),
    writeToken: readRequiredString(envSource, "WRITE_TOKEN"),
  };
}

export function toErrorResponse(error) {
  if (error instanceof ValidationError) {
    return jsonResponse(400, { error: error.message });
  }

  if (error instanceof ConfigurationError) {
    return jsonResponse(500, { error: "Server misconfigured." });
  }

  return jsonResponse(500, { error: "Internal Server Error" });
}

async function handleWebhookRequest({ allowedMethods, body, headers, storage, writeToken }) {
  const bearerToken = getBearerToken(headers);

  if (bearerToken !== writeToken) {
    return unauthorizedJsonResponse();
  }

  const payload = parseWebhookPayload(body, allowedMethods);
  const record = {
    ...payload,
    updatedAt: new Date().toISOString(),
  };

  await storage.putRecord(record.ruleName, record);

  return jsonResponse(200, {
    message: "Record updated successfully.",
    ruleName: record.ruleName,
    type: record.type,
  });
}

async function handleSubscriptionRequest({
  fallbackSubtype,
  headers,
  query,
  readToken,
  storage,
}) {
  const authToken = extractSubscriptionToken(headers, query);

  if (authToken !== readToken) {
    return unauthorizedJsonResponse();
  }

  const subtype = extractSubtype(query, fallbackSubtype);
  const records = await storage.listRecords();
  const shadowsocksRecords = records
    .filter((record) => record.type === "ss")
    .sort(compareRuleNamesAscending);

  if (shadowsocksRecords.length > 0) {
    const responseBody =
      subtype === "ss"
        ? utf8ToBase64(shadowsocksRecords.map(buildShadowsocksUri).join("\n"))
        : buildClashSubscription(shadowsocksRecords);

    return textResponse(200, responseBody, {
      "X-GoHomeEasy-Format": subtype,
    });
  }

  const legacySubscription = await storage.getLegacySubscription(subtype);

  if (!legacySubscription) {
    return textResponse(204, "");
  }

  return textResponse(200, normalizeLegacySubscriptionBody(subtype, legacySubscription), {
    "X-GoHomeEasy-Format": subtype,
    "X-GoHomeEasy-Legacy-Fallback": "true",
  });
}

async function handleDashboardRequest({
  headers,
  origin,
  query,
  readToken,
  requestUrl,
  sessionSecret,
  sessionTtlSeconds,
  writeToken,
}) {
  ensureDashboardConfigured(sessionSecret);

  const queryToken = readQueryValue(query, "api_key");

  if (queryToken) {
    const mode = resolveDashboardMode(queryToken, readToken, writeToken);

    if (!mode) {
      return htmlResponse(401, renderDashboardHtml({ showLogin: true }), {
        "X-GoHomeEasy-Auth-Error": "invalid-token",
      });
    }

    const secure = isSecureRequest({ origin, requestUrl, headers });
    const cookieValue = await createSignedSessionValue({
      expiresAt: currentUnixTimestamp() + sessionTtlSeconds,
      mode,
      secret: sessionSecret,
    });

    return redirectResponse("/dashboard", {
      "Set-Cookie": buildSessionCookie({
        secure,
        value: cookieValue,
      }),
    });
  }

  const session = await getSessionFromCookie({
    headers,
    sessionSecret,
  });

  if (!session) {
    return htmlResponse(200, renderDashboardHtml({ showLogin: true }));
  }

  return htmlResponse(200, renderDashboardHtml({ mode: session.mode }));
}

async function handleRecordsApiRequest({
  headers,
  origin,
  readToken,
  sessionSecret,
  storage,
  writeToken,
}) {
  ensureDashboardConfigured(sessionSecret);

  const access = await resolveApiAccess({
    headers,
    readToken,
    sessionSecret,
    writeToken,
  });

  if (!access) {
    return unauthorizedJsonResponse();
  }

  const records = (await storage.listRecords()).sort(compareRecordsByUpdatedAtDescending);
  const hasShadowsocksRecords = records.some((record) => record.type === "ss");
  const [legacySs, legacyClash] = await Promise.all([
    storage.getLegacySubscription("ss"),
    storage.getLegacySubscription("clash"),
  ]);

  return jsonResponse(200, {
    legacyFallbackActive: !hasShadowsocksRecords && Boolean(legacySs || legacyClash),
    mode: access.mode,
    records,
    subscriptionUrls: {
      clash: buildSubscriptionUrl({
        apiKey: readToken,
        origin,
        subtype: "clash",
      }),
      ss: buildSubscriptionUrl({
        apiKey: readToken,
        origin,
        subtype: "ss",
      }),
    },
  });
}

async function handleDeleteRequest({
  body,
  headers,
  origin,
  sessionSecret,
  storage,
  writeToken,
}) {
  ensureDashboardConfigured(sessionSecret);

  const access = await resolveDeleteAccess({
    headers,
    origin,
    sessionSecret,
    writeToken,
  });

  if (access === "unauthorized") {
    return unauthorizedJsonResponse();
  }

  if (access === "forbidden") {
    return jsonResponse(403, { error: "Forbidden" });
  }

  const payload = parseDeletePayload(body);
  await storage.deleteRecord(payload.ruleName);

  return createResponse(204, "", {});
}

function validateStorageAdapter(storage) {
  const requiredMethods = [
    "deleteRecord",
    "getLegacySubscription",
    "getRecord",
    "listRecords",
    "putRecord",
  ];

  if (!storage || typeof storage !== "object") {
    throw new ConfigurationError("Storage adapter is required.");
  }

  for (const methodName of requiredMethods) {
    if (typeof storage[methodName] !== "function") {
      throw new ConfigurationError(`Storage adapter must expose async ${methodName}().`);
    }
  }
}

function parseWebhookPayload(rawBody, allowedMethods) {
  const payload = parseJsonObject(rawBody);
  const ruleName = normalizeRuleName(payload.ruleName);
  const address = resolveAddress(payload);
  const type = normalizeRecordType(payload.type);
  const sourceTime = normalizeOptionalSourceTime(payload.time);

  if (type === "site") {
    if (hasNonEmptyString(payload.method) || hasNonEmptyString(payload.password)) {
      throw new ValidationError("type=site records must not include method or password.");
    }

    return {
      host: address.host,
      method: null,
      password: null,
      port: address.port,
      ruleName,
      sourceTime,
      type,
    };
  }

  const method = normalizeCipher(payload.method, allowedMethods);
  const password = normalizePassword(payload.password);

  return {
    host: address.host,
    method,
    password,
    port: address.port,
    ruleName,
    sourceTime,
    type,
  };
}

function parseDeletePayload(rawBody) {
  const payload = parseJsonObject(rawBody);
  return {
    ruleName: normalizeRuleName(payload.ruleName),
  };
}

function parseJsonObject(rawBody) {
  if (typeof rawBody !== "string" || rawBody.trim() === "") {
    throw new ValidationError("Request body must be a non-empty JSON object.");
  }

  let payload;

  try {
    payload = JSON.parse(rawBody);
  } catch {
    throw new ValidationError("Invalid JSON body.");
  }

  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new ValidationError("JSON body must be an object.");
  }

  return payload;
}

function resolveAddress(payload) {
  const prioritizedKeys = ["ip", "host", "server"];

  for (const key of prioritizedKeys) {
    if (hasNonEmptyString(payload[key])) {
      return {
        host: normalizeHost(payload[key], key),
        port: normalizePort(payload.port),
      };
    }
  }

  if (hasNonEmptyString(payload.ipAddr)) {
    return parseIpAddr(payload.ipAddr);
  }

  throw new ValidationError("Either ip/host/server plus port, or ipAddr, is required.");
}

function normalizeRuleName(value) {
  if (typeof value !== "string") {
    throw new ValidationError("ruleName must be a non-empty string.");
  }

  const ruleName = value.trim();

  if (!ruleName) {
    throw new ValidationError("ruleName must be a non-empty string.");
  }

  if (RULE_NAME_CONTROL_CHARACTER_PATTERN.test(ruleName)) {
    throw new ValidationError("ruleName must not contain control characters.");
  }

  if (new TextEncoder().encode(ruleName).length > 128) {
    throw new ValidationError("ruleName must be 128 bytes or fewer.");
  }

  return ruleName;
}

function normalizeRecordType(value) {
  if (value === undefined || value === null || String(value).trim() === "") {
    return "ss";
  }

  const normalized = String(value).trim().toLowerCase();

  if (normalized === "ss" || normalized === "site") {
    return normalized;
  }

  throw new ValidationError("type must be either 'ss' or 'site'.");
}

function normalizeOptionalSourceTime(value) {
  if (value === undefined || value === null) {
    return null;
  }

  const sourceTime = String(value).trim();
  return sourceTime === "" ? null : sourceTime;
}

function normalizeSubtype(value) {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();

  if (normalized === "ss" || normalized === "clash") {
    return normalized;
  }

  throw new ConfigurationError("SUBSCRIPTION_FORMAT must be either 'ss' or 'clash'.");
}

function extractSubtype(query, fallbackSubtype) {
  const explicitSubtype = readQueryValue(query, "subtype");

  if (!explicitSubtype) {
    return normalizeSubtype(fallbackSubtype);
  }

  try {
    return normalizeSubtype(explicitSubtype);
  } catch {
    throw new ValidationError("subtype must be either 'ss' or 'clash'.");
  }
}

function normalizeAllowedMethods(value) {
  if (!value) {
    return DEFAULT_ALLOWED_METHODS;
  }

  if (value instanceof Set) {
    return value;
  }

  if (Array.isArray(value)) {
    return new Set(value.map((item) => String(item).trim().toLowerCase()).filter(Boolean));
  }

  if (typeof value === "string") {
    const methods = value
      .split(",")
      .map((item) => item.trim().toLowerCase())
      .filter(Boolean);

    if (methods.length === 0) {
      throw new ConfigurationError("ALLOWED_METHODS must contain at least one cipher.");
    }

    return new Set(methods);
  }

  throw new ConfigurationError("ALLOWED_METHODS must be a comma-separated string, array, or Set.");
}

function normalizeHost(value, fieldName) {
  const host = requireNonEmptyString(value, fieldName).replace(/^\[(.*)\]$/, "$1");

  if (isValidIpv4(host) || isValidHostname(host) || isValidIpv6(host)) {
    return host;
  }

  throw new ValidationError(`${fieldName} must be a valid IPv4, IPv6, or DNS name.`);
}

function parseIpAddr(value) {
  const ipAddr = requireNonEmptyString(value, "ipAddr");

  const ipv6Match = ipAddr.match(IPV6_BRACKETED_AUTHORITY_PATTERN);

  if (ipv6Match) {
    return {
      host: normalizeHost(ipv6Match[1], "ipAddr"),
      port: normalizePort(ipv6Match[2]),
    };
  }

  const hostPortMatch = ipAddr.match(HOST_PORT_PATTERN);

  if (hostPortMatch) {
    return {
      host: normalizeHost(hostPortMatch[1], "ipAddr"),
      port: normalizePort(hostPortMatch[2]),
    };
  }

  throw new ValidationError("ipAddr must be in host:port or [ipv6]:port format.");
}

function normalizePort(value) {
  const portNumber = Number(value);

  if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) {
    throw new ValidationError("Port must be an integer between 1 and 65535.");
  }

  return portNumber;
}

function normalizeCipher(value, allowedMethods) {
  const cipher = requireNonEmptyString(value, "method").toLowerCase();

  if (!allowedMethods.has(cipher)) {
    throw new ValidationError(`Unsupported Shadowsocks cipher: ${cipher}`);
  }

  return cipher;
}

function normalizePassword(value) {
  const password = requireNonEmptyString(value, "password");

  if (password.length > 1024) {
    throw new ValidationError("Password is too long.");
  }

  return password;
}

function requireNonEmptyString(value, fieldName) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new ValidationError(`${fieldName} must be a non-empty string.`);
  }

  return value.trim();
}

function requireConfiguredString(value, fieldName) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new ConfigurationError(`${fieldName} must be a non-empty string.`);
  }

  return value.trim();
}

function normalizeSessionTtlSeconds(value) {
  const ttl = Number(value ?? DEFAULT_SESSION_TTL_SECONDS);

  if (!Number.isInteger(ttl) || ttl < 60) {
    throw new ConfigurationError("SESSION_TTL_SECONDS must be an integer of at least 60.");
  }

  return ttl;
}

function readRequiredString(envSource, key) {
  const value = readOptionalString(envSource, key);

  if (!value) {
    throw new ConfigurationError(`Missing required configuration: ${key}`);
  }

  return value;
}

function readOptionalString(envSource, key) {
  if (!envSource || typeof envSource !== "object") {
    return undefined;
  }

  const value = envSource[key];

  if (value === undefined || value === null) {
    return undefined;
  }

  const stringValue = String(value).trim();

  return stringValue === "" ? undefined : stringValue;
}

function hasNonEmptyString(value) {
  return typeof value === "string" && value.trim() !== "";
}

function extractSubscriptionToken(headers, query) {
  const bearerToken = getBearerToken(headers);

  if (bearerToken) {
    return bearerToken;
  }

  return readQueryValue(query, "api_key") ?? readQueryValue(query, "read_token");
}

function resolveDashboardMode(token, readToken, writeToken) {
  if (token === writeToken) {
    return "write";
  }

  if (token === readToken) {
    return "read";
  }

  return null;
}

async function resolveApiAccess({ headers, readToken, sessionSecret, writeToken }) {
  const bearerToken = getBearerToken(headers);

  if (bearerToken) {
    if (bearerToken === writeToken) {
      return { mode: "write", via: "header" };
    }

    if (bearerToken === readToken) {
      return { mode: "read", via: "header" };
    }

    return null;
  }

  const session = await getSessionFromCookie({
    headers,
    sessionSecret,
  });

  if (!session) {
    return null;
  }

  return {
    mode: session.mode,
    via: "cookie",
  };
}

async function resolveDeleteAccess({ headers, origin, sessionSecret, writeToken }) {
  const bearerToken = getBearerToken(headers);

  if (bearerToken) {
    return bearerToken === writeToken ? "allowed" : "unauthorized";
  }

  const session = await getSessionFromCookie({
    headers,
    sessionSecret,
  });

  if (!session) {
    return "unauthorized";
  }

  if (session.mode !== "write") {
    return "forbidden";
  }

  const requestOrigin = headers.origin;

  if (!requestOrigin || !origin || requestOrigin !== origin) {
    return "forbidden";
  }

  return "allowed";
}

async function getSessionFromCookie({ headers, sessionSecret }) {
  if (!sessionSecret) {
    return null;
  }

  const cookieHeader = headers.cookie;

  if (!cookieHeader) {
    return null;
  }

  const cookies = parseCookies(cookieHeader);
  const cookieValue = cookies[SESSION_COOKIE_NAME];

  if (!cookieValue) {
    return null;
  }

  return await verifySessionCookie(cookieValue, sessionSecret);
}

function ensureDashboardConfigured(sessionSecret) {
  if (!sessionSecret) {
    throw new ConfigurationError("Missing required configuration: SESSION_SECRET");
  }
}

function parseCookies(cookieHeader) {
  const cookies = {};

  for (const part of String(cookieHeader).split(";")) {
    const [rawName, ...rawValueParts] = part.split("=");
    const name = rawName?.trim();

    if (!name) {
      continue;
    }

    cookies[name] = rawValueParts.join("=").trim();
  }

  return cookies;
}

async function createSignedSessionValue({ expiresAt, mode, secret }) {
  const payload = base64UrlEncodeUtf8(JSON.stringify({ exp: expiresAt, mode }));
  const signature = await signPayload(payload, secret);
  return `${payload}.${signature}`;
}

async function verifySessionCookie(cookieValue, secret) {
  const parts = String(cookieValue).split(".");

  if (parts.length !== 2) {
    return null;
  }

  const [payload, signature] = parts;
  const expectedSignature = await signPayload(payload, secret);

  if (!timingSafeEqual(signature, expectedSignature)) {
    return null;
  }

  let decodedPayload;

  try {
    decodedPayload = JSON.parse(utf8FromBase64Url(payload));
  } catch {
    return null;
  }

  if (
    !decodedPayload ||
    (decodedPayload.mode !== "read" && decodedPayload.mode !== "write") ||
    !Number.isInteger(decodedPayload.exp)
  ) {
    return null;
  }

  if (decodedPayload.exp <= currentUnixTimestamp()) {
    return null;
  }

  return decodedPayload;
}

async function signPayload(payload, secret) {
  const subtle = globalThis.crypto?.subtle;

  if (!subtle) {
    throw new ConfigurationError("Web Crypto API is unavailable.");
  }

  const key = await subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { hash: "SHA-256", name: "HMAC" },
    false,
    ["sign"],
  );
  const signature = await subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(payload),
  );

  return base64UrlEncodeBytes(new Uint8Array(signature));
}

function buildSessionCookie({ secure, value }) {
  const parts = [
    `${SESSION_COOKIE_NAME}=${value}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
  ];

  if (secure) {
    parts.push("Secure");
  }

  return parts.join("; ");
}

function isSecureRequest({ origin, requestUrl, headers }) {
  if (origin.startsWith("https://")) {
    return true;
  }

  if (String(requestUrl).startsWith("https://")) {
    return true;
  }

  return headers["x-forwarded-proto"] === "https";
}

function resolveOrigin({ explicitOrigin, headers, requestUrl }) {
  if (explicitOrigin) {
    return explicitOrigin;
  }

  if (requestUrl) {
    try {
      return new URL(requestUrl).origin;
    } catch {
      return "";
    }
  }

  const host = headers["x-forwarded-host"] ?? headers.host;

  if (!host) {
    return "";
  }

  const protocol = headers["x-forwarded-proto"] === "https" ? "https" : "http";
  return `${protocol}://${host}`;
}

function buildSubscriptionUrl({ apiKey, origin, subtype }) {
  const base = origin || "";
  return `${base}/subscription?subtype=${encodeURIComponent(subtype)}&api_key=${encodeURIComponent(apiKey)}`;
}

function buildShadowsocksUri(record) {
  const authority = formatAuthority(record.host, record.port);
  const userInfo = `${record.method}:${record.password}@${authority}`;
  return `ss://${utf8ToBase64(userInfo)}#${encodeURIComponent(record.ruleName)}`;
}

function normalizeLegacySubscriptionBody(subtype, legacySubscription) {
  if (subtype !== "ss") {
    return legacySubscription;
  }

  const trimmedSubscription = String(legacySubscription).trim();

  if (!isRawShadowsocksSubscription(trimmedSubscription)) {
    return legacySubscription;
  }

  return utf8ToBase64(trimmedSubscription);
}

function isRawShadowsocksSubscription(value) {
  if (!value) {
    return false;
  }

  return value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .every((line) => line.startsWith("ss://"));
}

function buildClashSubscription(records) {
  const lines = ["proxies:"];

  for (const record of records) {
    lines.push(`  - name: ${yamlQuoted(record.ruleName)}`);
    lines.push("    type: ss");
    lines.push(`    server: ${yamlQuoted(record.host)}`);
    lines.push(`    port: ${record.port}`);
    lines.push(`    cipher: ${yamlQuoted(record.method)}`);
    lines.push(`    password: ${yamlQuoted(record.password)}`);
    lines.push("    udp: true");
  }

  lines.push("");

  return lines.join("\n");
}

function compareRuleNamesAscending(left, right) {
  if (left.ruleName === right.ruleName) {
    return 0;
  }

  return left.ruleName < right.ruleName ? -1 : 1;
}

function compareRecordsByUpdatedAtDescending(left, right) {
  if (left.updatedAt === right.updatedAt) {
    return compareRuleNamesAscending(left, right);
  }

  return left.updatedAt > right.updatedAt ? -1 : 1;
}

function normalizePath(path) {
  const normalized = typeof path === "string" && path !== "" ? path : "/";
  return normalized.startsWith("/") ? normalized : `/${normalized}`;
}

function getBearerToken(headers) {
  const authorization = headers.authorization;

  if (!authorization) {
    return null;
  }

  const match = authorization.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}

function normalizeHeaders(headers) {
  const normalized = {};

  if (!headers) {
    return normalized;
  }

  if (typeof headers.entries === "function") {
    for (const [key, value] of headers.entries()) {
      normalized[String(key).toLowerCase()] = String(value);
    }
    return normalized;
  }

  for (const [key, value] of Object.entries(headers)) {
    if (value !== undefined && value !== null) {
      normalized[String(key).toLowerCase()] = Array.isArray(value) ? value.join(",") : String(value);
    }
  }

  return normalized;
}

function readQueryValue(query, key) {
  if (!query || typeof query !== "object") {
    return null;
  }

  const value = query[key];
  return value === undefined || value === null ? null : String(value).trim();
}

function utf8ToBase64(value) {
  return base64EncodeBytes(new TextEncoder().encode(value));
}

function utf8FromBase64Url(value) {
  return new TextDecoder().decode(base64UrlDecodeBytes(value));
}

function base64UrlEncodeUtf8(value) {
  return base64UrlEncodeBytes(new TextEncoder().encode(value));
}

function base64EncodeBytes(bytes) {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }

  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64UrlEncodeBytes(bytes) {
  return base64EncodeBytes(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecodeBytes(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");

  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(padded, "base64"));
  }

  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
}

function timingSafeEqual(left, right) {
  if (left.length !== right.length) {
    return false;
  }

  let mismatch = 0;

  for (let index = 0; index < left.length; index += 1) {
    mismatch |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }

  return mismatch === 0;
}

function formatAuthority(host, port) {
  return isValidIpv6(host) ? `[${host}]:${port}` : `${host}:${port}`;
}

function yamlQuoted(value) {
  return JSON.stringify(String(value));
}

function isValidIpv4(host) {
  const parts = host.split(".");

  if (parts.length !== 4) {
    return false;
  }

  return parts.every((part) => {
    if (!/^\d+$/.test(part)) {
      return false;
    }

    const number = Number(part);
    return number >= 0 && number <= 255 && String(number) === part;
  });
}

function isValidHostname(host) {
  if (host.length > 253 || host.endsWith(".")) {
    return false;
  }

  return host.split(".").every((label) => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label));
}

function isValidIpv6(host) {
  if (!host.includes(":") || !/^[0-9a-fA-F:.]+$/.test(host)) {
    return false;
  }

  try {
    new URL(`http://[${host}]/`);
    return true;
  } catch {
    return false;
  }
}

function currentUnixTimestamp() {
  return Math.floor(Date.now() / 1000);
}

function unauthorizedJsonResponse() {
  return jsonResponse(401, { error: "Unauthorized" });
}

function jsonResponse(statusCode, payload, extraHeaders = {}) {
  return createResponse(statusCode, JSON.stringify(payload), {
    "Content-Type": "application/json; charset=utf-8",
    ...extraHeaders,
  });
}

function textResponse(statusCode, body, extraHeaders = {}) {
  const headers = statusCode === 204 ? extraHeaders : {
    "Content-Type": "text/plain; charset=utf-8",
    ...extraHeaders,
  };

  return createResponse(statusCode, body, headers);
}

function htmlResponse(statusCode, body, extraHeaders = {}) {
  return createResponse(statusCode, body, {
    "Content-Type": "text/html; charset=utf-8",
    ...extraHeaders,
  });
}

function redirectResponse(location, extraHeaders = {}) {
  return createResponse(302, "", {
    Location: location,
    ...extraHeaders,
  });
}

function createResponse(statusCode, body, headers = {}) {
  return {
    body,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...headers,
    },
    statusCode,
  };
}
