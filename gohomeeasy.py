#!/usr/bin/env python3
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, urlparse


DEFAULT_ALLOWED_METHODS = {
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
}
HOSTNAME_LABEL_PATTERN = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
RULE_NAME_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1F\x7F]")
IPV6_AUTHORITY_PATTERN = re.compile(r"^\[([^[\]]+)\]:(\d+)$")
HOST_PORT_PATTERN = re.compile(r"^([^:]+):(\d+)$")
SESSION_COOKIE_NAME = "ghe_session"


@dataclass
class Config:
    allowed_methods: set
    default_subscription_format: str
    listen_addr: str
    read_token: str
    session_secret: str
    session_ttl_seconds: int
    storage_path: Path
    write_token: str


def load_config() -> Config:
    default_format = os.getenv("SUBSCRIPTION_FORMAT", "ss").strip().lower()
    if default_format not in {"ss", "clash"}:
        raise RuntimeError("SUBSCRIPTION_FORMAT must be 'ss' or 'clash'")

    read_token = os.getenv("READ_TOKEN", "").strip()
    if not read_token:
        raise RuntimeError("READ_TOKEN is required")

    write_token = os.getenv("WRITE_TOKEN", "").strip()
    if not write_token:
        raise RuntimeError("WRITE_TOKEN is required")

    session_ttl = int(os.getenv("SESSION_TTL_SECONDS", "86400"))
    if session_ttl < 60:
        raise RuntimeError("SESSION_TTL_SECONDS must be at least 60")

    allowed_raw = os.getenv("ALLOWED_METHODS", "").strip()
    allowed_methods = DEFAULT_ALLOWED_METHODS if not allowed_raw else {
        item.strip().lower() for item in allowed_raw.split(",") if item.strip()
    }
    if not allowed_methods:
        raise RuntimeError("ALLOWED_METHODS must contain at least one cipher")

    return Config(
        allowed_methods=allowed_methods,
        default_subscription_format=default_format,
        listen_addr=os.getenv("LISTEN_ADDR", "127.0.0.1:8080").strip(),
        read_token=read_token,
        session_secret=os.getenv("SESSION_SECRET", "").strip(),
        session_ttl_seconds=session_ttl,
        storage_path=Path(os.getenv("STORAGE_PATH", "./data/records.json").strip()),
        write_token=write_token,
    )


class FileStorage:
    def __init__(self, path: Path, default_format: str) -> None:
        self.path = path
        self.default_format = default_format
        self._lock = threading.RLock()

    def load_document(self) -> Dict:
        if not self.path.exists():
            return {"version": 2, "records": {}, "legacy": {}}

        raw = self.path.read_text(encoding="utf-8")
        if not raw.strip():
            return {"version": 2, "records": {}, "legacy": {}}

        try:
            document = json.loads(raw)
            if isinstance(document, dict) and (
                document.get("version") == 2
                or "records" in document
                or "legacy" in document
            ):
                document.setdefault("records", {})
                document.setdefault("legacy", {})
                document["version"] = 2
                return document
        except json.JSONDecodeError:
            pass

        legacy = {}
        if self.default_format in {"ss", "clash"}:
            legacy[self.default_format] = raw
        return {"version": 2, "records": {}, "legacy": legacy}

    def save_document(self, document: Dict) -> None:
        document["version"] = 2
        document.setdefault("records", {})
        document.setdefault("legacy", {})
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_path_raw = tempfile.mkstemp(prefix="records-", suffix=".tmp", dir=self.path.parent)
        temp_path = Path(temp_path_raw)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(document, indent=2, ensure_ascii=False))
        os.replace(temp_path, self.path)

    def delete_record(self, rule_name: str) -> None:
        with self._lock:
            document = self.load_document()
            document["records"].pop(rule_name, None)
            self.save_document(document)

    def get_record(self, rule_name: str) -> Optional[Dict]:
        with self._lock:
            return self.load_document().get("records", {}).get(rule_name)

    def get_legacy_subscription(self, subtype: str) -> str:
        with self._lock:
            return self.load_document().get("legacy", {}).get(subtype, "")

    def list_records(self) -> List[Dict]:
        with self._lock:
            return list(self.load_document().get("records", {}).values())

    def put_record(self, record: Dict) -> None:
        with self._lock:
            document = self.load_document()
            document["records"][record["ruleName"]] = record
            self.save_document(document)


def normalize_rule_name(value: str) -> str:
    rule_name = (value or "").strip()
    if not rule_name:
        raise ValueError("ruleName must be a non-empty string.")
    if RULE_NAME_CONTROL_CHAR_PATTERN.search(rule_name):
        raise ValueError("ruleName must not contain control characters.")
    if len(rule_name.encode("utf-8")) > 128:
        raise ValueError("ruleName must be 128 bytes or fewer.")
    return rule_name


def normalize_record_type(value: str) -> str:
    if not (value or "").strip():
        return "ss"
    record_type = value.strip().lower()
    if record_type not in {"ss", "site"}:
        raise ValueError("type must be either 'ss' or 'site'.")
    return record_type


def normalize_host(value: str, field_name: str) -> str:
    host = value.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        ipaddress.IPv4Address(host)
        return host
    except ValueError:
        pass

    try:
        ipaddress.IPv6Address(host)
        return host
    except ValueError:
        pass

    if len(host) <= 253 and not host.endswith(".") and all(HOSTNAME_LABEL_PATTERN.match(label or "") for label in host.split(".")):
        return host

    raise ValueError(f"{field_name} must be a valid IPv4, IPv6, or DNS name.")


def normalize_port(value) -> int:
    try:
        port = int(str(value).strip())
    except (ValueError, TypeError):
        raise ValueError("Port must be an integer between 1 and 65535.") from None
    if port < 1 or port > 65535:
        raise ValueError("Port must be an integer between 1 and 65535.")
    return port


def normalize_cipher(value: str, allowed_methods: set) -> str:
    cipher = (value or "").strip().lower()
    if not cipher:
        raise ValueError("method must be a non-empty string.")
    if cipher not in allowed_methods:
        raise ValueError(f"Unsupported Shadowsocks cipher: {cipher}")
    return cipher


def normalize_password(value: str) -> str:
    password = (value or "").strip()
    if not password:
        raise ValueError("password must be a non-empty string.")
    if len(password) > 1024:
        raise ValueError("Password is too long.")
    return password


def resolve_address(raw: Dict) -> Tuple[str, int]:
    for key in ("ip", "host", "server"):
        value = str(raw.get(key, "")).strip()
        if not value:
            continue
        host = normalize_host(value, key)
        port = normalize_port(raw.get("port"))
        return host, port

    ip_addr = str(raw.get("ipAddr", "")).strip()
    if not ip_addr:
        raise ValueError("Either ip/host/server plus port, or ipAddr, is required.")

    ipv6_match = IPV6_AUTHORITY_PATTERN.match(ip_addr)
    if ipv6_match:
        return normalize_host(ipv6_match.group(1), "ipAddr"), normalize_port(ipv6_match.group(2))

    host_port_match = HOST_PORT_PATTERN.match(ip_addr)
    if host_port_match:
        return normalize_host(host_port_match.group(1), "ipAddr"), normalize_port(host_port_match.group(2))

    raise ValueError("ipAddr must be in host:port or [ipv6]:port format.")


def parse_record(body: bytes, allowed_methods: set) -> Dict:
    if not body or not body.strip():
        raise ValueError("Request body must be a non-empty JSON object.")

    try:
        raw = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid JSON body.") from exc

    if not isinstance(raw, dict):
        raise ValueError("JSON body must be an object.")

    record_type = normalize_record_type(str(raw.get("type", "")))
    host, port = resolve_address(raw)
    rule_name = normalize_rule_name(str(raw.get("ruleName", "")))
    source_time = str(raw.get("time", "")).strip()
    record = {
        "ruleName": rule_name,
        "type": record_type,
        "host": host,
        "port": port,
        "updatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    if source_time:
        record["sourceTime"] = source_time

    method = str(raw.get("method", "")).strip()
    password = str(raw.get("password", "")).strip()
    if record_type == "site":
        if method or password:
            raise ValueError("type=site records must not include method or password.")
        return record

    record["method"] = normalize_cipher(method, allowed_methods)
    record["password"] = normalize_password(password)
    return record


def build_ss_uri(record: Dict) -> str:
    authority = f"[{record['host']}]:{record['port']}" if ":" in record["host"] else f"{record['host']}:{record['port']}"
    user_info = f"{record['method']}:{record['password']}@{authority}"
    encoded = base64.b64encode(user_info.encode("utf-8")).decode("ascii")
    return f"ss://{encoded}#{quote(record['ruleName'])}"


def normalize_legacy_subscription_body(subtype: str, legacy_subscription: str) -> str:
    if subtype != "ss":
        return legacy_subscription

    trimmed = legacy_subscription.strip()
    if not is_raw_shadowsocks_subscription(trimmed):
        return legacy_subscription

    return base64.b64encode(trimmed.encode("utf-8")).decode("ascii")


def is_raw_shadowsocks_subscription(value: str) -> bool:
    if not value:
        return False

    lines = [line.strip() for line in value.splitlines() if line.strip()]
    return bool(lines) and all(line.startswith("ss://") for line in lines)


def build_clash(records: List[Dict]) -> str:
    lines = ["proxies:"]
    for record in records:
        lines.extend([
            f'  - name: {json.dumps(record["ruleName"], ensure_ascii=False)}',
            "    type: ss",
            f'    server: {json.dumps(record["host"], ensure_ascii=False)}',
            f'    port: {record["port"]}',
            f'    cipher: {json.dumps(record["method"], ensure_ascii=False)}',
            f'    password: {json.dumps(record["password"], ensure_ascii=False)}',
            "    udp: true",
        ])
    lines.append("")
    return "\n".join(lines)


def create_signed_session(mode: str, expires_at: int, secret: str) -> str:
    payload = json.dumps({"exp": expires_at, "mode": mode}, separators=(",", ":")).encode("utf-8")
    encoded_payload = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    signature = base64.urlsafe_b64encode(hmac.new(secret.encode("utf-8"), encoded_payload.encode("utf-8"), hashlib.sha256).digest()).decode("ascii").rstrip("=")
    return f"{encoded_payload}.{signature}"


def verify_session(cookie_value: str, secret: str) -> Optional[Dict]:
    try:
        encoded_payload, signature = cookie_value.split(".", 1)
    except ValueError:
        return None

    expected = base64.urlsafe_b64encode(hmac.new(secret.encode("utf-8"), encoded_payload.encode("utf-8"), hashlib.sha256).digest()).decode("ascii").rstrip("=")
    if not hmac.compare_digest(signature, expected):
        return None

    try:
        padded = encoded_payload + "=" * (-len(encoded_payload) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None

    if payload.get("mode") not in {"read", "write"}:
        return None
    if int(payload.get("exp", 0)) <= int(time.time()):
        return None
    return payload


def load_dashboard_template(view: str, mode: str) -> bytes:
    template = Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")
    return template.replace("__VIEW__", view).replace("__MODE__", mode).encode("utf-8")


class GoHomeEasyHandler(BaseHTTPRequestHandler):
    server_version = "GoHomeEasyPython/2"

    def do_OPTIONS(self):
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

    def do_GET(self):
        self.route_request()

    def do_POST(self):
        self.route_request()

    def route_request(self):
        config: Config = self.server.config  # type: ignore[attr-defined]
        storage: FileStorage = self.server.storage  # type: ignore[attr-defined]
        parsed = urlparse(self.path)
        path = parsed.path or "/"
        query = {key: values[-1] for key, values in parse_qs(parsed.query).items()}

        if path == "/healthz":
            if self.command != "GET":
                self.send_text(HTTPStatus.METHOD_NOT_ALLOWED, "Method Not Allowed", {"Allow": "GET"})
                return
            self.send_text(HTTPStatus.OK, "ok")
            return

        if path in {"/", "/subscription"} and self.command == "GET":
            fallback = config.default_subscription_format if path == "/" else "ss"
            self.handle_subscription(storage, config, query, fallback)
            return

        if path == "/" and self.command == "POST":
            self.handle_webhook(storage, config)
            return

        if path == "/webhook" and self.command == "POST":
            self.handle_webhook(storage, config)
            return

        if path == "/dashboard" and self.command == "GET":
            self.handle_dashboard(config, query)
            return

        if path == "/api/records" and self.command == "GET":
            self.handle_records_api(storage, config)
            return

        if path == "/api/delete" and self.command == "POST":
            self.handle_delete(storage, config)
            return

        if path in {"/", "/subscription"}:
            self.send_text(HTTPStatus.METHOD_NOT_ALLOWED, "Method Not Allowed", {"Allow": "GET, POST, OPTIONS" if path == "/" else "GET, OPTIONS"})
            return

        if path in {"/webhook", "/api/delete"}:
            self.send_text(HTTPStatus.METHOD_NOT_ALLOWED, "Method Not Allowed", {"Allow": "POST, OPTIONS"})
            return

        if path in {"/dashboard", "/api/records"}:
            self.send_text(HTTPStatus.METHOD_NOT_ALLOWED, "Method Not Allowed", {"Allow": "GET, OPTIONS"})
            return

        self.send_text(HTTPStatus.NOT_FOUND, "Not Found")

    def handle_subscription(self, storage: FileStorage, config: Config, query: Dict[str, str], fallback_subtype: str):
        token = self.read_bearer_token() or query.get("api_key", "").strip() or query.get("read_token", "").strip()
        if token != config.read_token:
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Unauthorized"})
            return

        subtype = (query.get("subtype") or fallback_subtype).strip().lower()
        if subtype not in {"ss", "clash"}:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "subtype must be either 'ss' or 'clash'."})
            return

        records = sorted((record for record in storage.list_records() if record.get("type") == "ss"), key=lambda record: record["ruleName"])
        if records:
            if subtype == "ss":
                body = base64.b64encode("\n".join(build_ss_uri(record) for record in records).encode("utf-8")).decode("ascii")
            else:
                body = build_clash(records)
            self.send_text(HTTPStatus.OK, body, {"X-GoHomeEasy-Format": subtype})
            return

        legacy = storage.get_legacy_subscription(subtype)
        if not legacy:
            self.send_text(HTTPStatus.NO_CONTENT, "")
            return

        self.send_text(HTTPStatus.OK, normalize_legacy_subscription_body(subtype, legacy), {
            "X-GoHomeEasy-Format": subtype,
            "X-GoHomeEasy-Legacy-Fallback": "true",
        })

    def handle_webhook(self, storage: FileStorage, config: Config):
        if self.read_bearer_token() != config.write_token:
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Unauthorized"})
            return

        body = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        try:
            record = parse_record(body, config.allowed_methods)
        except ValueError as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        storage.put_record(record)
        self.send_json(HTTPStatus.OK, {
            "message": "Record updated successfully.",
            "ruleName": record["ruleName"],
            "type": record["type"],
        })

    def handle_dashboard(self, config: Config, query: Dict[str, str]):
        if not config.session_secret:
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "dashboard not configured"})
            return

        token = query.get("api_key", "").strip()
        if token:
            mode = "write" if token == config.write_token else "read" if token == config.read_token else ""
            if not mode:
                self.send_html(HTTPStatus.UNAUTHORIZED, load_dashboard_template("login", ""))
                return

            session = create_signed_session(mode, int(time.time()) + config.session_ttl_seconds, config.session_secret)
            secure = self.request_origin().startswith("https://")
            cookie = f"{SESSION_COOKIE_NAME}={session}; Path=/; HttpOnly; SameSite=Lax"
            if secure:
                cookie += "; Secure"
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", "/dashboard")
            self.send_header("Set-Cookie", cookie)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            return

        session = self.read_session(config.session_secret)
        if not session:
            self.send_html(HTTPStatus.OK, load_dashboard_template("login", ""))
            return

        self.send_html(HTTPStatus.OK, load_dashboard_template("dashboard", session["mode"]))

    def handle_records_api(self, storage: FileStorage, config: Config):
        if not config.session_secret:
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "dashboard not configured"})
            return

        access = self.resolve_api_access(config)
        if not access:
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Unauthorized"})
            return

        records = sorted(storage.list_records(), key=lambda record: record["ruleName"])
        records.sort(key=lambda record: record.get("updatedAt", ""), reverse=True)
        has_ss = any(record.get("type") == "ss" for record in records)
        origin = self.request_origin()
        payload = {
            "legacyFallbackActive": not has_ss and bool(storage.get_legacy_subscription("ss") or storage.get_legacy_subscription("clash")),
            "mode": access["mode"],
            "records": records,
            "subscriptionUrls": {
                "ss": f"{origin}/subscription?subtype=ss&api_key={quote(config.read_token)}",
                "clash": f"{origin}/subscription?subtype=clash&api_key={quote(config.read_token)}",
            },
        }
        self.send_json(HTTPStatus.OK, payload)

    def handle_delete(self, storage: FileStorage, config: Config):
        if not config.session_secret:
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "dashboard not configured"})
            return

        delete_access = self.resolve_delete_access(config)
        if delete_access == "unauthorized":
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Unauthorized"})
            return
        if delete_access == "forbidden":
            self.send_json(HTTPStatus.FORBIDDEN, {"error": "Forbidden"})
            return

        body = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        try:
            payload = json.loads(body)
            if not isinstance(payload, dict):
                raise ValueError("JSON body must be an object.")
            rule_name = normalize_rule_name(str(payload.get("ruleName", "")))
        except (AttributeError, json.JSONDecodeError, ValueError) as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc) if str(exc) else "Invalid JSON body."})
            return

        storage.delete_record(rule_name)
        self.send_text(HTTPStatus.NO_CONTENT, "")

    def resolve_api_access(self, config: Config) -> Optional[Dict[str, str]]:
        bearer = self.read_bearer_token()
        if bearer:
            if bearer == config.write_token:
                return {"mode": "write", "via": "header"}
            if bearer == config.read_token:
                return {"mode": "read", "via": "header"}
            return None

        session = self.read_session(config.session_secret)
        if not session:
            return None
        return {"mode": session["mode"], "via": "cookie"}

    def resolve_delete_access(self, config: Config) -> str:
        bearer = self.read_bearer_token()
        if bearer:
            return "allowed" if bearer == config.write_token else "unauthorized"

        session = self.read_session(config.session_secret)
        if not session:
            return "unauthorized"
        if session.get("mode") != "write":
            return "forbidden"
        origin = self.headers.get("Origin", "")
        return "allowed" if origin and origin == self.request_origin() else "forbidden"

    def read_session(self, secret: str) -> Optional[Dict]:
        if not secret:
            return None
        cookie_header = self.headers.get("Cookie", "")
        cookies = SimpleCookie()
        cookies.load(cookie_header)
        morsel = cookies.get(SESSION_COOKIE_NAME)
        if not morsel:
            return None
        return verify_session(morsel.value, secret)

    def read_bearer_token(self) -> str:
        header = self.headers.get("Authorization", "")
        if not header.lower().startswith("bearer "):
            return ""
        return header.split(" ", 1)[1].strip()

    def request_origin(self) -> str:
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host", "")
        proto = self.headers.get("X-Forwarded-Proto", "http")
        return f"{proto}://{host}" if host else ""

    def send_html(self, status: HTTPStatus, body: bytes):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status: HTTPStatus, payload: Dict):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, status: HTTPStatus, body: str, headers: Optional[Dict[str, str]] = None):
        self.send_response(status)
        if status != HTTPStatus.NO_CONTENT:
            self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if status != HTTPStatus.NO_CONTENT:
            self.wfile.write(body.encode("utf-8"))


def main() -> None:
    config = load_config()
    host, port = config.listen_addr.rsplit(":", 1)
    server = ThreadingHTTPServer((host, int(port)), GoHomeEasyHandler)
    server.config = config  # type: ignore[attr-defined]
    server.storage = FileStorage(config.storage_path, config.default_subscription_format)  # type: ignore[attr-defined]
    print(f"starting GoHomeEasy Python on {config.listen_addr} with default_format={config.default_subscription_format} storage={config.storage_path}")
    server.serve_forever()


if __name__ == "__main__":
    main()
