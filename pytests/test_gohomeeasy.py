import base64
import io
import json
import os
import sys
import threading
import unittest
from http.cookies import SimpleCookie
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import gohomeeasy  # noqa: E402


class HandlerDouble:
    read_bearer_token = gohomeeasy.GoHomeEasyHandler.read_bearer_token
    read_session = gohomeeasy.GoHomeEasyHandler.read_session
    request_origin = gohomeeasy.GoHomeEasyHandler.request_origin
    resolve_api_access = gohomeeasy.GoHomeEasyHandler.resolve_api_access
    resolve_delete_access = gohomeeasy.GoHomeEasyHandler.resolve_delete_access

    def __init__(self, body="", headers=None):
        if isinstance(body, bytes):
            self.body = body
        else:
            self.body = str(body).encode("utf-8")

        self.headers = {
            "Content-Length": str(len(self.body)),
            "Host": "panel.example.com",
            "X-Forwarded-Proto": "https",
            **(headers or {}),
        }
        self.rfile = io.BytesIO(self.body)
        self.response = None
        self._response_headers = {}
        self._response_status = None

    def send_response(self, status):
        self._response_status = status
        self._response_headers = {}

    def send_header(self, key, value):
        self._response_headers[key] = value

    def end_headers(self):
        self.response = (self._response_status, self._response_headers, "")

    def send_html(self, status, body):
        html = body.decode("utf-8") if isinstance(body, bytes) else str(body)
        self.response = (status, {"Content-Type": "text/html; charset=utf-8"}, html)

    def send_json(self, status, payload):
        self.response = (
            status,
            {"Content-Type": "application/json; charset=utf-8"},
            json.dumps(payload, ensure_ascii=False),
        )

    def send_text(self, status, body, headers=None):
        self.response = (status, headers or {}, body)

    @property
    def status_code(self):
        return self.response[0]

    @property
    def response_headers(self):
        return self.response[1]

    @property
    def response_body(self):
        return self.response[2]


class GoHomeEasyPythonTests(unittest.TestCase):
    def test_load_config_uses_v2_defaults(self):
        with patch.dict(
            os.environ,
            {
                "READ_TOKEN": "read-token",
                "WRITE_TOKEN": "write-token",
                "SESSION_SECRET": "session-secret",
            },
            clear=True,
        ):
            config = gohomeeasy.load_config()

        self.assertEqual(config.default_subscription_format, "ss")
        self.assertEqual(config.storage_path, Path("./data/records.json"))
        self.assertEqual(config.listen_addr, "127.0.0.1:8080")
        self.assertEqual(config.session_ttl_seconds, 86400)

    def test_parse_record_enforces_type_and_address_rules(self):
        with self.assertRaisesRegex(ValueError, "type=site"):
            gohomeeasy.parse_record(
                json.dumps(
                    {
                        "ruleName": "portal",
                        "type": "site",
                        "host": "portal.example.com",
                        "port": 8443,
                        "password": "secret",
                    }
                ).encode("utf-8"),
                set(gohomeeasy.DEFAULT_ALLOWED_METHODS),
            )

        with self.assertRaisesRegex(ValueError, "ip must be a valid"):
            gohomeeasy.parse_record(
                json.dumps(
                    {
                        "ruleName": "broken",
                        "ip": "bad host",
                        "host": "good.example.com",
                        "port": 443,
                        "method": "aes-256-gcm",
                        "password": "secret",
                    }
                ).encode("utf-8"),
                set(gohomeeasy.DEFAULT_ALLOWED_METHODS),
            )

        record = gohomeeasy.parse_record(
            json.dumps(
                {
                    "ruleName": "edge",
                    "ipAddr": "edge.example.com:9443",
                    "method": "aes-256-gcm",
                    "password": "secret",
                }
            ).encode("utf-8"),
            set(gohomeeasy.DEFAULT_ALLOWED_METHODS),
        )

        self.assertEqual(record["host"], "edge.example.com")
        self.assertEqual(record["port"], 9443)
        self.assertEqual(record["type"], "ss")

    def test_http_flow_preserves_legacy_and_enforces_dashboard_rules(self):
        with TemporaryDirectory() as tempdir:
            storage_path = Path(tempdir) / "records.json"
            storage_path.write_text("legacy-clash", encoding="utf-8")
            storage = gohomeeasy.FileStorage(storage_path, "clash")
            config = gohomeeasy.Config(
                allowed_methods=set(gohomeeasy.DEFAULT_ALLOWED_METHODS),
                default_subscription_format="clash",
                listen_addr="127.0.0.1:0",
                read_token="read-token",
                session_secret="session-secret",
                session_ttl_seconds=86400,
                storage_path=storage_path,
                write_token="write-token",
            )

            legacy_handler = HandlerDouble(headers={"Authorization": "Bearer read-token"})
            gohomeeasy.GoHomeEasyHandler.handle_subscription(legacy_handler, storage, config, {}, "clash")
            self.assertEqual(legacy_handler.status_code, 200)
            self.assertEqual(legacy_handler.response_body, "legacy-clash")

            site_handler = HandlerDouble(
                body=json.dumps(
                    {
                        "ruleName": "portal",
                        "type": "site",
                        "host": "portal.example.com",
                        "port": 8443,
                    }
                ),
                headers={"Authorization": "Bearer write-token"},
            )
            gohomeeasy.GoHomeEasyHandler.handle_webhook(site_handler, storage, config)
            self.assertEqual(site_handler.status_code, 200)

            legacy_after_site = HandlerDouble(headers={"Authorization": "Bearer read-token"})
            gohomeeasy.GoHomeEasyHandler.handle_subscription(legacy_after_site, storage, config, {}, "clash")
            self.assertEqual(legacy_after_site.status_code, 200)
            self.assertEqual(legacy_after_site.response_body, "legacy-clash")

            ss_handler = HandlerDouble(
                body=json.dumps(
                    {
                        "ruleName": "alpha",
                        "ipAddr": "[2001:db8::1]:8388",
                        "method": "chacha20-ietf-poly1305",
                        "password": "密码123",
                    }
                ),
                headers={"Authorization": "Bearer write-token"},
            )
            gohomeeasy.GoHomeEasyHandler.handle_webhook(ss_handler, storage, config)
            self.assertEqual(ss_handler.status_code, 200)

            root_handler = HandlerDouble(headers={"Authorization": "Bearer read-token"})
            gohomeeasy.GoHomeEasyHandler.handle_subscription(root_handler, storage, config, {}, "clash")
            self.assertEqual(root_handler.status_code, 200)
            self.assertIn('proxies:\n  - name: "alpha"', root_handler.response_body)

            subscription_handler = HandlerDouble(headers={"Authorization": "Bearer read-token"})
            gohomeeasy.GoHomeEasyHandler.handle_subscription(
                subscription_handler,
                storage,
                config,
                {"subtype": "ss"},
                "ss",
            )
            self.assertEqual(subscription_handler.status_code, 200)
            self.assertEqual(
                base64.b64decode(subscription_handler.response_body).decode("utf-8"),
                "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTrlr4bnoIExMjNAWzIwMDE6ZGI4OjoxXTo4Mzg4#alpha",
            )

            dashboard_handler = HandlerDouble()
            gohomeeasy.GoHomeEasyHandler.handle_dashboard(dashboard_handler, config, {"api_key": "write-token"})
            self.assertEqual(dashboard_handler.status_code, 302)
            cookie_jar = SimpleCookie()
            cookie_jar.load(dashboard_handler.response_headers["Set-Cookie"])
            session_cookie = cookie_jar[gohomeeasy.SESSION_COOKIE_NAME].value

            query_only_handler = HandlerDouble()
            gohomeeasy.GoHomeEasyHandler.handle_records_api(query_only_handler, storage, config)
            self.assertEqual(query_only_handler.status_code, 401)

            records_handler = HandlerDouble(
                headers={"Cookie": f"{gohomeeasy.SESSION_COOKIE_NAME}={session_cookie}"}
            )
            gohomeeasy.GoHomeEasyHandler.handle_records_api(records_handler, storage, config)
            self.assertEqual(records_handler.status_code, 200)
            payload = json.loads(records_handler.response_body)
            self.assertEqual(payload["mode"], "write")
            self.assertEqual(len(payload["records"]), 2)
            self.assertEqual(
                payload["subscriptionUrls"]["ss"],
                "https://panel.example.com/subscription?subtype=ss&api_key=read-token",
            )

            delete_without_origin = HandlerDouble(
                body=json.dumps({"ruleName": "alpha"}),
                headers={"Cookie": f"{gohomeeasy.SESSION_COOKIE_NAME}={session_cookie}"},
            )
            gohomeeasy.GoHomeEasyHandler.handle_delete(delete_without_origin, storage, config)
            self.assertEqual(delete_without_origin.status_code, 403)

            delete_with_origin = HandlerDouble(
                body=json.dumps({"ruleName": "alpha"}),
                headers={
                    "Cookie": f"{gohomeeasy.SESSION_COOKIE_NAME}={session_cookie}",
                    "Origin": "https://panel.example.com",
                },
            )
            gohomeeasy.GoHomeEasyHandler.handle_delete(delete_with_origin, storage, config)
            self.assertEqual(delete_with_origin.status_code, 204)

    def test_legacy_ss_fallback_base64_encodes_raw_v1_uri(self):
        with TemporaryDirectory() as tempdir:
            storage_path = Path(tempdir) / "records.json"
            legacy_uri = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzQGVkZ2UuZXhhbXBsZS5jb206ODM4OA==#legacy"
            storage_path.write_text(legacy_uri, encoding="utf-8")
            storage = gohomeeasy.FileStorage(storage_path, "ss")
            config = gohomeeasy.Config(
                allowed_methods=set(gohomeeasy.DEFAULT_ALLOWED_METHODS),
                default_subscription_format="ss",
                listen_addr="127.0.0.1:0",
                read_token="read-token",
                session_secret="session-secret",
                session_ttl_seconds=86400,
                storage_path=storage_path,
                write_token="write-token",
            )

            handler = HandlerDouble(headers={"Authorization": "Bearer read-token"})
            gohomeeasy.GoHomeEasyHandler.handle_subscription(handler, storage, config, {}, "ss")

            self.assertEqual(handler.status_code, 200)
            self.assertEqual(base64.b64decode(handler.response_body).decode("utf-8"), legacy_uri)

    def test_file_storage_serializes_concurrent_writes(self):
        with TemporaryDirectory() as tempdir:
            storage = gohomeeasy.FileStorage(Path(tempdir) / "records.json", "ss")
            barrier = threading.Barrier(16)
            errors = []
            errors_lock = threading.Lock()

            def worker(index: int) -> None:
                try:
                    barrier.wait()
                    storage.put_record(
                        {
                            "ruleName": f"node-{index:02d}",
                            "type": "ss",
                            "host": f"edge-{index:02d}.example.com",
                            "port": 8000 + index,
                            "method": "aes-256-gcm",
                            "password": "secret",
                            "updatedAt": f"2026-06-26T00:00:{index:02d}Z",
                        }
                    )
                except Exception as exc:  # pragma: no cover - explicit failure capture
                    with errors_lock:
                        errors.append(exc)

            threads = [threading.Thread(target=worker, args=(index,)) for index in range(16)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            self.assertEqual(errors, [])
            self.assertEqual(len(storage.list_records()), 16)

    def test_delete_rejects_non_object_json(self):
        with TemporaryDirectory() as tempdir:
            storage = gohomeeasy.FileStorage(Path(tempdir) / "records.json", "ss")
            config = gohomeeasy.Config(
                allowed_methods=set(gohomeeasy.DEFAULT_ALLOWED_METHODS),
                default_subscription_format="ss",
                listen_addr="127.0.0.1:0",
                read_token="read-token",
                session_secret="session-secret",
                session_ttl_seconds=86400,
                storage_path=Path(tempdir) / "records.json",
                write_token="write-token",
            )

            handler = HandlerDouble(body="[]", headers={"Authorization": "Bearer write-token"})
            gohomeeasy.GoHomeEasyHandler.handle_delete(handler, storage, config)

            self.assertEqual(handler.status_code, 400)
            self.assertIn("JSON body must be an object.", handler.response_body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
