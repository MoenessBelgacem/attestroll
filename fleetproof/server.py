"""HTTP API around FleetState (stdlib only).
Auth model:
  - admin endpoints  : 'Authorization: Bearer <admin token>'
  - device endpoints : every request signed with the device's own Ed25519 key
                       (X-Device-Id, X-Timestamp, X-Nonce, X-Signature)
  - /enroll          : single-use enrollment token issued by an operator
Prototype caveat: plain HTTP. A real deployment MUST terminate TLS in front of this."""
import base64, hmac, json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from .state import FleetState, FleetError, AuthError


def make_server(state: FleetState, admin_token: str, host="127.0.0.1", port=0):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _raw(self):
            n = int(self.headers.get("Content-Length", 0))
            return self.rfile.read(n) if n else b""

        def _admin(self):
            got = self.headers.get("Authorization", "")
            if not hmac.compare_digest(got.encode(), f"Bearer {admin_token}".encode()):
                self._send(401, {"error": "admin token required"})
                return False
            return True

        def _device(self, method, raw):
            did = self.headers.get("X-Device-Id", "")
            state.authenticate(did, method, self.path, raw,
                               self.headers.get("X-Timestamp"), self.headers.get("X-Nonce", ""),
                               self.headers.get("X-Signature"))
            return did

        def _guard(self, fn):
            try:
                fn()
            except AuthError as e:
                self._send(e.http, {"error": str(e)})
            except (KeyError, ValueError, FleetError) as e:
                self._send(400, {"error": str(e)})

        def do_GET(self):
            self._guard(self._get)

        def do_POST(self):
            self._guard(self._post)

        def _get(self):
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            if u.path == "/desired":
                did = self._device("GET", b"")
                self._send(200, state.desired(did) or {"up_to_date": True})
            elif u.path in ("/status", "/audit", "/exposure"):
                if not self._admin():
                    return
                if u.path == "/status":
                    self._send(200, state.status())
                elif u.path == "/audit":
                    ok, bad = state.audit.verify()
                    self._send(200, {"valid": ok, "first_bad": bad, "entries": state.audit.entries})
                else:
                    self._send(200, {"devices": state.exposure(q["component"], q["versions"].split(","))})
            else:
                self._send(404, {"error": "not found"})

        def _post(self):
            raw = self._raw()
            if self.path == "/report":
                did = self._device("POST", raw)
                b = json.loads(raw or b"{}")
                state.report(did, b["rollout"], b["status"], b.get("detail", ""))
                self._send(200, {"ok": True})
                return
            b = json.loads(raw or b"{}")
            if self.path == "/enroll":
                state.enroll(b["id"], b["token"], b["pubkey"], b["hw"], b["group"], b["product"], b["version"])
                self._send(200, {"ok": True})
                return
            if not self._admin():
                return
            if self.path == "/releases":
                state.publish(b["manifest"], b["signature"], base64.b64decode(b["artifact_b64"]))
                self._send(200, {"ok": True})
            elif self.path == "/rollouts":
                rid = state.start_rollout(b["product"], b["version"], b.get("group", "*"),
                                          tuple(b.get("stages", (5, 25, 100))),
                                          b.get("max_failure_rate", 0.10))
                self._send(200, {"id": rid})
            elif self.path == "/admin/enrollment-tokens":
                self._send(200, {"token": state.create_enrollment_token(b["id"])})
            elif self.path == "/admin/revoke":
                state.revoke(b["id"])
                self._send(200, {"ok": True})
            else:
                self._send(404, {"error": "not found"})

    srv = ThreadingHTTPServer((host, port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
