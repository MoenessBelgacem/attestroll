"""Minimal HTTP API around FleetState (stdlib only). Prototype: no TLS, static admin token."""
import json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import base64
from .state import FleetState, FleetError

ADMIN_TOKEN = "demo-admin-token"   # prototype only


def make_server(state: FleetState, host="127.0.0.1", port=0):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence
            pass

        def _send(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
            n = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(n) or b"{}")

        def _admin(self):
            if self.headers.get("Authorization") != f"Bearer {ADMIN_TOKEN}":
                self._send(401, {"error": "admin token required"})
                return False
            return True

        def do_GET(self):
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            try:
                if u.path == "/desired":
                    self._send(200, state.desired(q["device"]) or {"up_to_date": True})
                elif u.path == "/status":
                    self._send(200, state.status())
                elif u.path == "/audit":
                    ok, bad = state.audit.verify()
                    self._send(200, {"valid": ok, "first_bad": bad, "entries": state.audit.entries})
                elif u.path == "/exposure":
                    self._send(200, {"devices": state.exposure(q["component"], q["versions"].split(","))})
                else:
                    self._send(404, {"error": "not found"})
            except (KeyError, FleetError) as e:
                self._send(400, {"error": str(e)})

        def do_POST(self):
            try:
                b = self._body()
                if self.path == "/register":
                    state.register(b["id"], b["hw"], b["group"], b["product"], b["version"])
                    self._send(200, {"ok": True})
                elif self.path == "/report":
                    state.report(b["device"], b["rollout"], b["status"], b.get("detail", ""))
                    self._send(200, {"ok": True})
                elif self.path == "/releases":
                    if not self._admin():
                        return
                    state.publish(b["manifest"], b["signature"], base64.b64decode(b["artifact_b64"]))
                    self._send(200, {"ok": True})
                elif self.path == "/rollouts":
                    if not self._admin():
                        return
                    rid = state.start_rollout(b["product"], b["version"], b.get("group", "*"),
                                              tuple(b.get("stages", (5, 25, 100))),
                                              b.get("max_failure_rate", 0.10))
                    self._send(200, {"id": rid})
                else:
                    self._send(404, {"error": "not found"})
            except (KeyError, FleetError) as e:
                self._send(400, {"error": str(e)})

    srv = ThreadingHTTPServer((host, port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
