#!/usr/bin/env python3
"""Simulateur ION API (Infor) autonome pour la démo : serveur de jetons OAuth 2 (grant password avec compte de
service saak/sask + client id/secret, grant refresh_token) et une API M3 factice protégée par Bearer.

  POST /<tenant>/as/token.oauth2                         grant_type=password|refresh_token (form-urlencoded)
  GET  /<tenant>/M3/m3api-rest/v2/execute/<prog>/<trans>  Authorization: Bearer <token>
  GET|POST /admin/ttl[?seconds=N]                         durée de vie des jetons (défaut 90 s, pour montrer le renouvellement)
  POST /admin/revoke                                     révoque tous les jetons émis (simule une invalidation côté Infor)

Usage : python3 ion_mock.py [port]   (défaut 8085). Aucune dépendance.
"""
import json, sys, time, threading, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8085
CLIENT_ID, CLIENT_SECRET = "demo-client-id", "demo-client-secret"
SAAK, SASK = "DEMO#saak-service-account", "sask-demo-secret"
STATE = {"ttl": 90, "tokens": {}, "refresh": set(), "issued": 0}
LOCK = threading.Lock()

class H(BaseHTTPRequestHandler):
    def _send(self, code, obj, extra=None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(body)

    def log_message(self, fmt, *args):
        sys.stdout.write("%s %s\n" % (time.strftime("%H:%M:%S"), fmt % args)); sys.stdout.flush()

    def do_OPTIONS(self):
        self._send(204, {})

    def _issue(self):
        with LOCK:
            tok, rt = "ion-" + uuid.uuid4().hex, "ionr-" + uuid.uuid4().hex
            STATE["tokens"][tok] = time.time() + STATE["ttl"]; STATE["refresh"].add(rt); STATE["issued"] += 1
            ttl = STATE["ttl"]
        return {"access_token": tok, "refresh_token": rt, "token_type": "Bearer", "expires_in": ttl}

    def do_POST(self):
        u = urlparse(self.path); ln = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(ln).decode() if ln else ""
        if u.path == "/admin/revoke":  # simule une invalidation côté Infor : tous les jetons deviennent inconnus
            with LOCK: n = len(STATE["tokens"]); STATE["tokens"].clear()
            return self._send(200, {"revoked": n})
        if u.path == "/admin/ttl":
            q = parse_qs(u.query); q.update(parse_qs(raw))
            try: STATE["ttl"] = max(5, int(q.get("seconds", [STATE["ttl"]])[0]))
            except ValueError: pass
            return self._send(200, {"ttl": STATE["ttl"]})
        if u.path.endswith("/as/token.oauth2"):
            f = {k: v[0] for k, v in parse_qs(raw).items()}
            if f.get("client_id") != CLIENT_ID or f.get("client_secret") != CLIENT_SECRET:
                return self._send(401, {"error": "invalid_client", "error_description": "client id / secret incorrects"})
            g = f.get("grant_type")
            if g == "password":
                if f.get("username") != SAAK or f.get("password") != SASK:
                    return self._send(401, {"error": "invalid_grant", "error_description": "compte de service (saak / sask) refusé"})
                return self._send(200, self._issue())
            if g == "refresh_token":
                if f.get("refresh_token") not in STATE["refresh"]:
                    return self._send(401, {"error": "invalid_grant", "error_description": "refresh token inconnu"})
                return self._send(200, self._issue())
            return self._send(400, {"error": "unsupported_grant_type"})
        return self._send(404, {"error": "not_found", "path": u.path})

    def do_GET(self):
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/admin/ttl":
            return self._send(200, {"ttl": STATE["ttl"], "issued": STATE["issued"], "active": sum(1 for e in STATE["tokens"].values() if e > time.time())})
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return self._send(401, {"error": "invalid_token", "error_description": "Authorization: Bearer manquant"}, {"WWW-Authenticate": 'Bearer realm="ION"'})
        exp = STATE["tokens"].get(auth[7:])
        if exp is None:
            return self._send(401, {"error": "invalid_token", "error_description": "jeton inconnu"})
        if exp < time.time():
            return self._send(401, {"error": "expired_token", "error_description": "jeton expiré"})
        parts = [p for p in u.path.split("/") if p]
        if "m3api-rest" in parts:
            prog, trans = parts[-2], parts[-1]
            cuno = q.get("CUNO", "C000001")
            rec = {"CUNO": cuno, "CUNM": f"Demo customer {cuno}", "CUA1": "12 Farm Road", "TOWN": "Rennes", "CSCD": "FR", "STAT": "20", "CUCL": "FARM"} if prog == "CRS610MI" \
                else {k: v for k, v in q.items()} | {"program": prog, "transaction": trans, "STAT": "20"}
            return self._send(200, {"results": [{"transaction": trans, "records": [rec]}]})
        return self._send(200, {"path": u.path, "query": q, "message": "ION API simulator"})

if __name__ == "__main__":
    print(f"ION API simulator on http://localhost:{PORT}  (token TTL {STATE['ttl']} s)", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
