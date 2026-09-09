#!/usr/bin/env python3
"""Simulateur universel d'authentification d'API pour la démo du package ApiAuth. Aucune dépendance obligatoire
(cryptography / pyjwt utilisés s'ils sont présents pour vérifier les JWT signés).

Serveur d'autorisation OAuth 2 :
  POST /oauth/token        grant_type = client_credentials | password | refresh_token | authorization_code
                           | urn:ietf:params:oauth:grant-type:jwt-bearer ; client authentifié dans le corps ou en Basic
  GET  /oauth/authorize    page de consentement (response_type=code, PKCE S256 optionnel) ; POST = approbation -> 302
API protégées (GET /api/<mode>/customers/<id>) :
  bearer   Authorization: Bearer <jeton OAuth 2 émis ici>
  basic    Authorization: Basic base64(basic-user:basic-pass)
  apikey   en-tête X-API-Key: key-demo-123   ou   ?api_key=key-demo-123
  static   Authorization: Bearer static-demo-token   (jeton d'accès personnel, ne change jamais)
  open     aucune authentification
Administration : GET|POST /admin/ttl[?seconds=N]  POST /admin/revoke  GET /admin/state

Usage : python3 auth_mock.py [port]   (défaut 8086)
"""
import base64, hashlib, json, os, sys, time, threading, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, urlencode

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8086
CLIENT_ID, CLIENT_SECRET = "demo-client-id", "demo-client-secret"
USER, PASSWORD = "svc-user", "svc-pass"                 # grant password (compte de service)
BASIC_USER, BASIC_PASS = "basic-user", "basic-pass"
API_KEY, STATIC_TOKEN = "key-demo-123", "static-demo-token"
CERT_PEM = os.path.join(os.path.dirname(os.path.abspath(__file__)), "is_cert.pem")   # certificat public de la clé IS (JWT bearer)
STATE = {"ttl": 90, "tokens": {}, "refresh": {}, "codes": {}, "issued": 0, "log": []}
LOCK = threading.Lock()

CONSENT = """<!doctype html><meta charset="utf-8"><title>Authorization server (simulator)</title>
<body style="font:15px system-ui;background:#0f1419;color:#e6edf3;display:grid;place-items:center;height:100vh;margin:0">
<form method="post" style="background:#161c24;border:1px solid #2a3542;border-radius:10px;padding:28px 32px;max-width:460px">
<h2 style="margin:0 0 6px">Authorization server <small style="color:#8b98a8;font-weight:400">(simulator)</small></h2>
<p style="color:#8b98a8">The application <b style="color:#e6edf3">{client_id}</b> requests access to your account.<br>Scope: <b style="color:#e6edf3">{scope}</b></p>
{hidden}
<p style="margin-top:22px"><button name="approve" value="1" style="background:#4589ff;color:#fff;border:0;padding:10px 18px;border-radius:6px;font:inherit;font-weight:600;cursor:pointer">Authorize</button>
<button name="approve" value="0" style="background:transparent;color:#e6edf3;border:1px solid #2a3542;padding:10px 18px;border-radius:6px;font:inherit;cursor:pointer">Deny</button></p>
</form></body>"""


def b64url_sha256(s):
    return base64.urlsafe_b64encode(hashlib.sha256(s.encode()).digest()).rstrip(b"=").decode()


def verify_jwt(assertion):
    """Décode l'assertion JWT ; vérifie la signature RS256 avec le certificat IS si cryptography est disponible."""
    parts = assertion.split(".")
    if len(parts) != 3:
        return None, "assertion JWT mal formée"
    def dec(p): return base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))
    try:
        header, claims = json.loads(dec(parts[0])), json.loads(dec(parts[1]))
    except Exception as e:
        return None, f"JWT illisible : {e}"
    if os.path.exists(CERT_PEM):
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            cert = x509.load_pem_x509_certificate(open(CERT_PEM, "rb").read())
            algo = {"RS256": hashes.SHA256(), "RS384": hashes.SHA384(), "RS512": hashes.SHA512()}[header.get("alg", "RS256")]
            cert.public_key().verify(dec(parts[2]), f"{parts[0]}.{parts[1]}".encode(), padding.PKCS1v15(), algo)
            claims["_signature"] = "verified (" + header.get("alg", "?") + ")"
        except ImportError:
            claims["_signature"] = "not checked (cryptography missing)"
        except Exception as e:
            return None, f"signature JWT invalide : {e}"
    else:
        claims["_signature"] = "not checked (no is_cert.pem)"
    if claims.get("exp") and float(claims["exp"]) < time.time():
        return None, "assertion JWT expirée"
    return claims, None


class H(BaseHTTPRequestHandler):
    def _send(self, code, obj, extra=None, html=None):
        body = html.encode("utf-8") if html is not None else json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ("text/html" if html is not None else "application/json") + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-API-Key")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(body)

    def log_message(self, fmt, *args):
        sys.stdout.write("%s %s\n" % (time.strftime("%H:%M:%S"), fmt % args)); sys.stdout.flush()

    def _log(self, what):
        with LOCK:
            STATE["log"].append({"time": time.strftime("%H:%M:%S"), "what": what}); STATE["log"] = STATE["log"][-40:]

    def do_OPTIONS(self):
        self._send(204, {})

    def _issue(self, grant, with_refresh=True, scope=None):
        with LOCK:
            tok, rt = "at-" + uuid.uuid4().hex, "rt-" + uuid.uuid4().hex
            STATE["tokens"][tok] = time.time() + STATE["ttl"]; STATE["issued"] += 1; ttl = STATE["ttl"]
            if with_refresh: STATE["refresh"][rt] = grant
        r = {"access_token": tok, "token_type": "Bearer", "expires_in": ttl}
        if with_refresh: r["refresh_token"] = rt
        if scope: r["scope"] = scope
        self._log(f"token issued ({grant}), ttl {ttl} s"); return r

    def _client_ok(self, f):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Basic "):
            try: u, p = base64.b64decode(auth[6:]).decode().split(":", 1)
            except Exception: return False, "Basic illisible"
            return (u == CLIENT_ID and p == CLIENT_SECRET), "client (Basic) : " + ("ok" if u == CLIENT_ID and p == CLIENT_SECRET else "refusé")
        return (f.get("client_id") == CLIENT_ID and f.get("client_secret") == CLIENT_SECRET), "client (corps) : " + ("ok" if f.get("client_id") == CLIENT_ID and f.get("client_secret") == CLIENT_SECRET else "refusé")

    def do_POST(self):
        u = urlparse(self.path); ln = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(ln).decode() if ln else ""
        f = {k: v[0] for k, v in parse_qs(raw).items()}
        if u.path == "/api/echo":
            return self._send(200, {"headers": {k: v for k, v in self.headers.items()}, "form": f, "raw": raw})
        if u.path == "/admin/revoke":
            with LOCK: n = len(STATE["tokens"]); STATE["tokens"].clear()
            self._log(f"all tokens revoked ({n})"); return self._send(200, {"revoked": n})
        if u.path == "/admin/ttl":
            q = parse_qs(u.query); q.update(parse_qs(raw))
            try: STATE["ttl"] = max(5, int(q.get("seconds", [STATE["ttl"]])[0]))
            except ValueError: pass
            return self._send(200, {"ttl": STATE["ttl"]})
        if u.path == "/oauth/authorize":            # approbation du consentement -> redirection avec le code
            q = {k: v[0] for k, v in parse_qs(u.query).items()}; q.update(f)
            sep = "&" if "?" in q.get("redirect_uri", "") else "?"
            if f.get("approve") != "1":
                return self._send(302, {}, {"Location": q["redirect_uri"] + sep + urlencode({"error": "access_denied", "state": q.get("state", "")})})
            code = "code-" + uuid.uuid4().hex
            with LOCK: STATE["codes"][code] = {"client_id": q.get("client_id"), "redirect_uri": q.get("redirect_uri"), "challenge": q.get("code_challenge"), "method": q.get("code_challenge_method"), "scope": q.get("scope"), "exp": time.time() + 120}
            self._log("authorization code issued (user consent)")
            return self._send(302, {}, {"Location": q["redirect_uri"] + sep + urlencode({"code": code, "state": q.get("state", "")})})
        if u.path == "/oauth/token":
            g = f.get("grant_type"); ok, why = self._client_ok(f)
            if g == "urn:ietf:params:oauth:grant-type:jwt-bearer":
                claims, err = verify_jwt(f.get("assertion", ""))
                if err: self._log("jwt-bearer refused: " + err); return self._send(401, {"error": "invalid_grant", "error_description": err})
                if claims.get("iss") != CLIENT_ID: return self._send(401, {"error": "invalid_grant", "error_description": f"issuer inconnu : {claims.get('iss')}"})
                self._log(f"jwt-bearer accepted, {claims.get('_signature')}")
                return self._send(200, self._issue("jwt-bearer", with_refresh=False, scope=claims.get("scope")))
            if not ok:
                self._log("token refused: " + why); return self._send(401, {"error": "invalid_client", "error_description": why})
            if g == "client_credentials":
                return self._send(200, self._issue("client_credentials", with_refresh=False, scope=f.get("scope")))
            if g == "password":
                if f.get("username") != USER or f.get("password") != PASSWORD:
                    self._log("password grant refused"); return self._send(401, {"error": "invalid_grant", "error_description": "identifiants du compte de service refusés"})
                return self._send(200, self._issue("password", scope=f.get("scope")))
            if g == "refresh_token":
                with LOCK: src = STATE["refresh"].pop(f.get("refresh_token"), None)   # rotation : un refresh token ne sert qu'une fois
                if not src: self._log("refresh refused (unknown or already used)"); return self._send(401, {"error": "invalid_grant", "error_description": "refresh token inconnu ou déjà utilisé"})
                return self._send(200, self._issue("refresh:" + src))
            if g == "authorization_code":
                with LOCK: c = STATE["codes"].pop(f.get("code"), None)
                if not c or c["exp"] < time.time(): return self._send(401, {"error": "invalid_grant", "error_description": "code inconnu ou expiré"})
                if c["redirect_uri"] != f.get("redirect_uri"): return self._send(401, {"error": "invalid_grant", "error_description": "redirect_uri différent"})
                if c["challenge"]:
                    v = f.get("code_verifier", "")
                    exp = b64url_sha256(v) if c["method"] == "S256" else v
                    if exp != c["challenge"]: self._log("PKCE verifier mismatch"); return self._send(401, {"error": "invalid_grant", "error_description": "PKCE : code_verifier invalide"})
                    self._log("PKCE verifier ok")
                return self._send(200, self._issue("authorization_code", scope=c.get("scope")))
            return self._send(400, {"error": "unsupported_grant_type", "error_description": str(g)})
        return self._send(404, {"error": "not_found", "path": u.path})

    def _check(self, mode, q):
        auth = self.headers.get("Authorization", "")
        if mode == "open": return None
        if mode == "bearer":
            if not auth.startswith("Bearer "): return (401, {"error": "invalid_token", "error_description": "Authorization: Bearer manquant"})
            exp = STATE["tokens"].get(auth[7:])
            if exp is None: return (401, {"error": "invalid_token", "error_description": "jeton inconnu (révoqué ?)"})
            if exp < time.time(): return (401, {"error": "expired_token", "error_description": "jeton expiré"})
            return None
        if mode == "static":
            return None if auth == "Bearer " + STATIC_TOKEN else (401, {"error": "invalid_token", "error_description": "jeton personnel invalide"})
        if mode == "basic":
            try: u_, p_ = base64.b64decode(auth[6:]).decode().split(":", 1) if auth.startswith("Basic ") else ("", "")
            except Exception: u_, p_ = "", ""
            return None if (u_, p_) == (BASIC_USER, BASIC_PASS) else (401, {"error": "unauthorized", "error_description": "Basic : utilisateur / mot de passe refusés"})
        if mode == "apikey":
            k = self.headers.get("X-API-Key") or q.get("api_key")
            return None if k == API_KEY else (401, {"error": "invalid_api_key", "error_description": "clé d'API absente ou incorrecte"})
        return (404, {"error": "unknown_mode", "error_description": mode})

    def do_GET(self):
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/admin/ttl":
            return self._send(200, {"ttl": STATE["ttl"], "issued": STATE["issued"], "active": sum(1 for e in STATE["tokens"].values() if e > time.time())})
        if u.path == "/admin/state":
            return self._send(200, {"ttl": STATE["ttl"], "issued": STATE["issued"], "active": sum(1 for e in STATE["tokens"].values() if e > time.time()), "log": STATE["log"][::-1]})
        if u.path == "/oauth/authorize":
            hidden = "".join(f'<input type="hidden" name="{k}" value="{v}">' for k, v in q.items())
            return self._send(200, {}, html=CONSENT.format(client_id=q.get("client_id", "?"), scope=q.get("scope", "-"), hidden=hidden))
        if u.path == "/api/echo":
            return self._send(200, {"headers": {k: v for k, v in self.headers.items()}, "query": q})
        parts = [p for p in u.path.split("/") if p]
        if len(parts) >= 2 and parts[0] == "api":
            mode = parts[1]; err = self._check(mode, q)
            if err:
                self._log(f"{mode}: {err[1]['error']}"); return self._send(err[0], err[1], {"WWW-Authenticate": "Bearer"} if err[0] == 401 else None)
            cid = parts[-1] if len(parts) > 3 else "C000001"
            return self._send(200, {"auth": mode, "customer": {"id": cid, "name": f"Demo customer {cid}", "city": "Rennes", "country": "FR", "segment": "FARM"}, "query": q})
        return self._send(200, {"message": "API auth simulator", "path": u.path})

    do_PUT = do_POST


if __name__ == "__main__":
    print(f"API auth simulator on http://localhost:{PORT}  (token TTL {STATE['ttl']} s, cert {'found' if os.path.exists(CERT_PEM) else 'missing'})", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
