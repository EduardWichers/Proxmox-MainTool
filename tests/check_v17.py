"""Tests version 1.7 of the backend in-process on the tool container, from a copy in /tmp with its own state folder.

Nothing on the cluster is changed and nothing is sent to the internet. SSO runs against stand-ins: an OpenID provider
and a Cloudflare team whose tokens are signed with RSA keys made by OpenSSL for this test only (so the tool's own
signature check is measured against an independent implementation), and a stand-in for Proxmox's login endpoint.
Disk resizing runs against a stand-in cluster that only writes down what it is asked to do. At the end the real
cluster is only read (realms, disk configurations, the report). No secrets are used or shown."""
import asyncio, base64, datetime as dt, hashlib, hmac, json, os, secrets, subprocess, sys, tempfile, time, urllib.parse
for line in open("/etc/maintool/maintool.env", encoding="utf-8"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ[k.strip()] = v.strip()
os.environ["STATE_DIRECTORY"] = "/tmp/mt-v17/state"
sys.path.insert(0, "/tmp/mt-v17/app")
import main  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.routing import APIRoute  # noqa: E402
from proxmoxer.core import ResourceException  # noqa: E402

FAILED, MAILLOG = [], []


def check(label, ok, extra=""):
    if not ok:
        FAILED.append(label)
    print(f"{'OK  ' if ok else 'FOUT'} {label} {extra}")


# ---------------------------------------------------------------- tripwires: niets mag naar buiten
TRIPPED = []
REAL_RUN, REAL_CONNECT, REAL_FETCH, REAL_SESSION = main.pve.run, main.pve.connect, main.fetch_json, main.requests.Session
main.agent = lambda *a, **k: TRIPPED.append(("agent", a)) or (_ for _ in ()).throw(AssertionError("agent"))


class FakeSMTP:
    def __init__(self, host, port, timeout=None, context=None):
        self.entry = {"host": host, "sent": []}
        MAILLOG.append(self.entry)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        pass

    def login(self, user, password):
        pass

    def noop(self):
        pass

    def send_message(self, msg):
        self.entry["sent"].append(msg["Subject"])


main.smtplib.SMTP = main.smtplib.SMTP_SSL = FakeSMTP

HOST = "tool.example"


def call(method, path, cookie=None, body=None, origin=f"https://{HOST}", host=HOST, headers=None, cookies=None, source="203.0.113.7"):
    """Een verzoek recht in de applicatie. Geeft (status, inhoud, set-cookie-regels, Location)."""
    route, _, query = path.partition("?")
    hdrs = [(b"host", host.encode())]
    if origin:
        hdrs.append((b"origin", origin.encode()))
    jar = dict(cookies or {})
    if cookie:
        jar[main.SESSION_COOKIE] = cookie
    if jar:
        hdrs.append((b"cookie", "; ".join(f"{k}={v}" for k, v in jar.items()).encode()))
    for k, v in (headers or {}).items():
        hdrs.append((k.lower().encode(), v.encode()))
    data = b"" if body is None else json.dumps(body).encode()
    if body is not None:
        hdrs += [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode())]
    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1", "method": method,
             "scheme": "https", "path": route, "raw_path": route.encode(), "query_string": query.encode(), "root_path": "",
             "headers": hdrs, "client": (source, 40000), "server": (host, 443)}
    sent, asked = [], []

    async def receive():
        if not asked:
            asked.append(1)
            return {"type": "http.request", "body": data, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    asyncio.run(main.app(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    try:
        parsed = json.loads(raw)
    except ValueError:
        parsed = raw.decode("utf-8", "replace")
    setc = [v.decode() for k, v in start["headers"] if k == b"set-cookie"]
    loc = next((v.decode() for k, v in start["headers"] if k == b"location"), "")
    return start["status"], parsed, setc, loc


def detail(r):
    return r[1].get("detail") if isinstance(r[1], dict) else str(r[1])[:90]


def session_of(setc):
    for c in setc:
        if c.startswith(main.SESSION_COOKIE + "=") and "Max-Age=0" not in c and 'maintool_session=""' not in c:
            return c.split(";")[0].split("=", 1)[1]
    return None


def cookie_of(setc, name):
    for c in setc:
        if c.startswith(name + "="):
            return c.split(";")[0].split("=", 1)[1]
    return None


# ---------------------------------------------------------------- RSA-sleutels en tokens, gemaakt door OpenSSL
TMP = tempfile.mkdtemp(prefix="v17-")


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def rsa_key(bits: int, name: str) -> dict:
    path = os.path.join(TMP, name + ".pem")
    subprocess.run(["openssl", "genrsa", "-out", path, str(bits)], check=True, capture_output=True)
    text = subprocess.run(["openssl", "rsa", "-in", path, "-noout", "-modulus"], check=True, capture_output=True, text=True).stdout
    n = int(text.strip().split("=", 1)[1], 16)
    return {"path": path, "jwk": {"kty": "RSA", "kid": name, "use": "sig", "alg": "RS256", "n": b64u(n.to_bytes((n.bit_length() + 7) // 8, "big")), "e": "AQAB"}}


def sign_rs256(key: dict, signing_input: bytes) -> bytes:
    return subprocess.run(["openssl", "dgst", "-sha256", "-sign", key["path"]], input=signing_input, check=True, capture_output=True).stdout


def jwt(key, claims, kid="__key__", alg="RS256", secret=None, header_extra=None):
    header = {"alg": alg, "typ": "JWT", **(header_extra or {})}
    if kid == "__key__" and key:
        header["kid"] = key["jwk"]["kid"]
    elif kid not in ("__key__", None):
        header["kid"] = kid
    signing = f"{b64u(json.dumps(header).encode())}.{b64u(json.dumps(claims).encode())}".encode()
    if alg == "RS256":
        sig = sign_rs256(key, signing)
    elif alg == "HS256":
        sig = hmac.new(secret.encode(), signing, hashlib.sha256).digest()
    else:
        sig = b""
    return signing.decode() + "." + b64u(sig)


K1, K2, KWEAK = rsa_key(2048, "sleutel-1"), rsa_key(2048, "sleutel-2"), rsa_key(1024, "zwak")
now = int(time.time())

print("--- A. handtekeningen en tokens")
signed = b"header.payload"
sig = sign_rs256(K1, signed)
check("een handtekening van OpenSSL wordt goedgekeurd", main.rs256_ok(K1["jwk"], signed, sig))
check("met een andere sleutel niet", not main.rs256_ok(K2["jwk"], signed, sig))
check("een gewijzigde inhoud niet", not main.rs256_ok(K1["jwk"], b"header.payloaD", sig))
check("een gewijzigde handtekening niet", not main.rs256_ok(K1["jwk"], signed, sig[:-1] + bytes([sig[-1] ^ 1])))
check("een te korte handtekening niet", not main.rs256_ok(K1["jwk"], signed, sig[1:]))
check("een sleutel van 1024 bit telt niet", not main.rs256_ok(KWEAK["jwk"], signed, sign_rs256(KWEAK, signed)))
check("een kapotte sleutel geeft nee, geen fout", not main.rs256_ok({"n": "!!", "e": "AQAB"}, signed, sig) and not main.rs256_ok({}, signed, sig))
ISS, AUD = "https://idp.voorbeeld.nl/realms/test", "maintool-client"
good = {"iss": ISS, "aud": AUD, "sub": "u-1", "exp": now + 300, "iat": now}


def jwt_reason(token, keys=(K1["jwk"],), secret=None, iss=ISS, aud=AUD):
    try:
        main.jwt_check(token, list(keys), secret, iss, aud)
        return "goed"
    except main.JWTError as err:
        return str(err)


check("een geldig token komt door", jwt_reason(jwt(K1, good)) == "goed")
check("doelgroep als lijst komt door", jwt_reason(jwt(K1, {**good, "aud": ["iets", AUD]})) == "goed")
for label, token, want in [
        ("alg none geweigerd", jwt(None, good, kid=None, alg="none"), "ondertekening"),
        ("HS256 zonder secret geweigerd", jwt(None, good, kid=None, alg="HS256", secret="x"), "ondertekening"),
        ("andere uitgever geweigerd", jwt(K1, {**good, "iss": "https://kwaad.example"}), "uitgever"),
        ("andere doelgroep geweigerd", jwt(K1, {**good, "aud": "ander"}), "doelgroep"),
        ("verlopen geweigerd", jwt(K1, {**good, "exp": now - 120}), "verlopen"),
        ("zonder exp geweigerd", jwt(K1, {k: v for k, v in good.items() if k != "exp"}), "verlopen"),
        ("nog niet geldig (nbf) geweigerd", jwt(K1, {**good, "nbf": now + 600}), "nog niet geldig"),
        ("van een onbekende sleutel: 'sleutel'", jwt(K2, good), "sleutel"),
        ("van K2 maar met de naam van K1 geweigerd", jwt(K2, good, kid="sleutel-1"), "handtekening"),
        ("onzin geweigerd", "a.b", "vorm"),
        ("te groot geweigerd", "a." + "b" * 20000 + ".c", "vorm")]:
    check(label, jwt_reason(token) == want, jwt_reason(token))
check("HS256 met het juiste secret komt door", jwt_reason(jwt(None, good, kid=None, alg="HS256", secret="geheim-1"), secret="geheim-1") == "goed")
check("HS256 met een ander secret geweigerd", jwt_reason(jwt(None, good, kid=None, alg="HS256", secret="geheim-2"), secret="geheim-1") == "handtekening")
check("zonder kid en met twee sleutels geweigerd", jwt_reason(jwt(K1, good, kid=None), keys=(K1["jwk"], K2["jwk"])) == "sleutel")
check("zonder kid en één sleutel komt door", jwt_reason(jwt(K1, good, kid=None)) == "goed")

# ---------------------------------------------------------------- de nagebootste diensten
CF_TEAM, CF_AUD = "voorbeeldteam", "ab" * 32
CF_ISS = f"https://{CF_TEAM}.cloudflareaccess.com"
IDP = {"keys": [K1["jwk"]], "auth_methods": ["client_secret_post", "client_secret_basic"], "codes": {}, "token_calls": [], "down": False, "cf_keys": [K2["jwk"]]}
FETCHES = []


def discovery(issuer):
    return {"issuer": issuer, "authorization_endpoint": issuer + "/auth", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys",
            "token_endpoint_auth_methods_supported": IDP["auth_methods"]}


def fake_fetch(url, data=None, auth=None):
    FETCHES.append(url)
    if IDP["down"]:
        raise main.SSOError("onbereikbaar (ConnectionError)")
    if url == CF_ISS + "/cdn-cgi/access/certs":
        return {"keys": IDP["cf_keys"]}
    if url.startswith("https://idp.voorbeeld.nl/") or url.startswith("https://login.microsoftonline.com/"):
        base = url.split("/.well-known")[0]
        if url.endswith("/.well-known/openid-configuration"):
            if "verkeerd" in url:
                return {**discovery(base), "issuer": "https://kwaad.example"}
            return discovery(base)
        if url.endswith("/keys"):
            return {"keys": IDP["keys"]}
        if url.endswith("/token"):
            IDP["token_calls"].append({"data": dict(data or {}), "auth": auth})
            grant = IDP["codes"].pop((data or {}).get("code"), None)
            if not grant:
                raise main.SSOError("HTTP 400 invalid_grant")
            if hashlib.sha256(data["code_verifier"].encode()).digest() != base64.urlsafe_b64decode(grant["challenge"] + "=="):
                raise main.SSOError("HTTP 400 pkce")
            if data.get("redirect_uri") != grant["redirect_uri"]:
                raise main.SSOError("HTTP 400 redirect_uri")
            return {"access_token": "x", "id_token": grant["make"](grant["nonce"])}
    raise main.SSOError("onbekend adres " + url)


main.fetch_json = fake_fetch
main._jwks.clear()
main._discovery.clear()


class World:
    def __init__(self):
        self.table, self.changes, self.answers, self.fail = {}, [], {}, None

    def call(self, method, path, kw):
        if method != "GET":
            self.changes.append((method, path, kw))
            if self.fail:
                raise self.fail
            return self.answers.get((method, path))
        if path in self.table:
            value = self.table[path]
            return value(kw) if callable(value) else value
        raise ResourceException(501, "niet nagebootst", path)


class Fake:
    def __init__(self, world, path=()):
        self.__dict__["world"], self.__dict__["path"] = world, path

    def __getattr__(self, name):
        if name in ("get", "post", "put", "delete"):
            return lambda **kw: self.world.call(name.upper(), "/".join(self.path), kw)
        return Fake(self.world, self.path + (name,))

    def __call__(self, *args):
        return Fake(self.world, self.path + tuple(str(a) for a in args))


W = World()
W.table["access/domains"] = [{"realm": "pam", "type": "pam", "comment": "Linux PAM"}, {"realm": "pve", "type": "pve", "comment": "Proxmox VE"},
                             {"realm": "slecht realm!", "type": "ad"}]


def run(fn):
    try:
        return fn(Fake(W))
    except ResourceException as e:
        raise HTTPException(e.status_code or 500, f"Proxmox: {e.status_message} {e.content or ''}".strip())


main.pve.run = run
main.pve.connect = lambda *a, **k: TRIPPED.append("verbinden") or (_ for _ in ()).throw(AssertionError("echte verbinding"))
TICKETS = []


class FakeSession:
    """Staat in voor de verbinding met /access/ticket van Proxmox."""
    def __init__(self):
        self.verify, self.mounted = None, []

    def mount(self, prefix, adapter):
        self.mounted.append((prefix, type(adapter).__name__))

    def post(self, url, data=None, timeout=None, allow_redirects=True):
        TICKETS.append({"url": url, "user": data["username"], "verify": self.verify, "mounted": list(self.mounted), "redirects": allow_redirects})
        ok = {"jan@pam": "juist-wachtwoord", "tfa@pve": "juist-wachtwoord", "ander@pam": "juist-wachtwoord"}
        if ok.get(data["username"]) != data["password"]:
            return type("R", (), {"status_code": 401, "json": lambda s: {"data": None}})()
        answer = {"ticket": "PVE:nagemaakt", "username": data["username"], "CSRFPreventionToken": "x"}
        if data["username"] == "tfa@pve":
            answer["NeedTFA"] = 1
        if data["username"] == "ander@pam":
            answer["username"] = "iemand-anders@pam"
        return type("R", (), {"status_code": 200, "json": lambda s: {"data": answer}})()


main.requests.Session = FakeSession

# ---------------------------------------------------------------- gebruikers
PW = {k: secrets.token_urlsafe(18) for k in ("lezer", "beheer2", "nieuw")}
main.login_guard.failures.clear()
r = call("POST", "/api/login", body={"username": main.APP_USER, "password": main.APP_PASSWORD}); ROOT = session_of(r[2])
check("hoofdaccount logt in (in het testproces)", r[0] == 200 and ROOT)
for name, roles in (("lezer", []), ("beheer2", ["admin"])):
    r = call("POST", "/api/users", ROOT, {"name": name, "roles": roles, "password": PW[name]})
    check(f"gebruiker {name} aangemaakt", r[0] == 200, detail(r) or "")
READER = session_of(call("POST", "/api/login", body={"username": "lezer", "password": PW["lezer"]})[2])
ADMIN2 = session_of(call("POST", "/api/login", body={"username": "beheer2", "password": PW["beheer2"]})[2])
check("lezer en beheer2 logden in", READER and ADMIN2)

print("--- B. OpenID Connect instellen")
base = {"enabled": True, "provider": "keycloak", "issuer": ISS, "client_id": AUD, "client_secret": "nagemaakt-secret-1", "public_url": "https://maintool.voorbeeld.nl/"}
for label, change, code in [
        ("uitgever via http geweigerd", {"issuer": "http://idp.voorbeeld.nl/realms/test"}, 400),
        ("uitgever met {tenantid} geweigerd", {"issuer": "https://login.microsoftonline.com/{tenantid}/v2.0"}, 400),
        ("adres van de tool met een pad geweigerd", {"public_url": "https://maintool.voorbeeld.nl/sub"}, 400),
        ("adres van de tool via http geweigerd", {"public_url": "http://maintool.voorbeeld.nl"}, 400),
        ("naam op de knop met < geweigerd", {"label": "<b>x</b>"}, 400),
        ("onbekende soort geweigerd", {"provider": "facebook"}, 400),
        ("zonder secret (nog niets bewaard) geweigerd", {"client_secret": None}, 400),
        ("client-ID met spatie geweigerd", {"client_id": "a b"}, 400),
        ("dienst met een andere uitgever geweigerd (502)", {"issuer": "https://idp.voorbeeld.nl/verkeerd"}, 502)]:
    r = call("PUT", "/api/sso/oidc", ROOT, {**base, **change})
    check(label, r[0] == code, f"{r[0]} {detail(r)}")
check("na de weigeringen is er niets bewaard", not main.SSO_FILE.exists())
IDP["down"] = True
r = call("PUT", "/api/sso/oidc", ROOT, base)
IDP["down"] = False
check("onbereikbare dienst: 502 en niets bewaard", r[0] == 502 and not main.SSO_FILE.exists(), detail(r))
r = call("PUT", "/api/sso/oidc", READER, base)
check("de lezer mag het niet instellen", r[0] == 403)
r = call("PUT", "/api/sso/oidc", ROOT, base, origin="https://kwaad.example")
check("vanaf een andere website geweigerd", r[0] == 403)
r = call("PUT", "/api/sso/oidc", ROOT, base)
check("beheerder zet OpenID aan", r[0] == 200 and r[1]["oidc"]["ready"], detail(r) or "")
check("het secret gaat niet terug naar de pagina, alleen dat er een is", "nagemaakt-secret-1" not in json.dumps(r[1]) and r[1]["oidc"]["secret_set"])
check("adres van de tool zonder / aan het eind, redirect-URI klopt", r[1]["oidc"]["public_url"] == "https://maintool.voorbeeld.nl"
      and r[1]["oidc"]["redirect_uri"] == "https://maintool.voorbeeld.nl/api/sso/oidc/callback")
check("sso.json is alleen voor de tool leesbaar (600)", oct(os.stat(main.SSO_FILE).st_mode & 0o777) == "0o600")
r = call("GET", "/api/sso", READER)
check("de lezer mag de instellingen niet zien", r[0] == 403)
r = call("PUT", "/api/sso/oidc", ROOT, {**base, "client_secret": None})
check("opnieuw opslaan zonder secret houdt het bewaarde", r[0] == 200 and main.sso_conf("oidc")["client_secret"] == "nagemaakt-secret-1")
r = call("PUT", "/api/sso/oidc", ROOT, {**base, "client_secret": None, "client_id": "andere-client"})
check("andere client-ID zonder secret geweigerd (het secret gaat niet mee naar een andere app)", r[0] == 400 and main.sso_conf("oidc")["client_id"] == AUD, detail(r))
r = call("GET", "/api/sso/options")
check("de inlogpagina ziet de knop, zonder geheimen", r[0] == 200 and r[1]["oidc"]["start"] == "https://maintool.voorbeeld.nl/api/sso/oidc/start"
      and "secret" not in json.dumps(r[1]) and AUD not in json.dumps(r[1]) and r[1]["cloudflare"] is False and r[1]["proxmox"] is None)

print("--- C. inloggen met OpenID Connect")
PUBLIC = "maintool.voorbeeld.nl"


def oidc_login(email="lezer@voorbeeld.nl", sub="u-1", then="", mutate=None, claims_extra=None, key=K1, host=PUBLIC, source="198.51.100.20"):
    """De hele ronde: start, de dienst geeft een code, terug naar de tool. Geeft (status, Location, sessie)."""
    r = call("GET", "/api/sso/oidc/start" + ("?then=" + then if then else ""), host=host, origin=None, source=source)
    if r[0] != 303 or not r[3].startswith(ISS + "/auth?"):
        return r[0], r[3], None
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(r[3]).query))
    state_cookie = cookie_of(r[2], main.OIDC_COOKIE)
    code = secrets.token_urlsafe(12)
    claims = {"iss": ISS, "aud": AUD, "sub": sub, "exp": int(time.time()) + 300, "iat": int(time.time()), "email": email, **(claims_extra or {})}
    IDP["codes"][code] = {"challenge": q["code_challenge"], "redirect_uri": q["redirect_uri"], "nonce": q["nonce"],
                          "make": lambda nonce: jwt(key, {**claims, "nonce": claims.get("nonce", nonce)})}
    params = {"code": code, "state": q["state"]}
    jar = {main.OIDC_COOKIE: state_cookie}
    if mutate:
        params, jar = mutate(params, jar)
    r = call("GET", "/api/sso/oidc/callback?" + urllib.parse.urlencode(params), host=host, origin=None, cookies={k: v for k, v in jar.items() if v}, source=source)
    return r[0], r[3], session_of(r[2]), q, r[2]


r = call("GET", "/api/sso/oidc/start", host="192.0.2.10:8443", origin=None)
check("start op een ander adres gaat eerst naar het adres van de tool", r[0] == 303 and r[3] == "https://maintool.voorbeeld.nl/api/sso/oidc/start")
st = call("GET", "/api/sso/oidc/start", host=PUBLIC, origin=None)
q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(st[3]).query))
ck = next(c for c in st[2] if c.startswith(main.OIDC_COOKIE + "="))
check("start stuurt door met code flow, PKCE S256, state en nonce",
      q.get("response_type") == "code" and q.get("client_id") == AUD and q.get("code_challenge_method") == "S256" and len(q.get("code_challenge", "")) == 43
      and len(q.get("state", "")) >= 30 and len(q.get("nonce", "")) >= 30 and q.get("redirect_uri") == "https://maintool.voorbeeld.nl/api/sso/oidc/callback"
      and q.get("scope") == "openid email profile", json.dumps({k: v for k, v in q.items() if k in ("response_type", "scope")}))
check("het cookie met de controlegegevens is HttpOnly, Secure, SameSite=Lax, 10 minuten, alleen voor /api/sso/oidc",
      "HttpOnly" in ck and "Secure" in ck and "SameSite=lax" in ck.replace("Lax", "lax") and "Max-Age=600" in ck and "Path=/api/sso/oidc" in ck)
check("de code_verifier staat niet in de doorverwijzing", "code_verifier" not in st[3])

res = oidc_login()
check("niet gekoppeld mailadres: terug naar inloggen (unknown), geen sessie", res[0] == 303 and res[1] == "/login?sso=unknown" and not res[2], str(res[:2]))
r = call("PUT", "/api/users/lezer", ROOT, {"sso": {"oidc": "Lezer@Voorbeeld.nl"}})
check("beheerder koppelt lezer aan een OpenID-mailadres (kleine letters)", r[0] == 200 and next(u for u in r[1] if u["name"] == "lezer")["sso"] == {"oidc": "lezer@voorbeeld.nl"})
check("koppeling toevoegen beëindigt de sessie van lezer niet", call("GET", "/api/me", READER)[0] == 200)
main.login_guard.failures.clear()
res = oidc_login()
call_me = call("GET", "/api/me", res[2]) if res[2] else (0, {})
check("gekoppeld: binnen, met een sessie van lezer, naar /", res[0] == 303 and res[1] == "/" and call_me[0] == 200 and call_me[1]["user"] == "lezer", str(res[:2]))
check("het controlecookie wordt na afloop gewist", any(c.startswith(main.OIDC_COOKIE + "=") and ("Max-Age=0" in c or 'expires=' in c.lower()) for c in res[4]))
tc = IDP["token_calls"][-1]
check("de code is met PKCE ingewisseld, met het secret in het formulier (client_secret_post)",
      tc["data"].get("grant_type") == "authorization_code" and tc["data"].get("code_verifier") and tc["data"].get("client_secret") == "nagemaakt-secret-1" and tc["auth"] is None)
check("het account bij de dienst is vastgelegd (uitgever en sub)", main.links_of("lezer").get("oidc_sub") == f"{ISS}|u-1")
check("na deze inlog telt de lezer geen mislukte pogingen", not main.login_guard.failures, str(main.login_guard.failures))
res = oidc_login(sub="iemand-anders")
check("zelfde mailadres maar ander account bij de dienst: geweigerd (mismatch)", res[0] == 303 and res[1] == "/login?sso=mismatch" and not res[2], res[1])
main.login_guard.failures.clear()
res = oidc_login(then="sxy")
check("met then=sxy komt hij op het dashboard uit", res[1] == "/#sxy" and res[2], res[1])
for label, kw, want in [
        ("verkeerde state: expired", {"mutate": lambda p, j: ({**p, "state": "anders"}, j)}, "expired"),
        ("zonder controlecookie: expired", {"mutate": lambda p, j: (p, {})}, "expired"),
        ("vervalst controlecookie: expired", {"mutate": lambda p, j: (p, {main.OIDC_COOKIE: j[main.OIDC_COOKIE][:-3] + "abc"})}, "expired"),
        ("dienst meldt een fout: denied", {"mutate": lambda p, j: ({"error": "access_denied", "state": p["state"]}, j)}, "denied"),
        ("verkeerde nonce: invalid", {"claims_extra": {"nonce": "anders"}}, "invalid"),
        ("ondertekend met een andere sleutel: invalid", {"key": K2}, "invalid"),
        ("onbevestigd mailadres: noemail", {"claims_extra": {"email_verified": False}}, "noemail"),
        ("onbevestigd als tekst 'false': noemail", {"claims_extra": {"email_verified": "false"}}, "noemail"),
        ("geen mailadres: noemail", {"email": None}, "noemail"),
        ("verlopen id-token: invalid", {"claims_extra": {"exp": int(time.time()) - 600}}, "invalid"),
        ("ander doel (aud): invalid", {"claims_extra": {"aud": "andere-app"}}, "invalid")]:
    main.login_guard.failures.clear()
    res = oidc_login(**kw)
    check(label, res[1] == f"/login?sso={want}" and not res[2], res[1])
# een oud controlecookie (ouder dan 10 minuten), met een geldige handtekening
main.login_guard.failures.clear()
old_payload = base64.urlsafe_b64encode(json.dumps({"s": "s1", "n": "n1", "v": "v" * 64, "t": int(time.time()) - 700, "x": ""}).encode()).decode().rstrip("=")
r = call("GET", "/api/sso/oidc/callback?code=c&state=s1", host=PUBLIC, origin=None, cookies={main.OIDC_COOKIE: f"{old_payload}.{main.sign('oidc:' + old_payload)}"})
check("controlecookie ouder dan 10 minuten: expired", r[3] == "/login?sso=expired")
check("een sessiecookie is geen geldig controlecookie (en andersom)", main.read_token(f"{old_payload}.{main.sign('oidc:' + old_payload)}") is None)
for i in range(6):
    oidc_login(email="onbekend@voorbeeld.nl", source="198.51.100.99")
res = oidc_login(source="198.51.100.99")
check("na vijf mislukte pogingen vanaf één adres: blocked, ook voor een gekoppeld account", res[1] == "/login?sso=blocked" and not res[2], res[1])
main.login_guard.failures.clear()
IDP["auth_methods"] = ["client_secret_basic"]
main._discovery.clear()   # de tool bewaart de instellingen van de dienst een uur
res = oidc_login()
tc = IDP["token_calls"][-1]
check("dienst die alleen client_secret_basic kent: secret via Basic, niet in het formulier", res[2] and tc["auth"] == (AUD, "nagemaakt-secret-1") and "client_secret" not in tc["data"])
IDP["auth_methods"] = ["client_secret_post", "client_secret_basic"]
main._discovery.clear()
# Microsoft: zonder 'email' telt de UPN
r = call("PUT", "/api/sso/oidc", ROOT, {**base, "provider": "microsoft", "issuer": "https://login.microsoftonline.com/tenant-voorbeeld/v2.0", "client_secret": "nagemaakt-secret-2"})
check("Microsoft Entra ID (met tenant) ingesteld", r[0] == 200 and r[1]["oidc"]["provider"] == "microsoft", detail(r) or "")
ISS_MS = "https://login.microsoftonline.com/tenant-voorbeeld/v2.0"
r = call("PUT", "/api/users/lezer", ROOT, {"sso": {"oidc": "lezer@voorbeeld.nl"}})
check("hetzelfde adres opnieuw opslaan houdt het vastgelegde account", main.links_of("lezer").get("oidc_sub") == f"{ISS}|u-1")
ISS_SAVE = ISS
ISS = ISS_MS
main.login_guard.failures.clear()
res = oidc_login(email=None, claims_extra={"preferred_username": "Lezer@Voorbeeld.nl"})
check("Microsoft zonder email: de UPN telt, maar het vastgelegde account van de vorige dienst niet (mismatch)", res[1] == "/login?sso=mismatch", res[1])
r = call("PUT", "/api/users/lezer", ROOT, {"sso": {"oidc": "lezer2@voorbeeld.nl"}})
check("ander gekoppeld adres: vastgelegd account vervalt en de sessies van lezer ook", "oidc_sub" not in main.links_of("lezer") and call("GET", "/api/me", READER)[0] == 401)
READER = session_of(call("POST", "/api/login", body={"username": "lezer", "password": PW["lezer"]})[2])
main.login_guard.failures.clear()
res = oidc_login(email=None, claims_extra={"preferred_username": "lezer2@voorbeeld.nl"})
check("Microsoft: inloggen met de UPN", res[1] == "/" and res[2], res[1])
ISS = ISS_SAVE
r = call("PUT", "/api/sso/oidc", ROOT, {"enabled": False})
check("OpenID uit: de knop verdwijnt en de terugkeer werkt niet meer", r[0] == 200 and call("GET", "/api/sso/options")[1]["oidc"] is None
      and call("GET", "/api/sso/oidc/callback?code=x&state=y", host=PUBLIC, origin=None)[3] == "/login?sso=off"
      and call("GET", "/api/sso/oidc/start", host=PUBLIC, origin=None)[3] == "/login?sso=off")
check("uitzetten bewaart de rest van de instelling", main.sso_conf("oidc").get("client_id") == AUD and main.sso_conf("oidc").get("enabled") is False)

print("--- D. Cloudflare Access")
for label, body, code in [("ongeldige AUD Tag geweigerd", {"enabled": True, "team": CF_TEAM, "aud": "abc"}, 400),
                          ("ongeldige teamnaam geweigerd", {"enabled": True, "team": "slecht team!", "aud": CF_AUD}, 400)]:
    r = call("PUT", "/api/sso/cloudflare", ROOT, body)
    check(label, r[0] == code, detail(r))
IDP["down"] = True
r = call("PUT", "/api/sso/cloudflare", ROOT, {"enabled": True, "team": CF_TEAM, "aud": CF_AUD})
IDP["down"] = False
check("sleutels niet op te halen: 502 en niet aan", r[0] == 502 and not main.sso_on("cloudflare"), detail(r))
r = call("PUT", "/api/sso/cloudflare", ROOT, {"enabled": True, "team": f"https://{CF_TEAM}.cloudflareaccess.com/", "aud": CF_AUD.upper()})
check("teamnaam als volledig adres en AUD in hoofdletters worden netjes bewaard", r[0] == 200 and main.sso_conf("cloudflare") == {"enabled": True, "team": CF_TEAM, "aud": CF_AUD}, detail(r) or "")
r = call("PUT", "/api/users/beheer2", ROOT, {"sso": {"cloudflare": "beheer2@voorbeeld.nl"}})
check("beheer2 gekoppeld aan Cloudflare", r[0] == 200)
cf = lambda **c: jwt(K2, {"iss": CF_ISS, "aud": [CF_AUD], "email": "beheer2@voorbeeld.nl", "sub": "cf-1", "exp": int(time.time()) + 600, "iat": int(time.time()), "type": "app", **c})  # noqa: E731
main.login_guard.failures.clear()
r = call("GET", "/", origin=None, headers={"Cf-Access-Jwt-Assertion": cf()}, source="192.0.2.50")
check("pagina met een geldig Cloudflare-token: meteen binnen als beheer2", r[0] == 200 and isinstance(r[1], str) and 'data-user="beheer2"' in r[1]
      and main.read_token(session_of(r[2])) == "beheer2")
r = call("GET", "/login", origin=None, headers={"Cf-Access-Jwt-Assertion": cf()}, source="192.0.2.50")
check("inlogpagina met een geldig token: door naar / met een sessie", r[0] == 303 and r[3] == "/" and main.read_token(session_of(r[2])) == "beheer2")
r = call("GET", "/", origin=None, cookies={"CF_Authorization": cf()}, source="192.0.2.50")
check("het token in het cookie CF_Authorization werkt ook", r[0] == 200 and main.read_token(session_of(r[2])) == "beheer2")
for label, token in [("ander mailadres (niet gekoppeld)", cf(email="vreemde@voorbeeld.nl")), ("andere AUD", cf(aud=["ff" * 32])),
                     ("ander team", cf(iss="https://ander.cloudflareaccess.com")), ("verlopen", cf(exp=int(time.time()) - 300)),
                     ("ondertekend met een andere sleutel", jwt(K1, {"iss": CF_ISS, "aud": [CF_AUD], "email": "beheer2@voorbeeld.nl", "exp": int(time.time()) + 600}, kid="sleutel-2")),
                     ("zonder mailadres (service token)", cf(email=None))]:
    r = call("GET", "/", origin=None, headers={"Cf-Access-Jwt-Assertion": token}, source="192.0.2.51")
    check(f"token met {label}: geen toegang", r[0] == 303 and r[3] == "/login" and not session_of(r[2]))
check("ongeldige tokens tellen als mislukte poging, een niet-gekoppeld mailadres niet",
      sum(1 for f in main.login_guard.failures if f[1] == "192.0.2.51") == 4, str(sum(1 for f in main.login_guard.failures if f[1] == "192.0.2.51")))
r = call("POST", "/api/logout", cookie=session_of(call("GET", "/", origin=None, headers={"Cf-Access-Jwt-Assertion": cf()}, source="192.0.2.52")[2]), source="192.0.2.52")
nosso = cookie_of(r[2], main.NOSSO_COOKIE)
check("uitloggen zet een merkje zodat Cloudflare niet meteen weer inlogt", r[0] == 200 and nosso == "1")
r = call("GET", "/", origin=None, headers={"Cf-Access-Jwt-Assertion": cf()}, cookies={main.NOSSO_COOKIE: "1"}, source="192.0.2.52")
check("met dat merkje: naar de inlogpagina", r[0] == 303 and r[3] == "/login")
r = call("POST", "/api/sso/cloudflare", headers={"Cf-Access-Jwt-Assertion": cf()}, cookies={main.NOSSO_COOKIE: "1"}, source="192.0.2.52")
check("de knop op de inlogpagina logt in en haalt het merkje weg", r[0] == 200 and main.read_token(session_of(r[2])) == "beheer2"
      and any(c.startswith(main.NOSSO_COOKIE + "=") and "Max-Age=0" in c for c in r[2]))
r = call("POST", "/api/sso/cloudflare", source="192.0.2.53")
check("de knop zonder token: 401 met uitleg", r[0] == 401 and "Cloudflare" in detail(r))
call("PUT", "/api/sso/cloudflare", ROOT, {"enabled": False})
r = call("GET", "/", origin=None, headers={"Cf-Access-Jwt-Assertion": cf()}, source="192.0.2.54")
check("Cloudflare uit: geen toegang met een token", r[0] == 303 and not session_of(r[2]))
check("Cloudflare uit: de knop geeft 400", call("POST", "/api/sso/cloudflare", headers={"Cf-Access-Jwt-Assertion": cf()})[0] == 400)
call("PUT", "/api/sso/cloudflare", ROOT, {"enabled": True, "team": CF_TEAM, "aud": CF_AUD})

print("--- E. Proxmox-account")
r = call("PUT", "/api/sso/proxmox", ROOT, {"enabled": True, "realms": ["pam", "bestaatniet"]})
check("realm die Proxmox niet kent geweigerd", r[0] == 400, detail(r))
r = call("PUT", "/api/sso/proxmox", ROOT, {"enabled": True, "realms": []})
check("aan zonder realm geweigerd", r[0] == 400)
r = call("PUT", "/api/sso/proxmox", ROOT, {"enabled": True, "realms": ["pam"]})
check("Proxmox-account aan voor pam", r[0] == 200 and r[1]["proxmox"]["ready"] and [x["realm"] for x in r[1]["proxmox"]["available"]] == ["pam", "pve"], detail(r) or "")
check("een realm met een vreemde naam wordt niet getoond", all(x["realm"] != "slecht realm!" for x in r[1]["proxmox"]["available"]))
r = call("PUT", "/api/users/lezer", ROOT, {"sso": {"oidc": "lezer2@voorbeeld.nl", "proxmox": "jan@pam"}})
check("lezer gekoppeld aan jan@pam", r[0] == 200)
READER = session_of(call("POST", "/api/login", body={"username": "lezer", "password": PW["lezer"]})[2]) or READER
main.login_guard.failures.clear()
n0 = len(TICKETS)
r = call("POST", "/api/login", body={"username": "jan", "password": "juist-wachtwoord", "method": "proxmox", "realm": "pam"}, source="198.51.100.30")
check("inloggen met jan@pam: binnen als lezer", r[0] == 200 and main.read_token(session_of(r[2])) == "lezer", detail(r) or "")
t0 = TICKETS[-1] if len(TICKETS) > n0 else {}
check("Proxmox is gevraagd op poort 8006, zonder doorverwijzingen, met de certificaatcontrole van het cluster",
      t0.get("url", "").endswith(":8006/api2/json/access/ticket") and t0.get("redirects") is False and t0.get("verify") == main.VERIFY
      and (not main.CA_FILE or ("https://", "ClusterCAAdapter") in t0.get("mounted", [])), json.dumps({k: t0.get(k) for k in ("redirects", "mounted")}))
n0 = len(TICKETS)
r = call("POST", "/api/login", body={"username": "jan", "password": "fout", "method": "proxmox", "realm": "pam"}, source="198.51.100.31")
check("verkeerd wachtwoord: 401 en geteld", r[0] == 401 and any(f[1] == "198.51.100.31" for f in main.login_guard.failures))
r = call("POST", "/api/login", body={"username": "root", "password": "wat-dan-ook", "method": "proxmox", "realm": "pam"}, source="198.51.100.32")
check("niet gekoppeld account: 401 en Proxmox is NIET gevraagd", r[0] == 401 and len(TICKETS) == n0 + 1, str(len(TICKETS) - n0))
r = call("POST", "/api/login", body={"username": "jan", "password": "juist-wachtwoord", "method": "proxmox", "realm": "pve"}, source="198.51.100.33")
check("realm die niet aan staat: 401 en Proxmox niet gevraagd", r[0] == 401 and len(TICKETS) == n0 + 1)
call("PUT", "/api/sso/proxmox", ROOT, {"enabled": True, "realms": ["pam", "pve"]})
call("PUT", "/api/users/beheer2", ROOT, {"sso": {"cloudflare": "beheer2@voorbeeld.nl", "proxmox": "tfa@pve"}})
ADMIN2 = session_of(call("POST", "/api/login", body={"username": "beheer2", "password": PW["beheer2"]})[2]) or ADMIN2
r = call("POST", "/api/login", body={"username": "tfa", "password": "juist-wachtwoord", "method": "proxmox", "realm": "pve"}, source="198.51.100.34")
check("account met tweestapsverificatie: 401 met uitleg", r[0] == 401 and "tweestapsverificatie" in detail(r), detail(r))
call("PUT", "/api/users/beheer2", ROOT, {"sso": {"cloudflare": "beheer2@voorbeeld.nl", "proxmox": "ander@pam"}})
ADMIN2 = session_of(call("POST", "/api/login", body={"username": "beheer2", "password": PW["beheer2"]})[2])   # gewijzigde koppeling: opnieuw inloggen
r = call("POST", "/api/login", body={"username": "ander", "password": "juist-wachtwoord", "method": "proxmox", "realm": "pam"}, source="198.51.100.35")
check("Proxmox noemt een andere gebruiker dan gevraagd: geweigerd", r[0] == 401)
call("PUT", "/api/sso/proxmox", ROOT, {"enabled": False, "realms": ["pam"]})
r = call("POST", "/api/login", body={"username": "jan", "password": "juist-wachtwoord", "method": "proxmox", "realm": "pam"}, source="198.51.100.36")
check("Proxmox-account uit: 400", r[0] == 400, detail(r))
call("PUT", "/api/sso/proxmox", ROOT, {"enabled": True, "realms": ["pam"]})
check("het eigen wachtwoord werkt naast SSO gewoon door", call("POST", "/api/login", body={"username": "lezer", "password": PW["lezer"]})[0] == 200)

print("--- F. gebruikers met SSO")
main.login_guard.failures.clear()
r = call("POST", "/api/users", ROOT, {"name": "kiosk", "roles": [], "password_login": False, "sso": {}})
check("zonder wachtwoord en zonder koppeling geweigerd", r[0] == 400, detail(r))
r = call("POST", "/api/users", ROOT, {"name": "kiosk", "roles": [], "password_login": False, "sso": {"cloudflare": "beheer2@voorbeeld.nl"}})
check("koppeling die al van een ander is geweigerd (409)", r[0] == 409 and "beheer2" in detail(r), detail(r))
r = call("POST", "/api/users", ROOT, {"name": "kiosk", "roles": [], "password_login": False, "sso": {"cloudflare": "niet-een-adres"}})
check("ongeldig mailadres geweigerd", r[0] == 400)
r = call("POST", "/api/users", ROOT, {"name": "kiosk", "roles": [], "password_login": False, "sso": {"proxmox": "geen realm"}})
check("ongeldig Proxmox-account geweigerd", r[0] == 400)
r = call("POST", "/api/users", ROOT, {"name": "kiosk", "roles": [], "password_login": False, "sso": {"facebook": "x@y.nl"}})
check("onbekende manier geweigerd", r[0] == 400)
r = call("POST", "/api/users", ROOT, {"name": "kiosk", "roles": [], "password_login": False, "sso": {"cloudflare": "Scherm@Voorbeeld.nl"}})
row = next((u for u in r[1] if u["name"] == "kiosk"), {}) if r[0] == 200 else {}
check("gebruiker die alleen via SSO inlogt aangemaakt", r[0] == 200 and row.get("password_login") is False and row.get("sso") == {"cloudflare": "scherm@voorbeeld.nl"}, detail(r) or "")
raw = json.loads(main.USERS_FILE.read_text())["users"]["kiosk"]
check("in users.json: wel een (onbekend) wachtwoord, pw false - een oudere versie laat hem dus niet binnen",
      raw.get("pw") is False and len(raw.get("hash", "")) == 64 and len(raw.get("salt", "")) == 32)
check("met een wachtwoord inloggen kan dan niet", not main.check_login("kiosk", "") and call("POST", "/api/login", body={"username": "kiosk", "password": "x"})[0] == 401)
check("de lijst toont geen hashes en geen vastgelegd account", all(k not in json.dumps(r[1]) for k in ('"hash"', '"salt"', "oidc_sub")))
main.login_guard.failures.clear()
r = call("GET", "/", origin=None, headers={"Cf-Access-Jwt-Assertion": cf(email="scherm@voorbeeld.nl")}, source="192.0.2.60")
KIOSK = session_of(r[2])
check("kiosk komt binnen via Cloudflare; de pagina weet dat er geen wachtwoord is", r[0] == 200 and 'data-pw="0"' in r[1] and main.read_token(KIOSK) == "kiosk")
me = call("GET", "/api/me", KIOSK)[1]
check("wie ben ik: zonder wachtwoord, met Cloudflare", me.get("password_login") is False and me.get("sso") == ["cloudflare"], json.dumps(me))
check("kiosk kan geen wachtwoord wijzigen (geen huidig wachtwoord)", call("POST", "/api/password", KIOSK, {"current": "", "new": PW["nieuw"]})[0] == 403)
r = call("PUT", "/api/users/kiosk", ROOT, {"password_login": True})
check("wachtwoord weer aan zonder nieuw wachtwoord geweigerd", r[0] == 400, detail(r))
r = call("PUT", "/api/users/kiosk", ROOT, {"sso": {}})
check("laatste koppeling weghalen zonder wachtwoord geweigerd", r[0] == 400 and main.links_of("kiosk").get("cloudflare"), detail(r))
r = call("PUT", "/api/users/kiosk", ROOT, {"password_login": True, "password": PW["nieuw"]})
check("wachtwoord weer aan met een nieuw wachtwoord", r[0] == 200 and main.check_login("kiosk", PW["nieuw"]))
check("een nieuw wachtwoord beëindigt de sessies van kiosk (opnieuw inloggen)", call("GET", "/api/me", KIOSK)[0] == 401)
KIOSK = session_of(call("POST", "/api/login", body={"username": "kiosk", "password": PW["nieuw"]})[2])
r = call("PUT", "/api/users/kiosk", ROOT, {"sso": {"cloudflare": "scherm@voorbeeld.nl", "oidc": "scherm@voorbeeld.nl"}})
check("een koppeling erbij: de sessie blijft geldig", r[0] == 200 and call("GET", "/api/me", KIOSK)[0] == 200)
r = call("PUT", "/api/users/kiosk", ROOT, {"sso": {"oidc": "scherm@voorbeeld.nl"}})
check("een koppeling weg: de sessie vervalt", r[0] == 200 and call("GET", "/api/me", KIOSK)[0] == 401)
KIOSK = session_of(call("POST", "/api/login", body={"username": "kiosk", "password": PW["nieuw"]})[2])
r = call("PUT", "/api/users/kiosk", ROOT, {"password_login": False})
check("inloggen met een wachtwoord uit: de sessie vervalt en het wachtwoord werkt niet meer", r[0] == 200 and call("GET", "/api/me", KIOSK)[0] == 401
      and not main.check_login("kiosk", PW["nieuw"]))
r = call("PUT", f"/api/users/{main.APP_USER}", ROOT, {"sso": {"oidc": "beheer@voorbeeld.nl"}})
check("het hoofdaccount krijgt een koppeling (in sso.json), zijn sessie blijft", r[0] == 200 and main.links_of(main.APP_USER) == {"oidc": "beheer@voorbeeld.nl"}
      and call("GET", "/api/me", ROOT)[0] == 200 and next(u for u in r[1] if u["builtin"])["sso"] == {"oidc": "beheer@voorbeeld.nl"})
check("van het hoofdaccount de rechten wijzigen blijft geweigerd", call("PUT", f"/api/users/{main.APP_USER}", ROOT, {"roles": []})[0] == 409
      and call("PUT", f"/api/users/{main.APP_USER}", ROOT, {"password_login": False})[0] == 409)
r = call("POST", "/api/users", ROOT, {"name": "dubbel", "roles": [], "password": PW["nieuw"], "sso": {"oidc": "beheer@voorbeeld.nl"}})
check("een adres van het hoofdaccount kan niet ook bij een ander", r[0] == 409, detail(r))
r = call("PUT", "/api/users/beheer2", ADMIN2, {"sso": {"cloudflare": "beheer2@voorbeeld.nl"}})
NEW2 = session_of(r[2])
check("wie zijn eigen koppeling weghaalt krijgt meteen een nieuwe sessie", r[0] == 200 and NEW2 and main.read_token(NEW2) == "beheer2" and call("GET", "/api/me", ADMIN2)[0] == 401)
ADMIN2 = NEW2
check("eigen rechten wijzigen blijft geweigerd", call("PUT", "/api/users/beheer2", ADMIN2, {"roles": []})[0] == 409)
check("de lezer mag geen koppelingen wijzigen", call("PUT", "/api/users/kiosk", READER, {"sso": {}})[0] == 403)

print("--- G. de indeling van het dashboard")
layout = [{"id": "gauge:cpu:pve1", "x": 0, "y": 0, "w": 4, "h": 5}, {"id": "chart:net", "x": 4, "y": 0, "w": 20, "h": 6}, {"id": "clock", "x": 0, "y": 6, "w": 6, "h": 3}]
dash = {"layout": layout, "hidden": ["nums", "gauge:mem:pve2"], "live": 10, "history": 300, "fit": True}
r = call("PUT", "/api/settings", READER, {"dashboard": dash})
check("de lezer bewaart zijn eigen indeling", r[0] == 200 and r[1]["dashboard"] == {**dash, "hidden": sorted(dash["hidden"])}, detail(r) or "")
check("en leest hem terug", call("GET", "/api/settings", READER)[1]["dashboard"]["live"] == 10)
check("de indeling van een ander verandert er niet door", call("GET", "/api/settings", ROOT)[1].get("dashboard") is None)
r = call("PUT", "/api/settings", READER, {"language": "en"})
check("taal wijzigen laat de indeling staan", r[0] == 200 and r[1]["dashboard"]["live"] == 10 and r[1]["language"] == "en")
for label, d in [("tegel buiten het raster", {**dash, "layout": [{"id": "nums", "x": 20, "y": 0, "w": 6, "h": 3}]}),
                 ("breedte 0", {**dash, "layout": [{"id": "nums", "x": 0, "y": 0, "w": 0, "h": 3}]}),
                 ("hoogte 61", {**dash, "layout": [{"id": "nums", "x": 0, "y": 0, "w": 3, "h": 61}]}),
                 ("onbekende tegel", {**dash, "layout": [{"id": "<script>", "x": 0, "y": 0, "w": 3, "h": 3}]}),
                 ("tegel twee keer", {**dash, "layout": [{"id": "nums", "x": 0, "y": 0, "w": 3, "h": 3}, {"id": "nums", "x": 3, "y": 0, "w": 3, "h": 3}]}),
                 ("waar/onwaar als getal", {**dash, "layout": [{"id": "nums", "x": True, "y": 0, "w": 3, "h": 3}]}),
                 ("verversen elke 3 s", {**dash, "live": 3}), ("grafieken elke 7 s", {**dash, "history": 7}),
                 ("201 tegels", {**dash, "layout": [{"id": f"gauge:cpu:n{i}", "x": 0, "y": i, "w": 4, "h": 4} for i in range(201)]}),
                 ("verborgen tegel met een rare naam", {**dash, "hidden": ["../x"]}), ("geen woordenboek", [1, 2])]:
    r = call("PUT", "/api/settings", READER, {"dashboard": d})
    check(f"geweigerd: {label}", r[0] in (400, 422), str(r[0]))
check("na de weigeringen staat de goede indeling er nog", call("GET", "/api/settings", READER)[1]["dashboard"]["history"] == 300)
r = call("PUT", "/api/settings", READER, {"dashboard": None})
check("null zet de standaard terug", r[0] == 200 and r[1]["dashboard"] is None)
check("zonder inlog geen instellingen", call("PUT", "/api/settings", None, {"dashboard": dash})[0] == 401)

print("--- H. het overzicht per mail: planning")
TZ = main.REPORT_TZ
at = lambda *a: dt.datetime(*a, tzinfo=TZ)  # noqa: E731
cfg = lambda **k: {**main.report_config(), **k}  # noqa: E731
check("standaard: elke week, alle onderdelen", main.report_config()["frequency"] == "weekly" and main.report_config()["parts"] == list(main.REPORT_PARTS))
check("elke dag, vóór de tijd: gisteren", main.report_moment(at(2026, 10, 14, 4, 0), cfg(frequency="daily", time="05:00")) == at(2026, 10, 13, 5, 0))
check("elke dag, na de tijd: vandaag", main.report_moment(at(2026, 10, 14, 6, 0), cfg(frequency="daily", time="05:00")) == at(2026, 10, 14, 5, 0))
check("elke week op zondag", main.report_moment(at(2026, 10, 14, 6, 0), cfg(frequency="weekly", day=6, time="05:00")) == at(2026, 10, 11, 5, 0))
check("elke maand op de 15e, vóór de 15e: vorige maand", main.report_moment(at(2026, 10, 14, 6, 0), cfg(frequency="monthly", monthday=15, time="05:00")) == at(2026, 9, 15, 5, 0))
check("elke maand over de jaargrens", main.report_moment(at(2027, 1, 3, 6, 0), cfg(frequency="monthly", monthday=15, time="05:00")) == at(2026, 12, 15, 5, 0))
check("niet automatisch: geen moment", main.report_moment(at(2026, 10, 14), cfg(frequency="off")) is None and main.report_next(cfg(frequency="off")) is None)
bi = cfg(frequency="biweekly", day=6, time="05:00", parity=0)
moments, t = [], at(2026, 11, 1, 6, 0)
for _ in range(60):
    m = main.report_moment(t, bi)
    if not moments or moments[-1] != m:
        moments.append(m)
    t += dt.timedelta(days=7)
gaps = {(b - a).days for a, b in zip(moments, moments[1:])}
check("om de week: steeds precies 14 dagen ertussen, ook over de jaargrens (53 weken)", gaps == {14} and len(moments) > 20, str(gaps))
r = call("PUT", "/api/report/config", ROOT, {"frequency": "biweekly", "day": 2, "monthday": 1, "time": "07:30", "parts": ["issues", "backups"], "only_issues": True})
c = main.report_config()
upcoming = main.report_next(c)
check("om de week opslaan: de eerstvolgende keer is de eerstvolgende woensdag", r[0] == 200 and upcoming.weekday() == 2 and upcoming.strftime("%H:%M") == "07:30"
      and 0 <= (upcoming - dt.datetime.now(TZ)).total_seconds() < 7 * 86400 and r[1]["frequency"] == "biweekly" and r[1]["parts"] == ["issues", "backups"], str(upcoming))
saved = main.state.load()
check("een moment van vóór het opslaan wordt niet alsnog verstuurd", main.report_due(saved, c, upcoming - dt.timedelta(days=13)) is None)
check("het eerstvolgende moment wel", main.report_due(saved, c, upcoming + dt.timedelta(minutes=2)) == upcoming)
check("een dag later niet meer", main.report_due(saved, c, upcoming + dt.timedelta(hours=25)) is None)
check("al verstuurd: niet nog eens", main.report_due({**saved, "report_sent": upcoming.timestamp() + 60}, c, upcoming + dt.timedelta(minutes=5)) is None)
d = cfg(frequency="daily", time="05:00")
check("elke dag: na een halve dag niet meer alsnog", main.report_due({}, d, at(2026, 10, 14, 17, 30)) is None and main.report_due({}, d, at(2026, 10, 14, 16, 0)) == at(2026, 10, 14, 5, 0))
for label, body in [("onbekende frequentie", {"frequency": "hourly"}), ("dag 7", {"day": 7}), ("dag van de maand 29", {"monthday": 29}), ("tijd 25:00", {"time": "25:00"}),
                    ("tijd zonder dubbele punt", {"time": "0500"}), ("geen onderdelen", {"parts": []}), ("onbekend onderdeel", {"parts": ["alles"]}),
                    ("dag als true", {"day": True})]:
    r = call("PUT", "/api/report/config", ROOT, {"frequency": "weekly", "day": 6, "monthday": 1, "time": "05:00", "parts": ["issues"], "only_issues": False, **body})
    check(f"geweigerd: {label}", r[0] in (400, 422), f"{r[0]} {detail(r)}")
check("de lezer mag de planning niet wijzigen", call("PUT", "/api/report/config", READER, {"frequency": "daily", "parts": ["issues"]})[0] == 403)
st = call("GET", "/api/report/status", READER)[1]
check("de status meldt de planning", st["frequency"] == "biweekly" and st["day"] == 2 and st["time"] == "07:30" and st["only_issues"] is True
      and st["next"] == int(upcoming.timestamp()) and st["when"] == "om de week op woensdag om 07:30", st["when"])
for f in ("daily", "weekly", "biweekly", "monthly", "off"):
    since, until = main.report_period(cfg(frequency=f), until=at(2026, 10, 14, 6, 0).timestamp())
    days = round((until - since) / 86400)
    check(f"periode bij {f}: {days} dagen", days == {"daily": 1, "weekly": 7, "biweekly": 14, "monthly": 30, "off": 7}[f])

print("--- H2. inhoud van het overzicht")
D = {"nodes": [{"node": "n1", "status": "online", "uptime": 5 * 3600}, {"node": "n2", "status": "offline"}],
     "guests": [{"vmid": 101, "name": "web", "type": "lxc", "node": "n1", "status": "running"}], "tasks": [], "files": [], "ceph": None,
     "jobs": [], "stores": [{"storage": "nas", "disk": 95, "maxdisk": 100}], "updates": {"nodes": {}, "guests": {}}, "events": [], "snapshots": {}}
s0, s1 = time.time() - 86400, time.time()
subj, page, plain, n = main.compose_report(D, s0, s1, cfg(frequency="daily", parts=list(main.REPORT_PARTS)))
check("dagoverzicht: titel, onderwerp en geen 'deze week'", "Dagoverzicht Proxmox" in page and subj.startswith("Proxmox dagoverzicht") and "deze week" not in page and "de afgelopen dag" in page)
check("alle onderdelen: nodes, back-ups en opslag staan erin, met hun aandachtspunten", all(x in page for x in (">Nodes<", ">Back-ups<", ">Opslag<", "n2 is niet online", "voor 95% vol")) and n >= 3, str(n))
subj, page, plain, n2 = main.compose_report(D, s0, s1, cfg(frequency="monthly", parts=["storage"]))
check("alleen opslag: alleen dat onderdeel, alleen die aandachtspunten, geen kader", ">Opslag<" in page and ">Nodes<" not in page and ">Back-ups<" not in page
      and "n2 is niet online" not in page and n2 == 1 and "Maandoverzicht" in page and "Geen aandachtspunten" not in page, str(n2))
check("de platte tekst volgt dezelfde keuze", "NODES" not in plain and "OPSLAG" in plain)
check("build_report geeft nog steeds drie delen (zoals voorheen)", len(main.build_report(D, s0, s1, cfg(frequency="weekly"))) == 3)
main.make_report = lambda cfg=None: ("onderwerp", "<p>x</p>", "x", 0)
main.mail_ready = lambda: True
MAILLOG.clear()
call("PUT", "/api/report/config", ROOT, {"frequency": "weekly", "day": 6, "monthday": 1, "time": "05:00", "parts": ["issues"], "only_issues": True})
check("gepland, alleen bij aandachtspunten en er zijn er geen: overgeslagen, niets gemaild", main.send_report(scheduled=True) is None and not MAILLOG
      and main.state.load().get("report_skipped") is True)
r = call("POST", "/api/report/send", ROOT)
check("met de hand versturen gaat altijd", r[0] == 200 and MAILLOG and MAILLOG[-1]["sent"] == ["onderwerp"] and main.state.load().get("report_skipped") is False, detail(r) or "")
main.make_report = lambda cfg=None: ("onderwerp 2", "<p>x</p>", "x", 2)
MAILLOG.clear()
check("gepland met aandachtspunten: verstuurd", main.send_report(scheduled=True) == "onderwerp 2" and MAILLOG)

print("--- I. een schijf vergroten (nagebootst cluster)")
GiB = 2 ** 30
CT = {"hostname": "proef", "cores": 2, "memory": 1024, "swap": 512, "digest": "d1", "rootfs": "ceph-pool:vm-901-disk-0,size=8G",
      "mp0": "ceph-pool:vm-901-disk-1,mp=/data,size=1T", "mp1": "/mnt/nas,mp=/nas", "mp2": "local-lvm:vm-901-disk-2,mp=/x,size=512M", "net0": "name=eth0,bridge=vmbr0"}
VM = {"name": "vmproef", "cores": 2, "memory": 2048, "digest": "e1", "scsi0": "ceph-pool:vm-902-disk-0,iothread=1,size=32G", "ide2": "local:iso/debian.iso,media=cdrom,size=600M",
      "ide1": "ceph-pool:vm-902-cloudinit,media=cdrom", "efidisk0": "ceph-pool:vm-902-disk-1,efitype=4m,size=1M", "tpmstate0": "ceph-pool:vm-902-disk-2,size=4M",
      "virtio1": "/dev/disk/by-id/ata-x,size=100G", "sata0": "local-lvm:vm-902-disk-3,size=10.5G", "unused0": "ceph-pool:vm-902-disk-9"}
ds = main.resizable_disks("lxc", CT)
check("CT: rootfs, mp0 en mp2 te vergroten; de map van de node (mp1) niet", [(d["key"], d["size"]) for d in ds] == [("mp0", 2 ** 40), ("mp2", 512 * 2 ** 20), ("rootfs", 8 * GiB)]
      or sorted((d["key"], d["size"]) for d in ds) == [("mp0", 2 ** 40), ("mp2", 512 * 2 ** 20), ("rootfs", 8 * GiB)], json.dumps([(d["key"], d["size"]) for d in ds]))
dv = main.resizable_disks("qemu", VM)
check("VM: scsi0 en sata0; geen cd-rom, cloud-init, EFI, TPM, apparaat of unused", sorted((d["key"], d["size"]) for d in dv) == [("sata0", int(10.5 * GiB)), ("scsi0", 32 * GiB)], json.dumps([d["key"] for d in dv]))
W.table.update({
    "cluster/resources": [{"vmid": 901, "node": "n1", "type": "lxc", "name": "proef", "status": "running"},
                          {"vmid": 902, "node": "n1", "type": "qemu", "name": "vmproef", "status": "running"},
                          {"vmid": 903, "node": "n1", "type": "lxc", "name": "sjabloon", "template": 1, "status": "stopped"},
                          {"vmid": 904, "node": "n1", "type": "lxc", "name": "op-slot", "status": "running"}],
    "nodes/n1/status": {"cpuinfo": {"cpus": 8}, "memory": {"total": 16 * GiB}},
    "nodes/n1/lxc/901/config": lambda kw: dict(CT), "nodes/n1/qemu/902/config": lambda kw: dict(VM),
    "nodes/n1/lxc/903/config": {"rootfs": "ceph-pool:base-903-disk-0,size=4G", "template": 1, "digest": "t"},
    "nodes/n1/lxc/904/config": {"rootfs": "ceph-pool:vm-904-disk-0,size=4G", "lock": "backup", "digest": "l"},
    "nodes/n1/storage/ceph-pool/status": {"avail": 100 * GiB, "total": 500 * GiB}, "nodes/n1/storage/local-lvm/status": {"avail": 5 * GiB}})
W.answers[("PUT", "nodes/n1/lxc/901/resize")] = "UPID:n1:0001:resize:901:root@pam:"
W.answers[("PUT", "nodes/n1/qemu/902/resize")] = None
OVER = None
r = call("POST", "/api/users", ROOT, {"name": "overzicht", "roles": ["overview"], "password": PW["nieuw"]})
OVER = session_of(call("POST", "/api/login", body={"username": "overzicht", "password": PW["nieuw"]})[2])
call("POST", "/api/users", ROOT, {"name": "opslagman", "roles": ["storage"], "password": PW["nieuw"]})
STOR = session_of(call("POST", "/api/login", body={"username": "opslagman", "password": PW["nieuw"]})[2])
r = call("GET", "/api/guest/n1/lxc/901/config", OVER)
check("bewerkvenster: de schijven met de vrije ruimte van hun opslag", r[0] == 200 and {d["key"]: d["free"] for d in r[1]["disks"]} == {"rootfs": 100 * GiB, "mp0": 100 * GiB, "mp2": 5 * GiB}, detail(r) or "")
W.changes.clear()
r = call("PUT", "/api/guest/n1/lxc/901/disk/rootfs", OVER, {"grow_gb": 10, "digest": "d1"})
check("CT: rootfs + 10 GB, met het controlegetal; Proxmox start een taak", r[0] == 200 and r[1]["task"].startswith("UPID:") and r[1]["size"] == 18 * GiB
      and W.changes == [("PUT", "nodes/n1/lxc/901/resize", {"disk": "rootfs", "size": "+10G", "digest": "d1"})], json.dumps(W.changes))
W.changes.clear()
r = call("PUT", "/api/guest/n1/qemu/902/disk/scsi0", OVER, {"grow_gb": 1})
check("VM: scsi0 + 1 GB, zonder taak terug", r[0] == 200 and r[1]["task"] is None and W.changes == [("PUT", "nodes/n1/qemu/902/resize", {"disk": "scsi0", "size": "+1G", "digest": "e1"})])
W.changes.clear()
for label, path, body, code, cookie in [
        ("0 GB", "/api/guest/n1/lxc/901/disk/rootfs", {"grow_gb": 0}, 400, OVER),
        ("16385 GB", "/api/guest/n1/lxc/901/disk/rootfs", {"grow_gb": 16385}, 400, OVER),
        ("true als getal", "/api/guest/n1/lxc/901/disk/rootfs", {"grow_gb": True}, 422, OVER),
        ("getal als tekst", "/api/guest/n1/lxc/901/disk/rootfs", {"grow_gb": "10"}, 422, OVER),
        ("kommagetal", "/api/guest/n1/lxc/901/disk/rootfs", {"grow_gb": 1.5}, 422, OVER),
        ("meer dan er vrij is", "/api/guest/n1/lxc/901/disk/mp2", {"grow_gb": 6}, 409, OVER),
        ("de map van de node", "/api/guest/n1/lxc/901/disk/mp1", {"grow_gb": 1}, 400, OVER),
        ("een netwerkkaart", "/api/guest/n1/lxc/901/disk/net0", {"grow_gb": 1}, 400, OVER),
        ("EFI-schijf", "/api/guest/n1/qemu/902/disk/efidisk0", {"grow_gb": 1}, 400, OVER),
        ("cd-rom", "/api/guest/n1/qemu/902/disk/ide2", {"grow_gb": 1}, 400, OVER),
        ("schijf die er niet is", "/api/guest/n1/qemu/902/disk/scsi5", {"grow_gb": 1}, 400, OVER),
        ("oud controlegetal", "/api/guest/n1/lxc/901/disk/rootfs", {"grow_gb": 1, "digest": "oud"}, 409, OVER),
        ("sjabloon", "/api/guest/n1/lxc/903/disk/rootfs", {"grow_gb": 1}, 409, OVER),
        ("vergrendelde guest", "/api/guest/n1/lxc/904/disk/rootfs", {"grow_gb": 1}, 409, OVER),
        ("guest op een andere node", "/api/guest/n2/lxc/901/disk/rootfs", {"grow_gb": 1}, 404, OVER),
        ("door de lezer", "/api/guest/n1/lxc/901/disk/rootfs", {"grow_gb": 1}, 403, READER),
        ("door de opslagbeheerder", "/api/guest/n1/lxc/901/disk/rootfs", {"grow_gb": 1}, 403, STOR),
        ("zonder inlog", "/api/guest/n1/lxc/901/disk/rootfs", {"grow_gb": 1}, 401, None)]:
    r = call("PUT", path, cookie, body)
    check(f"geweigerd: {label} ({code})", r[0] == code, f"{r[0]} {detail(r)}")
r = call("PUT", "/api/guest/n1/lxc/901/disk/rootfs", OVER, {"grow_gb": 1}, origin="https://kwaad.example")
check("geweigerd: vanaf een andere website", r[0] == 403)
check("bij al die weigeringen is er niets naar het cluster gestuurd", W.changes == [], json.dumps(W.changes))
W.fail = ResourceException(500, "Internal Server Error", "detected modified configuration - file changed by other user? Try again. (digest)")
r = call("PUT", "/api/guest/n1/lxc/901/disk/rootfs", OVER, {"grow_gb": 1})
check("Proxmox meldt een ander controlegetal: 409 met uitleg", r[0] == 409 and "intussen" in detail(r), detail(r))
W.fail = None

print("--- J. wie mag bij de nieuwe adressen")
guards = {}
for route in main.app.routes:
    if isinstance(route, APIRoute):
        calls = [dd.call for dd in route.dependant.dependencies]
        g = "admin" if main.admin in calls else ",".join(calls[0].areas) if calls and hasattr(calls[0], "areas") else "auth" if main.auth in calls else "open"
        for m in route.methods - {"HEAD", "OPTIONS"}:
            guards[(m, route.path)] = g
want = {("GET", "/api/sso"): "admin", ("PUT", "/api/sso/oidc"): "admin", ("PUT", "/api/sso/cloudflare"): "admin", ("PUT", "/api/sso/proxmox"): "admin",
        ("GET", "/api/sso/options"): "open", ("GET", "/api/sso/oidc/start"): "open", ("GET", "/api/sso/oidc/callback"): "open", ("POST", "/api/sso/cloudflare"): "open",
        ("PUT", "/api/report/config"): "events", ("PUT", "/api/guest/{node}/{kind}/{vmid}/disk/{disk}"): "overview", ("PUT", "/api/settings"): "auth"}
check("de nieuwe adressen hebben de juiste bewaking", all(guards.get(k) == v for k, v in want.items()), json.dumps({f"{k[0]} {k[1]}": guards.get(k) for k in want if guards.get(k) != v}))
opened = sorted(f"{m} {p}" for (m, p), g in guards.items() if g == "open")
check("zonder inlog open: alleen inloggen, uitloggen, de vier SSO-adressen en inloggen met een sleutel (1.3.1)", opened == sorted(["GET /", "GET /login", "POST /api/login", "POST /api/logout", "GET /api/sso/options",
      "GET /api/sso/oidc/start", "GET /api/sso/oidc/callback", "POST /api/sso/cloudflare", "POST /api/webauthn/login/start", "POST /api/webauthn/login/finish"]), str(opened))
# De bewaker van de updates start al bij het inladen van main (zoals in de echte dienst) en vraagt de nodes alleen om
# informatie ('info cts'); die vraag is door de struikeldraad tegengehouden. Alles wat iets zou wijzigen telt wel.
TRIPPED = [x for x in TRIPPED if not (x[0] == "agent" and tuple(x[1][1:]) == ("info", "cts"))]
check("niets in de test heeft het echte cluster, een node of het internet bereikt", not TRIPPED and all(u.startswith(("https://idp.voorbeeld.nl/", "https://login.microsoftonline.com/tenant-voorbeeld", CF_ISS)) for u in FETCHES), str(TRIPPED))

print("--- K. het echte cluster, alleen lezen")
main.pve.run, main.pve.connect, main.fetch_json, main.requests.Session = REAL_RUN, REAL_CONNECT, REAL_FETCH, REAL_SESSION
reads = []
realms = main.pve.run(main.proxmox_realms)
check("de realms van het echte cluster", {"pam", "pve"} <= {x["realm"] for x in realms}, ", ".join(x["realm"] for x in realms))


def disks_everywhere(api):
    out = []
    for g in api.cluster.resources.get(type="vm"):
        if g.get("template"):
            continue
        cfg_ = main.guest(api, g["node"], g["type"], g["vmid"]).config.get()
        expected = [k for k, v in cfg_.items() if (main.LXC_DISK_RE.match(k) if g["type"] == "lxc" else main.VM_DATA_DISK_RE.match(k))
                    and "size=" in str(v) and "media=cdrom" not in str(v) and ":" in str(v).split(",")[0] and not str(v).startswith("/")]
        got = main.resizable_disks(g["type"], cfg_)
        out.append((g["vmid"], sorted(expected), sorted(d["key"] for d in got), [d["size"] for d in got]))
    return out


found = main.pve.run(disks_everywhere)
check(f"alle schijven van de {len(found)} echte guests worden herkend, met een grootte", all(e == k and all(s and s > 0 for s in sizes) for _, e, k, sizes in found),
      "; ".join(f"{v}: {k}" for v, e, k, _ in found))
total = sum(len(k) for _, _, k, _ in found)
print(f"     {total} schijven gevonden, bv. " + ", ".join(f"{v} {k[0]}" for v, _, k, _ in found[:4] if k))
until = time.time()
for f in ("daily", "weekly", "monthly"):
    c_ = cfg(frequency=f, parts=list(main.REPORT_PARTS))
    since, _ = main.report_period(c_, until)
    data = main.pve.run(lambda api: main.report_data(api, since))
    subj, page, plain, n = main.compose_report(data, since, until, c_)
    check(f"overzicht van het echte cluster als {f}: {n} aandachtspunt(en)", subj.startswith("Proxmox " + main.REPORT_TITLE[f].lower()) and "<h2" in page)
subj, page, plain, n = main.compose_report(data, since, until, cfg(frequency="weekly", parts=["storage"]))
check("echt overzicht met alleen opslag", page.count("<h2") == 1 and ">Opslag<" in page)

print()
print("ALLES GOED" if not FAILED else f"FOUT ({len(FAILED)}): {FAILED}")
