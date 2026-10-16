"""Tests version 1.3.1 of the backend in-process on the tool container, from a copy in /tmp with its own state folder:
security keys (WebAuthn: registering, logging in with only the key, the key after the password), the console of a node,
Proxmox API tokens with their permissions, and the saved table layout. Everything runs against a stand-in cluster and a
stand-in security key; nothing real is changed and no real password or token is used."""
import asyncio, base64, datetime as dt, hashlib, hmac, json, os, secrets, subprocess, sys, tempfile, time, urllib.parse
for line in open("/etc/maintool/maintool.env", encoding="utf-8"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ[k.strip()] = v.strip()
os.environ["STATE_DIRECTORY"] = "/tmp/mt-v131/state"
sys.path.insert(0, "/tmp/mt-v131/app")
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


def run(fn):
    try:
        return fn(Fake(W))
    except ResourceException as e:
        raise HTTPException(e.status_code or 500, f"Proxmox: {e.status_message} {e.content or ''}".strip())


main.pve.run = run
main.pve.connect = lambda *a, **k: TRIPPED.append("verbinden") or (_ for _ in ()).throw(AssertionError("echte verbinding"))
main.agent = lambda ip, *words, **k: ("maintool-agent 3 pve1" if words[:1] == ("ping",) else "") if words[:1] in (("info",), ("refresh",), ("ping",)) else TRIPPED.append(("agent", words)) or ""   # de nagebootste agent: alleen versie en lezen
main.updates.start = lambda lists=True: False
main.updates.busy = False
W.table.update({"nodes": [{"node": "pve1", "status": "online"}], "cluster/resources": [], "cluster/status": [], "cluster/ha/status/current": []})


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def login(name, pw, **extra):
    r = call("POST", "/api/login", body={"username": name, "password": pw, **extra})
    return r, session_of(r[2])


main.login_guard.failures.clear()
r, ROOT = login(main.APP_USER, main.APP_PASSWORD)
PW = secrets.token_urlsafe(18)
call("POST", "/api/users", ROOT, {"name": "lezer", "roles": [], "password": PW})
call("POST", "/api/users", ROOT, {"name": "beheer2", "roles": ["admin"], "password": PW})
call("POST", "/api/users", ROOT, {"name": "kiosk", "roles": [], "password_login": False, "sso": {"cloudflare": "kiosk@voorbeeld.nl"}})
READER, ADMIN2 = login("lezer", PW)[1], login("beheer2", PW)[1]
KIOSK = main.make_token("kiosk")
check("uitgangssituatie: drie sessies", all([ROOT, READER, ADMIN2]))

# ================================================================ A. de rekenkunde, nagekeken tegen OpenSSL
print("--- A. ES256 en RS256 tegen OpenSSL, DER en CBOR")
with tempfile.TemporaryDirectory() as d:
    sh = lambda *a: subprocess.run(a, check=True, capture_output=True).stdout  # noqa: E731
    sh("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", f"{d}/k.pem")
    Path = main.Path
    Path(f"{d}/m").write_bytes(b"hallo maintool")
    sh("openssl", "dgst", "-sha256", "-sign", f"{d}/k.pem", "-out", f"{d}/s", f"{d}/m")
    pub = sh("openssl", "ec", "-in", f"{d}/k.pem", "-pubout", "-outform", "DER")
    pt, sig = pub[-65:], Path(f"{d}/s").read_bytes()
    X, Y = int.from_bytes(pt[1:33], "big"), int.from_bytes(pt[33:], "big")
    rs = main.der_rs(sig)
    check("OpenSSL-sleutel ligt op de kromme", pt[0] == 4 and main.p256_on_curve((X, Y)))
    check("handtekening van OpenSSL klopt", rs is not None and main.p256_verify(X, Y, b"hallo maintool", *rs))
    check("ander bericht: klopt niet", not main.p256_verify(X, Y, b"hallo maintooL", *rs))
    check("andere s: klopt niet", not main.p256_verify(X, Y, b"hallo maintool", rs[0], (rs[1] + 1) % main.P256_N))
    check("r = 0 of s >= n: geweigerd", not main.p256_verify(X, Y, b"x", 0, 5) and not main.p256_verify(X, Y, b"x", 5, main.P256_N))
    check("punt naast de kromme: geweigerd", not main.p256_verify(X, Y + 1, b"hallo maintool", *rs))
    sh("openssl", "genrsa", "-out", f"{d}/r.pem", "2048")
    sh("openssl", "dgst", "-sha256", "-sign", f"{d}/r.pem", "-out", f"{d}/rs", f"{d}/m")
    n = int(sh("openssl", "rsa", "-in", f"{d}/r.pem", "-noout", "-modulus").decode().strip().split("=", 1)[1], 16)
    rkey = {"kty": "RSA", "n": b64u(n.to_bytes(256, "big")), "e": b64u((65537).to_bytes(3, "big"))}
    check("RS256 van OpenSSL klopt (via de opgeslagen sleutel)", main.wa_verify(rkey, b"hallo maintool", Path(f"{d}/rs").read_bytes()))
    check("RS256 met ander bericht: klopt niet", not main.wa_verify(rkey, b"hallo", Path(f"{d}/rs").read_bytes()))
check("DER: rommel, te kort, iets erachter", main.der_rs(b"") is None and main.der_rs(b"\x30\x02\x02\x00") is None and main.der_rs(sig + b"\x00") is None)
check("CBOR: map met getallen als sleutel, bytes, tekst, lijst", main.cbor_item(bytes.fromhex("a3016161 20 42 0102 03 82 f5 f6".replace(" ", "")))[0] == {1: "a", -1: b"\x01\x02", 3: [True, None]})
for label, raw in (("afgebroken", "a201"), ("onbepaalde lengte", "5f"), ("tag", "c1"), ("kommagetal", "f93c00"), ("dubbele sleutel", "a201010102")):
    try:
        main.cbor_item(bytes.fromhex(raw))
        check(f"CBOR geweigerd: {label}", False)
    except ValueError:
        check(f"CBOR geweigerd: {label}", True)
check("COSE: Ed25519 en een te korte RSA-sleutel niet", main.cose_key({1: 1, 3: -8, -1: 6, -2: b"x" * 32}) is None
      and main.cose_key({1: 3, 3: -257, -1: b"\x01" * 128, -2: b"\x01\x00\x01"}) is None)

# ================================================================ een nagebootste beveiligingssleutel
N, G = main.P256_N, main.P256_G


def cbor(v):
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | info]) + n.to_bytes(size, "big")
    if isinstance(v, bool):
        return b"\xf5" if v else b"\xf4"
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        return head(3, len(v.encode())) + v.encode()
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(cbor(x) for x in v)
    return head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())


def der(r, s):
    part = lambda x: (lambda b: b"\x02" + bytes([len(b)]) + b)(x.to_bytes((x.bit_length() + 8) // 8, "big"))  # noqa: E731
    body = part(r) + part(s)
    return b"\x30" + bytes([len(body)]) + body


class Key:
    def __init__(self, rp=HOST):
        self.d = secrets.randbelow(N - 1) + 1
        self.x, self.y = main.p256_mul(self.d, G)
        self.id, self.count, self.rp = secrets.token_bytes(32), 0, rp

    def sign(self, msg):
        e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
        while True:
            k = secrets.randbelow(N - 1) + 1
            r = main.p256_mul(k, G)[0] % N
            s = pow(k, -1, N) * (e + r * self.d) % N
            if r and s:
                return der(r, s)

    def auth(self, flags, attested=False, rp=None, count=None):
        self.count = self.count + 1 if count is None else count
        ad = hashlib.sha256((rp or self.rp).encode()).digest() + bytes([flags]) + self.count.to_bytes(4, "big")
        if attested:
            key = {1: 2, 3: -7, -1: 1, -2: self.x.to_bytes(32, "big"), -3: self.y.to_bytes(32, "big")}
            ad += bytes(16) + len(self.id).to_bytes(2, "big") + self.id + cbor(key)
        return ad


def client(kind, challenge, origin=f"https://{HOST}"):
    return json.dumps({"type": kind, "challenge": challenge, "origin": origin}).encode()


def reg_start(cookie, pw):
    return call("POST", "/api/webauthn/register/start", cookie, {"password": pw})


def reg_finish(cookie, start, key, name="YubiKey blauw", cd=None, ad=None, cred=None):
    o = start[1]["publicKey"]
    body = {"state": start[1]["state"], "name": name, "id": b64u(cred if cred is not None else key.id),
            "clientDataJSON": b64u(cd or client("webauthn.create", o["challenge"])),
            "attestationObject": b64u(cbor({"fmt": "none", "attStmt": {}, "authData": ad or key.auth(0x45, attested=True)})), "transports": ["usb", "warp"]}
    return call("POST", "/api/webauthn/register/finish", cookie, body)


def get(key, start, flags=0x05, cd=None, rp=None, count=None, handle=None, bad_sig=False, cred=None):
    o = start[1]["publicKey"]
    cd = cd or client("webauthn.get", o["challenge"])
    ad = key.auth(flags, rp=rp, count=count)
    sig = key.sign(ad + hashlib.sha256(cd).digest() + (b"x" if bad_sig else b""))
    return {"state": start[1]["state"], "id": b64u(cred if cred is not None else key.id), "clientDataJSON": b64u(cd),
            "authenticatorData": b64u(ad), "signature": b64u(sig), "userHandle": handle}


def finish(body, **kw):
    return call("POST", "/api/webauthn/login/finish", body=body, **kw)


def fresh():
    main.login_guard.failures.clear()


# ================================================================ B. een sleutel toevoegen
print("--- B. een sleutel toevoegen")
r = call("GET", "/api/webauthn", ROOT)
check("nog geen sleutels; de naam van dit adres", r[0] == 200 and r[1]["keys"] == [] and r[1]["rp"] == HOST and r[1]["password"] is True, json.dumps(r[1]))
check("via een IP-adres: geen naam", call("GET", "/api/webauthn", ROOT, host="192.168.1.10")[1]["rp"] is None)
r = reg_start(ROOT, "")
check("toevoegen zonder wachtwoord: geweigerd", r[0] == 403, detail(r))
r = reg_start(ROOT, "fout-wachtwoord")
check("met een verkeerd wachtwoord: geweigerd", r[0] == 403 and main.login_guard.failures, detail(r))
fresh()
r = call("POST", "/api/webauthn/register/start", ROOT, {"password": main.APP_PASSWORD}, origin="https://192.168.1.10", host="192.168.1.10")
check("via een IP-adres: uitleg dat het een naam moet zijn", r[0] == 409 and "IP-adres" in detail(r), detail(r))
r = call("POST", "/api/webauthn/register/start", ROOT, {"password": main.APP_PASSWORD}, origin="https://kwaad.example")
check("vanaf een andere website: geweigerd", r[0] == 403)
K1 = Key()
s = reg_start(ROOT, main.APP_PASSWORD)
o = s[1].get("publicKey", {}) if s[0] == 200 else {}
check("de vraag aan de browser: naam, gebruiker, ES256 en RS256, geen attestatie", s[0] == 200 and o["rp"] == {"id": HOST, "name": "Proxmox Maintool"}
      and o["user"]["name"] == main.APP_USER and [p["alg"] for p in o["pubKeyCredParams"]] == [-7, -257] and o["attestation"] == "none"
      and o["excludeCredentials"] == [], json.dumps(o)[:200])
handle = o.get("user", {}).get("id")
for label, make in (("ander soort antwoord", lambda c: client("webauthn.get", c)),
                    ("andere uitdaging", lambda c: client("webauthn.create", b64u(b"x" * 32))),
                    ("ander adres in het antwoord", lambda c: client("webauthn.create", c, "https://kwaad.example"))):
    s2 = reg_start(ROOT, main.APP_PASSWORD)
    r = reg_finish(ROOT, s2, K1, cd=make(s2[1]["publicKey"]["challenge"]))
    check(f"geweigerd: {label}", r[0] == 400, detail(r))
s2 = reg_start(ROOT, main.APP_PASSWORD)
r = reg_finish(ROOT, s2, K1, ad=K1.auth(0x45, attested=True, rp="kwaad.example"))
check("geweigerd: sleutel voor een andere naam (rp-id)", r[0] == 400, detail(r))
s2 = reg_start(ROOT, main.APP_PASSWORD)
r = reg_finish(ROOT, s2, K1, ad=K1.auth(0x40, attested=True))
check("geweigerd: niet aangeraakt (geen UP-vlag)", r[0] == 400, detail(r))
s2 = reg_start(ROOT, main.APP_PASSWORD)
r = reg_finish(ROOT, s2, K1, cred=b"y" * 32)
check("geweigerd: ID van de browser hoort niet bij de sleutel", r[0] == 400, detail(r))
s2 = reg_start(ROOT, main.APP_PASSWORD)
okp = hashlib.sha256(HOST.encode()).digest() + b"\x45" + (1).to_bytes(4, "big") + bytes(16) + len(K1.id).to_bytes(2, "big") + K1.id + cbor({1: 1, 3: -8, -1: 6, -2: b"z" * 32})
r = reg_finish(ROOT, s2, K1, ad=okp)
check("geweigerd: soort handtekening die de tool niet kent (Ed25519)", r[0] == 400 and "ES256" in detail(r), detail(r))
s2 = reg_start(ROOT, main.APP_PASSWORD)
r = reg_finish(ROOT, s2, K1, name="<script>")
check("geweigerd: rare naam", r[0] == 400, detail(r))
K1.count = 0
r = reg_finish(ROOT, s, K1)
check("goede sleutel toegevoegd", r[0] == 200 and [k["name"] for k in r[1]["keys"]] == ["YubiKey blauw"] and r[1]["keys"][0]["here"] is True, detail(r))
r = reg_finish(ROOT, s, K1)
check("dezelfde uitdaging nog een keer: geweigerd", r[0] == 400 and "duurde te lang" in detail(r), detail(r))
s2 = reg_start(ROOT, main.APP_PASSWORD)
check("de sleutel staat nu bij 'niet nog een keer'", s2[1]["publicKey"]["excludeCredentials"] == [{"type": "public-key", "id": b64u(K1.id)}])
r = reg_finish(ROOT, s2, K1)
check("dezelfde sleutel nog een keer: geweigerd", r[0] == 409, detail(r))
st = main.wa_state()[main.APP_USER]
check("bewaard: alleen de openbare sleutel, de teller, de naam, het adres; onbekende transport weg", st["keys"][0]["kty"] == "EC"
      and "d" not in st["keys"][0] and st["keys"][0]["rp"] == HOST and st["keys"][0]["transports"] == ["usb"] and st["handle"] == handle)
check("het bestand is alleen voor de tool leesbaar", oct(os.stat(main.WEBAUTHN_FILE).st_mode & 0o777) == "0o600")
r = reg_start(READER, PW)
K2 = Key()
r = reg_finish(READER, r, K2, name="Sleutel lezer")
check("een gewone gebruiker voegt ook een sleutel toe", r[0] == 200 and len(r[1]["keys"]) == 1, detail(r))
s3 = call("POST", "/api/webauthn/register/start", KIOSK, {})
K3 = Key()
r = reg_finish(KIOSK, s3, K3, name="Kiosk")
check("wie alleen via SSO inlogt, hoeft geen wachtwoord te geven", s3[0] == 200 and r[0] == 200, detail(r))
r = reg_start(READER, PW)
check("de uitdaging hoort bij de gebruiker: een ander kan hem niet afmaken", reg_finish(ROOT, r, Key())[0] == 400)

# ================================================================ C. inloggen met alleen de sleutel
print("--- C. inloggen met alleen de sleutel")
fresh()
s = call("POST", "/api/webauthn/login/start", body={"username": ""})
check("zonder naam: de sleutel kiest zelf (lege lijst), pincode gevraagd", s[0] == 200 and s[1]["publicKey"]["allowCredentials"] == []
      and s[1]["publicKey"]["userVerification"] == "required" and s[1]["publicKey"]["rpId"] == HOST, json.dumps(s[1])[:200])
r = finish(get(K1, s))
tok = session_of(r[2])
check("ingelogd als het hoofdaccount", r[0] == 200 and main.read_token(tok) == main.APP_USER, detail(r))
check("de teller en het laatste gebruik zijn bijgewerkt", main.wa_user(main.APP_USER)["keys"][0]["count"] == K1.count and main.wa_user(main.APP_USER)["keys"][0]["used"])
s = call("POST", "/api/webauthn/login/start", body={"username": "lezer"})
check("met naam: alleen zijn sleutels", s[1]["publicKey"]["allowCredentials"] == [{"type": "public-key", "id": b64u(K2.id), "transports": ["usb"]}], json.dumps(s[1]["publicKey"]["allowCredentials"]))
r = finish(get(K2, s, handle=main.wa_user("lezer")["handle"]))
check("ingelogd als lezer (met de handle van de sleutel)", r[0] == 200 and main.read_token(session_of(r[2])) == "lezer", detail(r))
s = call("POST", "/api/webauthn/login/start", body={"username": "bestaat-niet"})
check("onbekende naam: zelfde soort antwoord (lege lijst)", s[0] == 200 and s[1]["publicKey"]["allowCredentials"] == [])
fresh()
cases = [("zonder pincode (geen UV-vlag)", lambda s: get(K1, s, flags=0x01), "pincode"),
         ("verkeerde handtekening", lambda s: get(K1, s, bad_sig=True), "niet herkend"),
         ("onbekende sleutel", lambda s: get(Key(), s), "niet herkend"),
         ("handle van een ander", lambda s: get(K1, s, handle=main.wa_user("lezer")["handle"]), "niet herkend"),
         ("andere naam (rp-id) in het antwoord", lambda s: get(K1, s, rp="kwaad.example"), "niet herkend"),
         ("teller niet hoger (een kopie?)", lambda s: get(K1, s, count=main.wa_user(main.APP_USER)["keys"][0]["count"]), "teller"),
         ("ander soort antwoord", lambda s: get(K1, s, cd=client("webauthn.create", s[1]["publicKey"]["challenge"])), "klopt niet")]
for label, make, word in cases:
    fresh()
    s = call("POST", "/api/webauthn/login/start", body={})
    r = finish(make(s))
    check(f"geweigerd: {label}", r[0] in (400, 401) and word in detail(r) and not session_of(r[2]), detail(r))
fresh()
s = call("POST", "/api/webauthn/login/start", body={})
body = get(K1, s)
r = finish(body, origin="https://kwaad.example")
check("geweigerd: antwoord vanaf een andere website", r[0] == 401)
r = finish(body)
check("geweigerd: dezelfde uitdaging nog een keer", r[0] == 400)
fresh()
s = call("POST", "/api/webauthn/login/start", body={}, origin="https://192.168.1.10", host="192.168.1.10")
check("inloggen met de sleutel via een IP-adres: uitleg", s[0] == 409 and "IP-adres" in detail(s), detail(s))
for _ in range(5):
    main.login_guard.failed("203.0.113.7")
check("na te veel mislukte pogingen: dicht", call("POST", "/api/webauthn/login/start", body={})[0] == 429)
fresh()
check("de inlogpagina weet dat er sleutels zijn", call("GET", "/api/sso/options")[1].get("webauthn") is True)

# ================================================================ D. de sleutel na het wachtwoord
print("--- D. de sleutel na het wachtwoord")
r = call("PUT", "/api/webauthn", READER, {"required": True})
check("verplicht maken zonder wachtwoord: geweigerd", r[0] == 403)
fresh()
r = call("PUT", "/api/webauthn", READER, {"required": True, "password": PW})
check("lezer maakt de sleutel verplicht", r[0] == 200 and r[1]["required"] is True)
r = call("PUT", "/api/webauthn", KIOSK, {"required": True})
check("zonder wachtwoord-inlog is verplicht maken zinloos: geweigerd", r[0] == 400, detail(r))
r = call("POST", "/api/login", body={"username": "lezer", "password": PW, "remember": True})
check("wachtwoord goed: nog geen sessie, wel de vraag om de sleutel", r[0] == 200 and r[1].get("next") == "webauthn" and not session_of(r[2])
      and r[1]["publicKey"]["allowCredentials"][0]["id"] == b64u(K2.id) and r[1]["publicKey"]["userVerification"] == "discouraged", json.dumps(r[1])[:200])
r2 = finish(get(K2, r, flags=0x01))
line = next((c for c in r2[2] if c.startswith(main.SESSION_COOKIE + "=")), "")
check("met de sleutel erachteraan (aanraken is genoeg): ingelogd, en Ingelogd blijven reist mee", r2[0] == 200 and main.read_token(session_of(r2[2])) == "lezer" and "Max-Age" in line, detail(r2))
fresh()
r = call("POST", "/api/login", body={"username": "lezer", "password": PW})
r2 = finish(get(K1, r, flags=0x05))
check("de sleutel van een ander helpt niet", r2[0] == 401 and not session_of(r2[2]))
fresh()
r = call("POST", "/api/login", body={"username": "lezer", "password": PW}, origin="https://192.168.1.10", host="192.168.1.10")
check("via een IP-adres: geweigerd, met waar het wel kan", r[0] == 409 and HOST in detail(r) and not session_of(r[2]), detail(r))
r = call("POST", "/api/login", body={"username": "lezer", "password": "fout"})
check("verkeerd wachtwoord: gewoon geweigerd (geen vraag om de sleutel)", r[0] == 401 and "next" not in r[1])
fresh()
r = call("POST", "/api/login", body={"username": "beheer2", "password": PW})
check("wie de sleutel niet verplicht heeft, logt gewoon in", r[0] == 200 and session_of(r[2]))
r = call("PUT", "/api/webauthn", READER, {"remove": b64u(K2.id), "password": PW})
check("de laatste sleutel weg: dan ook niet meer verplicht", r[0] == 200 and r[1]["keys"] == [] and r[1]["required"] is False)
r = call("PUT", "/api/webauthn", READER, {"required": True, "password": PW})
check("verplicht maken zonder sleutel: geweigerd", r[0] == 400, detail(r))
r = call("PUT", "/api/webauthn", READER, {"remove": "bestaat-niet-xxxxxxxxxxxx", "password": PW})
check("een sleutel die er niet is: 404", r[0] == 404)
check("niets te wijzigen: 400", call("PUT", "/api/webauthn", READER, {"password": PW})[0] == 400)

# ================================================================ E. de beheerder en de gebruikerslijst
print("--- E. de beheerder en de gebruikerslijst")
users = {u["name"]: u for u in call("GET", "/api/users", ROOT)[1]}
check("de lijst toont sleutels en of ze verplicht zijn", users[main.APP_USER]["keys"] == 1 and users["kiosk"]["keys"] == 1 and users["lezer"]["keys"] == 0
      and users[main.APP_USER]["key_required"] is False)
me = call("GET", "/api/me", ROOT)[1]
check("wie ben ik: met sleutels", me.get("webauthn") == {"keys": 1, "required": False})
check("de lezer mag de sleutels van een ander niet weghalen", call("DELETE", "/api/users/kiosk/webauthn", READER)[0] == 403)
r = call("DELETE", "/api/users/kiosk/webauthn", ROOT)
check("de beheerder haalt de sleutels van kiosk weg (sleutel kwijt)", r[0] == 200 and {u["name"]: u for u in r[1]}["kiosk"]["keys"] == 0)
check("nog een keer: niets meer weg te halen (404)", call("DELETE", "/api/users/kiosk/webauthn", ROOT)[0] == 404)
s = reg_start(READER, PW)
reg_finish(READER, s, Key(), name="tijdelijk")
call("DELETE", "/api/users/lezer", ROOT)
check("gebruiker verwijderd: zijn sleutels ook", "lezer" not in main.wa_state())
ev = [e for e in main.state.events(0) if e.get("kind") == "webauthn"]
check("het logboek noemt toevoegen en weghalen (zonder sleutels erin)", any("toegevoegd" in e["result"] for e in ev) and any("weggehaald" in e["result"] for e in ev)
      and not any(b64u(K1.id) in json.dumps(e) for e in ev))
main.WEBAUTHN_FILE.write_text("{kapot", encoding="utf-8")
check("beschadigd sleutelbestand: geen sleutels, de tool blijft werken", main.wa_state() == {} and call("GET", "/api/webauthn", ROOT)[0] == 200)
main.WEBAUTHN_FILE.unlink()

# ================================================================ F. de console van een node
print("--- F. de console van een node")
check("wie geen beheerder is: geen toegang", call("GET", "/api/nodeconsole", KIOSK)[0] == 403)
r = call("GET", "/api/nodeconsole", ROOT)
check("nog niet ingelogd voor de console", r[0] == 200 and r[1] == {"ready": False, "user": None, "until": None, "need_code": False}, json.dumps(r[1]))
TICKETS = []


def fake_ticket(userid, password, **extra):
    TICKETS.append((userid, password, extra))
    if password == "goed":
        return {"username": userid, "ticket": "PVE:" + userid + ":TEST", "CSRFPreventionToken": "csrf-test"}
    if password == "tfa":
        return {"username": userid, "ticket": "PVE:!tfa!challenge", "NeedTFA": 1}
    if password in ("totp:123456", "recovery:abcd-efgh-ijkl") and extra.get("tfa-challenge") == "PVE:!tfa!challenge":
        return {"username": userid, "ticket": "PVE:" + userid + ":NA-TFA", "CSRFPreventionToken": "csrf-tfa"}
    if password == "verkeerd-realm":
        return {"username": "root@pve", "ticket": "x", "CSRFPreventionToken": "y"}
    return None


main.pve_ticket = fake_ticket
fresh()
r = call("POST", "/api/nodeconsole/login", ROOT, {"username": "root", "password": "fout"})
check("verkeerd wachtwoord: 403 (geen 401, dat zou de pagina naar het inloggen sturen), telt als mislukte poging", r[0] == 403 and main.login_guard.failures, detail(r))
for label, answer, word in (("account staat uit in Proxmox (1.3.2)", {"enable": 0, "expire": 0}, "staat in Proxmox uit"),
                            ("account is verlopen (1.3.2)", {"enable": 1, "expire": int(time.time()) - 60}, "is in Proxmox verlopen"),
                            ("account bestaat niet (1.3.2)", lambda kw: (_ for _ in ()).throw(ResourceException(500, "Internal Server Error", "no such user ('root@pam')")), "bestaat niet in Proxmox")):
    fresh()
    W.table["access/users/root@pam"] = answer
    r = call("POST", "/api/nodeconsole/login", ROOT, {"username": "root", "password": "fout"})
    check(f"de melding zegt waarom: {label}", r[0] == 403 and word in detail(r) and "root@pam" in detail(r), detail(r))
W.table.pop("access/users/root@pam", None)
fresh()
r = call("POST", "/api/nodeconsole/login", ROOT, {"username": "root", "password": "fout"}, cookies={"maintool_lang": "en"})
check("die melding ook vertaald (Engels), als Proxmox niets bijzonders meldt de gewone", r[0] == 403 and detail(r) == "User name, password or code is not right", detail(r))
fresh()
check("rare gebruikersnaam: 400", call("POST", "/api/nodeconsole/login", ROOT, {"username": "root;rm", "password": "goed"})[0] == 400)
check("ander realm dan pam: niet gebruikt", call("POST", "/api/nodeconsole/login", ROOT, {"username": "root", "password": "verkeerd-realm"})[0] == 502)
r = call("POST", "/api/nodeconsole/login", ROOT, {"username": "root@pam", "password": "goed"})
check("goed: klaar voor de console, als root@pam", r[0] == 200 and r[1]["ready"] and r[1]["user"] == "root@pam" and TICKETS[-1][0] == "root@pam", json.dumps(r[1]))
check("het wachtwoord staat nergens in de toestand van de tool", "goed" not in json.dumps({k: {**v, "ticket": "", "csrf": ""} for k, v in main._nodecon.items()}))
check("alleen voor deze sessie: een andere sessie van dezelfde gebruiker moet zelf inloggen",
      call("GET", "/api/nodeconsole", login(main.APP_USER, main.APP_PASSWORD)[1])[1]["ready"] is False)
check("en niet voor een andere beheerder", call("GET", "/api/nodeconsole", ADMIN2)[1]["ready"] is False)
r = call("POST", "/api/nodeconsole/login", ADMIN2, {"username": "root", "password": "tfa"})
check("met tweestapsverificatie: eerst de vraag om de code", r[0] == 200 and r[1]["need_code"] and not r[1]["ready"], json.dumps(r[1]))
r = call("POST", "/api/nodeconsole/login", ADMIN2, {"code": "123 456"})
check("de code (TOTP) erachteraan: klaar", r[0] == 200 and r[1]["ready"] and TICKETS[-1][1] == "totp:123456" and TICKETS[-1][2] == {"tfa-challenge": "PVE:!tfa!challenge"}, str(TICKETS[-1]))
call("DELETE", "/api/nodeconsole", ADMIN2)
call("POST", "/api/nodeconsole/login", ADMIN2, {"username": "root", "password": "tfa"})
r = call("POST", "/api/nodeconsole/login", ADMIN2, {"code": "abcd-efgh-ijkl"})
check("of een herstelcode", r[0] == 200 and r[1]["ready"] and TICKETS[-1][1] == "recovery:abcd-efgh-ijkl")
check("een code zonder eerste stap: 400", call("POST", "/api/nodeconsole/login", ROOT, {"code": "123456"})[0] == 400)
check("vergeten", call("DELETE", "/api/nodeconsole", ADMIN2)[1]["ready"] is False and call("GET", "/api/nodeconsole", ADMIN2)[1]["ready"] is False)


class FakeResponse:
    def __init__(self, status, data):
        self.status_code, self._data, self.headers = status, data, {"content-type": "application/json;charset=UTF-8"}

    def json(self):
        return {"data": self._data}


POSTS = []


class FakeSession:
    verify = None

    def mount(self, *a):
        pass

    def post(self, url, **kw):
        POSTS.append((url, kw))
        return FakeResponse(*SESSION_ANSWER)


real_session = main.requests.Session
main.requests.Session = FakeSession
entry = {"user": "root@pam", "ticket": "PVE:root@pam:TEST", "csrf": "csrf-test"}
SESSION_ANSWER = (200, {"port": "5900", "ticket": "PVEVNC:xyz", "user": "root@pam", "upid": "UPID:x"})
main.pve.host = "10.20.30.1"
got = main.node_termproxy(entry, "pve1")
check("termproxy: met het ticket en de CSRF-sleutel van de beheerder, op de juiste node", got["port"] == "5900" and POSTS[-1][0].endswith("/nodes/pve1/termproxy")
      and POSTS[-1][1]["cookies"] == {"PVEAuthCookie": "PVE:root@pam:TEST"} and POSTS[-1][1]["headers"] == {"CSRFPreventionToken": "csrf-test"}, str(POSTS[-1])[:200])
for status, word in ((401, "verlopen"), (403, "mag geen console")):
    SESSION_ANSWER = (status, None)
    try:
        main.node_termproxy(entry, "pve1")
        check(f"termproxy {status}: nette melding", False)
    except HTTPException as err:
        check(f"termproxy {status}: nette melding", err.status_code == status and word in err.detail, err.detail)
main.requests.Session = real_session


def ws(path, cookie=None, origin=f"https://{HOST}"):
    headers = [(b"host", HOST.encode()), (b"origin", origin.encode())]
    if cookie:
        headers.append((b"cookie", f"{main.SESSION_COOKIE}={cookie}".encode()))
    scope = {"type": "websocket", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1", "scheme": "wss", "path": path,
             "raw_path": path.encode(), "query_string": b"", "root_path": "", "headers": headers, "client": ("203.0.113.7", 40000),
             "server": (HOST, 443), "subprotocols": []}
    sent, asked = [], []

    async def receive():
        if not asked:
            asked.append(1)
            return {"type": "websocket.connect"}
        await asyncio.sleep(0.05)
        return {"type": "websocket.disconnect", "code": 1006}

    async def send(message):
        sent.append(message)
    asyncio.run(main.app(scope, receive, send))
    return sent


def closed_with(sent):
    return next((m.get("code") for m in sent if m["type"] == "websocket.close"), None)


check("console van een node: zonder sessie dicht", closed_with(ws("/api/nodeconsole/pve1")) == 4401)
check("console van een node: wie geen beheerder is geweigerd", closed_with(ws("/api/nodeconsole/pve1", KIOSK)) == 4403)
check("console van een node: andere website geweigerd", closed_with(ws("/api/nodeconsole/pve1", ROOT, origin="https://kwaad.example")) == 4401)
check("console van een node: rare nodenaam", closed_with(ws("/api/nodeconsole/pve_1", ROOT)) == 4400)
sent = ws("/api/nodeconsole/pve1", ADMIN2)
text = b"".join(m.get("bytes") or b"" for m in sent if m["type"] == "websocket.send").decode()
check("console van een node zonder inloggen: uitleg in de terminal", any(m["type"] == "websocket.accept" for m in sent) and "Log eerst in voor de console" in text, text)
r = call("POST", "/api/logout", ROOT)
check("uitloggen vergeet ook het consoleticket", r[0] == 200 and not any(v["owner"] == main.APP_USER and v.get("ticket") == "PVE:root@pam:TEST" for v in main._nodecon.values()))
r, ROOT = login(main.APP_USER, main.APP_PASSWORD)
ev = [e for e in main.state.events(0) if e.get("kind") == "console"]
check("het logboek noemt wie inlogde voor de console (zonder wachtwoord)", any(e.get("name") == "root@pam" for e in ev) and "goed" not in json.dumps(ev))

# ================================================================ G. API-tokens van Proxmox
print("--- G. API-tokens")
TOOL = main.PVE_USER
W.table.update({
    "access/users": [{"userid": "root@pam", "enable": 1, "tokens": [{"tokenid": "terraform", "privsep": 0}]},
                     {"userid": TOOL, "enable": 1, "tokens": [{"tokenid": main.TOKEN_NAME, "privsep": 0}]},
                     {"userid": "chef@pve", "enable": 1, "groups": "", "tokens": [{"tokenid": "backup", "privsep": 1, "comment": "nachtelijk", "expire": 0}]},
                     {"userid": "anna@pve", "enable": 1, "tokens": []}],
    "access/groups": [], "access/domains": [{"realm": "pve", "type": "pve"}, {"realm": "pam", "type": "pam"}],
    "access/roles": [{"roleid": "PVEAuditor", "privs": "Sys.Audit", "special": 1}, {"roleid": "Administrator", "privs": "Sys.Audit", "special": 1}],
    "access/acl": [{"path": "/", "type": "user", "ugid": "chef@pve", "roleid": "Administrator", "propagate": 1},
                   {"path": "/vms", "type": "token", "ugid": "chef@pve!backup", "roleid": "PVEAuditor", "propagate": 1}],
    "pools": [], "cluster/resources": []})
r = call("GET", "/api/access", ROOT)
toks = {tk["tokenid"]: tk for tk in r[1].get("tokens", [])} if r[0] == 200 else {}
check("alle tokens in de lijst, met hun eigen rechten", r[0] == 200 and sorted(toks) == sorted(["root@pam!terraform", f"{TOOL}!{main.TOKEN_NAME}", "chef@pve!backup"])
      and toks["chef@pve!backup"]["privsep"] and toks["chef@pve!backup"]["acl"] == [{"path": "/vms", "type": "token", "ugid": "chef@pve!backup", "roleid": "PVEAuditor", "propagate": True}]
      and toks["chef@pve!backup"]["comment"] == "nachtelijk", json.dumps(r[1].get("tokens"))[:300])
check("het token van de tool en dat van root zijn beschermd", toks[f"{TOOL}!{main.TOKEN_NAME}"]["tool"] and toks[f"{TOOL}!{main.TOKEN_NAME}"]["protected"] and toks["root@pam!terraform"]["protected"])
SECRET = "11111111-2222-3333-4444-" + secrets.token_hex(6)
W.answers[("POST", "access/users/anna@pve/token/script")] = {"full-tokenid": "anna@pve!script", "info": {"privsep": "1"}, "value": SECRET}
W.changes.clear()
r = call("POST", "/api/access/tokens", ROOT, {"userid": "anna@pve", "tokenid": "script", "comment": "voor het script", "expire": 0, "privsep": True})
check("token aangemaakt: het geheim komt één keer terug", r[0] == 200 and r[1] == {"ok": True, "tokenid": "anna@pve!script", "secret": SECRET, "privsep": True}, detail(r))
check("naar Proxmox: privsep 1 en de opmerking", W.changes == [("POST", "access/users/anna@pve/token/script", {"privsep": 1, "comment": "voor het script"})], str(W.changes))
check("het geheim staat niet in het logboek", SECRET not in main.state.log.read_text(encoding="utf-8"))
for label, body, code in (("van root@pam", {"userid": "root@pam", "tokenid": "nieuw"}, 409), ("van de tool zelf", {"userid": TOOL, "tokenid": "nieuw"}, 409),
                          ("rare naam", {"userid": "anna@pve", "tokenid": "1-begint-met-cijfer"}, 400), ("naam te kort", {"userid": "anna@pve", "tokenid": "a"}, 400),
                          ("onbekende gebruiker", {"userid": "niemand@pve", "tokenid": "nieuw"}, 404), ("bestaat al", {"userid": "chef@pve", "tokenid": "backup"}, 409),
                          ("ongeldige datum", {"userid": "anna@pve", "tokenid": "nieuw", "expire": 12}, 400)):
    W.changes.clear()
    r = call("POST", "/api/access/tokens", ROOT, body)
    check(f"geweigerd: {label}", r[0] == code and W.changes == [], f"{r[0]} {detail(r)}")
check("wie geen beheerder is, maakt geen tokens", call("POST", "/api/access/tokens", KIOSK, {"userid": "anna@pve", "tokenid": "x2"})[0] == 403)
check("vanaf een andere website niet", call("POST", "/api/access/tokens", ROOT, {"userid": "anna@pve", "tokenid": "x2"}, origin="https://kwaad.example")[0] == 403)
W.changes.clear()
r = call("PUT", "/api/access/tokens/chef@pve/backup", ROOT, {"privsep": False, "comment": ""})
check("token aangepast: alleen wat is opgegeven", r[0] == 200 and W.changes == [("PUT", "access/users/chef@pve/token/backup", {"comment": "", "privsep": 0})], str(W.changes))
check("niets opgegeven: 400", call("PUT", "/api/access/tokens/chef@pve/backup", ROOT, {})[0] == 400)
check("onbekend token: 404", call("PUT", "/api/access/tokens/chef@pve/weg", ROOT, {"comment": "x"})[0] == 404)
W.changes.clear()
r = call("DELETE", "/api/access/tokens/chef@pve/backup", ROOT)
check("token verwijderd", r[0] == 200 and W.changes == [("DELETE", "access/users/chef@pve/token/backup", {})], str(W.changes))
check("het token van de tool verwijdert de tool niet", call("DELETE", f"/api/access/tokens/{TOOL}/{main.TOKEN_NAME}", ROOT)[0] == 409)
W.changes.clear()
r = call("PUT", "/api/access/acl", ROOT, {"path": "/storage", "role": "PVEAuditor", "token": "chef@pve!backup"})
check("recht voor een token: tokens= naar Proxmox", r[0] == 200 and W.changes == [("PUT", "access/acl", {"path": "/storage", "roles": "PVEAuditor", "tokens": "chef@pve!backup", "propagate": 1})], str(W.changes))
check("recht voor een onbekend token: 404", call("PUT", "/api/access/acl", ROOT, {"path": "/", "role": "PVEAuditor", "token": "chef@pve!weg"})[0] == 404)
check("recht voor een token van root: 409", call("PUT", "/api/access/acl", ROOT, {"path": "/", "role": "PVEAuditor", "token": "root@pam!terraform"})[0] == 409)
check("gebruiker én token tegelijk: 400", call("PUT", "/api/access/acl", ROOT, {"path": "/", "role": "PVEAuditor", "token": "chef@pve!backup", "user": "chef@pve"})[0] == 400)
W.changes.clear()
r = call("PUT", "/api/access/acl", ROOT, {"path": "/vms", "role": "PVEAuditor", "token": "chef@pve!backup", "remove": True})
check("recht van een token intrekken", r[0] == 200 and W.changes and W.changes[-1][2].get("delete") == 1 and W.changes[-1][2].get("tokens") == "chef@pve!backup", str(W.changes))
r = call("PUT", "/api/access/acl", ROOT, {"path": "/", "role": "PVEAuditor", "user": "anna@pve"})
check("rechten voor gebruikers werken nog zoals altijd", r[0] == 200)

# ================================================================ H. tabellen aanpassen
print("--- H. tabellen aanpassen")
T = {"cols": {"overview.guests": {"sig": 13, "hide": ["os", "i4"], "add": ["disk", "tags"]}, "pveusers.users": {"sig": 8, "hide": ["i2"]}},
     "order": {"pveusers": ["pveusers.tokens", "pveusers.users", "pveusers.groups"], "overview": ["overview.guests", "overview.nodes"]}}
r = call("PUT", "/api/settings", ROOT, {"tables": T})
check("indeling bewaard en teruggegeven (nageklopt)", r[0] == 200 and r[1]["tables"] == {"cols": {"overview.guests": {"sig": 13, "hide": ["i4", "os"], "add": ["disk", "tags"]},
                                                                                               "pveusers.users": {"sig": 8, "hide": ["i2"], "add": []}}, "order": T["order"]}, json.dumps(r[1].get("tables")))
check("andere gebruikers zien hun eigen (lege) indeling", call("GET", "/api/settings", ADMIN2)[1]["tables"] is None)
for label, bad in (("onbekend veld", {"cols": {}, "x": 1}), ("rare tabelnaam", {"cols": {"Overview!": {"sig": 2}}}),
                   ("sig 0", {"cols": {"a.b": {"sig": 0}}}), ("kolom met rare naam", {"cols": {"a.b": {"sig": 3, "hide": ["<x>"]}}}),
                   ("dubbele volgorde", {"order": {"overview": ["a.b", "a.b"]}}), ("te veel", {"cols": {f"t.k{i}": {"sig": 2} for i in range(61)}}),
                   ("geen object", ["x"])):
    check(f"geweigerd: {label}", call("PUT", "/api/settings", ROOT, {"tables": bad})[0] in (400, 422))
r = call("PUT", "/api/settings", ROOT, {"tables": None})
check("terug naar de standaard", r[0] == 200 and r[1]["tables"] is None)

check("het echte cluster is niet aangeraakt", not TRIPPED, str(TRIPPED))
print()
print("ALLES GOED" if not FAILED else f"FOUT ({len(FAILED)}): {FAILED}")
