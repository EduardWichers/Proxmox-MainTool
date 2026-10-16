"""Tests version 1.2.1 of the backend in-process on the tool container, from a copy in /tmp with its own state folder:
sessions: Stay logged in, session cookies, the session settings and the idle logout setting.
Everything runs against a stand-in cluster that only writes down what it is asked to do; nothing real is changed."""
import asyncio, base64, datetime as dt, hashlib, hmac, json, os, secrets, subprocess, sys, tempfile, time, urllib.parse
for line in open("/etc/maintool/maintool.env", encoding="utf-8"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ[k.strip()] = v.strip()
os.environ["STATE_DIRECTORY"] = "/tmp/mt-v221/state"
sys.path.insert(0, "/tmp/mt-v221/app")
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
main.agent = lambda ip, *words, **k: ("maintool-agent 3 pve1" if words[:1] == ("ping",) else "") if words[:1] in (("info",), ("refresh",), ("ping",)) else TRIPPED.append(("agent", words)) or ""   # ping: de versievraag van de bewaker van de updates (hangt van de timing af)
main.updates.start = lambda lists=True: False
main.updates.busy = False
W.table.update({"nodes": [], "cluster/resources": [], "cluster/status": [], "cluster/ha/status/current": []})
NOW = time.time()
HOURS = main.session_policy()["session_hours"]


def cookie_line(setc):
    return next((c for c in setc if c.startswith(main.SESSION_COOKIE + "=") and 'maintool_session=""' not in c), "")


def token_data(tok):
    payload = (tok or "").partition(".")[0]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def login(name, pw, remember=None, **extra):
    body = {"username": name, "password": pw, **({} if remember is None else {"remember": remember}), **extra}
    r = call("POST", "/api/login", body=body)
    line = cookie_line(r[2])
    return r, line, session_of(r[2])


main.login_guard.failures.clear()
r, line, ROOT = login(main.APP_USER, main.APP_PASSWORD)
PW = secrets.token_urlsafe(18)
for name, roles in (("over", ["overview"]), ("lezer", []), ("opslag", ["storage"])):
    call("POST", "/api/users", ROOT, {"name": name, "roles": roles, "password": PW})
check("inloggen van de testgebruikers", ROOT and session_of(call("POST", "/api/login", body={"username": "lezer", "password": PW})[2]))

print("--- A. zonder en met Ingelogd blijven")
p = main.session_policy()
check("standaard: niet uitloggen zonder activiteit, ingelogd blijven mag, 30 dagen, gewone sessie zoals SESSION_HOURS", p["idle"] == 0 and p["remember"] is True and p["remember_days"] == 30
      and p["session_hours"] == min(max(round(main.SESSION_SECONDS / 3600), 1), 24), json.dumps(p))
r, line, tok = login("lezer", PW)
d = token_data(tok)
check("zonder vinkje: een sessiecookie (geen Max-Age), verdwijnt bij sluiten van de browser", r[0] == 200 and line and "Max-Age" not in line and "expires" not in line.lower(), line[:120])
check("zonder vinkje: de sessie duurt de gewone tijd en is niet blijvend", abs(d["e"] - (time.time() + HOURS * 3600)) < 10 and "r" not in d, json.dumps(d))
r, line, tok = login("lezer", PW, remember=True)
d = token_data(tok)
check("met vinkje: een blijvend cookie van 30 dagen", "Max-Age=2592000" in line, line[:160])
check("met vinkje: de sessie duurt 30 dagen en is gemarkeerd als blijvend", abs(d["e"] - (time.time() + 30 * 86400)) < 10 and d.get("r") == 1, json.dumps(d))
check("en hij werkt gewoon", call("GET", "/api/me", tok)[0] == 200)
LONG = tok
old = base64.urlsafe_b64encode(json.dumps({"u": "lezer", "e": int(time.time()) + 3600, "g": main.account("lezer")["gen"]}).encode()).decode().rstrip("=")
check("een sessie uit een oudere versie (zonder r) blijft geldig", main.read_token(old + "." + main.sign(old)) == "lezer" and main.token_remembered(old + "." + main.sign(old)) is False)
check("de vlag r is ondertekend: wie hem toevoegt maakt de sessie ongeldig", main.read_token(base64.urlsafe_b64encode(json.dumps({**token_data(old + ".x"), "r": 1}).encode()).decode().rstrip("=") + "." + main.sign(old)) is None)

print("--- B. de instellingen (alleen beheerders)")
OVER = session_of(call("POST", "/api/login", body={"username": "over", "password": PW})[2])
READER = session_of(call("POST", "/api/login", body={"username": "lezer", "password": PW})[2])
for who, label in ((READER, "alleen lezen"), (OVER, "rol Overzicht")):
    check(f"{label}: lezen en wijzigen geweigerd", call("GET", "/api/policy", who)[0] == 403 and call("PUT", "/api/policy", who, {"idle": 30})[0] == 403)
x = call("GET", "/api/policy", ROOT)[1]
check("beheerder ziet de keuzes", x.get("choices") == {"idle": [0, 15, 30, 60, 120, 240, 480], "remember_days": [7, 14, 30, 90], "session_hours": [1, 24]} and x.get("idle") == 0, json.dumps(x)[:200])
bad = [({"idle": 7}, 400), ({"idle": "30"}, 422), ({"idle": True}, 422), ({"remember_days": 10}, 400), ({"session_hours": 0}, 400), ({"session_hours": 25}, 400),
       ({"session_hours": 1.5}, 422), ({}, 400), ({"remember": "ja"}, 422)]
wrong = [(b, c, call("PUT", "/api/policy", ROOT, b)[0]) for b, c in bad if call("PUT", "/api/policy", ROOT, b)[0] != c]
check(f"{len(bad)} ongeldige instellingen geweigerd met de juiste code", not wrong, str(wrong))
check("zonder Origin geweigerd", call("PUT", "/api/policy", ROOT, {"idle": 30}, origin=None)[0] == 403)
r = call("PUT", "/api/policy", ROOT, {"idle": 30, "session_hours": 2, "remember_days": 7})
check("opslaan: 30 minuten, gewone sessie 2 uur, ingelogd blijven 7 dagen", r[0] == 200 and r[1]["idle"] == 30 and r[1]["session_hours"] == 2 and r[1]["remember_days"] == 7 and r[1]["remember"] is True)
check("de andere instellingen blijven staan", r[1]["min_password"] == main.min_password() and r[1]["cloudflare"] in ("ask", "readonly", "off"))
r, line, tok = login("lezer", PW)
check("een gewone sessie duurt nu 2 uur", abs(token_data(tok)["e"] - (time.time() + 7200)) < 10)
r, line, tok = login("lezer", PW, remember=True)
check("ingelogd blijven duurt nu 7 dagen", "Max-Age=604800" in line and abs(token_data(tok)["e"] - (time.time() + 7 * 86400)) < 10)
r = call("PUT", "/api/policy", ROOT, {"remember": False})
r, line, tok = login("lezer", PW, remember=True)
check("ingelogd blijven uitgezet: het vinkje doet niets meer (sessiecookie, 2 uur)", "Max-Age" not in line and "r" not in token_data(tok) and abs(token_data(tok)["e"] - (time.time() + 7200)) < 10)
o = call("GET", "/api/sso/options")[1]
check("de inlogpagina hoort dat het vinkje er niet is", o.get("remember") == {"allowed": False, "days": 7}, json.dumps(o.get("remember")))
call("PUT", "/api/policy", ROOT, {"remember": True})
o = call("GET", "/api/sso/options")[1]
check("en weer wel, met het aantal dagen", o.get("remember") == {"allowed": True, "days": 7})

print("--- C. de pagina: na hoeveel minuten zonder activiteit")
r, line, NORMAL = login("lezer", PW)
r, line, KEPT = login("lezer", PW, remember=True)
page = call("GET", "/", NORMAL)[1]
check("gewone sessie: de pagina logt uit na 30 minuten", 'data-idle="30"' in page and "{{IDLE}}" not in page)
check("ingelogd blijven: de pagina logt niet uit", 'data-idle="0"' in call("GET", "/", KEPT)[1])
check("het waarschuwingsvenster, de Cloudflare-balk en de instellingen staan in de pagina", 'id="idledlg"' in page and 'id="relogin"' in page and 'id="us-sessbox"' in page)
login_page = call("GET", "/login")[1]
check("de inlogpagina heeft het vinkje en de melding na uitloggen", 'id="keep"' in login_page and "idle" in login_page and "{{" not in login_page)
call("PUT", "/api/policy", ROOT, {"idle": 0})
check("uitloggen zonder activiteit uit: 0", 'data-idle="0"' in call("GET", "/", NORMAL)[1])

print("--- D. de keuze blijft bij een nieuw cookie")
gen = main.account("lezer")["gen"]


def near_end(remember):
    data = {"u": "lezer", "e": int(time.time()) + 60, "g": gen, **({"r": 1} if remember else {})}
    payload = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
    return f"{payload}.{main.sign(payload)}"


main.issues.get = lambda *a, **k: []
r = call("GET", "/api/dashboard", near_end(True))
line = cookie_line(r[2])
check("dashboard aan de muur, blijvende sessie bijna om: nieuw blijvend cookie", r[0] == 200 and "Max-Age=604800" in line and token_data(session_of(r[2])).get("r") == 1, line[:120])
r = call("GET", "/api/dashboard", near_end(False))
line = cookie_line(r[2])
check("gewone sessie bijna om: nieuw sessiecookie", r[0] == 200 and line and "Max-Age" not in line and "r" not in token_data(session_of(r[2])))
r, line, KEPT = login("lezer", PW, remember=True)
NEWPW = secrets.token_urlsafe(18)
r = call("POST", "/api/password", KEPT, {"current": PW, "new": NEWPW})
check("eigen wachtwoord wijzigen met ingelogd blijven: het nieuwe cookie blijft blijvend", r[0] == 200 and "Max-Age=604800" in cookie_line(r[2]) and token_data(session_of(r[2])).get("r") == 1)
check("het oude cookie is daarna ongeldig", call("GET", "/api/me", KEPT)[0] == 401)
PW = NEWPW

print("--- E. ingelogd blijven via SSO")
saved = (main.sso_on, main.sso_conf, main.oidc_discovery, main.cloudflare_user)
main.sso_on = lambda m: True
main.cloudflare_user = lambda request: "lezer"
r = call("POST", "/api/sso/cloudflare?remember=1")
check("Cloudflare Access met vinkje: blijvend cookie", r[0] == 200 and "Max-Age=604800" in cookie_line(r[2]))
r = call("POST", "/api/sso/cloudflare")
check("Cloudflare Access zonder vinkje: sessiecookie", r[0] == 200 and "Max-Age" not in cookie_line(r[2]))
main.sso_conf = lambda m: {"public_url": f"https://{HOST}", "client_id": "x", "issuer": "https://idp.example", "provider": "other", "label": "Test"} if m == "oidc" else {}
main.oidc_discovery = lambda issuer: {"authorization_endpoint": "https://idp.example/auth"}
r = call("GET", "/api/sso/oidc/start?remember=1&then=sxy")
st = cookie_of(r[2], "maintool_oidc") or ""
st = json.loads(base64.urlsafe_b64decode(st.partition(".")[0] + "=" * (-len(st.partition(".")[0]) % 4))) if st else {}
check("OpenID Connect met vinkje: de keuze reist mee in het ondertekende cookie", r[0] == 303 and st.get("k") == 1 and st.get("x") == "sxy", json.dumps(st)[:120])
r = call("GET", "/api/sso/oidc/start?remember=1", host="192.168.1.10:8443")
check("vanaf een ander adres: doorgestuurd naar het openbare adres, met het vinkje erbij", r[0] == 303 and r[3] == f"https://{HOST}/api/sso/oidc/start?remember=1", r[3])
r = call("GET", "/api/sso/oidc/start")
st = cookie_of(r[2], "maintool_oidc") or ""
st = json.loads(base64.urlsafe_b64decode(st.partition(".")[0] + "=" * (-len(st.partition(".")[0]) % 4))) if st else {}
check("OpenID Connect zonder vinkje: k = 0", st.get("k") == 0)
main.sso_on, main.sso_conf, main.oidc_discovery, main.cloudflare_user = saved
r = call("PUT", "/api/policy", ROOT, {"idle": 10}, cookies={"maintool_lang": "en"})
check("meldingen in de taal van de pagina", detail(r) == "Choose a valid time for logging out without activity", detail(r))

TRIPPED = [x for x in TRIPPED if not (x[0] == "agent" and tuple(x[1][1:]) == ("info", "cts"))]
check("het echte cluster is niet aangeraakt", not TRIPPED, str(TRIPPED))
print()
print("ALLES GOED" if not FAILED else f"FOUT ({len(FAILED)}): {FAILED}")
