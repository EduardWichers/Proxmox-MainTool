"""Tests version 1.3 of the backend in-process on the tool container, from a copy in /tmp with its own state
folder: its own session key, its own users file, its own settings. The real tool, its password and its sessions are
untouched. Requests go straight into the application (no network, no real login).

Part A proves the permissions. While it runs, every way to reach the cluster is replaced by a tripwire, and every
address is filled with things that do not exist, so a request that should have been refused cannot do anything.
Part B only reads from the cluster (storage, node information, which nodes there are). No secrets are printed."""
import asyncio, json, os, secrets, stat, sys, time
for line in open("/etc/maintool/maintool.env", encoding="utf-8"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ[k.strip()] = v.strip()
os.environ["STATE_DIRECTORY"] = "/tmp/mt-v13/state"
sys.path.insert(0, "/tmp/mt-v13/app")
import main  # noqa: E402
from fastapi.routing import APIRoute  # noqa: E402

FAILED = []


def check(label, ok, extra=""):
    if not ok:
        FAILED.append(label)
    print(f"{'OK  ' if ok else 'FOUT'} {label} {extra}")


HOST = "tool.example"


def call(method, path, cookie=None, body=None, origin=f"https://{HOST}", source="203.0.113.7"):
    """One request through the whole application. Returns (status, parsed body or text, set-cookie value)."""
    route, _, query = path.partition("?")
    headers = [(b"host", HOST.encode())]
    if origin:
        headers.append((b"origin", origin.encode()))
    if cookie:
        headers.append((b"cookie", f"{main.SESSION_COOKIE}={cookie}".encode()))
    data = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    if body is not None:
        headers += [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode())]
    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1", "method": method,
             "scheme": "https", "path": route, "raw_path": route.encode(), "query_string": query.encode(), "root_path": "",
             "headers": headers, "client": (source, 40000), "server": (HOST, 443)}
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
    setcookie = next((v.decode() for k, v in start["headers"] if k == b"set-cookie"), "")
    token = setcookie.split(f"{main.SESSION_COOKIE}=", 1)[1].split(";", 1)[0].strip('"') if f"{main.SESSION_COOKIE}=" in setcookie else ""
    try:
        parsed = json.loads(raw)
    except ValueError:
        parsed = raw.decode("utf-8", "replace")
    return start["status"], parsed, token


def socket_close(path, cookie=None, origin=f"https://{HOST}"):
    """Opens the console address; returns the code it was closed with, or 'accepted'."""
    headers = [(b"host", HOST.encode()), (b"origin", origin.encode())]
    if cookie:
        headers.append((b"cookie", f"{main.SESSION_COOKIE}={cookie}".encode()))
    scope = {"type": "websocket", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1", "scheme": "wss",
             "path": path, "raw_path": path.encode(), "query_string": b"", "root_path": "", "headers": headers,
             "client": ("203.0.113.7", 40000), "server": (HOST, 443), "subprotocols": []}
    sent, asked = [], []

    async def receive():
        if not asked:
            asked.append(1)
            return {"type": "websocket.connect"}
        return {"type": "websocket.disconnect", "code": 1006}

    async def send(message):
        sent.append(message)

    asyncio.run(main.app(scope, receive, send))
    if any(m["type"] == "websocket.accept" for m in sent):
        return "accepted"
    return next((m.get("code") for m in sent if m["type"] == "websocket.close"), None)


def detail(reply):
    return reply[1].get("detail") if isinstance(reply[1], dict) else str(reply[1])[:80]


print("versie:", main.VERSION, "| eigen map voor de test:", main.STATE_DIR)
check("de test draait op een eigen kopie, niet op de echte tool", str(main.STATE_DIR).startswith("/tmp/") and not main.USERS_FILE.exists() and not main.AUTH_FILE.exists())
waited = 0
while main.updates.busy and waited < 300:   # de eerste achtergrondronde (alleen lezen) laten uitlopen
    time.sleep(2)
    waited += 2

# ================================================================== deel A: rechten, met de struikeldraad gespannen
TRIPPED = []


def tripwire(name):
    def trip(*a, **k):
        TRIPPED.append(name)
        raise AssertionError("een geweigerd verzoek bereikte " + name)
    return trip


REAL = {"run": main.pve.run, "agent": main.agent, "send_report": main.send_report, "start": main.updates.start,
        "subprocess": main.subprocess.run, "connect": main.pve.connect}
main.pve.run, main.pve.connect = tripwire("het cluster"), tripwire("het cluster (verbinden)")
main.agent, main.send_report, main.updates.start = tripwire("een node via SSH"), tripwire("de mail"), tripwire("de updatecontrole")
main.subprocess.run = tripwire("een programma")

ROOT = main.make_token(main.APP_USER)   # ondertekend met de sleutel van deze testkopie; ongeldig op de echte tool
PW = {n: "Proef-" + secrets.token_urlsafe(12) for n in ("lezer", "beheer2", "nieuw", "eigen")}

# ---- gebruikers aanmaken
check("zonder gebruikersbestand is er alleen het hoofdaccount", call("GET", "/api/users", ROOT)[1] == [{"name": main.APP_USER, "roles": ["admin"], "role": "admin", "builtin": True, "password_login": True, "sso": {}, "bound": False, "keys": 0, "key_required": False}])   # sinds 1.7 met de SSO-velden
r = call("POST", "/api/users", ROOT, {"name": "lezer", "role": "readonly", "password": PW["lezer"]})
check("gebruiker 'lezer' (alleen lezen) aangemaakt", r[0] == 200 and [u["name"] for u in r[1]] == [main.APP_USER, "lezer"], detail(r) or "")
r = call("POST", "/api/users", ROOT, {"name": "Beheer2", "role": "admin", "password": PW["beheer2"]})
check("gebruiker 'beheer2' (beheerder) aangemaakt; hoofdletters in de naam worden klein", r[0] == 200 and "beheer2" in [u["name"] for u in r[1]])
text = main.USERS_FILE.read_text()
check("gebruikersbestand: alleen hashes, alleen leesbaar voor de tool", stat.S_IMODE(main.USERS_FILE.stat().st_mode) == 0o600 and not any(p in text for p in PW.values()),
      "velden: " + ",".join(sorted(json.loads(text)["users"]["lezer"])))
for name, why in (("a", "te kort"), ("x" * 33, "te lang"), ("-abc", "begint met streepje"), ("jan piet", "spatie"), ("jan/../x", "schuine streep"),
                  ("<b>x</b>", "html"), (main.APP_USER, "naam van het hoofdaccount"), ("lezer", "bestaat al"), ("LEZER", "bestaat al, hoofdletters")):
    r = call("POST", "/api/users", ROOT, {"name": name, "role": "readonly", "password": PW["nieuw"]})
    check(f"naam geweigerd ({why})", r[0] in (400, 409), f"{r[0]} {detail(r)}")
r = call("POST", "/api/users", ROOT, {"name": "nieuw", "role": "baas", "password": PW["nieuw"]}); check("onbekende rechten geweigerd", r[0] == 400, detail(r))
r = call("POST", "/api/users", ROOT, {"name": "nieuw", "role": "readonly", "password": "tekort"}); check("te kort wachtwoord geweigerd", r[0] == 400, detail(r))
r = call("POST", "/api/users", ROOT, {"name": "nieuw", "role": "readonly", "password": " " + PW["nieuw"]}); check("wachtwoord met spatie vooraan geweigerd", r[0] == 400)
r = call("POST", "/api/users", ROOT, {"name": "nieuw", "role": "readonly", "password": PW["nieuw"]}, origin="https://kwaad.example"); check("aanmaken vanaf een andere website geweigerd", r[0] == 403, detail(r))
r = call("POST", "/api/users", ROOT, {"name": "nieuw", "role": "readonly", "password": PW["nieuw"]}, origin=None); check("aanmaken zonder herkomst geweigerd", r[0] == 403)
check("na al die weigeringen nog steeds twee gebruikers", sorted(main.users_state()) == ["beheer2", "lezer"])
limit, main.MAX_USERS = main.MAX_USERS, 2
r = call("POST", "/api/users", ROOT, {"name": "nieuw", "role": "readonly", "password": PW["nieuw"]}); check("boven het maximum aantal gebruikers geweigerd", r[0] == 409, detail(r))
main.MAX_USERS = limit

# ---- inloggen
r = call("POST", "/api/login", None, {"username": "lezer", "password": PW["lezer"]}); READER = r[2]
check("lezer logt in en krijgt een sessie", r[0] == 200 and main.read_token(READER) == "lezer")
r = call("POST", "/api/login", None, {"username": " Lezer ", "password": PW["lezer"]}); check("naam met hoofdletter en spaties eromheen werkt ook", r[0] == 200)
r = call("POST", "/api/login", None, {"username": "beheer2", "password": PW["beheer2"]}); ADMIN2 = r[2]
check("beheer2 logt in", r[0] == 200 and main.read_token(ADMIN2) == "beheer2")
r = call("POST", "/api/login", None, {"username": "lezer", "password": PW["beheer2"]}, source="198.51.100.1"); check("wachtwoord van een ander geweigerd", r[0] == 401, detail(r))
r = call("POST", "/api/login", None, {"username": "bestaatniet", "password": PW["lezer"]}, source="198.51.100.1"); check("onbekende gebruiker geweigerd, met dezelfde melding", r[0] == 401, detail(r))
r = call("POST", "/api/login", None, {"username": main.APP_USER, "password": PW["lezer"]}, source="198.51.100.1"); check("hoofdaccount met het wachtwoord van een ander geweigerd", r[0] == 401)
check("hoofdaccount: het wachtwoord uit de instellingen geldt nog steeds", main.check_login(main.APP_USER, main.APP_PASSWORD) and not main.AUTH_FILE.exists())
for i in range(4):
    call("POST", "/api/login", None, {"username": "lezer", "password": "fout-%d" % i}, source="198.51.100.2")
r = call("POST", "/api/login", None, {"username": "lezer", "password": "fout-5"}, source="198.51.100.2")
r2 = call("POST", "/api/login", None, {"username": "lezer", "password": PW["lezer"]}, source="198.51.100.2")
check("na vijf mislukte pogingen vanaf één adres is inloggen daar dicht, ook met het goede wachtwoord", r[0] == 401 and r2[0] == 429, detail(r2))
main.login_guard.failures.clear()
check("wie ben ik: lezer", {k: call("GET", "/api/me", READER)[1][k] for k in ("user", "role", "builtin", "can")} == {"user": "lezer", "role": "readonly", "builtin": False, "can": []})
check("wie ben ik: beheer2", {k: call("GET", "/api/me", ADMIN2)[1][k] for k in ("user", "role", "builtin")} == {"user": "beheer2", "role": "admin", "builtin": False})
check("wie ben ik: hoofdaccount", {k: call("GET", "/api/me", ROOT)[1][k] for k in ("user", "role", "builtin")} == {"user": main.APP_USER, "role": "admin", "builtin": True})
page = call("GET", "/", READER)[1]
check("de pagina weet wie er is ingelogd en met welke rechten", 'data-user="lezer"' in page and 'data-role="readonly"' in page and "{{" not in page)
page = call("GET", "/", ADMIN2)[1]
check("idem voor een beheerder", 'data-user="beheer2"' in page and 'data-role="admin"' in page)
check("zonder sessie naar de inlogpagina", call("GET", "/")[0] == 303)

# ---- vervalste en verlopen sessies
payload = READER.split(".")[0]
forged = main.base64.urlsafe_b64encode(json.dumps({"u": "lezer", "e": int(time.time()) + 3600, "g": 0}).encode()).decode().rstrip("=")
check("sessie met een andere handtekening geweigerd", main.read_token(forged + "." + "0" * 64) is None and main.read_token(forged + "." + READER.split(".")[1]) is None)
promoted = main.base64.urlsafe_b64encode(json.dumps({"u": main.APP_USER, "e": int(time.time()) + 3600, "g": 0}).encode()).decode().rstrip("=")
check("sessie van de lezer omgebouwd tot hoofdaccount geweigerd", main.read_token(promoted + "." + READER.split(".")[1]) is None)
ghost = main.base64.urlsafe_b64encode(json.dumps({"u": "spook", "e": int(time.time()) + 3600, "g": 0}).encode()).decode().rstrip("=")
check("geldig ondertekende sessie van een niet-bestaande gebruiker geweigerd", main.read_token(ghost + "." + main.sign(ghost)) is None)
old = main.base64.urlsafe_b64encode(json.dumps({"u": "lezer", "e": int(time.time()) - 5, "g": 0}).encode()).decode().rstrip("=")
check("verlopen sessie geweigerd", main.read_token(old + "." + main.sign(old)) is None)

# ---- elke route: wie mag erbij?
FILL = {"node": "geen-node", "kind": "lxc", "vmid": "999999", "action": "stop", "target": "node", "job": "geen-taak",
        "storage": "geen-opslag", "upid": "geen", "name": "geen", "nic": "net0", "disk": "rootfs", "sid": "ct:999999", "userid": "niemand@pve", "groupid": "geen-groep",   # sid: HA (1.0), userid/groupid: Users (1.0.2)
        "rule": "geen-regel", "osdid": "999", "monid": "geen-mon", "mgrid": "geen-mgr", "tokenid": "geen-token"}   # HA-regels en Ceph (1.2)
OPEN = {("GET", "/"), ("GET", "/login"), ("POST", "/api/login"), ("POST", "/api/logout"),
        ("GET", "/api/sso/options"), ("GET", "/api/sso/oidc/start"), ("GET", "/api/sso/oidc/callback"), ("POST", "/api/sso/cloudflare"),
        ("POST", "/api/webauthn/login/start"), ("POST", "/api/webauthn/login/finish")}   # inloggen met een beveiligingssleutel (1.3.1)   # SSO (1.7)
OWN = {("POST", "/api/password"), ("PUT", "/api/settings"), ("POST", "/api/viewonly"),
       ("POST", "/api/webauthn/register/start"), ("POST", "/api/webauthn/register/finish"), ("PUT", "/api/webauthn"),   # eigen sleutels (1.3.1)
       ("DELETE", "/api/nodeconsole")}   # het eigen ticket voor de console van de nodes vergeten (1.3.1)   # wijzigen alleen iets van de gebruiker zelf
routes = []
for route in main.app.routes:
    if isinstance(route, APIRoute):
        guards = [d.call for d in route.dependant.dependencies]
        guard = "admin" if any(g is main.admin or hasattr(g, "areas") for g in guards) else "auth" if main.auth in guards else "geen"
        for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
            routes.append((method, route.path, guard, route.name))
print(f"     {len(routes)} adressen gevonden: {sum(1 for r in routes if r[2] == 'admin')} alleen voor beheerders, "
      f"{sum(1 for r in routes if r[2] == 'auth')} voor iedereen die is ingelogd, {sum(1 for r in routes if r[2] == 'geen')} zonder inlog")
wrong = [(m, p) for m, p, g, n in routes if g == "geen" and (m, p) not in OPEN]
check("alleen de inlogpagina, in- en uitloggen werken zonder sessie", not wrong and {(m, p) for m, p, g, n in routes if g == "geen"} == OPEN, str(wrong))
wrong = [(m, p) for m, p, g, n in routes if m != "GET" and g != "admin" and (m, p) not in OPEN | OWN]
check("alles wat iets verandert (POST/PUT/DELETE) is alleen voor beheerders", not wrong, str(wrong))
print("     voor beheerders, ook al is het alleen kijken:", ", ".join(p for m, p, g, n in routes if m == "GET" and g == "admin"))
print("     voor iedereen die is ingelogd:", ", ".join(sorted({p for m, p, g, n in routes if g == "auth"})))


def fill(path):
    for key, value in FILL.items():
        path = path.replace("{" + key + "}", value)
    assert "{" not in path, path
    return path


no_session, reader_refused, reader_wrong = [], [], []
for method, path, guard, name in routes:
    if (method, path) in OPEN:
        continue
    r = call(method, fill(path), None, {} if method != "GET" else None)
    if r[0] != 401:
        no_session.append((method, path, r[0]))
    if guard == "admin":
        r = call(method, fill(path), READER, {} if method != "GET" else None)
        (reader_refused if r[0] == 403 and detail(r) in ("Hiervoor zijn beheerdersrechten nodig", "Hiervoor heb je niet de juiste rol") else reader_wrong).append((method, path, r[0]))
check("zonder sessie wordt elk adres geweigerd (401)", not no_session, str(no_session))
check(f"de lezer wordt op alle {len(reader_refused)} beheerdersadressen geweigerd (403)", not reader_wrong and len(reader_refused) == sum(1 for r in routes if r[2] == "admin"), str(reader_wrong))
check("console: zonder sessie dicht", socket_close("/api/console/geen-node/999999") == 4401)
check("console: lezer geweigerd", socket_close("/api/console/geen-node/999999", READER) == 4403)
check("console: vanaf een andere website geweigerd, ook als beheerder", socket_close("/api/console/geen-node/999999", ADMIN2, origin="https://kwaad.example") == 4401)
check("console: beheerder komt door de rechtencontrole (en strandt op het ongeldige adres)", socket_close("/api/console/geen_node/999999", ADMIN2) == 4400)
check("geen enkel geweigerd verzoek heeft het cluster, een node, de mail of een programma bereikt", not TRIPPED, str(TRIPPED))

# ---- beheerder mag wel: bewezen op adressen die zelf niets kunnen aanrichten
r = call("GET", "/api/users", ADMIN2); check("beheer2 ziet de gebruikerslijst", r[0] == 200 and len(r[1]) == 3)
r = call("GET", "/api/users", READER); check("de lezer niet", r[0] == 403)
r = call("POST", "/api/create/ct", ADMIN2, {}); check("beheer2 komt bij het aanmaken door de rechtencontrole (en strandt op het lege formulier)", r[0] == 422)
r = call("POST", "/api/create/ct", READER, {}); check("de lezer strandt daar al op de rechten", r[0] == 403)
check("ook hierbij is het cluster niet aangeraakt", not TRIPPED, str(TRIPPED))

# ---- eigen wachtwoord wijzigen (lezer)
r = call("POST", "/api/password", READER, {"current": "verkeerd-wachtwoord", "new": PW["eigen"]}); check("lezer: verkeerd huidig wachtwoord geweigerd", r[0] == 403, detail(r))
r = call("POST", "/api/password", READER, {"current": PW["beheer2"], "new": PW["eigen"]}); check("lezer: wachtwoord van een ander als huidig geweigerd", r[0] == 403)
r = call("POST", "/api/password", READER, {"current": PW["lezer"], "new": PW["eigen"]}, origin="https://kwaad.example"); check("lezer: vanaf een andere website geweigerd", r[0] == 403)
main.login_guard.failures.clear()
r = call("POST", "/api/password", READER, {"current": PW["lezer"], "new": PW["eigen"]}); READER2 = r[2]
check("lezer wijzigt zijn eigen wachtwoord", r[0] == 200 and main.read_token(READER2) == "lezer", detail(r) or "")
check("zijn oude sessie is vervallen, de nieuwe werkt", call("GET", "/api/me", READER)[0] == 401 and call("GET", "/api/me", READER2)[0] == 200)
check("zijn oude wachtwoord werkt niet meer, het nieuwe wel", not main.check_login("lezer", PW["lezer"]) and main.check_login("lezer", PW["eigen"]))
check("het hoofdaccount en beheer2 zijn er niet door geraakt", main.read_token(ROOT) == main.APP_USER and main.read_token(ADMIN2) == "beheer2" and not main.AUTH_FILE.exists() and main.check_login("beheer2", PW["beheer2"]))
READER = READER2

# ---- beheerder wijzigt een ander
r = call("PUT", "/api/users/lezer", ADMIN2, {"role": "admin"}); check("beheer2 maakt lezer beheerder", r[0] == 200 and {u["name"]: u["role"] for u in r[1]}["lezer"] == "admin")
check("de sessie van lezer is daardoor vervallen (opnieuw inloggen)", call("GET", "/api/me", READER)[0] == 401)
r = call("POST", "/api/login", None, {"username": "lezer", "password": PW["eigen"]}); READER = r[2]
check("na opnieuw inloggen mag hij bij de gebruikers", call("GET", "/api/users", READER)[0] == 200)
r = call("PUT", "/api/users/lezer", ADMIN2, {"role": "readonly"}); check("en weer terug naar alleen lezen", r[0] == 200 and call("GET", "/api/me", READER)[0] == 401)
r = call("PUT", "/api/users/lezer", ADMIN2, {"password": PW["nieuw"]}); check("beheer2 zet een nieuw wachtwoord voor lezer", r[0] == 200 and main.check_login("lezer", PW["nieuw"]) and not main.check_login("lezer", PW["eigen"]))
r = call("PUT", "/api/users/lezer", ADMIN2, {"password": "kort"}); check("te kort nieuw wachtwoord geweigerd", r[0] == 400)
r = call("PUT", "/api/users/lezer", ADMIN2, {}); check("wijzigen zonder iets op te geven geweigerd", r[0] == 400, detail(r))
r = call("PUT", "/api/users/bestaatniet", ADMIN2, {"role": "admin"}); check("onbekende gebruiker wijzigen geweigerd", r[0] == 404, detail(r))
r = call("PUT", "/api/users/beheer2", ADMIN2, {"role": "readonly"}); check("eigen rechten afpakken geweigerd", r[0] == 409, detail(r))
r = call("DELETE", "/api/users/beheer2", ADMIN2); check("zichzelf verwijderen geweigerd", r[0] == 409)
r = call("DELETE", "/api/users/" + main.APP_USER, ADMIN2); check("het hoofdaccount verwijderen geweigerd", r[0] == 409, detail(r))
r = call("PUT", "/api/users/" + main.APP_USER, ADMIN2, {"role": "readonly"}); check("het hoofdaccount alleen-lezen maken geweigerd", r[0] == 409)
r = call("PUT", "/api/users/" + main.APP_USER, ADMIN2, {"password": PW["nieuw"]}); check("het wachtwoord van het hoofdaccount overschrijven geweigerd", r[0] == 409 and not main.AUTH_FILE.exists())
r = call("DELETE", "/api/users/lezer", ADMIN2, origin="https://kwaad.example"); check("verwijderen vanaf een andere website geweigerd", r[0] == 403)

# ---- instellingen per gebruiker
main.state.change(lambda d: d.update(settings={"background": "#112233", "default": "#112233", "language": "nl"}))   # zoals het in 1.2 stond
check("het hoofdaccount houdt de instellingen van vóór deze versie", call("GET", "/api/settings", ROOT)[1] == {"background": "#112233", "default": "#112233", "language": "nl", "dashboard": None, "tables": None})   # sinds 1.7 ook de indeling van het dashboard
check("een nieuwe gebruiker begint zonder eigen instellingen", call("GET", "/api/settings", ADMIN2)[1] == {"background": None, "default": None, "language": None, "dashboard": None, "tables": None})   # sinds 1.7 ook de indeling van het dashboard
r = call("PUT", "/api/settings", ADMIN2, {"language": "de", "background": "#445566"})
check("beheer2 kiest Duits en een eigen kleur", r[1] == {"background": "#445566", "default": None, "language": "de", "dashboard": None, "tables": None})   # sinds 1.7 ook de indeling van het dashboard
check("dat verandert niets voor het hoofdaccount", call("GET", "/api/settings", ROOT)[1]["language"] == "nl" and call("GET", "/api/settings", ROOT)[1]["background"] == "#112233")
r = call("PUT", "/api/settings", ROOT, {"language": "en"})
check("het hoofdaccount wijzigt alleen de taal: de kleur blijft", r[1] == {"background": "#112233", "default": "#112233", "language": "en", "dashboard": None, "tables": None})   # sinds 1.7 ook de indeling van het dashboard
r = call("POST", "/api/login", None, {"username": "lezer", "password": PW["nieuw"]}); READER = r[2]
r = call("PUT", "/api/settings", READER, {"background": "#778899"}); check("ook een lezer mag zijn eigen kleur bewaren", r[0] == 200 and r[1]["background"] == "#778899")

# ---- verwijderen
r = call("DELETE", "/api/users/lezer", ADMIN2); check("beheer2 verwijdert lezer", r[0] == 200 and [u["name"] for u in r[1]] == [main.APP_USER, "beheer2"])
check("zijn sessie is direct ongeldig en inloggen kan niet meer", call("GET", "/api/me", READER)[0] == 401 and not main.check_login("lezer", PW["nieuw"]))
check("zijn instellingen zijn mee opgeruimd", "lezer" not in (main.state.load().get("user_settings") or {}) and "beheer2" in main.state.load()["user_settings"])
r = call("DELETE", "/api/users/lezer", ADMIN2); check("nog een keer verwijderen: bestaat niet", r[0] == 404)
r = call("POST", "/api/users", ROOT, {"name": "tijdelijk", "role": "admin", "password": PW["nieuw"]})
TEMP = call("POST", "/api/login", None, {"username": "tijdelijk", "password": PW["nieuw"]})[2]
check("proef: beheerder 'tijdelijk' aangemaakt en ingelogd", call("GET", "/api/users", TEMP)[0] == 200)
call("DELETE", "/api/users/tijdelijk", ROOT)
r = call("POST", "/api/users", ROOT, {"name": "tijdelijk", "role": "readonly", "password": PW["eigen"]})
check("naam verwijderd en opnieuw aangemaakt: de sessie van de vorige 'tijdelijk' leeft niet weer op", r[0] == 200 and call("GET", "/api/me", TEMP)[0] == 401 and call("GET", "/api/users", TEMP)[0] == 401)
call("DELETE", "/api/users/tijdelijk", ROOT)
r = call("POST", "/api/users", ROOT, {"name": "lezer", "role": "readonly", "password": PW["lezer"]})
check("lezer opnieuw aangemaakt voor het vervolg", r[0] == 200 and call("GET", "/api/me", READER)[0] == 401)

# ---- beschadigd bestand
keep = main.USERS_FILE.read_text()
main.USERS_FILE.write_text("{kapot")
check("beschadigd gebruikersbestand: niemand behalve het hoofdaccount komt binnen", main.users_state() == {} and call("GET", "/api/me", ADMIN2)[0] == 401 and main.read_token(ROOT) == main.APP_USER)
main.USERS_FILE.write_text(json.dumps({"users": {"x": {"role": "admin", "salt": "zz", "hash": "zz"}, "../y": {"role": "admin"}, "ok": {"role": "god", "salt": "0" * 32, "hash": "0" * 64}}}))
check("regels met een ongeldige naam, rol of hash worden genegeerd", main.users_state() == {})
main.USERS_FILE.write_text(keep)
os.chmod(main.USERS_FILE, 0o600)
check("hersteld bestand wordt weer gelezen", sorted(main.users_state()) == ["beheer2", "lezer"] and call("GET", "/api/me", ADMIN2)[0] == 200)

# ---- vertaling van de nieuwe meldingen
missing = [m for m in ("Hiervoor zijn beheerdersrechten nodig", "Deze gebruikersnaam bestaat al", "Deze gebruiker bestaat niet", "Ongeldige rechten",
                       "Het hoofdaccount kan hier niet gewijzigd of verwijderd worden", "Je kunt je eigen account niet verwijderen of je eigen rechten wijzigen",
                       "Er is niets om te wijzigen", "Er kunnen niet meer dan 50 gebruikers zijn", "De gebruikers konden niet bewaard worden",
                       "Ongeldige gebruikersnaam: 2-32 tekens, kleine letters, cijfers, punt, streepje")
           if main.translate(m, "en") == m or main.translate(m, "de") == m]
check("alle nieuwe meldingen bestaan in het Engels en het Duits", not missing, str(missing))

check("STRUIKELDRAAD: in heel deel A is het cluster niet aangeraakt", not TRIPPED, str(TRIPPED))
main.pve.run, main.pve.connect, main.agent, main.send_report = REAL["run"], REAL["connect"], REAL["agent"], REAL["send_report"]
main.updates.start, main.subprocess.run = REAL["start"], REAL["subprocess"]

# ================================================================== deel B: alleen lezen van het echte cluster
r = call("POST", "/api/login", None, {"username": "lezer", "password": PW["lezer"]}); READER = r[2]
print("\n--- deel B: als 'lezer' (alleen lezen) kijken naar het echte cluster")
for path in ("/api/overview", "/api/live", "/api/updates", "/api/backup/overview", "/api/scripts", "/api/report/status", "/api/selfupdate/status"):
    r = call("GET", path, READER)
    check(f"lezer mag kijken: {path}", r[0] == 200, "" if r[0] == 200 else detail(r))
overview = call("GET", "/api/overview", READER)[1]
nodes = [n["node"] for n in overview["nodes"]]

r = call("GET", "/api/storage", READER)
check("opslagoverzicht", r[0] == 200 and {"storages", "ceph", "disks"} <= set(r[1]), "" if r[0] == 200 else detail(r))
if r[0] == 200:
    S = r[1]
    def gb(n):
        return "?" if n is None else f"{n / 2**30:.1f} GB"
    for s in S["storages"]:
        use = "; ".join(f"{u['node']}: {gb(u['disk'])} van {gb(u['maxdisk'])}" for u in s["usage"]) or "geen cijfers"
        print(f"     {s['storage']:<18} {s['type']:<8} {'gedeeld' if s['shared'] else 'per node':<8} {'aan' if s['enabled'] else 'UIT':<3} "
              f"inhoud={','.join(s['content'])} doel={s['target']!r} | {use} | aantallen={s['counts']} bewaren={s['prune']}")
    check("elke opslag heeft type, inhoud en cijfers", all(s["type"] and s["content"] and (s["usage"] or s["unavailable"] or not s["enabled"]) for s in S["storages"]))
    check("gedeelde opslag staat er één keer in, lokale per node", all(len(s["usage"]) <= 1 for s in S["storages"] if s["shared"]) and any(len(s["usage"]) > 1 for s in S["storages"] if not s["shared"]))
    c = S["ceph"]
    if c:
        print(f"     Ceph: {c['health']} | {gb(c['used'])} van {gb(c['total'])} | {c['osds_up']}/{c['osds']} OSD's actief, {c['osds_in']} in gebruik | {c['pgs']} PG's {c['states']}")
        for chk in c["checks"]:
            print(f"       melding {chk['severity']} {chk['code']}: {chk['text']}")
        for p in c["pools"]:
            print(f"       pool {p['name']}: {p['size']}/{p['min_size']} kopieën, {p['pgs']} PG's, {gb(p['used'])}, {None if p['percent'] is None else round(p['percent'] * 100, 1)}%")
        check("Ceph: gezondheid, vulling, pools en OSD's aanwezig", c["health"] and c["total"] and c["pools"] and len(c["osd_list"]) == c["osds"])
    else:
        print("     geen Ceph gevonden")
    for node, disks in S["disks"].items():
        for d in disks or []:
            print(f"     {node} {d['dev']:<14} {gb(d['size']):>10} {d['type']:<5} {d['health']:<8} slijtage={d['wearout']} gebruik={d['used']} osd={d['osds']} {d['model']}")
    check("de schijf onder een Ceph-OSD is als zodanig herkend", not c or sorted(o for ds in S["disks"].values() for d in ds or [] for o in d["osds"]) == list(range(c["osds"])))
    check("schijven van elke node gevonden", set(S["disks"]) == {n["node"] for n in overview["nodes"] if n.get("status") == "online"} and all(S["disks"].values()))

for node in nodes:
    r = call("GET", f"/api/node/{node}/info", READER)
    i = r[1]
    check(f"node-informatie {node}", r[0] == 200 and i.get("online") and i.get("pve") and i.get("cpu") and i.get("maxmem"), "" if r[0] == 200 else detail(r))
    if r[0] == 200:
        print(f"     {i['ip']} PVE {i['pve']} kernel {i['kernel']} | {i['cpu']} ({i['sockets']} socket, {i['cores']} cores, {i['threads']} threads) | load {i['load']} | "
              f"geheugen {i['mem'] / 2**30:.1f}/{i['maxmem'] / 2**30:.1f} GB | swap {i['swap']}/{i['maxswap']} | systeemschijf {i['root'] / 2**30:.1f}/{i['maxroot'] / 2**30:.1f} GB | "
              f"aan sinds {i['uptime'] // 86400} dagen | {i['running']}/{i['guests']} guests aan | opstart {i['boot']}")
r = call("GET", "/api/node/bestaat-niet/info", READER); check("onbekende node: nette melding", r[0] == 404, detail(r))
r = call("GET", "/api/node/a_b/info", READER); check("ongeldige nodenaam geweigerd", r[0] == 400, detail(r))

# ---- volgt de tool het cluster?
print("\n--- nodes die erbij komen of verdwijnen")
check("uitgangspunt: de API-adressen zijn die uit de instellingen", main.pve.hosts == main.HOSTS and main.IP_HOSTS, str(main.pve.hosts))
main.pve.follow()
members = sorted(e["ip"] for e in main.pve.api.cluster.status.get() if e.get("type") == "node")
check("het cluster meldt dezelfde adressen: de lijst blijft gelijk", main.pve.hosts == main.HOSTS and sorted(main.HOSTS) == members, f"cluster: {members}")
check("er is niets bewaard zolang er niets verandert", "hosts" not in main.state.load())


class FakeApi:
    """Stands in for the cluster's answer to 'which nodes are there', nothing else."""
    def __init__(self, ips):
        self.cluster = type("C", (), {"status": type("S", (), {"get": staticmethod(lambda: [{"type": "cluster", "name": "x"}] + [
            {"type": "node", "name": f"n{i}", "ip": ip} for i, ip in enumerate(ips)])})()})()


c = main.Cluster()
c.host = main.HOSTS[0]
c.api = FakeApi(main.HOSTS + ["192.0.2.44"])
c.follow()
check("een node die erbij komt wordt vanzelf een API-adres", c.hosts == main.HOSTS + ["192.0.2.44"], str(c.hosts))
check("en dat wordt onthouden voor na een herstart", main.state.load().get("hosts") == main.HOSTS + ["192.0.2.44"] and main.Cluster().hosts == main.HOSTS + ["192.0.2.44"])
status = c.hosts_status()
check("de nieuwe node staat in de statusregel (hier onbereikbaar, want hij bestaat niet)", [h["host"] for h in status] == c.hosts and status[-1]["ok"] is False and all(h["ok"] for h in status[:-1]))
c.api = FakeApi(main.HOSTS[:1] + main.HOSTS[2:] + ["192.0.2.44"])
c.follow()
check("een node die uit het cluster is gehaald valt af", c.hosts == main.HOSTS[:1] + main.HOSTS[2:] + ["192.0.2.44"], str(c.hosts))
c.api = FakeApi(main.HOSTS[1:])   # het adres waarmee de tool verbonden is ontbreekt in het antwoord
before = list(c.hosts)
c.follow()
check("meldt het cluster het eigen verbindingsadres niet, dan blijft de lijst zoals hij is", c.hosts == before)
c.api = FakeApi([])
c.follow()
check("een leeg antwoord verandert niets", c.hosts == before)
c.api = FakeApi(["niet-een-adres", main.HOSTS[0], "999.1.1.1"])
c.follow()
check("ongeldige adressen in het antwoord worden genegeerd", c.hosts == [main.HOSTS[0]], str(c.hosts))
keep_ip, main.IP_HOSTS = main.IP_HOSTS, False
c2 = main.Cluster()
c2.host, c2.api = main.HOSTS[0], FakeApi(main.HOSTS + ["192.0.2.45"])
c2.follow()
check("zijn er namen in plaats van adressen ingesteld, dan blijft de ingestelde lijst gelden", c2.hosts == main.HOSTS)
main.IP_HOSTS = keep_ip
main.state.change(lambda d: d.update(hosts=["192.0.2.44", "geen adres", 5, main.HOSTS[0]]))
check("bewaarde lijst: alleen geldige, nieuwe adressen komen erbij", main.Cluster().hosts == main.HOSTS + ["192.0.2.44"])
main.state.change(lambda d: d.pop("hosts", None))

found = main.pve.run(lambda api: main.updates._gather(api, False))
print("     hulpscript per node:", {n: (v or {}).get("agent") for n, v in found["nodes"].items()})
check("van elke node is bekend of het hulpscript er staat", all(isinstance((v or {}).get("agent"), int) and v["agent"] > 0 for v in found["nodes"].values()))
check("een node zonder hulpscript of zonder adres geeft 0 in plaats van een fout", main.Updates._agent(None) == 0 and main.Updates._agent("192.0.2.44") == 0)
check("de echte verbinding is door de proef niet veranderd", main.pve.hosts == main.HOSTS)

print("\n" + ("ALLES GOED" if not FAILED else f"{len(FAILED)} FOUT: " + "; ".join(FAILED)))
