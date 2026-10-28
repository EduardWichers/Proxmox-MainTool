"""Tests version 1.5.1 of the backend in-process, from a copy in /tmp with its own state folder: logging in for the
console of a node with an account in realm pam or pve (the choice in the window, @pam/@pve typed after the name, the
name rules per realm, two-factor authentication, why Proxmox refused). Proxmox is a stand-in; nothing goes out over
the network. Runs on the tool container (with its maintool.env) and elsewhere (then with test settings)."""
import asyncio, json, os, secrets, shutil, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
COPY = Path("/tmp/mt-v151")
shutil.rmtree(COPY, ignore_errors=True)
shutil.copytree(HERE.parent / "app", COPY / "app")
if os.path.isfile("/etc/maintool/maintool.env"):
    for line in open("/etc/maintool/maintool.env", encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ[k.strip()] = v.strip()
else:
    os.environ.update({"PVE_HOSTS": "192.0.2.1", "PVE_TOKEN_VALUE": "test-only", "APP_PASSWORD": "test-" + secrets.token_hex(8)})
os.environ["STATE_DIRECTORY"] = str(COPY / "state")
(COPY / "state").mkdir(parents=True)

import proxmoxer  # noqa: E402

proxmoxer.ProxmoxAPI = lambda *a, **k: (_ for _ in ()).throw(AssertionError("geen echte verbinding met Proxmox in deze test"))
sys.path.insert(0, str(COPY / "app"))
import main  # noqa: E402
from fastapi import HTTPException  # noqa: E402

FAILED = []


def check(label, ok, extra=""):
    if not ok:
        FAILED.append(label)
    print(f"{'OK  ' if ok else 'FOUT'} {label} {extra}")


HOST = "tool.example"


def call(method, path, cookie=None, body=None, origin=f"https://{HOST}"):
    route, _, query = path.partition("?")
    hdrs = [(b"host", HOST.encode())]
    if origin:
        hdrs.append((b"origin", origin.encode()))
    if cookie:
        hdrs.append((b"cookie", f"{main.SESSION_COOKIE}={cookie}".encode()))
    data = b"" if body is None else json.dumps(body).encode()
    if body is not None:
        hdrs += [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode())]
    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1", "method": method,
             "scheme": "https", "path": route, "raw_path": route.encode(), "query_string": query.encode(), "root_path": "",
             "headers": hdrs, "client": ("203.0.113.7", 40000), "server": (HOST, 443)}
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
    out = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    try:
        parsed = json.loads(out)
    except ValueError:
        parsed = out.decode("utf-8", "replace")
    return start["status"], parsed, [v.decode() for k, v in start["headers"] if k == b"set-cookie"]


def session_of(setc):
    return next((c.split(";")[0].split("=", 1)[1] for c in setc if c.startswith(main.SESSION_COOKIE + "=") and "Max-Age=0" not in c), None)


def detail(r):
    return r[1].get("detail") if isinstance(r[1], dict) else str(r[1])[:120]


# ---------------------------------------------------------------- nagebootst Proxmox: tickets en gebruikers
TICKETS = []
USERS = {"root@pam": {"enable": 1}, "Eduard@pve": {"enable": 1}, "tfa@pve": {"enable": 1}, "vreemd@pve": {"enable": 1},
         "uit@pve": {"enable": 0}, "oud@pve": {"enable": 1, "expire": int(time.time()) - 86400}, "eduard@pam": {"enable": 1}}


def fake_ticket(userid, password, **extra):
    TICKETS.append((userid, password, extra))
    if "tfa-challenge" in extra:
        return {"ticket": "PVE:tfa@pve:ok", "CSRFPreventionToken": "c", "username": userid} if password == "totp:123456" else None
    if password != "goed":
        return None
    if userid == "tfa@pve":
        return {"ticket": "uitdaging", "NeedTFA": 1, "username": userid}
    if userid == "vreemd@pve":
        return {"ticket": "PVE:x", "CSRFPreventionToken": "c", "username": "vreemd@pam"}   # een ander realm dan gevraagd
    return {"ticket": f"PVE:{userid}:ok", "CSRFPreventionToken": "c", "username": userid}


class Users:
    def __init__(self, userid=None):
        self.userid = userid

    def __call__(self, userid):
        return Users(userid)

    def get(self):
        if self.userid not in USERS:
            raise HTTPException(500, f"Proxmox: no such user ('{self.userid}')")
        return USERS[self.userid]


class Api:
    access = type("A", (), {"users": Users()})()


main.pve_ticket = fake_ticket
main.pve.run = lambda fn: fn(Api())

main.login_guard.reset()
ROOT = session_of(call("POST", "/api/login", body={"username": main.APP_USER, "password": main.APP_PASSWORD})[2])
PW = secrets.token_urlsafe(18)
call("POST", "/api/users", ROOT, {"name": "lezer", "roles": [], "password": PW})
READER = session_of(call("POST", "/api/login", body={"username": "lezer", "password": PW})[2])
check("uitgangssituatie: beheerder en lezer", all([ROOT, READER]))


def login(**body):
    main.login_guard.reset()
    call("DELETE", "/api/nodeconsole", ROOT)
    TICKETS.clear()
    return call("POST", "/api/nodeconsole/login", ROOT, body)


# ================================================================ A. realm kiezen
print("--- A. realm pam of pve")
r = login(username="root", password="goed")
check("zonder keuze: pam, zoals voorheen", r[0] == 200 and r[1].get("ready") and r[1].get("user") == "root@pam" and TICKETS[0][0] == "root@pam", str(r[1]))
r = login(username="Eduard", password="goed", realm="pve")
check("realm pve: Eduard@pve, met hoofdletter", r[0] == 200 and r[1].get("user") == "Eduard@pve" and TICKETS[0][0] == "Eduard@pve", str(r[1]))
check("de console onthoudt het pve-account", call("GET", "/api/nodeconsole", ROOT)[1].get("user") == "Eduard@pve")
r = login(username="Eduard@pve", password="goed")
check("@pve achter de naam getypt (keuze nog pam): pve", r[0] == 200 and TICKETS[0][0] == "Eduard@pve", str(TICKETS))
r = login(username="Eduard@PVE", password="goed", realm="pam")
check("... ook in hoofdletters", r[0] == 200 and TICKETS[0][0] == "Eduard@pve", str(TICKETS))
r = login(username="eduard@pam", password="goed", realm="pve")
check("@pam achter de naam getypt (keuze pve): pam", r[0] == 200 and TICKETS[0][0] == "eduard@pam", str(TICKETS))
r = login(username="root", password="goed", realm="ldap")
check("een ander realm kan niet", r[0] == 422, str(r[0]))

# ================================================================ B. namen per realm
print("--- B. gebruikersnamen")
r = login(username="Eduard", password="goed", realm="pam")
check("pam: alleen een Linux-naam (kleine letters)", r[0] == 400 and "node" in detail(r) and not TICKETS, detail(r))
for bad in ("a b", "x:y", "../x", "naam/x", "é", "x" * 65):
    r = login(username=bad, password="goed", realm="pve")
    check(f"pve: ongeldige naam {bad[:12]!r} geweigerd zonder Proxmox te vragen", r[0] in (400, 422) and not TICKETS, f"{r[0]} {detail(r)}")
r = login(username="Eduard", password="", realm="pve")
check("pve zonder wachtwoord: melding over realm pve", r[0] == 400 and "pve" in detail(r), detail(r))
r = login(username="ed.ward-2_x", password="goed", realm="pve")
check("pve: punten, streepjes en cijfers mogen", r[0] in (200, 403) and TICKETS and TICKETS[0][0] == "ed.ward-2_x@pve", str(TICKETS))

# ================================================================ C. antwoord van Proxmox
print("--- C. antwoord van Proxmox")
r = login(username="vreemd", password="goed", realm="pve")
check("Proxmox meldt een ander realm dan gevraagd: geweigerd", r[0] == 502, f"{r[0]} {detail(r)}")
r = login(username="tfa", password="goed", realm="pve")
check("pve met tweestapsverificatie: eerst om de code vragen", r[0] == 200 and r[1].get("need_code"), str(r[1]))
TICKETS.clear()
r = call("POST", "/api/nodeconsole/login", ROOT, {"code": "123456"})
check("... daarna de code, voor hetzelfde pve-account", r[0] == 200 and r[1].get("user") == "tfa@pve"
      and TICKETS and TICKETS[0][0] == "tfa@pve" and TICKETS[0][2].get("tfa-challenge") == "uitdaging", str(TICKETS))

# ================================================================ D. waarom het niet lukte
print("--- D. waarom Proxmox weigerde")
for user, realm, expect in (("weg", "pve", "maak het account aan op het tabblad Gebruikers, in realm pve"),
                            ("weg", "pam", "een pam-account moet daar bestaan"),
                            ("uit", "pve", "staat in Proxmox uit"),
                            ("oud", "pve", "is in Proxmox verlopen"),
                            ("Eduard", "pve", "Gebruikersnaam, wachtwoord of code klopt niet")):
    r = login(username=user, password="fout", realm=realm)
    check(f"{user}@{realm}: 403 met '{expect[:35]}…'", r[0] == 403 and expect in detail(r), detail(r))
r = login(username="uit", password="fout", realm="pve")
check("de melding noemt geen pam-account meer voor een pve-account", "pam" not in detail(r), detail(r))

# ================================================================ E. rechten, logboek, vertalingen, pagina
print("--- E. overige")
main.login_guard.reset()
check("alleen beheerders", call("POST", "/api/nodeconsole/login", READER, {"username": "Eduard", "password": "goed", "realm": "pve"})[0] == 403)
login(username="Eduard", password="goed", realm="pve")
events = [json.loads(l) for l in (COPY / "state" / "events.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
check("logboek: wie inlogde, met realm", any(e.get("kind") == "console" and e.get("name") == "Eduard@pve" for e in events))
for nl in ("Vul een gebruiker van Proxmox in (realm pve) en zijn wachtwoord",
           "{0} bestaat niet in Proxmox; maak het account aan op het tabblad Gebruikers, in realm pve",
           "{0} staat in Proxmox uit (Datacenter, Permissions, Users). Zet het account daar aan, of log in met een ander account dat een console mag openen",
           "{0} is in Proxmox verlopen. Verleng het account (tabblad Gebruikers), of log in met een ander account"):
    text = nl.replace("{0}", "x@pve")
    check(f"melding vertaald: {nl[:40]}…", main.translate(text, "en") != text and main.translate(text, "de") != text)
page = main.INDEX.read_text(encoding="utf-8")
check("venster: keuze @pam en @pve", 'id="nc-realm"' in page and '<option value="pam">@pam</option>' in page and '<option value="pve">@pve</option>' in page)
check("de pagina stuurt de keuze mee", "realm: $(\"#nc-realm\").value" in page)
check("de pagina onthoudt gebruiker en realm, niet het wachtwoord", "NC_KEY" in page and "password: body" not in page)

print()
print("ALLES GOED" if not FAILED else f"FOUT ({len(FAILED)}): {FAILED}")
sys.exit(1 if FAILED else 0)
