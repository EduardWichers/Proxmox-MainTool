"""Tests version 1.0.2 of the backend in-process on the tool container, from a copy in /tmp with its own state folder:
managing Proxmox users, groups and permissions (tab Users). Everything runs against a stand-in cluster that only
writes down what it is asked to do; nothing on the real cluster is changed. Passwords are made up for the test."""
import asyncio, base64, datetime as dt, hashlib, hmac, json, os, secrets, subprocess, sys, tempfile, time, urllib.parse
for line in open("/etc/maintool/maintool.env", encoding="utf-8"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ[k.strip()] = v.strip()
os.environ["STATE_DIRECTORY"] = "/tmp/mt-v202/state"
sys.path.insert(0, "/tmp/mt-v202/app")
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
TOOL = main.PVE_USER
PW_NEW = "Proefwachtwoord-" + secrets.token_hex(4)   # verzonnen, alleen voor deze test

USERS = {"root@pam": {"enable": 0, "groups": set()}, TOOL: {"enable": 1, "groups": {"Tool"}, "tokens": [{"tokenid": "webtool"}]},
         "chef@pve": {"enable": 1, "groups": {"Admins"}, "firstname": "Che", "email": "chef@example.com"},
         "anna@pve": {"enable": 1, "groups": set()}, "piet@pam": {"enable": 1, "groups": {"Kijkers"}}, "o'neil@pve": {"enable": 1, "groups": set()}}
GROUPS = {"Admins": "", "Kijkers": "kijken", "Tool": "", "Beheer": ""}
ACL = [{"path": "/", "type": "user", "ugid": TOOL, "roleid": "Administrator", "propagate": 1},
       {"path": "/", "type": "user", "ugid": "chef@pve", "roleid": "Administrator", "propagate": 1},
       {"path": "/vms", "type": "group", "ugid": "Kijkers", "roleid": "PVEAuditor", "propagate": 1}]
ROLES = ["Administrator", "NoAccess", "PVEAdmin", "PVEAuditor", "PVEVMUser"]
FLAGS = {"pwfail": None}


def user_rows(kw):
    return [{"userid": uid, "enable": u["enable"], "expire": u.get("expire", 0), "groups": ",".join(sorted(u["groups"])), "realm-type": uid.rpartition("@")[2],
             "tokens": u.get("tokens", []), **{k: u[k] for k in ("firstname", "lastname", "email", "comment") if k in u}} for uid, u in USERS.items()]


def access_world(method, path, kw):
    if method != "GET" and (path.startswith("access/") or path == "access"):
        W.changes.append((method, path, dict(kw)))
        parts = path.split("/")
        if parts[1] == "users" and method == "POST":
            USERS[kw["userid"]] = {"enable": kw["enable"], "groups": set(main.access_list(kw.get("groups"))), "expire": kw.get("expire", 0)}
        elif parts[1] == "users" and method == "PUT":
            u = USERS[parts[2]]
            if "groups" in kw:
                u["groups"] = (u["groups"] if kw.get("append") else set()) | set(main.access_list(kw["groups"]))
            u.update({k: v for k, v in kw.items() if k not in ("groups", "append")})
        elif parts[1] == "users" and method == "DELETE":
            del USERS[parts[2]]
            ACL[:] = [a for a in ACL if not (a["type"] == "user" and a["ugid"] == parts[2])]
        elif parts[1] == "password":
            if FLAGS["pwfail"]:
                raise FLAGS["pwfail"]
        elif parts[1] == "groups" and method == "POST":
            GROUPS[kw["groupid"]] = kw.get("comment", "")
        elif parts[1] == "groups" and method == "PUT":
            GROUPS[parts[2]] = kw.get("comment", GROUPS[parts[2]])
        elif parts[1] == "groups" and method == "DELETE":
            del GROUPS[parts[2]]
            for u in USERS.values():
                u["groups"].discard(parts[2])
            ACL[:] = [a for a in ACL if not (a["type"] == "group" and a["ugid"] == parts[2])]
        elif parts[1] == "acl":
            kind, ugid = ("user", kw["users"]) if "users" in kw else ("group", kw["groups"])
            entry = {"path": kw["path"], "type": kind, "ugid": ugid, "roleid": kw["roles"]}
            if kw.get("delete"):
                ACL[:] = [a for a in ACL if not all(a[k] == v for k, v in entry.items())]
            else:
                ACL.append({**entry, "propagate": kw["propagate"]})
        return None
    return _orig_call(method, path, kw)


_orig_call = W.call
W.call = access_world
W.table.update({
    "access/users": user_rows,
    "access/groups": lambda kw: [{"groupid": g, "comment": c, "users": ",".join(sorted(uid for uid, u in USERS.items() if g in u["groups"]))} for g, c in GROUPS.items()],
    "access/acl": lambda kw: [dict(a) for a in ACL],
    "access/domains": [{"realm": "pam", "type": "pam", "comment": "Linux PAM"}, {"realm": "pve", "type": "pve", "comment": "Proxmox VE"}, {"realm": "corp", "type": "ad"}],
    "access/roles": [{"roleid": r, "privs": "VM.Audit,Sys.Audit" if r != "NoAccess" else "", "special": 1} for r in ROLES] + [{"roleid": "Eigen", "privs": "VM.PowerMgmt"}],
    "pools": [{"poolid": "web"}],
    "nodes": [{"node": "n1", "status": "online"}, {"node": "n2", "status": "online"}],
    "cluster/resources": lambda kw: [{"storage": "ceph", "shared": 1}] if kw.get("type") == "storage" else [{"vmid": 101, "name": "web", "type": "lxc", "node": "n1"}],
})

main.login_guard.failures.clear()
ROOT = session_of(call("POST", "/api/login", body={"username": main.APP_USER, "password": main.APP_PASSWORD})[2])
PW = secrets.token_urlsafe(18)
for name, roles in (("over", ["overview"]), ("lezer", []), ("beheer2", ["admin"])):
    call("POST", "/api/users", ROOT, {"name": name, "roles": roles, "password": PW})
OVER = session_of(call("POST", "/api/login", body={"username": "over", "password": PW})[2])
READER = session_of(call("POST", "/api/login", body={"username": "lezer", "password": PW})[2])
ADMIN2 = session_of(call("POST", "/api/login", body={"username": "beheer2", "password": PW})[2])
check("inloggen van de testgebruikers", all([ROOT, OVER, READER, ADMIN2]))
check("minimale wachtwoordlengte is de standaard (12)", main.min_password() == 12)


def changes():
    out = list(W.changes)
    W.changes.clear()
    return out


print("--- A. bekijken")
r = call("GET", "/api/access", ROOT)
x = r[1] if r[0] == 200 else {}
check("de beheerder ziet de Proxmox-gebruikers", r[0] == 200, detail(r) if r[0] != 200 else "")
check("de rol Overzicht en alleen lezen niet, zonder sessie niet", call("GET", "/api/access", OVER)[0] == 403 and call("GET", "/api/access", READER)[0] == 403 and call("GET", "/api/access")[0] == 401)
users = {u["userid"]: u for u in x.get("users", [])}
check("alle gebruikers, op naam", list(users) == sorted(USERS, key=str.lower), str(list(users)))
check("wie alles mag: alleen chef (de tool telt niet, root staat uit)", x.get("admins") == ["chef@pve"] and users["chef@pve"]["admin"] and not users[TOOL]["admin"])
check("beschermd: root, de tool en een onbekende naam; de rest niet", bool(users["root@pam"]["protected"]) and bool(users[TOOL]["protected"]) and bool(users["o'neil@pve"]["protected"])
      and users["chef@pve"]["protected"] is None and users[TOOL]["tool"] and users[TOOL]["tokens"] == 1)
check("groepen bij de gebruiker en de leden bij de groep", users["chef@pve"]["groups"] == ["Admins"] and {g["groupid"]: g["members"] for g in x["groups"]}["Kijkers"] == ["piet@pam"]
      and {g["groupid"]: g["has_tool"] for g in x["groups"]}["Tool"] is True)
check("rechten per gebruiker en groep", users["chef@pve"]["acl"] == [{"path": "/", "type": "user", "ugid": "chef@pve", "roleid": "Administrator", "propagate": True}]
      and {g["groupid"]: g["acl"] for g in x["groups"]}["Kijkers"][0]["roleid"] == "PVEAuditor")
check("realms, rollen (standaard eerst) en de plekken", [d["realm"] for d in x["realms"]] == ["pam", "pve", "corp"] and x["roles"][-1]["roleid"] == "Eigen" and not x["roles"][-1]["builtin"]
      and x["paths"] == {"guests": [{"vmid": 101, "name": "web", "type": "lxc"}], "storages": ["ceph"], "nodes": ["n1", "n2"], "pools": ["web"]}, json.dumps(x.get("paths")))
check("bekijken verandert niets", not changes())

print("--- B. gebruiker aanmaken")
NEW = {"name": "kees", "realm": "pve", "password": PW_NEW, "firstname": " Kees ", "email": "kees@example.com", "groups": ["Kijkers"], "expire": 2000000000}
for who, label in ((OVER, "rol Overzicht"), (READER, "alleen lezen")):
    check(f"{label}: geweigerd", call("POST", "/api/access/users", who, NEW)[0] == 403)
check("vanaf een andere website of zonder Origin: geweigerd", call("POST", "/api/access/users", ROOT, NEW, origin="https://kwaad.example")[0] == 403
      and call("POST", "/api/access/users", ROOT, NEW, origin=None)[0] == 403)
check("via Cloudflare in alleen bekijken: geweigerd", call("POST", "/api/access/users", ROOT, NEW, headers={"Cf-Ray": "x"}, cookies={main.VIEW_COOKIE: "1"})[0] == 403)
bad = [({**NEW, "name": "kees de"}, 400), ({**NEW, "name": "kees@x"}, 400), ({**NEW, "realm": "nergens"}, 400), ({**NEW, "password": None}, 400),
       ({**NEW, "realm": "pam"}, 400), ({**NEW, "password": "kort"}, 400), ({**NEW, "password": PW_NEW + "\n"}, 400), ({**NEW, "password": "x" * 65}, 400),
       ({**NEW, "email": "geen-adres"}, 400), ({**NEW, "firstname": "twee\nregels"}, 400), ({**NEW, "expire": 5}, 400), ({**NEW, "expire": True}, 422),
       ({**NEW, "enable": "ja"}, 422), ({**NEW, "groups": ["Bestaatniet"]}, 400), ({**NEW, "name": "chef"}, 409), ({**NEW, "name": "root", "realm": "pam", "password": None}, 409),
       ({**NEW, "name": TOOL.split("@")[0], "realm": TOOL.split("@")[1]}, 409)]
wrong = [(b.get("name"), b.get("realm"), code, call("POST", "/api/access/users", ROOT, b)[0]) for b, code in bad if call("POST", "/api/access/users", ROOT, b)[0] != code]
check(f"{len(bad)} ongeldige verzoeken geweigerd met de juiste code", not wrong, str(wrong))
r = call("POST", "/api/access/users", ROOT, {**NEW, "password": "kort"})
check("de melding over de lengte noemt het minimum", detail(r) == "Het wachtwoord moet 12 tot 64 tekens lang zijn", detail(r))
r = call("POST", "/api/access/users", ROOT, {**NEW, "realm": "pve", "password": None}, cookies={main.LANG_COOKIE: "de"})
check("de melding in de taal van de gebruiker", detail(r) == "Wähle ein Passwort: ein Benutzer im Realm pve meldet sich damit an", detail(r))
check("na al die weigeringen is er niets naar Proxmox gestuurd", not changes())
before = len(main.state.events(0))
r = call("POST", "/api/access/users", ADMIN2, NEW)
sent = changes()
check("aanmaken in realm pve door een beheerder", r[0] == 200 and r[1] == {"ok": True, "userid": "kees@pve"}, detail(r) or "")
check("precies dit naar Proxmox, met het wachtwoord, zonder spaties rond de naam", sent == [("POST", "access/users", {"userid": "kees@pve", "enable": 1, "firstname": "Kees",
      "email": "kees@example.com", "expire": 2000000000, "groups": "Kijkers", "password": PW_NEW})], str([(m, p, {k: v for k, v in kw.items() if k != "password"}) for m, p, kw in sent]))
ev = main.state.events(0)[before:]
check("in het logboek: wie en welke gebruiker, zonder het wachtwoord", [(e["kind"], e["result"], e["target"], e["user"]) for e in ev] == [("access", "Proxmox-gebruiker aangemaakt", "kees@pve", "beheer2")]
      and PW_NEW not in json.dumps(main.state.events(0)) and PW_NEW not in json.dumps(r[1]))
r = call("POST", "/api/access/users", ROOT, {"name": "lien", "realm": "pam", "groups": [], "enable": False})
check("realm pam zonder wachtwoord, uitgeschakeld, zonder lege velden", r[0] == 200 and changes() == [("POST", "access/users", {"userid": "lien@pam", "enable": 0})], detail(r) or "")

print("--- C. gebruiker aanpassen")
for uid, why in (("root@pam", "root@pam wijzigt de tool niet"), (TOOL, "Met deze gebruiker werkt de tool zelf"), ("o'neil@pve", "Deze naam kent de tool niet")):
    r = call("PUT", f"/api/access/users/{uid}", ROOT, {"comment": "x"})
    check(f"{uid}: niet te wijzigen, met de juiste reden", r[0] == 409 and detail(r).startswith(why), detail(r))
    check(f"{uid}: ook niet te verwijderen", call("DELETE", f"/api/access/users/{uid}", ROOT)[0] == 409)
check("onbekende gebruiker: 404, niets opgegeven: 400", call("PUT", "/api/access/users/niemand@pve", ROOT, {"comment": "x"})[0] == 404
      and call("PUT", "/api/access/users/anna@pve", ROOT, {})[0] == 400)
r = call("PUT", "/api/access/users/chef@pve", ROOT, {"enable": False})
check("de enige beheerder uitzetten: geweigerd", r[0] == 409 and "niemand meer volledige beheerrechten" in detail(r), detail(r))
r = call("PUT", "/api/access/users/chef@pve", ROOT, {"expire": int(time.time()) - 60})
check("de enige beheerder laten verlopen: geweigerd", r[0] == 409)
r = call("PUT", "/api/access/users/chef@pve", ROOT, {"groups": []})
check("de enige beheerder uit zijn groepen halen mag (hij is beheerder via zichzelf)", r[0] == 200)
check("daarbij niets anders dan de groepen", changes() == [("PUT", "access/users/chef@pve", {"groups": ""})])
r = call("PUT", "/api/access/users/anna@pve", ROOT, {"firstname": "Anna", "lastname": "", "email": "", "comment": "test", "enable": False, "expire": 0, "groups": ["Kijkers", "Admins"]})
check("aanpassen: alleen wat is opgegeven, lege tekst maakt leeg, groepen op volgorde", r[0] == 200 and changes() == [("PUT", "access/users/anna@pve",
      {"firstname": "Anna", "lastname": "", "comment": "test", "email": "", "expire": 0, "enable": 0, "groups": "Admins,Kijkers"})], detail(r) or "")

print("--- D. wachtwoord")
check("pam: hier geen wachtwoord", call("PUT", "/api/access/users/piet@pam/password", ROOT, {"password": PW_NEW})[0] == 400)
check("root en de tool: geweigerd", call("PUT", "/api/access/users/root@pam/password", ROOT, {"password": PW_NEW})[0] == 409
      and call("PUT", f"/api/access/users/{TOOL}/password", ROOT, {"password": PW_NEW})[0] == 409)
check("te kort: geweigerd", call("PUT", "/api/access/users/anna@pve/password", ROOT, {"password": "kort"})[0] == 400)
check("rol Overzicht: geweigerd", call("PUT", "/api/access/users/anna@pve/password", OVER, {"password": PW_NEW})[0] == 403)
check("niets naar Proxmox", not changes())
r = call("PUT", "/api/access/users/anna@pve/password", ROOT, {"password": PW_NEW})
check("nieuw wachtwoord", r[0] == 200 and changes() == [("PUT", "access/password", {"userid": "anna@pve", "password": PW_NEW})] and PW_NEW not in json.dumps(main.state.events(0)), detail(r) or "")
FLAGS["pwfail"] = ResourceException(400, "Parameter verification failed.", "", errors={"confirmation-password": "property is missing and it is not optional"})
r = call("PUT", "/api/access/users/anna@pve/password", ROOT, {"password": PW_NEW})
check("vraagt Proxmox het eigen wachtwoord van wie het wijzigt: duidelijke uitleg", r[0] == 409 and "Proxmox zelf" in detail(r), detail(r))
FLAGS["pwfail"] = ResourceException(500, "Internal Server Error", "iets anders")
r = call("PUT", "/api/access/users/anna@pve/password", ROOT, {"password": PW_NEW})
check("een andere fout van Proxmox komt gewoon door", r[0] == 500 and "iets anders" in detail(r), detail(r))
FLAGS["pwfail"] = None
changes()

print("--- E. groepen")
check("ongeldige naam, bestaat al, onbekend of beschermd lid: geweigerd",
      [call("POST", "/api/access/groups", ROOT, b)[0] for b in ({"groupid": "-x"}, {"groupid": "Admins"}, {"groupid": "Nieuw", "members": ["niemand@pve"]},
                                                               {"groupid": "Nieuw", "members": ["root@pam"]})] == [400, 409, 400, 409])
check("niets naar Proxmox", not changes())
r = call("POST", "/api/access/groups", ROOT, {"groupid": "Ops", "comment": "beheer", "members": ["piet@pam", "anna@pve"]})
check("groep met leden: eerst de groep, dan elk lid erbij (append)", r[0] == 200 and changes() == [("POST", "access/groups", {"groupid": "Ops", "comment": "beheer"}),
      ("PUT", "access/users/anna@pve", {"groups": "Ops", "append": 1}), ("PUT", "access/users/piet@pam", {"groups": "Ops", "append": 1})], detail(r) or "")
r = call("PUT", "/api/access/groups/Ops", ROOT, {"members": ["anna@pve", "kees@pve"]})
check("leden wijzigen: kees erbij, piet eruit met behoud van zijn andere groep", r[0] == 200 and changes() == [("PUT", "access/users/kees@pve", {"groups": "Ops", "append": 1}),
      ("PUT", "access/users/piet@pam", {"groups": "Kijkers"})] and USERS["piet@pam"]["groups"] == {"Kijkers"}, str(USERS["piet@pam"]["groups"]))
check("de tool of root in of uit een groep: geweigerd", call("PUT", "/api/access/groups/Ops", ROOT, {"members": ["anna@pve", "kees@pve", "root@pam"]})[0] == 409
      and call("PUT", "/api/access/groups/Tool", ROOT, {"members": []})[0] == 409)
check("opmerking: alleen de groep zelf", call("PUT", "/api/access/groups/Ops", ROOT, {"comment": "anders"})[0] == 200 and changes() == [("PUT", "access/groups/Ops", {"comment": "anders"})])
check("een groep met de tool erin verwijderen: geweigerd", call("DELETE", "/api/access/groups/Tool", ROOT)[0] == 409)
r = call("DELETE", "/api/access/groups/Ops", ROOT)
check("groep verwijderen", r[0] == 200 and changes() == [("DELETE", "access/groups/Ops", {})] and "Ops" not in GROUPS, detail(r) or "")
check("onbekende groep: 404", call("DELETE", "/api/access/groups/Ops", ROOT)[0] == 404 and call("PUT", "/api/access/groups/Ops", ROOT, {"comment": "x"})[0] == 404)

print("--- F. rechten, en altijd iemand die alles mag")
A = lambda **kw: {"path": "/", "role": "Administrator", **kw}  # noqa: E731
check("ongeldige verzoeken: geen of twee ontvangers, rare plek, onbekende rol, beschermde gebruiker",
      [call("PUT", "/api/access/acl", ROOT, b)[0] for b in (A(), A(user="anna@pve", group="Admins"), A(user="anna@pve", path="/etc"), A(user="anna@pve", role="Baas"),
                                                           A(user="root@pam"), A(user=TOOL, remove=True), A(user="niemand@pve"), A(group="Geen"))] == [400, 400, 400, 400, 409, 409, 404, 404])
check("de rechten van een groep met de tool erin intrekken: geweigerd", call("PUT", "/api/access/acl", ROOT, A(group="Tool", remove=True))[0] == 409)
check("niets naar Proxmox", not changes())
r = call("PUT", "/api/access/acl", ROOT, {"path": "/vms/101", "role": "PVEVMUser", "user": "anna@pve", "propagate": False})
check("recht toekennen op één guest", r[0] == 200 and changes() == [("PUT", "access/acl", {"path": "/vms/101", "roles": "PVEVMUser", "users": "anna@pve", "propagate": 0})], detail(r) or "")
r = call("PUT", "/api/access/acl", ROOT, A(user="chef@pve", remove=True))
check("de enige beheerder zijn beheerrecht afnemen: geweigerd", r[0] == 409 and not changes(), detail(r))
r = call("PUT", "/api/access/acl", ROOT, A(user="chef@pve", role="NoAccess"))
check("of hem NoAccess op alles geven: ook geweigerd", r[0] == 409 and not changes(), detail(r))
r = call("DELETE", "/api/access/users/chef@pve", ROOT)
check("of hem verwijderen: ook geweigerd", r[0] == 409 and not changes(), detail(r))
r = call("PUT", "/api/access/acl", ROOT, A(group="Beheer"))
check("een groep Beheer volledig beheer geven", r[0] == 200 and changes() == [("PUT", "access/acl", {"path": "/", "roles": "Administrator", "groups": "Beheer", "propagate": 1})])
check("anna in Beheer zetten", call("PUT", "/api/access/groups/Beheer", ROOT, {"members": ["anna@pve"]})[0] == 200 and changes())
check("anna staat uit, dus nog steeds alleen chef", call("GET", "/api/access", ROOT)[1]["admins"] == ["chef@pve"])
check("anna weer aanzetten", call("PUT", "/api/access/users/anna@pve", ROOT, {"enable": True})[0] == 200 and changes())
check("nu mogen chef en anna alles", call("GET", "/api/access", ROOT)[1]["admins"] == ["anna@pve", "chef@pve"])
r = call("PUT", "/api/access/acl", ROOT, A(user="chef@pve", remove=True))
check("chef zijn beheerrecht afnemen mag nu (anna blijft)", r[0] == 200 and changes() == [("PUT", "access/acl", {"path": "/", "roles": "Administrator", "users": "chef@pve", "propagate": 1, "delete": 1})])
check("anna uit Beheer halen: geweigerd (dan niemand)", call("PUT", "/api/access/groups/Beheer", ROOT, {"members": []})[0] == 409)
check("Beheer verwijderen: geweigerd", call("DELETE", "/api/access/groups/Beheer", ROOT)[0] == 409)
check("het recht van Beheer intrekken: geweigerd", call("PUT", "/api/access/acl", ROOT, A(group="Beheer", remove=True))[0] == 409)
check("anna zelf NoAccess op alles: geweigerd (haar eigen recht wint van de groep)", call("PUT", "/api/access/acl", ROOT, A(user="anna@pve", role="NoAccess"))[0] == 409)
check("een recht dat er niet is intrekken: 404", call("PUT", "/api/access/acl", ROOT, {"path": "/storage", "role": "PVEAuditor", "user": "kees@pve", "remove": True})[0] == 404)
check("van al deze weigeringen ging niets naar Proxmox", not changes())
r = call("DELETE", "/api/access/users/kees@pve", ROOT)
check("een gewone gebruiker verwijderen", r[0] == 200 and changes() == [("DELETE", "access/users/kees@pve", {})] and "kees@pve" not in USERS)

print("--- G. Events")
rows = [e for e in main.event_rows(Fake(W), [], 0) if e["type"] == "access"]
check("Events: elke wijziging staat erbij, met wie het deed", len(rows) >= 14 and {e["user"] for e in rows} == {main.APP_USER, "beheer2"}, str(len(rows)))
acl_rows = [e for e in rows if e["text"] in ("recht toegekend", "recht ingetrokken")]
check("bij een recht de rol en de plek", {e["name"] for e in acl_rows} >= {"PVEVMUser, /vms/101", "Administrator, /"}, str({e["name"] for e in acl_rows}))
check("nergens in het logboek een wachtwoord", PW_NEW not in json.dumps(main.state.events(0)))

print("--- H. bewakers")
names = {"access_info", "access_user_add", "access_user_change", "access_user_delete", "access_user_password", "access_group_add", "access_group_change",
         "access_group_delete", "access_acl"}
guards = {r.name: [d.call for d in r.dependant.dependencies] for r in main.app.routes if isinstance(r, APIRoute) and r.name in names}
check("alle adressen van het tabblad Users zijn alleen voor beheerders", set(guards) == names and all(main.admin in g for g in guards.values()), str(set(names) - set(guards)))

TRIPPED = [x for x in TRIPPED if not (x[0] == "agent" and tuple(x[1][1:]) == ("info", "cts"))]
check("het echte cluster is niet aangeraakt", not TRIPPED, str(TRIPPED))

print()
print("ALLES GOED" if not FAILED else f"FOUT ({len(FAILED)}): {FAILED}")
