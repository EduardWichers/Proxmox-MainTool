"""Tests version 1.6 of the backend in-process on the tool container, from a copy in /tmp with its own state folder.

Nothing on the cluster is changed. Everything that changes something runs against a stand-in cluster that only writes
down what it is asked to do (the real connection is replaced by a tripwire for those parts), and against a stand-in
mail server. The real cluster is only read, plus a few requests built to be refused before anything is sent.
The mail settings of the installation are replaced by made-up ones inside this test; no secrets are used or shown."""
import asyncio, json, os, secrets, ssl, stat, sys, time
for line in open("/etc/maintool/maintool.env", encoding="utf-8"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ[k.strip()] = v.strip()
os.environ["STATE_DIRECTORY"] = "/tmp/mt-v16/state"
sys.path.insert(0, "/tmp/mt-v16/app")
import main  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.routing import APIRoute  # noqa: E402
from proxmoxer.core import ResourceException  # noqa: E402

FAILED, MAILLOG, MAILMODE, SEEN = [], [], ["ok"], []


class FakeSMTP:
    kind = "SMTP"

    def __init__(self, host, port, timeout=None, context=None):
        if MAILMODE[0] == "down":
            raise OSError("nagebootst: geen verbinding")
        self.entry = {"kind": self.kind, "host": host, "port": port, "starttls": False, "login": None, "noop": False, "sent": [],
                      "verify": None if context is None else context.verify_mode != ssl.CERT_NONE}
        MAILLOG.append(self.entry)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        self.entry["starttls"] = True
        self.entry["verify"] = context.verify_mode != ssl.CERT_NONE

    def login(self, user, password):
        if MAILMODE[0] == "auth":
            raise main.smtplib.SMTPAuthenticationError(535, b"nagebootst")
        self.entry["login"] = (user, password)

    def noop(self):
        self.entry["noop"] = True

    def send_message(self, msg):
        self.entry["sent"].append({"to": msg["To"], "from": msg["From"], "subject": msg["Subject"]})


class FakeSSL(FakeSMTP):
    kind = "SMTP_SSL"


main.smtplib.SMTP, main.smtplib.SMTP_SSL = FakeSMTP, FakeSSL
OLD_PW = "oud-wachtwoord-uit-installatie"
main.MAIL_HOST, main.MAIL_PORT = "smtp.voorbeeld.nl", 587
main.MAIL_USER = main.MAIL_TO = main.MAIL_FROM = "oud@voorbeeld.nl"
main.MAIL_PASSWORD = OLD_PW


def check(label, ok, extra=""):
    if not ok:
        FAILED.append(label)
    print(f"{'OK  ' if ok else 'FOUT'} {label} {extra}")


def refused(fn, *a):
    try:
        fn(*a)
        return None
    except HTTPException as e:
        return e


HOST = "tool.example"


def call(method, path, cookie=None, body=None, origin=f"https://{HOST}", full=False):
    route, _, query = path.partition("?")
    headers = [(b"host", HOST.encode())]
    if origin:
        headers.append((b"origin", origin.encode()))
    if cookie:
        headers.append((b"cookie", f"{main.SESSION_COOKIE}={cookie}".encode()))
    data = b"" if body is None else json.dumps(body).encode()
    if body is not None:
        headers += [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode())]
    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1", "method": method,
             "scheme": "https", "path": route, "raw_path": route.encode(), "query_string": query.encode(), "root_path": "",
             "headers": headers, "client": ("203.0.113.7", 40000), "server": (HOST, 443)}
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
    SEEN.append(raw.decode("utf-8", "replace"))
    try:
        parsed = json.loads(raw)
    except ValueError:
        parsed = raw.decode("utf-8", "replace")
    if full:
        return start["status"], parsed, next((v.decode() for k, v in start["headers"] if k == b"set-cookie"), "")
    return start["status"], parsed


def socket_close(path, cookie=None):
    headers = [(b"host", HOST.encode()), (b"origin", f"https://{HOST}".encode())]
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
    return "accepted" if any(m["type"] == "websocket.accept" for m in sent) else next((m.get("code") for m in sent if m["type"] == "websocket.close"), None)


def detail(r):
    return r[1].get("detail") if isinstance(r[1], dict) else str(r[1])[:90]


class World:
    """A stand-in cluster: answers reads from a table and writes down every change it is asked to make."""
    def __init__(self):
        self.table, self.changes, self.pending, self.answers, self.fail = {}, [], {}, {}, None
        self.store = {"session": self, "base_url": "https://nagebootst/api2/json"}

    def request(self, method, url, timeout=None):
        name, world = url.split("/nodes/")[1].split("/")[0], self
        return type("R", (), {"status_code": 200, "json": lambda s: {"data": [], "changes": world.pending.get(name)}})()

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
        if name == "_store":
            return self.world.store
        return Fake(self.world, self.path + (name,))

    def __call__(self, *args):
        return Fake(self.world, self.path + tuple(str(a) for a in args))


TRIPPED = []
REAL_RUN, REAL_CONNECT = main.pve.run, main.pve.connect


def stand_in(world):
    """From here on the tool talks to the stand-in cluster; the real connection is a tripwire."""
    def run(fn):
        try:
            return fn(Fake(world))
        except ResourceException as e:
            raise HTTPException(e.status_code or 500, f"Proxmox: {e.status_message} {e.content or ''}".strip())
    main.pve.run = run
    main.pve.connect = lambda *a, **k: TRIPPED.append("verbinden") or (_ for _ in ()).throw(AssertionError("echte verbinding"))


def real_again():
    main.pve.run, main.pve.connect = REAL_RUN, REAL_CONNECT


print("versie:", main.VERSION, "| eigen map voor de test:", main.STATE_DIR)
waited = 0
while main.updates.busy and waited < 300:
    time.sleep(2)
    waited += 2
REAL_UPDATES = main.updates.info

# ================================================================== A. gebruikers van vóór 1.6 blijven werken
print("\n--- A. rollen")
OLD = "Oud-wachtwoord-van-jan"
salt = secrets.token_bytes(16)
main.USERS_FILE.write_text(json.dumps({"users": {
    "jan": {"role": "readonly", "salt": salt.hex(), "hash": main.password_hash(OLD, salt), "gen": 5, "created": 1},
    "baas": {"role": "admin", "salt": salt.hex(), "hash": main.password_hash(OLD, salt), "gen": 7, "created": 2}}}))
os.chmod(main.USERS_FILE, 0o600)
check("gebruikersbestand van versie 1.5: 'jan' blijft alleen lezen, 'baas' blijft beheerder",
      main.users_state()["jan"]["roles"] == [] and main.users_state()["baas"]["roles"] == ["admin"] and main.account("jan")["role"] == "readonly" and main.account("baas")["admin"])
check("en ze loggen nog in met hun eigen wachtwoord", main.check_login("jan", OLD) and call("POST", "/api/login", None, {"username": "jan", "password": OLD})[0] == 200)
ROOT = main.make_token(main.APP_USER)   # signed with the key of this test copy only
PW = "Proef-" + secrets.token_urlsafe(14)
TOK = {}
for name, roles in (("lezer", []), ("overzicht", ["overview"]), ("opslag", ["storage"]), ("netwerk", ["network"]), ("backup", ["backups"]),
                    ("events", ["events"]), ("combi", ["backups", "network"]), ("beheer2", ["admin", "storage"])):
    r = call("POST", "/api/users", ROOT, {"name": name, "roles": roles, "password": PW})
    check(f"gebruiker '{name}' aangemaakt met rollen {roles}", r[0] == 200, detail(r) if r[0] != 200 else "")
    TOK[name] = main.make_token(name)
check("de volgorde van rollen is die van de tabbladen, en 'admin' vervangt de rest",
      main.users_state()["combi"]["roles"] == ["network", "backups"] and main.users_state()["beheer2"]["roles"] == ["admin"])
for bad in (["baas"], ["storage", "x"], "storage", ["storage", 5]):
    r = call("POST", "/api/users", ROOT, {"name": "fout", "roles": bad, "password": PW})
    check(f"ongeldige rollen geweigerd: {bad!r}", r[0] in (400, 422), f"{r[0]}")
r = call("POST", "/api/users", ROOT, {"name": "oudevorm", "role": "readonly", "password": PW}); check("de oude vorm (role: readonly) wordt nog begrepen", r[0] == 200 and main.users_state()["oudevorm"]["roles"] == [])
me = call("GET", "/api/me", TOK["combi"])[1]
check("wie ben ik (combi): rollen en wat hij mag", me["roles"] == ["network", "backups"] and me["can"] == ["network", "backups"] and me["role"] == "custom" and me["min_password"] == 12, json.dumps(me))
me = call("GET", "/api/me", TOK["beheer2"])[1]
check("wie ben ik (beheerder): mag alles", me["role"] == "admin" and me["can"] == ["admin", *main.AREAS])
page = call("GET", "/", TOK["opslag"])[1]
check("de pagina krijgt mee wat de gebruiker mag", 'data-can="storage"' in page and 'data-role="custom"' in page and 'data-user="opslag"' in page and "{{" not in page)
page = call("GET", "/", TOK["lezer"])[1]
check("idem voor alleen lezen: niets", 'data-can=""' in page and 'data-role="readonly"' in page)
check("idem voor het hoofdaccount: alles", 'data-can="admin overview storage network backups events"' in call("GET", "/", ROOT)[1])

# ---- elk adres heeft de bedoelde bewaker
WANT = {
    "overview": ["destroy", "power", "migrate", "create_snap", "delete_snap", "rollback_snap", "xterm_file", "updates_check", "upgrade_start",
                 "release_start", "reboot_node", "create_template", "create_ct", "create_vm", "guest_config", "guest_config_save",
                 "guest_disk_grow", "autoupdate_put", "autoupdate_run", "ha_add", "ha_change", "ha_remove",
                 "node_settings_save", "balance_put", "balance_guest",   # 1.7, 1.9, HA (1.0), node-instellingen (1.0.4), loadbalancer (1.1)
                 "ha_setup_put", "ha_disarm", "ha_arm", "ha_rule_add", "ha_rule_change", "ha_rule_delete",   # HA instellen (1.2)
                 "autoupdate_add", "autoupdate_edit", "autoupdate_remove", "autoupdate_run_one"],   # meer schema's automatisch bijwerken (1.4)
    "storage": ["create_storage", "create_scan", "library_iso", "library_template", "library_delete",   # bibliotheek (1.0.6)
                "ceph_flag", "ceph_osd_action", "ceph_osd_create", "ceph_osd_destroy", "ceph_mon_create", "ceph_mon_destroy",
                "ceph_mgr_create", "ceph_mgr_destroy", "ceph_pool_create", "ceph_pool_change", "ceph_pool_delete", "ceph_init"],   # Ceph instellen (1.2)
    "overview+storage": ["create_options"],
    "network": ["network_vnet_create", "network_vnet_delete", "network_sdn_apply", "network_vlan_create", "network_node_apply",
                "network_node_revert", "network_guest_nic"],
    "backups": ["backup_job_create", "backup_job_update", "backup_job_enable", "backup_job_delete", "backup_job_run", "backup_now",
                "backup_file_delete", "backup_restore"],
    "events": ["report_send", "report_mail_save", "report_mail_reset", "report_mail_test", "alerts_put", "alerts_reset", "report_config_save"],
    "admin": ["users_get", "users_add", "users_change", "users_delete", "policy_put", "selfupdate_upload", "selfupdate_discard", "selfupdate_apply",
              "sso_get", "sso_oidc_put", "sso_cloudflare_put", "sso_proxmox_put", "policy_get",   # SSO instellen (1.7), beleid lezen (1.9)
              "access_info", "access_user_add", "access_user_change", "access_user_delete", "access_user_password", "access_group_add",
              "access_group_change", "access_group_delete", "access_acl",   # Proxmox-gebruikers (1.0.2)
              "access_token_add", "access_token_change", "access_token_delete",   # API-tokens (1.3.1)
              "wa_reset", "nodecon_get", "nodecon_login"],   # sleutels van een ander weghalen, console van een node (1.3.1)
    "open": ["sso_options", "oidc_start", "oidc_callback", "cloudflare_login", "wa_login_start", "wa_login_finish"],   # inloggen met SSO (1.7), net als /api/login
}
want = {name: area for area, names in WANT.items() for name in names}
OPEN = {("GET", "/"), ("GET", "/login"), ("POST", "/api/login"), ("POST", "/api/logout"),
        ("GET", "/api/sso/options"), ("GET", "/api/sso/oidc/start"), ("GET", "/api/sso/oidc/callback"), ("POST", "/api/sso/cloudflare"),
        ("POST", "/api/webauthn/login/start"), ("POST", "/api/webauthn/login/finish")}   # inloggen met een beveiligingssleutel (1.3.1)
OWN = {("POST", "/api/password"), ("PUT", "/api/settings"), ("POST", "/api/viewonly"),
       ("POST", "/api/webauthn/register/start"), ("POST", "/api/webauthn/register/finish"), ("PUT", "/api/webauthn"),   # eigen sleutels (1.3.1)
       ("DELETE", "/api/nodeconsole")}   # het eigen ticket voor de console van de nodes vergeten (1.3.1)   # viewonly: alleen de eigen keuze (1.9)
routes, wrong = [], []
for route in main.app.routes:
    if isinstance(route, APIRoute):
        calls = [d.call for d in route.dependant.dependencies]
        guard = next((c for c in calls if c is main.admin or hasattr(c, "areas")), None)
        kind = "admin" if guard is main.admin else "+".join(guard.areas) if guard else "auth" if main.auth in calls else "open"
        for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
            routes.append((method, route.path, kind, route.name, guard))
            if want.get(route.name, "auth" if (method, route.path) not in OPEN else "open") != kind:
                wrong.append((route.name, kind))
            if method != "GET" and kind in ("auth", "open") and (method, route.path) not in OPEN | OWN:
                wrong.append((route.name, "wijzigt zonder bewaker"))
by = {}
for r in routes:
    by[r[2]] = by.get(r[2], 0) + 1
print(f"     {len(routes)} adressen:", by)
check("elk adres heeft precies de bedoelde bewaker; alles wat iets verandert is afgeschermd", not wrong and set(want) <= {r[3] for r in routes}, str(wrong) + str(set(want) - {r[3] for r in routes}))

# ---- wie komt waar door de bewaker: uitgerekend op de bewaker zelf, en als weigering door de hele applicatie
ALLOWED = {"lezer": set(), "overzicht": {"overview"}, "opslag": {"storage"}, "netwerk": {"network"}, "backup": {"backups"}, "events": {"events"},
           "combi": {"network", "backups"}, "beheer2": {"admin", *main.AREAS}}
FILL = {"node": "geen-node", "kind": "lxc", "vmid": "999999", "action": "stop", "target": "node", "job": "geen-taak", "storage": "geen-opslag",
        "upid": "geen", "name": "geen", "nic": "net0", "sid": "ct:999999", "userid": "niemand@pve", "groupid": "geen-groep"}


def fill(path):
    for key, value in FILL.items():
        path = path.replace("{" + key + "}", value)
    return path


class Req:
    def __init__(self, token):
        self.cookies = {main.SESSION_COOKIE: token}


stand_in(World())   # elk verzoek hieronder dat tóch zou doorlopen komt bij een leeg nagebootst cluster uit, niet bij het echte
main.agent = main.send_report = lambda *a, **k: TRIPPED.append("agent of mail") or (_ for _ in ()).throw(AssertionError("struikeldraad"))
mistakes, refusals = [], 0
for method, path, kind, name, guard in routes:
    if guard is None:
        continue
    for user, may in ALLOWED.items():
        allowed = "admin" in may if guard is main.admin else ("admin" in may or any(a in may for a in guard.areas))
        e = refused(guard, Req(TOK[user]))
        if (e is None) != allowed:
            mistakes.append((user, name, "bewaker"))
        if not allowed:
            r = call(method, fill(path), TOK[user], {} if method != "GET" else None)
            refusals += 1
            if r[0] != 403:
                mistakes.append((user, name, r[0]))
    r = call(method, fill(path), None, {} if method != "GET" else None)
    if r[0] != 401:
        mistakes.append(("niemand", name, r[0]))
check(f"elke rol komt alleen door de bewaker van zijn eigen tabblad ({refusals} weigeringen nagelopen), zonder sessie nergens", not mistakes, str(mistakes[:8]))
check("console: alleen lezen en opslagbeheerder geweigerd, overzichtbeheerder komt door de rechtencontrole",
      socket_close("/api/console/geen-node/999999", TOK["lezer"]) == 4403 and socket_close("/api/console/geen-node/999999", TOK["opslag"]) == 4403
      and socket_close("/api/console/geen_node/999999", TOK["overzicht"]) == 4400)
r = call("PUT", "/api/users/combi", ROOT, {"roles": ["storage"]})
check("rollen wijzigen logt die gebruiker uit", r[0] == 200 and call("GET", "/api/me", TOK["combi"])[0] == 401 and main.users_state()["combi"]["roles"] == ["storage"])
r = call("PUT", "/api/users/combi", ROOT, {"roles": ["storage"]}); TOK["combi"] = main.make_token("combi")
r = call("PUT", "/api/users/combi", ROOT, {"roles": ["storage"]})
check("dezelfde rollen nog eens opslaan logt niet opnieuw uit", r[0] == 200 and call("GET", "/api/me", TOK["combi"])[0] == 200)
r = call("PUT", "/api/users/beheer2", TOK["beheer2"], {"roles": []}); check("eigen rollen afpakken blijft geweigerd", r[0] == 409)
r = call("GET", "/api/users", ROOT)
check("de gebruikerslijst toont de rollen", {u["name"]: u["roles"] for u in r[1]}["combi"] == ["storage"] and r[1][0] == {"name": main.APP_USER, "roles": ["admin"], "role": "admin", "builtin": True, "password_login": True, "sso": {}, "bound": False, "keys": 0, "key_required": False})

# ================================================================== B. minimale wachtwoordlengte
print("\n--- B. minimale wachtwoordlengte")
check("standaard 12", main.min_password() == 12)
r = call("PUT", "/api/policy", TOK["events"], {"min_password": 8}); check("alleen een beheerder mag dit instellen", r[0] == 403 and call("PUT", "/api/policy", None, {"min_password": 8})[0] == 401)
for n in (7, 129, 0, -5):
    r = call("PUT", "/api/policy", ROOT, {"min_password": n}); check(f"lengte {n} geweigerd", r[0] == 400, detail(r))
r = call("PUT", "/api/policy", ROOT, {"min_password": 16}, origin="https://kwaad.example"); check("vanaf een andere website geweigerd", r[0] == 403 and main.min_password() == 12)
r = call("PUT", "/api/policy", ROOT, {"min_password": 16}); check("ingesteld op 16", r[0] == 200 and r[1]["min_password"] == 16 and main.min_password() == 16)   # sinds 1.9 staat ook "cloudflare" in het antwoord
r = call("POST", "/api/users", ROOT, {"name": "kort", "roles": [], "password": "a" * 15}); check("nieuwe gebruiker met 15 tekens geweigerd, met het juiste getal in de melding", r[0] == 400 and "16" in detail(r), detail(r))
r = call("POST", "/api/users", ROOT, {"name": "kort", "roles": [], "password": "a" * 16}); check("met 16 tekens wel", r[0] == 200)
r = call("POST", "/api/password", TOK["lezer"], {"current": PW, "new": "b" * 15}); check("eigen wachtwoord wijzigen volgt dezelfde regel", r[0] == 400 and "16" in detail(r))
r = call("PUT", "/api/users/lezer", ROOT, {"password": "c" * 15}); check("een nieuw wachtwoord door de beheerder ook", r[0] == 400)
check("bestaande, kortere wachtwoorden blijven werken", main.check_login("jan", OLD) and len(OLD) >= 12)
check("de pagina en /api/me geven het getal mee", call("GET", "/api/me", TOK["lezer"])[1]["min_password"] == 16)
r = call("PUT", "/api/policy", ROOT, {"min_password": 8}); r2 = call("POST", "/api/users", ROOT, {"name": "acht", "roles": [], "password": "abcdefgh"})
check("ingesteld op 8: een wachtwoord van 8 tekens mag", r[0] == 200 and r2[0] == 200)
main.state.change(lambda d: d.update(policy={"min_password": "veel"})); check("onzin in het bestand: terug naar 12", main.min_password() == 12)
main.state.change(lambda d: d.update(policy={"min_password": 3})); check("te laag getal in het bestand: terug naar 12", main.min_password() == 12)
call("PUT", "/api/policy", ROOT, {"min_password": 12})
en = call("POST", "/api/users", ROOT, {"name": "kort2", "roles": [], "password": "x"})
check("de melding met het getal bestaat ook in het Engels en Duits", "at least 12" in main.translate(detail(en), "en") and "mindestens 12" in main.translate(detail(en), "de"))

# ================================================================== C. triggers en drempels
print("\n--- C. triggers en drempels (nagebootst cluster)")
now = int(time.time())
W = World()
W.table.update({
    "nodes": [{"node": "n1", "status": "online", "mem": 95, "maxmem": 100, "disk": 50, "maxdisk": 100},
              {"node": "n2", "status": "online", "mem": 98, "maxmem": 100, "disk": 86, "maxdisk": 100},
              {"node": "n3", "status": "offline"}],
    "cluster/status": [{"type": "cluster", "name": "proef", "quorate": 1}],
    "cluster/ha/status/current": [{"type": "service", "sid": "ct:104", "state": "error", "node": "n1"}, {"type": "service", "sid": "ct:101", "state": "started", "node": "n1"}],
    "cluster/resources": lambda kw: [
        {"vmid": 101, "type": "lxc", "node": "n1", "name": "een", "status": "running", "disk": 91, "maxdisk": 100},
        {"vmid": 102, "type": "lxc", "node": "n1", "name": "twee", "status": "stopped", "disk": 99, "maxdisk": 100},
        {"vmid": 103, "type": "lxc", "node": "n2", "name": "drie", "status": "running", "disk": 10, "maxdisk": 100},
        {"vmid": 900, "type": "lxc", "node": "n3", "name": "weg", "status": "unknown"}] if kw.get("type") == "vm" else [
        {"storage": "nas", "node": "n1", "shared": 1, "status": "available", "disk": 92, "maxdisk": 100},
        {"storage": "nas", "node": "n2", "shared": 1, "status": "available", "disk": 92, "maxdisk": 100},
        {"storage": "local", "node": "n1", "shared": 0, "status": "available", "disk": 20, "maxdisk": 100},
        {"storage": "local", "node": "n2", "shared": 0, "status": "unknown"},
        {"storage": "local", "node": "n3", "shared": 0, "status": "unknown"}],
    "nodes/n1/ceph/status": {"health": {"status": "HEALTH_ERR", "checks": {"OSD_DOWN": {"severity": "HEALTH_WARN", "summary": {"message": "1 osds down"}},
                                                                         "PG_DAMAGED": {"severity": "HEALTH_ERR", "summary": {"message": "pg damaged"}}}}},
    "nodes/n1/disks/list": [{"devpath": "/dev/sda", "health": "FAILED", "wearout": 50}, {"devpath": "/dev/sdb", "health": "PASSED", "wearout": "N/A"}],
    "nodes/n2/disks/list": [{"devpath": "/dev/nvme0n1", "health": "PASSED", "wearout": 5}],
    "nodes/n1/network": [{"iface": "vmbr0", "type": "bridge", "cidr": "10.0.0.1/24", "active": 1}],
    "nodes/n2/network": [{"iface": "vmbr0", "type": "bridge", "cidr": "10.0.0.9/24", "active": 1}],
    "nodes/n1/dns": {}, "nodes/n2/dns": {},
    "cluster/sdn/zones": [{"zone": "vlans", "type": "vlan", "bridge": "vmbr0"}],
    "cluster/sdn/vnets": [{"vnet": "gasten", "zone": "vlans", "tag": 20}, {"vnet": "nieuw", "type": "vnet", "state": "new", "pending": {"zone": "vlans", "tag": 30}}],
    "nodes/n1/sdn/zones/vlans/content": [{"vnet": "gasten", "status": "available"}],
    "nodes/n2/sdn/zones/vlans/content": [{"vnet": "gasten", "status": "error"}],
    "nodes/n1/lxc/101/config": {"net0": "name=eth0,bridge=vmbr0,ip=10.0.0.5/24"},
    "nodes/n1/lxc/102/config": {"net0": "name=eth0,bridge=vmbr0,ip=10.0.0.5/24", "net1": "name=eth1,bridge=vmbr0,ip=dhcp"},
    "nodes/n2/lxc/103/config": {"net0": "name=eth0,bridge=vmbr0,ip=10.0.0.9/24"},
    "nodes/n1/tasks": lambda kw: [] if kw.get("typefilter") != "vzdump" else [
        {"id": "101", "starttime": now - 100, "endtime": now - 50, "status": "job errors", "upid": "UPID:n1:a"},
        {"id": "101", "starttime": now - 9000, "endtime": now - 8000, "status": "OK", "upid": "UPID:n1:b"},
        {"id": "102", "starttime": now - 9000, "endtime": now - 8000, "status": "kapot", "upid": "UPID:n1:c"},
        {"id": "104", "starttime": now - 10, "upid": "UPID:n1:d"}],
    "nodes/n2/tasks": lambda kw: [] if kw.get("typefilter") != "vzdump" else [
        {"id": "102", "starttime": now - 200, "endtime": now - 100, "status": "OK", "upid": "UPID:n2:e"},
        {"id": "103", "starttime": now - 200, "endtime": now - 100, "status": "WARNINGS: 1", "upid": "UPID:n2:f"},
        {"id": "", "starttime": now - 300, "endtime": now - 100, "status": "OK", "upid": "UPID:n2:g"}],
    "storage": [{"storage": "nas", "content": "backup,images", "shared": 1}, {"storage": "local", "content": "backup"}],
    "nodes/n1/storage/nas/content": [{"vmid": 101, "ctime": now - 10 * 86400}, {"vmid": 101, "ctime": now - 30 * 86400}, {"vmid": 102, "ctime": now - 3600}],
    "cluster/backup": [{"id": "j1", "all": 1, "exclude": "102", "enabled": 1}, {"id": "j2", "vmid": "102", "enabled": 0}],
})
W.pending["n1"] = "--- a\n+++ b\n+auto vmbr0.20"
stand_in(W)
main.updates.info = {"nodes": {"n1": {"agent": 0, "reboot": None}, "n2": {"agent": 3, "reboot": "7.0.14-23-pve"}, "n3": {"agent": 0}}}


def found():
    return sorted(((i["code"], i["level"], i["tab"], i.get("node") or i.get("storage") or i.get("id") or i.get("vnet") or i.get("ip") or i.get("vmid") or i.get("sid") or "")
                  for i in main.gather_issues(Fake(W))), key=str)


EXPECT = sorted([
    ("node_offline", "error", "overview", "n3"), ("node_mem", "warning", "overview", "n1"), ("node_mem", "error", "overview", "n2"),
    ("node_root", "warning", "overview", "n2"), ("ha", "error", "overview", "n1"), ("no_agent", "warning", "overview", "n1"),
    ("reboot", "info", "overview", "n2"), ("guest_disk", "warning", "overview", 101),
    ("storage_full", "warning", "storage", "nas"), ("storage_unavailable", "warning", "storage", "n2"),
    ("ceph_warn", "warning", "storage", ""), ("ceph_err", "error", "storage", ""), ("disk", "error", "storage", "n1"), ("disk_wear", "warning", "storage", "n2"),
    ("net_pending", "warning", "network", "n1"), ("net_pending", "warning", "network", ""), ("vnet_error", "error", "network", "n2"),
    ("ip_double", "warning", "network", "10.0.0.5"), ("ip_double", "warning", "network", "10.0.0.9"),
    ("backup_failed", "error", "backups", "n1"), ("backup_warning", "warning", "backups", "n2")], key=str)
got = sorted(found(), key=str)
check("met de standaardinstellingen: precies de verwachte aandachtspunten, elk op zijn eigen tabblad en met het juiste niveau", got == EXPECT,
      "\n       te veel: " + str([g for g in got if g not in EXPECT]) + "\n       te weinig: " + str([e for e in EXPECT if e not in got]) if got != EXPECT else f"({len(got)} punten)")
items = main.gather_issues(Fake(W))
double = next(i for i in items if i["code"] == "ip_double" and i["ip"] == "10.0.0.9")
check("een dubbel adres noemt wie het hebben, ook als het een node is", double["who"] == ["103 drie", "n2"], str(double["who"]))
failed = next(i for i in items if i["code"] == "backup_failed")
check("een mislukte back-up noemt de guest, de melding en de taak (voor het log)", failed["id"] == "101" and failed["name"] == "een" and failed["text"] == "job errors" and failed["upid"] == "UPID:n1:a")
check("een latere geslaagde back-up wist een eerdere fout, en een lopende back-up telt niet", not any(i.get("id") in ("102", "104", "") for i in items if i["tab"] == "backups"))
check("drempels geven de gemeten waarde mee", next(i for i in items if i["code"] == "storage_full")["value"] == 92 and next(i for i in items if i["code"] == "disk_wear")["value"] == 95)
check("niets wat hiervoor is opgevraagd heeft iets veranderd", W.changes == [])

view = call("GET", "/api/alerts", TOK["lezer"])
check("iedereen die is ingelogd kan de instellingen bekijken", view[0] == 200 and len(view[1]["alerts"]) == len(main.ALERTS) and view[1]["levels"] == ["off", "info", "warning", "error"])
check("standaard staat 'back-up te oud' uit", next(a for a in view[1]["alerts"] if a["code"] == "backup_old")["value"] == {"warning": None, "error": None})
for user in ("lezer", "opslag", "overzicht"):
    check(f"'{user}' mag de instellingen niet wijzigen", call("PUT", "/api/alerts", TOK[user], {"alerts": {"reboot": "warning"}})[0] == 403)
for label, body in [("onbekende trigger", {"bestaatniet": "off"}), ("onbekend niveau", {"reboot": "paars"}), ("drempel als niveau", {"storage_full": "error"}),
                    ("niveau als drempel", {"reboot": {"warning": 5, "error": 9}}), ("drempel boven 100%", {"storage_full": {"warning": 90, "error": 101}}),
                    ("drempel 0", {"storage_full": {"warning": 0, "error": 90}}), ("oranje niet lager dan rood", {"storage_full": {"warning": 95, "error": 95}}),
                    ("tekst als drempel", {"storage_full": {"warning": "90", "error": 97}}), ("extra veld", {"storage_full": {"warning": 90, "error": 97, "x": 1}}),
                    ("dagen boven 365", {"backup_old": {"warning": 400, "error": None}}), ("waar/onwaar als drempel", {"node_mem": {"warning": True, "error": None}})]:
    r = call("PUT", "/api/alerts", TOK["events"], {"alerts": body})
    check(f"geweigerd: {label}", r[0] == 400, detail(r))
check("na al die weigeringen is er niets bewaard", "alerts" not in main.state.load())
r = call("PUT", "/api/alerts", TOK["events"], {"alerts": {"storage_full": {"warning": 95, "error": None}, "node_offline": "warning", "ceph_warn": "off", "reboot": "warning",
                                                         "node_mem": {"warning": None, "error": 96}, "backup_old": {"warning": 7, "error": 30}, "disk_wear": {"warning": 50, "error": 95}}})
check("de events-beheerder past drempels en triggers aan", r[0] == 200 and next(a for a in r[1]["alerts"] if a["code"] == "storage_full")["value"] == {"warning": 95, "error": None})
got = found()
changed = {("storage_full", "nas"): None, ("node_offline", "n3"): "warning", ("ceph_warn", ""): None, ("reboot", "n2"): "warning", ("node_mem", "n1"): None,
           ("node_mem", "n2"): "error", ("disk_wear", "n2"): "error", ("disk_wear", "n1"): "warning", ("backup_old", 101): "warning", ("backup_old", 103): "error"}
levels = {(c, w): lvl for c, lvl, _t, w in got}
check("de nieuwe instellingen werken door: opslag 92% is geen punt meer, node weg is oranje, Ceph-waarschuwing uit, herstart oranje, geheugen alleen rood vanaf 96%, slijtage strenger",
      all(levels.get(k) == v for k, v in changed.items()), str({k: levels.get(k) for k in changed if levels.get(k) != changed[k]}))
old = [i for i in main.gather_issues(Fake(W)) if i["code"] == "backup_old"]
check("back-up te oud: 101 (10 dagen) oranje, 103 en 900 (nooit) rood, 102 valt buiten het schema", [(i["vmid"], i["level"], i["never"]) for i in old] == [(101, "warning", False), (103, "error", True), (900, "error", True)], str(old))
r = call("PUT", "/api/alerts", TOK["events"], {"alerts": {"net_pending": "off", "ip_double": "off", "vnet_error": "off", "disk": "off", "disk_wear": {"warning": None, "error": None}}})
asked = []
W.table["nodes/n1/disks/list"] = lambda kw: asked.append("schijven") or []
W.table["nodes/n1/lxc/101/config"] = lambda kw: asked.append("guest") or {}
main.gather_issues(Fake(W))
check("wat uit staat wordt ook niet meer opgevraagd (schijven, netwerk van guests)", asked == [], str(asked))
r = call("DELETE", "/api/alerts", TOK["opslag"]); check("terug naar standaard mag alleen wie het tabblad Events beheert", r[0] == 403)
r = call("DELETE", "/api/alerts", TOK["events"]); check("terug naar de standaard", r[0] == 200 and "alerts" not in main.state.load() and all(a["value"] == a["default"] for a in r[1]["alerts"]))
main.state.change(lambda d: d.update(alerts={"reboot": "paars", "storage_full": {"warning": 500}, "bestaatniet": 1, "ha": "off"}))
cfg = main.alert_settings()
check("onzin in het bestand valt per trigger terug op de standaard; wat klopt blijft gelden", cfg["reboot"] == "info" and cfg["storage_full"] == {"warning": 90, "error": 97} and cfg["ha"] == "off")
main.state.change(lambda d: d.pop("alerts", None))
main.issues.at = 0.0
check("STRUIKELDRAAD: in A t/m C is de echte verbinding niet gebruikt", not TRIPPED, str(TRIPPED))

# ================================================================== D. een guest bewerken
print("\n--- D. guest bewerken (regels en nagebootst cluster)")
E, LIM = main.GuestEdit, {"cores": 12, "memory": 16000}
CT = {"hostname": "web", "cores": 2, "memory": 1024, "swap": 512, "onboot": 1, "description": "oude notitie", "digest": "abc"}
VM = {"name": "win", "cores": 2, "sockets": 2, "memory": "4096", "digest": "def"}
check("container: wat de tool uit de instellingen leest", main.guest_settings("lxc", CT) == {"name": "web", "cores": 2, "sockets": None, "memory": 1024, "swap": 512, "onboot": True, "protection": False, "description": "oude notitie", "tags": []})   # labels sinds 1.4
check("VM: cores is het totaal over de sockets", main.guest_settings("qemu", VM)["cores"] == 4 and main.guest_settings("qemu", VM)["memory"] == 4096 and main.guest_settings("qemu", VM)["swap"] is None)
p = main.edit_plan("lxc", CT, E(memory=2048, cores=4, swap=0, onboot=False, protection=True, name="web2", description="nieuwe\nnotitie", digest="abc"), LIM, False)
check("container: alles wat wijzigt gaat mee, met de controlecode", p == {"hostname": "web2", "cores": 4, "memory": 2048, "swap": 0, "onboot": 0, "protection": 1, "description": "nieuwe\nnotitie", "digest": "abc"}, json.dumps(p))
check("wat gelijk blijft gaat niet mee", main.edit_plan("lxc", CT, E(memory=2048, cores=2, swap=512, onboot=True, name="web", description="oude notitie"), LIM, False) == {"memory": 2048})
check("een lege notitie haalt de notitie weg", main.edit_plan("lxc", CT, E(description="  "), LIM, False) == {"delete": "description"})
p = main.edit_plan("qemu", VM, E(cores=6, memory=8192, name="win11"), LIM, False)
check("VM: het gevraagde aantal cores komt op één socket", p == {"name": "win11", "cores": 6, "sockets": 1, "memory": 8192}, json.dumps(p))
for label, kind, cfg, body, own, code in [
        ("niets gewijzigd", "lxc", CT, E(memory=1024), False, 400), ("helemaal leeg", "lxc", CT, E(), False, 400),
        ("0 cores", "lxc", CT, E(cores=0), False, 400), ("meer cores dan de node heeft", "lxc", CT, E(cores=13), False, 400),
        ("te weinig geheugen", "lxc", CT, E(memory=32), False, 400), ("meer geheugen dan de node heeft", "lxc", CT, E(memory=16001), False, 400),
        ("VM te weinig geheugen", "qemu", VM, E(memory=64), False, 400), ("negatieve swap", "lxc", CT, E(swap=-1), False, 400),
        ("swap bij een VM", "qemu", VM, E(swap=512), False, 400), ("naam met spatie", "lxc", CT, E(name="mijn web"), False, 400),
        ("naam met vreemde tekens", "lxc", CT, E(name="web;rm"), False, 400), ("notitie met stuurteken", "lxc", CT, E(description="a\x07b"), False, 400),
        ("de eigen container hernoemen", "lxc", CT, E(name="anders"), True, 409), ("de eigen container onder 512 MB", "lxc", CT, E(memory=256), True, 400),
        ("vergrendelde guest", "lxc", {**CT, "lock": "backup"}, E(memory=2048), False, 409), ("sjabloon", "lxc", {**CT, "template": 1}, E(memory=2048), False, 409)]:
    e = refused(main.edit_plan, kind, cfg, body, LIM, own)
    check(f"geweigerd: {label}", e is not None and e.status_code == code, getattr(e, "detail", "NIET GEWEIGERD"))
check("de eigen container mag wel meer geheugen krijgen", main.edit_plan("lxc", CT, E(memory=2048), LIM, True) == {"memory": 2048})

W = World()
W.table.update({
    "cluster/resources": [{"vmid": 101, "type": "lxc", "node": "n1", "name": "web", "status": "running"}, {"vmid": 200, "type": "qemu", "node": "n1", "name": "win", "status": "running"},
                          {"vmid": 109, "type": "lxc", "node": "n1", "name": main.socket.gethostname(), "status": "running"}],
    "nodes/n1/status": {"cpuinfo": {"cpus": 12}, "memory": {"total": 16000 * 2**20}},
    "nodes/n1/lxc/101/config": dict(CT), "nodes/n1/qemu/200/config": dict(VM), "nodes/n1/lxc/109/config": {"hostname": main.socket.gethostname(), "memory": 1024, "net0": "name=eth0,bridge=vmbr0"},
    "nodes/n1/qemu/200/pending": [{"key": "memory", "value": "4096", "pending": "8192"}, {"key": "name", "value": "win11"}, {"key": "cores", "value": 2, "pending": 6}],
    "nodes/n1/network": lambda kw: [{"iface": "vmbr0", "type": "bridge"}, {"iface": "gasten", "type": "vnet"}] if kw.get("type") == "any_bridge" else [],
})
stand_in(W)
r = call("GET", "/api/guest/n1/lxc/101/config", TOK["overzicht"])
check("venster openen: huidige waarden en wat de node aankan", r[0] == 200 and r[1]["memory"] == 1024 and r[1]["limits"] == {"cores": 12, "memory": 16000} and r[1]["digest"] == "abc" and r[1]["own"] is False and r[1]["min_memory"] == 64, json.dumps(r[1]))
check("de eigen container wordt herkend", call("GET", "/api/guest/n1/lxc/109/config", TOK["overzicht"])[1]["own"] is True)
check("alleen lezen en andere rollen mogen het venster niet eens openen", call("GET", "/api/guest/n1/lxc/101/config", TOK["lezer"])[0] == 403 and call("GET", "/api/guest/n1/lxc/101/config", TOK["netwerk"])[0] == 403)
r = call("PUT", "/api/guest/n1/lxc/101/config", TOK["overzicht"], {"memory": 2048, "cores": 4, "digest": "abc"})
check("container opslaan: één opdracht met alleen de wijzigingen; direct actief", r == (200, {"ok": True, "changed": ["cores", "memory"], "pending": []}) and W.changes == [("PUT", "nodes/n1/lxc/101/config", {"cores": 4, "memory": 2048, "digest": "abc"})], str(W.changes))
W.changes.clear()
r = call("PUT", "/api/guest/n1/qemu/200/config", TOK["overzicht"], {"memory": 8192, "cores": 6, "name": "win11"})
check("draaiende VM: het antwoord zegt wat pas na een herstart geldt", r[0] == 200 and r[1]["pending"] == ["cores", "memory"] and r[1]["changed"] == ["cores", "memory", "name", "sockets"], json.dumps(r[1]))
W.changes.clear()
r = call("PUT", "/api/guest/n1/lxc/101/config", TOK["overzicht"], {"name": "web2"}); check("naam van een draaiende container: geldt na de volgende start", r[1]["pending"] == ["hostname"])
W.changes.clear()
r = call("PUT", "/api/guest/n1/lxc/101/config", TOK["overzicht"], {"memory": 1024}); check("niets gewijzigd: geen opdracht aan het cluster", r[0] == 400 and W.changes == [], detail(r))
r = call("PUT", "/api/guest/n1/lxc/101/config", TOK["overzicht"], {"memory": 2048}, origin="https://kwaad.example"); check("vanaf een andere website geweigerd", r[0] == 403 and W.changes == [])
r = call("PUT", "/api/guest/n2/lxc/101/config", TOK["overzicht"], {"memory": 2048}); check("guest staat niet op die node: geweigerd", r[0] == 404 and W.changes == [], detail(r))
W.fail = ResourceException(500, "Internal Server Error", "detected modified configuration - file changed by other user? digest mismatch")
r = call("PUT", "/api/guest/n1/lxc/101/config", TOK["overzicht"], {"memory": 2048, "digest": "oud"}); check("intussen door een ander gewijzigd: duidelijke melding", r[0] == 409 and "intussen" in detail(r), detail(r))
W.fail = None

# ================================================================== E. het netwerk van een guest
print("\n--- E. netwerk van een guest (regels en nagebootst cluster)")
N, NETS = main.NicIn, {"vmbr0": "bridge", "vmbr1": "bridge", "gasten": "vnet"}
LXC = "name=eth0,bridge=vmbr0,firewall=1,gw=192.168.1.1,hwaddr=BC:24:11:0F:FF:56,ip=192.168.1.10/24,type=veth"
QM = "virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,firewall=1,tag=10"
check("container naar een VLAN-nummer: alleen dat komt erbij, de rest blijft letterlijk staan",
      main.nic_plan(LXC, N(bridge="vmbr0", tag=20), NETS) == "name=eth0,bridge=vmbr0,tag=20,firewall=1,gw=192.168.1.1,hwaddr=BC:24:11:0F:FF:56,ip=192.168.1.10/24,type=veth")
check("container naar een VLAN-netwerk", main.nic_plan(LXC, N(bridge="gasten"), NETS) == LXC.replace("bridge=vmbr0", "bridge=gasten"))
check("VM: ander VLAN-nummer", main.nic_plan(QM, N(bridge="vmbr0", tag=30), NETS) == "virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,tag=30,firewall=1")
check("VM: VLAN-nummer eraf", main.nic_plan(QM, N(bridge="vmbr0"), NETS) == "virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,firewall=1")
check("VM: andere bridge, zelfde VLAN-nummer", main.nic_plan(QM, N(bridge="vmbr1", tag=10), NETS) == "virtio=BC:24:11:AA:BB:CC,bridge=vmbr1,tag=10,firewall=1")
check("kaart zonder netwerk krijgt er een", main.nic_plan("name=eth1,type=veth", N(bridge="vmbr1"), NETS) == "name=eth1,type=veth,bridge=vmbr1")
for label, value, body, code in [("onbekend netwerk", LXC, N(bridge="vmbr9"), 400), ("netwerk met vreemde tekens", LXC, N(bridge="vmbr0,x=1"), 400),
                                 ("VLAN-nummer 0", LXC, N(bridge="vmbr0", tag=0), 400), ("VLAN-nummer 4095", LXC, N(bridge="vmbr0", tag=4095), 400),
                                 ("VLAN-nummer op een VLAN-netwerk", LXC, N(bridge="gasten", tag=20), 400), ("niets gewijzigd", QM, N(bridge="vmbr0", tag=10), 400),
                                 ("niets gewijzigd (zonder nummer)", LXC, N(bridge="vmbr0"), 400)]:
    e = refused(main.nic_plan, value, body, NETS)
    check(f"geweigerd: {label}", e is not None and e.status_code == code, getattr(e, "detail", "NIET GEWEIGERD"))
W.changes.clear()
W.table["nodes/n1/lxc/101/config"] = {"hostname": "web", "net0": LXC, "digest": "abc"}
r = call("PUT", "/api/network/guest/n1/lxc/101/net0", TOK["netwerk"], {"bridge": "gasten", "tag": None, "digest": "abc"})
check("opslaan: één opdracht voor precies die kaart", r == (200, {"ok": True, "nic": "net0", "bridge": "gasten", "tag": None, "running": True})
      and W.changes == [("PUT", "nodes/n1/lxc/101/config", {"net0": LXC.replace("bridge=vmbr0", "bridge=gasten"), "digest": "abc"})], str(W.changes))
W.changes.clear()
for label, path, body, user, code in [("kaart die niet bestaat", "/api/network/guest/n1/lxc/101/net7", {"bridge": "vmbr0", "tag": 5}, "netwerk", 404),
                                      ("ongeldige kaartnaam", "/api/network/guest/n1/lxc/101/eth0", {"bridge": "vmbr0", "tag": 5}, "netwerk", 400),
                                      ("netwerk dat niet bestaat", "/api/network/guest/n1/lxc/101/net0", {"bridge": "vmbr7"}, "netwerk", 400),
                                      ("de eigen container van de tool", "/api/network/guest/n1/lxc/109/net0", {"bridge": "gasten"}, "netwerk", 409),
                                      ("overzichtbeheerder (niet zijn tabblad)", "/api/network/guest/n1/lxc/101/net0", {"bridge": "gasten"}, "overzicht", 403),
                                      ("alleen lezen", "/api/network/guest/n1/lxc/101/net0", {"bridge": "gasten"}, "lezer", 403)]:
    r = call("PUT", path, TOK[user], body)
    check(f"geweigerd: {label}", r[0] == code and W.changes == [], f"{r[0]} {detail(r)}")
W.table["nodes/n1/lxc/101/config"] = {"hostname": "web", "net0": LXC, "lock": "migrate"}
r = call("PUT", "/api/network/guest/n1/lxc/101/net0", TOK["netwerk"], {"bridge": "gasten"}); check("geweigerd: vergrendelde guest", r[0] == 409 and W.changes == [], detail(r))
check("STRUIKELDRAAD: in D en E is de echte verbinding niet gebruikt", not TRIPPED, str(TRIPPED))

# ================================================================== F. mail voor meer soorten mailservers
print("\n--- F. mail (nagebootste mailserver)")
BASE = {"to": "nieuw@voorbeeld.nl", "sender": "oud@voorbeeld.nl", "host": "smtp.voorbeeld.nl", "port": 587, "security": "starttls", "auth": True}
s = call("GET", "/api/report/status", TOK["lezer"])[1]
check("uitgangspunt: instellingen uit de installatie, in de nieuwe vorm", s["source"] == "env" and s["login"] == "oud@voorbeeld.nl" and s["security"] == "starttls" and s["auth"] is True and s["verify"] is True and s["password_set"] is True and "password" not in s)
check("alleen wie Events beheert mag de mail instellen", call("PUT", "/api/report/mail", TOK["opslag"], BASE)[0] == 403 and call("PUT", "/api/report/mail", TOK["lezer"], BASE)[0] == 403 and MAILLOG == [])
for label, body in [("onbekende beveiliging", {**BASE, "security": "tls13"}), ("poort 0", {**BASE, "port": 0}), ("poort 70000", {**BASE, "port": 70000}),
                    ("wachtwoord over een onversleutelde verbinding", {**BASE, "security": "none"}), ("afzender is geen adres", {**BASE, "sender": "geen adres"}),
                    ("naam met aanhalingsteken", {**BASE, "name": 'Mijn "tool"'}), ("naam met regeleinde", {**BASE, "name": "a\r\nBcc: x@y.nl"}),
                    ("inlognaam met spatie", {**BASE, "login": "mijn naam"}), ("andere inlognaam zonder wachtwoord", {**BASE, "login": "apikey"}),
                    ("ANDERE MAILSERVER zonder wachtwoord (het bewaarde wachtwoord mag daar niet heen)", {**BASE, "host": "smtp.kwaad.example"})]:
    r = call("PUT", "/api/report/mail", TOK["events"], body)
    check(f"geweigerd: {label}", r[0] == 400, detail(r))
check("bij al die weigeringen is geen mailserver benaderd en niets bewaard", MAILLOG == [] and not main.MAIL_FILE.exists())
r = call("PUT", "/api/report/mail", TOK["events"], {**BASE, "name": "Proxmox thuis"})
check("events-beheerder wijzigt de ontvanger en de naam; het bestaande wachtwoord blijft", r[0] == 200 and r[1]["to"] == "nieuw@voorbeeld.nl" and r[1]["name"] == "Proxmox thuis" and MAILLOG[-1]["login"] == ("oud@voorbeeld.nl", OLD_PW) and MAILLOG[-1]["starttls"] and MAILLOG[-1]["verify"] is True)
check("bestand alleen leesbaar voor de tool", stat.S_IMODE(main.MAIL_FILE.stat().st_mode) == 0o600)
MAILLOG.clear()
r = call("PUT", "/api/report/mail", TOK["events"], {"to": "a@voorbeeld.nl", "sender": "meldingen@voorbeeld.nl", "host": "smtp.sendgrid.net", "port": 465, "security": "ssl", "auth": True, "login": "apikey", "password": "SG.geheim-token"})
check("dienst waar de inlognaam geen adres is, direct versleuteld op 465", r[0] == 200 and r[1]["login"] == "apikey" and r[1]["from"] == "meldingen@voorbeeld.nl" and MAILLOG[-1]["kind"] == "SMTP_SSL" and MAILLOG[-1]["login"] == ("apikey", "SG.geheim-token") and not MAILLOG[-1]["starttls"])
MAILLOG.clear()
r = call("PUT", "/api/report/mail", TOK["events"], {"to": "a@voorbeeld.nl", "sender": "nas@voorbeeld.nl", "host": "192.168.1.10", "port": 25, "security": "none", "auth": False})
check("eigen doorstuurserver op een IP-adres, zonder inlog en zonder versleuteling: alleen een teken van leven gevraagd", r[0] == 200 and r[1]["auth"] is False and r[1]["password_set"] is False and r[1]["ready"] is True
      and MAILLOG[-1]["login"] is None and MAILLOG[-1]["noop"] and not MAILLOG[-1]["starttls"] and json.loads(main.MAIL_FILE.read_text())["password"] == "")
MAILLOG.clear()
r = call("PUT", "/api/report/mail", TOK["events"], {"to": "a@voorbeeld.nl", "sender": "nas@voorbeeld.nl", "host": "mail.thuis.lan", "port": 587, "security": "starttls", "auth": True, "login": "nas", "password": "abcd efgh ijkl mnop", "verify": False})
check("eigen server met zelfgemaakt certificaat: versleuteld maar zonder controle, alleen omdat het zo is ingesteld", r[0] == 200 and r[1]["verify"] is False and MAILLOG[-1]["verify"] is False and MAILLOG[-1]["login"] == ("nas", "abcdefghijklmnop"))
MAILMODE[0] = "auth"; before = main.MAIL_FILE.read_text()
r = call("PUT", "/api/report/mail", TOK["events"], {**BASE, "password": "verkeerd-wachtwoord"}); check("inlog geweigerd door de server: melding, niets bewaard", r[0] == 502 and main.MAIL_FILE.read_text() == before, detail(r))
MAILMODE[0] = "down"
r = call("PUT", "/api/report/mail", TOK["events"], {**BASE, "password": "goed-wachtwoord"}); check("server onbereikbaar: melding, niets bewaard", r[0] == 502 and "niets bewaard" in detail(r) and main.MAIL_FILE.read_text() == before)
MAILMODE[0] = "ok"
call("PUT", "/api/report/mail", TOK["events"], {"to": "a@voorbeeld.nl, b@voorbeeld.nl", "sender": "iemand@gmail.com", "name": "Proxmox thuis", "host": "smtp.gmail.com", "port": 587, "security": "starttls", "auth": True, "password": "abcd efgh ijkl mnop"})
MAILLOG.clear()
r = call("POST", "/api/report/mail/test", TOK["events"])
check("testbericht: naar de ingestelde adressen, met de naam van de afzender", r == (200, {"to": "a@voorbeeld.nl, b@voorbeeld.nl"}) and MAILLOG[-1]["sent"] == [{"to": "a@voorbeeld.nl, b@voorbeeld.nl", "from": "Proxmox thuis <iemand@gmail.com>", "subject": "Proxmox Maintool: testbericht"}], str(MAILLOG[-1]["sent"]))
check("een testbericht mag alleen wie Events beheert", call("POST", "/api/report/mail/test", TOK["backup"])[0] == 403 and call("POST", "/api/report/mail/test", TOK["events"], origin="https://kwaad.example")[0] == 403)
main.MAIL_FILE.write_text(json.dumps({"host": "smtp.gmail.com", "port": 465, "user": "oud@gmail.com", "password": "abcdefghijklmnop", "to": "x@voorbeeld.nl"}))
c = main.mail_config()
check("een bestand in de vorm van versie 1.5 blijft werken", c["source"] == "tool" and c["sender"] == c["login"] == "oud@gmail.com" and c["security"] == "ssl" and c["auth"] and c["verify"] and main.mail_ready())
main.MAIL_FILE.write_text(json.dumps({"host": "x", "port": 587, "security": "starttls", "auth": True, "login": "a", "password": "", "sender": "a@b.nl", "to": "a@b.nl"}))
check("een bestand dat niet klopt wordt genegeerd", main.mail_config()["source"] == "env")
r = call("DELETE", "/api/report/mail", TOK["events"]); check("wissen: terug naar de installatie", r[0] == 200 and r[1]["source"] == "env" and not main.MAIL_FILE.exists())
everything = "\n".join(SEEN)
check("in geen enkel antwoord van de tool staat een wachtwoord", not any(x in everything for x in (OLD_PW, "abcdefghijklmnop", "abcd efgh", "SG.geheim-token", "verkeerd-wachtwoord", "goed-wachtwoord", PW, OLD)))

# ================================================================== G. alleen lezen van het echte cluster
print("\n--- G. het echte cluster, alleen lezen")
real_again()
main.updates.info = REAL_UPDATES
main.issues.at = 0.0
t0 = time.time()
real = main.pve.run(main.gather_issues)
print(f"     aandachtspunten nu ({time.time() - t0:.1f} s):", json.dumps(real)[:900])
check("de triggers lopen het echte cluster na zonder fouten", isinstance(real, list) and all(i["tab"] in main.AREAS and i["level"] in main.LEVELS for i in real))
r = call("GET", "/api/overview", TOK["lezer"])
check("het overzicht geeft dezelfde punten mee (voor de kleur van de tabbladen)", r[0] == 200 and sorted(json.dumps(i, sort_keys=True) for i in r[1]["issues"]) == sorted(json.dumps(i, sort_keys=True) for i in real))
t0 = time.time(); r2 = call("GET", "/api/overview", TOK["lezer"])
check("een tweede keer komt het uit het geheugen", r2[0] == 200 and time.time() - t0 < 3, f"{time.time() - t0:.2f} s")
main.state.change(lambda d: d.update(alerts={"storage_full": {"warning": 1, "error": None}, "node_mem": {"warning": 1, "error": 2}}))
low = main.pve.run(main.gather_issues)
check("met een drempel van 1% kleurt elke echte opslag oranje en elke node rood", sum(1 for i in low if i["code"] == "storage_full" and i["level"] == "warning") >= 3 and sum(1 for i in low if i["code"] == "node_mem" and i["level"] == "error") == 3,
      str(sorted({(i["code"], i["level"]) for i in low})))
main.state.change(lambda d: d.pop("alerts", None))

day = now - (now % 86400)
r = call("GET", f"/api/events?since={day - 86400}&until={day}", TOK["lezer"])
check("gebeurtenissen van één gekozen dag: alles valt binnen die dag", r[0] == 200 and r[1]["days"] is None and all(day - 86400 <= e["time"] <= day for e in r[1]["events"]), f"{len(r[1]['events'])} regels")
wide = call("GET", f"/api/events?since={now - 3 * 86400}&until={now}", TOK["lezer"])[1]
three = call("GET", "/api/events?days=7", TOK["lezer"])[1]
check("een eigen periode van 3 dagen geeft niet meer dan de laatste 7 dagen, en dezelfde opbouw", len(wide["events"]) <= len(three["events"]) and set(wide) == set(three) and "now" in wide)
for bad in (f"since={now}&until={now - 5}", f"since={now - 500 * 86400}&until={now}", "since=0", f"since={now - 10}&until={now + 10 * 86400}", "since=abc"):
    r = call("GET", "/api/events?" + bad, TOK["lezer"]); check(f"ongeldige periode geweigerd ({bad[:28]}…)", r[0] in (400, 422), f"{r[0]}")
check("de vaste periodes werken nog", call("GET", "/api/events?days=1", TOK["lezer"])[1]["days"] == 1 and call("GET", "/api/events?days=99", TOK["lezer"])[1]["days"] == 7)

guests = call("GET", "/api/overview", ROOT)[1]["guests"]
ct = next(g for g in guests if g["type"] == "lxc" and g["name"] != main.socket.gethostname())
own = next((g for g in guests if g["type"] == "lxc" and g["name"] == main.socket.gethostname()), None)
r = call("GET", f"/api/guest/{ct['node']}/lxc/{ct['vmid']}/config", TOK["overzicht"])
check(f"echte container {ct['vmid']}: instellingen gelezen", r[0] == 200 and r[1]["memory"] >= 64 and r[1]["limits"]["cores"] >= 1 and r[1]["digest"], json.dumps({k: r[1][k] for k in ("cores", "memory", "swap", "onboot", "limits", "own", "status")}))
before = main.pve.run(lambda api: api.nodes(ct["node"]).lxc(ct["vmid"]).config.get()["digest"])
for label, path, body, code in [("niets gewijzigd", f"/api/guest/{ct['node']}/lxc/{ct['vmid']}/config", {}, 400), ("9999 cores", f"/api/guest/{ct['node']}/lxc/{ct['vmid']}/config", {"cores": 9999}, 400)]:
    r = call("PUT", path, TOK["overzicht"], body); check(f"echt cluster: bewerken strandt vóór er iets verstuurd wordt ({label})", r[0] == code, detail(r))
r = call("PUT", f"/api/network/guest/{ct['node']}/lxc/{ct['vmid']}/net0", TOK["netwerk"], {"bridge": "bestaatniet0"}); check("echt cluster: netwerk dat niet bestaat strandt vóór er iets verstuurd wordt", r[0] == 400, detail(r))
if own:
    r = call("PUT", f"/api/network/guest/{own['node']}/lxc/{own['vmid']}/net0", TOK["netwerk"], {"bridge": "bestaatniet0"}); check("echt cluster: de tool weigert het netwerk van zijn eigen container", r[0] == 409, detail(r))
    r = call("GET", f"/api/guest/{own['node']}/lxc/{own['vmid']}/config", TOK["overzicht"]); check("echt cluster: de tool herkent zijn eigen container", r[1]["own"] is True and r[1]["min_memory"] == 512)
check("daarna is de echte container ongewijzigd", main.pve.run(lambda api: api.nodes(ct["node"]).lxc(ct["vmid"]).config.get()["digest"]) == before)

r = call("GET", "/api/dashboard", TOK["lezer"], full=True)
hist = r[1]["history"]
check("dashboard: het laatste uur van elke node", r[0] == 200 and len(hist) == 3 and all(h and len(h["t"]) >= 30 and len({len(v) for v in h.values()}) == 1 and all(0 <= x <= 1 for x in h["cpu"] + h["mem"]) for h in hist.values()),
      str({n: len(h["t"]) for n, h in hist.items()}))
check("een verse sessie wordt niet vernieuwd", r[2] == "")
short = main.base64.urlsafe_b64encode(json.dumps({"u": "lezer", "e": now + 600, "g": main.account("lezer")["gen"]}).encode()).decode().rstrip("=")
r = call("GET", "/api/dashboard", short + "." + main.sign(short), full=True)
fresh = r[2].split(f"{main.SESSION_COOKIE}=", 1)[1].split(";", 1)[0] if main.SESSION_COOKIE in r[2] else ""
check("een sessie die bijna afloopt wordt door het dashboard verlengd (voor een scherm aan de muur)", r[0] == 200 and main.read_token(fresh) == "lezer" and main.token_expiry(fresh) > now + 3600 and "HttpOnly" in r[2] and "Secure" in r[2])
gone = main.base64.urlsafe_b64encode(json.dumps({"u": "lezer", "e": now - 5, "g": main.account("lezer")["gen"]}).encode()).decode().rstrip("=")
check("een verlopen sessie wordt niet meer verlengd", call("GET", "/api/dashboard", gone + "." + main.sign(gone))[0] == 401)

print("\n" + ("ALLES GOED" if not FAILED else f"{len(FAILED)} FOUT: " + "; ".join(FAILED)))
