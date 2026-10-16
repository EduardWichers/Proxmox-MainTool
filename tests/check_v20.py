"""Tests version 1.0 (the renumbered successor of 1.9) of the backend in-process on the tool container, from a copy in
/tmp with its own state folder: HA status, putting guests in HA, changing their HA settings and removing them again.
Everything runs against a stand-in cluster that only writes down what it is asked to do; nothing on the real cluster or
the nodes is changed. No secrets are used or shown."""
import asyncio, base64, datetime as dt, hashlib, hmac, json, os, secrets, subprocess, sys, tempfile, time, urllib.parse
for line in open("/etc/maintool/maintool.env", encoding="utf-8"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ[k.strip()] = v.strip()
os.environ["STATE_DIRECTORY"] = "/tmp/mt-v20/state"
sys.path.insert(0, "/tmp/mt-v20/app")
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
ME = main.socket.gethostname()   # de container van de tool heet in Proxmox net als zijn hostnaam

VMS = [{"vmid": 201, "node": "n1", "type": "lxc", "name": "web", "status": "running", "hastate": "started"},
       {"vmid": 202, "node": "n2", "type": "lxc", "name": "db", "status": "stopped"},
       {"vmid": 209, "node": "n1", "type": "lxc", "name": ME, "status": "running"},
       {"vmid": 300, "node": "n1", "type": "qemu", "name": "vm", "status": "running"},
       {"vmid": 301, "node": "n2", "type": "qemu", "name": "sjabloon", "status": "stopped", "template": 1}]
STORES = [{"storage": "ceph", "node": "n1", "shared": 1}, {"storage": "ceph", "node": "n2", "shared": 1},
          {"storage": "nas", "node": "n1", "shared": 1}, {"storage": "lokaal", "node": "n1", "shared": 0}, {"storage": "local", "node": "n1", "shared": 0}]
HARES = [{"sid": "ct:201", "type": "ct", "state": "started", "digest": "a" * 40},
         {"sid": "ct:999", "type": "ct", "state": "stopped", "max_restart": 3, "comment": "oud", "digest": "a" * 40}]
STATUS = [{"id": "quorum", "type": "quorum", "node": "n1", "status": "OK", "quorate": 1},
          {"id": "master", "type": "master", "node": "n2", "status": "n2 (active, Wed Oct 14 11:27:14 2026)", "timestamp": 1791970034},
          {"id": "fencing", "type": "fencing", "node": "n2", "status": "armed (CRM watchdog active)", "armed-state": "armed"},
          {"id": "lrm:n1", "type": "lrm", "node": "n1", "status": "n1 (active, watchdog active, Wed Oct 14 11:27:18 2026)", "timestamp": 1},
          {"id": "lrm:n2", "type": "lrm", "node": "n2", "status": "n2 (maintenance mode, Wed Oct 14 11:27:16 2026)", "timestamp": 1},
          {"id": "service:ct:201", "type": "service", "sid": "ct:201", "node": "n1", "state": "started", "crm_state": "started", "max_restart": 1, "max_relocate": 1},
          {"id": "service:ct:999", "type": "service", "sid": "ct:999", "node": "n2", "state": "error", "crm_state": "error", "max_restart": 3, "max_relocate": 1}]


def raise_groups(kw):
    raise ResourceException(500, "Internal Server Error", "cannot index groups: ha groups have been migrated to rules")


W.table.update({
    "cluster/resources": lambda kw: STORES if kw.get("type") == "storage" else VMS,
    "cluster/ha/resources": lambda kw: [dict(r) for r in HARES],
    "cluster/ha/status/current": STATUS,
    "cluster/ha/rules": [{"rule": "web-bij-n1", "type": "node-affinity", "resources": "ct:201,vm:300", "nodes": "n1:2,n2", "strict": 0, "digest": "x"}],
    "cluster/ha/groups": raise_groups,
    "cluster/options": {"ha": "shutdown_policy=migrate", "keyboard": "en-us"},
    "cluster/log": [],
    "nodes/n1/lxc/201/config": {"rootfs": "ceph:vm-201-disk-0,size=8G", "mp0": "lokaal:subvol-201-disk-1,mp=/data,size=4G", "net0": "name=eth0,bridge=vmbr0"},
    "nodes/n2/lxc/202/config": {"rootfs": "ceph:vm-202-disk-0,size=8G", "mp0": "/mnt/gedeeld,mp=/gedeeld,shared=1", "unused0": "lokaal:oud"},
    "nodes/n1/lxc/209/config": {"rootfs": "ceph:vm-209-disk-0,size=8G", "mp1": "/mnt/host,mp=/host"},
    "nodes/n1/qemu/300/config": {"scsi0": "ceph:vm-300-disk-0,size=32G", "ide2": "local:iso/debian.iso,media=cdrom", "efidisk0": "ceph:vm-300-disk-1,size=4M",
                                 "sata1": "none,media=cdrom", "unused0": "lokaal:vm-300-disk-9", "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0"},
})
_orig_call = W.call


def ha_world(method, path, kw):
    if method != "GET" and path.startswith("cluster/ha/resources"):
        W.changes.append((method, path, kw))
        if W.fail:
            raise W.fail
        sid = path.rpartition("/")[2] if path != "cluster/ha/resources" else kw["sid"]
        if method == "POST":
            HARES.append({"sid": sid, "type": sid[:2], **{k: v for k, v in kw.items() if k != "sid"}, "digest": "b" * 40})
        elif method == "PUT":
            r = next(x for x in HARES if x["sid"] == sid)
            r.update({k: v for k, v in kw.items() if k not in ("delete", "digest")})
            if kw.get("delete") == "comment":
                r.pop("comment", None)
        elif method == "DELETE":
            HARES[:] = [x for x in HARES if x["sid"] != sid]
        return None
    return _orig_call(method, path, kw)


W.call = ha_world
main.login_guard.failures.clear()
ROOT = session_of(call("POST", "/api/login", body={"username": main.APP_USER, "password": main.APP_PASSWORD})[2])
PW = secrets.token_urlsafe(18)
for name, roles in (("over", ["overview"]), ("lezer", []), ("opslag", ["storage"])):
    call("POST", "/api/users", ROOT, {"name": name, "roles": roles, "password": PW})
OVER = session_of(call("POST", "/api/login", body={"username": "over", "password": PW})[2])
READER = session_of(call("POST", "/api/login", body={"username": "lezer", "password": PW})[2])
STOR = session_of(call("POST", "/api/login", body={"username": "opslag", "password": PW})[2])
check("inloggen van de testgebruikers", all([ROOT, OVER, READER, STOR]))

print("--- A. de toestand van HA bekijken")
r = call("GET", "/api/ha", READER)
h = r[1] if r[0] == 200 else {}
check("iedereen die is ingelogd ziet HA", r[0] == 200, detail(r) if r[0] != 200 else "")
check("zonder sessie niet", call("GET", "/api/ha")[0] == 401)
check("meerderheid en manager", h.get("quorum") == {"ok": True, "node": "n1"} and h.get("master", {}).get("node") == "n2" and h["master"]["state"] == "active", json.dumps(h.get("master")))
check("fencing en wat er bij uitzetten gebeurt", h.get("fencing") == "armed" and h.get("shutdown_policy") == "migrate")
check("per node de toestand, uit de statustekst gehaald", [(n["node"], n["state"], n["watchdog"]) for n in h.get("nodes", [])] == [("n1", "active", True), ("n2", "maintenance mode", False)],
      json.dumps(h.get("nodes")))
res = {x["sid"]: x for x in h.get("resources", [])}
w = res.get("ct:201", {})
check("guest in HA: naam, node, toestand, gewenst en de standaard 1/1", (w.get("name"), w.get("node"), w.get("status"), w.get("state"), w.get("crm_state"), w.get("max_restart"), w.get("max_relocate"))
      == ("web", "n1", "running", "started", "started", 1, 1), json.dumps(w))
check("de regel die hem noemt staat erbij", w.get("rules") == ["web-bij-n1"])
check("een schijf op lokale opslag wordt gemeld, de schijf op Ceph en de netwerkkaart niet", w.get("local") == [{"key": "mp0", "storage": "lokaal"}], json.dumps(w.get("local")))
o = res.get("ct:999", {})
check("een HA-regel van een guest die niet meer bestaat: zichtbaar, met de fout", o.get("exists") is False and o.get("crm_state") == "error" and o.get("max_restart") == 3
      and o.get("comment") == "oud" and o.get("local") is None, json.dumps(o))
check("wat er nog bij kan: geen guest in HA, geen sjabloon", [g["vmid"] for g in h.get("free", [])] == [202, 209, 300], json.dumps(h.get("free")))
check("Proxmox 9: geen groepen (fout van Proxmox opgevangen), wel regels", h.get("groups") is None and [x["rule"] for x in h.get("rules", [])] == ["web-bij-n1"]
      and h["rules"][0]["resources"] == ["ct:201", "vm:300"] and h["rules"][0]["nodes"] == ["n1:2", "n2"])
check("de eigen container is bekend, en de toegestane toestanden", h.get("self_vmid") == 209 and h.get("states") == ["started", "stopped", "disabled", "ignored"] and h.get("max") == 10)
check("bekijken heeft niets veranderd", not W.changes, str(W.changes))

print("--- B. lokale schijven")
r = call("GET", "/api/ha/check/n1/qemu/300", READER)
check("VM: cd-rom met een ISO op lokale opslag telt, een lege cd-rom, EFI op Ceph en een losse schijf niet", r[0] == 200 and r[1]["local"] == [{"key": "ide2", "storage": "local"}], json.dumps(r[1]))
r = call("GET", "/api/ha/check/n2/lxc/202", READER)
check("CT: een gedeelde map (shared=1) telt niet", r[1].get("local") == [], json.dumps(r[1]))
r = call("GET", "/api/ha/check/n1/lxc/209", READER)
check("CT: een map van de node zelf telt wel", r[1].get("local") == [{"key": "mp1", "storage": "/mnt/host"}], json.dumps(r[1]))
r = call("GET", "/api/ha/check/n9/lxc/202", READER)
check("niet te lezen (verkeerde node): geen oordeel in plaats van een fout", r[0] == 200 and r[1] == {"local": None}, json.dumps(r[1]))
check("ongeldig adres geweigerd", call("GET", "/api/ha/check/n_1/lxc/202", READER)[0] == 400 and call("GET", "/api/ha/check/n1/kvm/202", READER)[0] == 400)
check("een echte cd-speler en een doorgegeven schijf tellen ook", main.local_disks("qemu", {"ide0": "cdrom,media=cdrom", "scsi2": "/dev/disk/by-id/ata-x,size=1T"}, set())
      == [{"key": "ide0", "storage": "cdrom"}, {"key": "scsi2", "storage": "/dev/disk/by-id/ata-x"}])

print("--- C. wie mag wijzigen")
ADD = {"sid": "ct:202", "state": "stopped", "max_restart": 2, "max_relocate": 3, "comment": "  database  "}
for who, label in ((READER, "alleen lezen"), (STOR, "rol Opslag")):
    r = call("POST", "/api/ha", who, ADD)
    check(f"{label}: toevoegen geweigerd", r[0] == 403, detail(r))
    check(f"{label}: aanpassen en eruit halen geweigerd", call("PUT", "/api/ha/ct:201", who, {"state": "stopped"})[0] == 403 and call("DELETE", "/api/ha/ct:201", who)[0] == 403)
check("zonder sessie geweigerd", call("POST", "/api/ha", None, ADD)[0] == 401 and call("DELETE", "/api/ha/ct:201")[0] == 401)
r = call("POST", "/api/ha", OVER, ADD, origin="https://kwaad.example")
check("vanaf een andere website geweigerd, ook met de juiste rol", r[0] == 403 and detail(r) == "Dit verzoek komt niet van de pagina van de tool")
check("ook zonder Origin", call("POST", "/api/ha", OVER, ADD, origin=None)[0] == 403 and call("DELETE", "/api/ha/ct:201", OVER, origin=None)[0] == 403)
r = call("POST", "/api/ha", OVER, ADD, headers={"Cf-Ray": "8abc-AMS"}, cookies={main.VIEW_COOKIE: "1"})
check("via Cloudflare in alleen bekijken: geweigerd", r[0] == 403, detail(r))
check("er is niets naar Proxmox gestuurd", not W.changes, str(W.changes))

print("--- D. controles op wat er wordt opgegeven")
bad = [({"sid": "lxc:202"}, 400), ({"sid": "ct:02"}, 400), ({"sid": "ct:202", "state": "running"}, 400), ({"sid": "ct:202", "max_restart": 11}, 400),
       ({"sid": "ct:202", "max_relocate": -1}, 400), ({"sid": "ct:202", "max_restart": True}, 422), ({"sid": "ct:202", "max_restart": "2"}, 422),
       ({"sid": "ct:202", "comment": "twee\nregels"}, 400), ({"sid": "ct:202", "comment": "x" * 201}, 422), ({"sid": "x" * 21}, 422)]
wrong = [(b, call("POST", "/api/ha", OVER, b)[0]) for b, code in bad if call("POST", "/api/ha", OVER, b)[0] != code]
check(f"{len(bad)} ongeldige verzoeken geweigerd met de juiste code", not wrong, str(wrong))
for sid, code, text in (("vm:301", 409, "Een sjabloon kan niet in HA"), ("ct:300", 404, "Deze guest bestaat niet (meer)"), ("vm:777", 404, "Deze guest bestaat niet (meer)"),
                        ("ct:201", 409, "Deze guest staat al in HA")):
    r = call("POST", "/api/ha", OVER, {"sid": sid})
    check(f"{sid}: {text}", r[0] == code and detail(r) == text, f"{r[0]} {detail(r)}")
for st in ("stopped", "disabled"):
    r = call("POST", "/api/ha", OVER, {"sid": "ct:209", "state": st})
    check(f"de tool zelf met {st}: geweigerd", r[0] == 409 and "container van de tool zelf" in detail(r), detail(r))
check("na al die weigeringen is er niets naar Proxmox gestuurd", not W.changes, str(W.changes))
r = call("POST", "/api/ha", OVER, {"sid": "vm:777"}, cookies={main.LANG_COOKIE: "en"})
check("de melding in de taal van de gebruiker", detail(r) == "This guest does not exist (any more)", detail(r))

print("--- E. toevoegen")
before = len(main.state.events(0))
r = call("POST", "/api/ha", OVER, ADD)
check("toevoegen met de rol Overzicht", r[0] == 200 and r[1] == {"ok": True, "sid": "ct:202", "local": []}, json.dumps(r[1]))
check("precies dit naar Proxmox: naam, toestand, aantallen, opmerking zonder spaties eromheen",
      W.changes == [("POST", "cluster/ha/resources", {"sid": "ct:202", "state": "stopped", "max_restart": 2, "max_relocate": 3, "comment": "database"})], str(W.changes))
ev = main.state.events(0)[before:]
check("in het logboek: wie, wat en welke guest", [(e["kind"], e["result"], e["target"], e["node"], e["name"], e["user"]) for e in ev] == [("ha", "in HA gezet", "202", "n2", "db", "over")], json.dumps(ev))
W.changes.clear()
r = call("POST", "/api/ha", ROOT, {"sid": "vm:300"})
check("standaard: aan, 1 keer herstarten en 1 keer verhuizen, geen lege opmerking; antwoord meldt de lokale schijf",
      W.changes == [("POST", "cluster/ha/resources", {"sid": "vm:300", "state": "started", "max_restart": 1, "max_relocate": 1})] and r[1].get("local") == [{"key": "ide2", "storage": "local"}],
      str(W.changes) + json.dumps(r[1]))
W.changes.clear()
r = call("POST", "/api/ha", OVER, {"sid": "ct:209", "state": "ignored"})
check("de tool zelf met ignored mag wel", r[0] == 200 and W.changes[-1][2]["state"] == "ignored", detail(r) or "")
W.changes.clear()
r = call("GET", "/api/ha", READER)
check("daarna staan ze in HA en niet meer bij wat erbij kan", {x["sid"] for x in r[1]["resources"]} >= {"ct:202", "vm:300", "ct:209"} and r[1]["free"] == [], json.dumps(r[1]["free"]))

print("--- F. aanpassen")
r = call("PUT", "/api/ha/ct:201", OVER, {"state": "disabled", "max_restart": 0, "comment": "onderhoud", "digest": "a" * 40})
check("aanpassen: alleen wat is opgegeven, met de digest", r[0] == 200 and W.changes == [("PUT", "cluster/ha/resources/ct:201",
      {"state": "disabled", "max_restart": 0, "comment": "onderhoud", "digest": "a" * 40})], str(W.changes))
W.changes.clear()
r = call("PUT", "/api/ha/ct:201", OVER, {"comment": ""})
check("een lege opmerking haalt hem weg", r[0] == 200 and W.changes == [("PUT", "cluster/ha/resources/ct:201", {"delete": "comment"})], str(W.changes))
W.changes.clear()
for body, code, label in (({}, 400, "niets opgegeven"), ({"state": "aan"}, 400, "onbekende toestand"), ({"digest": "xyz"}, 422, "rare digest"),
                          ({"max_relocate": 1.5}, 422, "geen geheel getal")):
    r = call("PUT", "/api/ha/ct:201", OVER, body)
    check(f"aanpassen geweigerd: {label}", r[0] == code, f"{r[0]} {detail(r)}")
r = call("PUT", "/api/ha/ct:209", OVER, {"state": "stopped"})
check("de tool zelf uitzetten via aanpassen: geweigerd", r[0] == 409, detail(r))
r = call("PUT", "/api/ha/ct:205", OVER, {"state": "stopped"})
check("aanpassen van een guest die niet bestaat: 404", r[0] == 404, detail(r))
HARES[:] = [x for x in HARES if x["sid"] != "vm:300"]
r = call("PUT", "/api/ha/vm:300", OVER, {"state": "stopped"})
check("aanpassen van een guest die niet (meer) in HA staat: 404", r[0] == 404 and detail(r) == "Deze guest staat niet (meer) in HA", detail(r))
check("niets van dit alles naar Proxmox", not W.changes, str(W.changes))
W.fail = ResourceException(500, "Internal Server Error", "detected modified configuration - file changed by other user? Try again.")
before = len(main.state.events(0))
r = call("PUT", "/api/ha/ct:201", OVER, {"state": "started", "digest": "c" * 40})
check("een weigering van Proxmox komt door, en wordt niet als gelukt gelogd", r[0] == 500 and "modified configuration" in detail(r) and len(main.state.events(0)) == before, detail(r))
W.fail = None
W.changes.clear()

print("--- G. eruit halen")
before = len(main.state.events(0))
r = call("DELETE", "/api/ha/ct:202", OVER)
check("eruit halen", r[0] == 200 and W.changes == [("DELETE", "cluster/ha/resources/ct:202", {})], str(W.changes))
ev = main.state.events(0)[before:]
check("in het logboek", [(e["result"], e["target"], e["name"], e["user"]) for e in ev] == [("uit HA gehaald", "202", "db", "over")], json.dumps(ev))
W.changes.clear()
r = call("DELETE", "/api/ha/ct:999", ROOT)
check("ook een HA-regel van een guest die niet meer bestaat", r[0] == 200 and W.changes == [("DELETE", "cluster/ha/resources/ct:999", {})], detail(r) or "")
ev = main.state.events(0)[-1]
check("in het logboek met het nummer, zonder naam", (ev["target"], ev["name"], ev["node"]) == ("999", "", None), json.dumps(ev))
W.changes.clear()
check("niet in HA: 404", call("DELETE", "/api/ha/ct:202", OVER)[0] == 404)
check("ongeldige naam: 400", call("DELETE", "/api/ha/ct:2x2", OVER)[0] == 400 and call("DELETE", "/api/ha/qemu:300", OVER)[0] == 400)
check("niets naar Proxmox", not W.changes, str(W.changes))

print("--- H. Events en het overzicht per mail")
rows = [x for x in main.event_rows(Fake(W), [], 0) if x["type"] == "ha"]
check("Events: de HA-wijzigingen staan erbij, met wie het deed", len(rows) >= 5 and {x["user"] for x in rows} == {"over", main.APP_USER} and all(x["level"] == "info" for x in rows),
      json.dumps(rows[:2]))
now = time.time()
d = {"nodes": [], "guests": [], "tasks": [], "files": [], "ceph": None, "jobs": [], "stores": [], "updates": {"nodes": {}, "guests": {}}, "snapshots": {},
     "events": [{"t": now - 60, "kind": "ha", "result": "in HA gezet", "node": "n2", "target": "202", "name": "db"},
                {"t": now - 30, "kind": "update", "result": "gelukt", "node": "n1", "target": "201", "name": "web"}]}
try:
    subject, body_html, plain = main.build_report(d, now - 7 * 86400, now)
    check("overzicht per mail: onder Updates de update, niet de HA-wijziging (en die is geen aandachtspunt)",
          "CT 201 web" in plain and "CT 202" not in plain and "in HA gezet" not in body_html, plain[:400])
except Exception as err:  # noqa: BLE001
    check("overzicht per mail opbouwen", False, repr(err))

TRIPPED = [x for x in TRIPPED if not (x[0] == "agent" and tuple(x[1][1:]) == ("info", "cts"))]
check("het echte cluster en de echte nodes zijn niet aangeraakt", not TRIPPED, str(TRIPPED))

print()
print("ALLES GOED" if not FAILED else f"FOUT ({len(FAILED)}): {FAILED}")
