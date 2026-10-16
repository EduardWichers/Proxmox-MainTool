"""Tests version 1.1 of the backend in-process on the tool container, from a copy in /tmp with its own state folder:
the load balancer of Proxmox (Cluster Resource Scheduling), which HA guests take part, and the time window for containers.
Everything runs against a stand-in cluster that only writes down what it is asked to do; nothing real is changed."""
import asyncio, base64, datetime as dt, hashlib, hmac, json, os, secrets, subprocess, sys, tempfile, time, urllib.parse
for line in open("/etc/maintool/maintool.env", encoding="utf-8"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ[k.strip()] = v.strip()
os.environ["STATE_DIRECTORY"] = "/tmp/mt-v210/state"
sys.path.insert(0, "/tmp/mt-v210/app")
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

NOW = int(time.time())
OPTS = {}                     # wat Proxmox in Datacenter > Opties heeft staan
HA_RES = {"ct:101": {"state": "started"}, "ct:102": {"state": "started"}, "ct:103": {"state": "started"},
          "vm:300": {"state": "started"}, "ct:105": {"state": "stopped"}}
VERSION = {"version": "9.2.21"}
FAIL_PUT = set()              # deze HA-guests weigert Proxmox aan te passen
GUESTS = [{"vmid": 101, "name": "web", "node": "n1", "type": "lxc", "status": "running"},
          {"vmid": 102, "name": "db", "node": "n1", "type": "lxc", "status": "running"},
          {"vmid": 103, "name": "lokaal", "node": "n2", "type": "lxc", "status": "running"},
          {"vmid": 300, "name": "win", "node": "n2", "type": "qemu", "status": "running"},
          {"vmid": 104, "name": "los", "node": "n2", "type": "lxc", "status": "running"},
          {"vmid": 105, "name": "uit", "node": "n1", "type": "lxc", "status": "stopped"},
          {"vmid": 900, "name": "sjabloon", "node": "n1", "type": "lxc", "status": "stopped", "template": 1}]
TASKS = {
    "n1": [{"upid": "UPID:n1:1:vzmigrate:101:root@pam:", "type": "vzmigrate", "id": "101", "user": "root@pam", "starttime": NOW - 3600, "endtime": NOW - 3598, "status": "OK"}],
    "n2": [{"upid": "UPID:n2:2:hamigrate:300:tool:", "type": "hamigrate", "id": "300", "user": "maintool@pve!ct109", "starttime": NOW - 7200, "endtime": NOW - 7200, "status": "OK"},
           {"upid": "UPID:n2:3:qmigrate:300:root@pam:", "type": "qmigrate", "id": "300", "user": "root@pam", "starttime": NOW - 7190, "endtime": NOW - 7150, "status": "OK"},
           {"upid": "UPID:n2:4:vzmigrate:104:root@pam:", "type": "vzmigrate", "id": "104", "user": "root@pam", "starttime": NOW - 600, "endtime": NOW - 590, "status": "migration aborted"}],
}
LOGS = {"UPID:n1:1:vzmigrate:101:root@pam:": [{"n": 1, "t": "2026-10-14 10:00:00 starting migration of CT 101 to node 'n2' (10.0.0.2)"}],
        "UPID:n2:3:qmigrate:300:root@pam:": [{"n": 1, "t": "2026-10-14 09:00:00 use dedicated network address for sending migration traffic"},
                                             {"n": 2, "t": "2026-10-14 09:00:01 starting migration of VM 300 to node 'n1' (10.0.0.1)"}],
        "UPID:n2:4:vzmigrate:104:root@pam:": [{"n": 1, "t": "2026-10-14 11:00:00 starting migration of CT 104 to node 'n1' (10.0.0.1)"}]}
CONFIGS = {"nodes/n1/lxc/101/config": {"rootfs": "ceph:vm-101-disk-0,size=8G"}, "nodes/n1/lxc/102/config": {"rootfs": "ceph:vm-102-disk-0,size=8G"},
           "nodes/n2/lxc/103/config": {"rootfs": "local-lvm:vm-103-disk-0,size=8G"}, "nodes/n2/qemu/300/config": {"scsi0": "ceph:vm-300-disk-0,size=32G"},
           "nodes/n1/lxc/105/config": {"rootfs": "ceph:vm-105-disk-0,size=8G"}}


def tasks(node):
    def get(kw):
        rows = [x for x in TASKS.get(node, []) if x["type"] == kw.get("typefilter") and x["starttime"] >= kw.get("since", 0)]
        return [dict(x, node=node) for x in rows]
    return get


def resources(kw):
    if kw.get("type") == "storage":
        return [{"storage": "ceph", "shared": 1, "node": "n1"}, {"storage": "local-lvm", "shared": 0, "node": "n1"}]
    return [dict(g) for g in GUESTS]


_orig = W.call


def world(method, path, kw):
    if method != "GET":
        W.changes.append((method, path, dict(kw)))
        if path.startswith("cluster/ha/resources/") and method == "PUT":
            sid = path.rsplit("/", 1)[1]
            if sid in FAIL_PUT:
                raise ResourceException(500, "Internal Server Error", "kon niet schrijven")
            if "auto-rebalance" in kw:
                HA_RES[sid]["auto-rebalance"] = kw["auto-rebalance"]
            return None
        if path == "cluster/options" and method == "PUT":
            if "crs" in kw and "bad-key" in kw["crs"]:
                raise ResourceException(400, "Parameter verification failed.", "{'crs': 'invalid format'}")
            if kw.get("delete") == "crs":
                OPTS.pop("crs", None)
            elif "crs" in kw:
                OPTS["crs"] = kw["crs"]
            return None
        return None
    if path.startswith("nodes/") and "/tasks/" in path and path.endswith("/log"):
        return LOGS.get(path.split("/tasks/")[1][:-4], [])
    return _orig(method, path, kw)


W.call = world
W.table.update({
    "version": lambda kw: dict(VERSION),
    "nodes": [{"node": "n1", "status": "online", "cpu": 0.25, "maxcpu": 12, "mem": 30 * 2**30, "maxmem": 64 * 2**30},
              {"node": "n2", "status": "online", "cpu": 0.05, "maxcpu": 12, "mem": 10 * 2**30, "maxmem": 64 * 2**30},
              {"node": "n3", "status": "offline"}],
    "cluster/options": lambda kw: dict(OPTS),
    "cluster/resources": resources,
    "cluster/ha/resources": lambda kw: [dict(v, sid=k, type=k[:2] if k[:2] == "vm" else "ct") for k, v in HA_RES.items()],
    "cluster/ha/rules": [{"rule": "samen", "type": "resource-affinity", "resources": "ct:101,ct:102", "affinity": "positive"}],
    "cluster/ha/status/manager_status": {"manager_status": {"imbalance": 12.5, "master_node": "n1"}},
    "nodes/n1/tasks": tasks("n1"), "nodes/n2/tasks": tasks("n2"),
    **CONFIGS,
})
main.login_guard.failures.clear()
ROOT = session_of(call("POST", "/api/login", body={"username": main.APP_USER, "password": main.APP_PASSWORD})[2])
PW = secrets.token_urlsafe(18)
for name, roles in (("over", ["overview"]), ("lezer", []), ("opslag", ["storage"])):
    call("POST", "/api/users", ROOT, {"name": name, "roles": roles, "password": PW})
OVER, READER, STOR = (session_of(call("POST", "/api/login", body={"username": n, "password": PW})[2]) for n in ("over", "lezer", "opslag"))
check("inloggen van de testgebruikers", all([ROOT, OVER, READER, STOR]))


def changes():
    out = list(W.changes)
    W.changes.clear()
    return out


def hhmm(minutes):
    minutes %= 24 * 60
    return f"{minutes // 60:02d}:{minutes % 60:02d}"


print("--- A. losse onderdelen: CRS lezen en schrijven, het tijdvenster")
v, other = main.crs_read("ha=static,ha-rebalance-on-start=1")
check("tekst uitpakken, de rest op de standaard", v["ha"] == "static" and v["ha-rebalance-on-start"] is True and v["ha-auto-rebalance"] is False and v["ha-auto-rebalance-threshold"] == 30 and other == {}, json.dumps(v))
v, other = main.crs_read({"ha": "dynamic", "ha-auto-rebalance": 1, "ha-auto-rebalance-threshold": "22.5", "ha-auto-rebalance-method": "topsis", "toekomst": "ja"})
check("al uitgepakt (zoals de API het kan geven), komma-getal, onbekende sleutel bewaard", v["ha"] == "dynamic" and v["ha-auto-rebalance"] is True and v["ha-auto-rebalance-threshold"] == 22.5
      and v["ha-auto-rebalance-method"] == "topsis" and other == {"toekomst": "ja"}, json.dumps([v, other]))
v, other = main.crs_read("ha=raar,ha-auto-rebalance-threshold=500,ha-auto-rebalance-method=gok,x=a b")
check("ongeldige waarden vallen terug op de standaard; een rare sleutel/waarde gaat niet mee", v["ha"] == "basic" and v["ha-auto-rebalance-threshold"] == 30 and v["ha-auto-rebalance-method"] == "bruteforce" and other == {}, json.dumps([v, other]))
check("alles standaard = geen instelling", main.crs_text(dict(main.CRS_DEFAULT)) is None and main.crs_read(None)[0] == main.CRS_DEFAULT)
check("de fijnafstelling alleen als de loadbalancer aan staat", main.crs_text(dict(main.CRS_DEFAULT, ha="static", **{"ha-auto-rebalance-threshold": 50})) == "ha=static")
full = dict(main.CRS_DEFAULT, ha="dynamic", **{"ha-auto-rebalance": True, "ha-rebalance-on-start": True})
check("volledige tekst in een vaste volgorde", main.crs_text(full, {"toekomst": "ja"}) == "ha=dynamic,ha-rebalance-on-start=1,ha-auto-rebalance=1,ha-auto-rebalance-threshold=30,ha-auto-rebalance-margin=10,ha-auto-rebalance-hold-duration=3,ha-auto-rebalance-method=bruteforce,toekomst=ja",
      main.crs_text(full, {"toekomst": "ja"}))
check("heen en terug geeft hetzelfde", main.crs_read(main.crs_text(full))[0] == full)
at = lambda h, m: dt.datetime(2026, 10, 14, h, m, tzinfo=main.REPORT_TZ)  # noqa: E731
night, late = {"window": True, "from": "02:00", "to": "05:00", "pinned": []}, {"window": True, "from": "22:00", "to": "05:00", "pinned": []}
check("venster 02:00-05:00: begin telt mee, einde niet", [main.bal_window_open(night, at(h, m)) for h, m in ((1, 59), (2, 0), (4, 59), (5, 0), (12, 0))] == [False, True, True, False, False])
check("venster over middernacht (22:00-05:00)", [main.bal_window_open(late, at(h, m)) for h, m in ((21, 59), (22, 0), (23, 30), (0, 10), (4, 59), (5, 0), (13, 0))] == [False, True, True, True, True, False, False])
check("de versie van Proxmox als getallen", main.pve_version(Fake(W)) == (9, 2, 21))
check("niets veranderd", not changes())

print("--- B. bekijken")
r = call("GET", "/api/balance", READER)
x = r[1] if r[0] == 200 else {}
check("iedereen die is ingelogd ziet de loadbalancer", r[0] == 200, detail(r) if r[0] != 200 else "")
check("de instelling van Proxmox: nog de standaard, versie ondersteund, onbalans van de HA-manager", x.get("crs") == main.CRS_DEFAULT and x.get("supported") is True and x.get("version") == "9.2.21" and x.get("imbalance") == 12.5)
g = {r["sid"]: r for r in x.get("guests", [])}
check("de vijf HA-guests, in volgorde van ID", [r["vmid"] for r in x.get("guests", [])] == [101, 102, 103, 105, 300], str(list(g)))
check("zonder tijdvenster doet iedereen mee zoals Proxmox zegt", all(r["takes_part"] and r["flag"] and not r["window"] for r in g.values()))
check("een schijf op lokale opslag wordt gemeld", g["ct:103"]["local"] == [{"key": "rootfs", "storage": "local-lvm"}] and g["ct:101"]["local"] == [], json.dumps(g.get("ct:103")))
check("de regels per guest", g["ct:101"]["rules"] == ["samen"] and g["vm:300"]["rules"] == [])
check("guests buiten HA (geen sjablonen)", [f["vmid"] for f in x.get("free", [])] == [104], json.dumps(x.get("free")))
n = {r["node"]: r for r in x.get("nodes", [])}
check("de nodes met hun belasting en hoeveel er draaien (en in HA)", n["n1"]["running"] == 2 and n["n1"]["ha"] == 2 and n["n2"]["running"] == 3 and n["n2"]["ha"] == 2 and n["n3"]["online"] is False, json.dumps(x.get("nodes")))
m = {(r["vmid"], r["type"]): r for r in x.get("moves", [])}
check("verplaatsingen, nieuwste eerst", [r["vmid"] for r in x.get("moves", [])] == [104, 101, 300], str([r["vmid"] for r in x.get("moves", [])]))
check("101 als root@pam zonder verzoek: door Proxmox zelf, naar n2", m[(101, "lxc")]["by"] == "ha" and m[(101, "lxc")]["to"] == "n2" and m[(101, "lxc")]["ok"] is True)
check("300 na een verzoek via de tool: wie het vroeg, naar n1, herkend als de tool", m[(300, "qemu")]["by"] == "user" and m[(300, "qemu")]["user"] == "maintool@pve!ct109" and m[(300, "qemu")]["to"] == "n1" and m[(300, "qemu")]["tool"] is True)
check("een andere gebruiker is niet de tool", m[(104, "lxc")]["tool"] is False and m[(101, "lxc")]["tool"] is False)
check("104 (niet in HA) als root@pam: met de hand, mislukt", m[(104, "lxc")]["by"] == "user" and m[(104, "lxc")]["user"] == "root@pam" and m[(104, "lxc")]["ok"] is False)
check("het tijdvenster staat uit, met de standaardtijden", x.get("window", {}).get("on") is False and x["window"]["from"] == "02:00" and x["window"]["to"] == "05:00")
check("bekijken verandert niets", not changes())

print("--- C. instellen: wie mag het, en wat wordt geweigerd")
OK = {"mode": "dynamic", "rebalance_on_start": False, "auto": True, "threshold": 25, "margin": 10, "hold": 3, "method": "bruteforce",
      "window": False, "window_from": "02:00", "window_to": "05:00"}
for who, label in ((READER, "alleen lezen"), (STOR, "rol Opslag")):
    check(f"{label}: geweigerd", call("PUT", "/api/balance", who, OK)[0] == 403)
check("zonder Origin geweigerd", call("PUT", "/api/balance", OVER, OK, origin=None)[0] == 403)
bad = [({**OK, "mode": "slim"}, 400), ({**OK, "method": "gok"}, 400), ({**OK, "mode": "basic"}, 400), ({**OK, "threshold": 101}, 400),
       ({**OK, "margin": -1}, 400), ({**OK, "hold": 61}, 400), ({**OK, "window_from": "25:00"}, 400), ({**OK, "window": True, "window_to": "02:00"}, 400),
       ({**OK, "threshold": "30"}, 422), ({**OK, "threshold": True}, 422), ({**OK, "mode": "x" * 40}, 422)]
wrong = [(b, code, call("PUT", "/api/balance", OVER, b)[0]) for b, code in bad if call("PUT", "/api/balance", OVER, b)[0] != code]
check(f"{len(bad)} ongeldige instellingen geweigerd met de juiste code", not wrong, str(wrong)[:300])
r = call("PUT", "/api/balance", OVER, {**OK, "mode": "basic"}, cookies={"maintool_lang": "en"})
check("de melding komt in de taal van de pagina", detail(r) == "The load balancer only works when Proxmox looks at usage: choose Dynamic or Static", detail(r))
VERSION["version"] = "9.1.4"
r = call("PUT", "/api/balance", OVER, OK)
check("op Proxmox VE 9.1 weigert de tool de loadbalancer", r[0] == 409 and "9.2" in detail(r), detail(r))
r = call("GET", "/api/balance", READER)
check("en meldt dat het niet kan", r[1].get("supported") is False and r[1].get("version") == "9.1.4")
VERSION["version"] = "9.2.21"
check("niets naar Proxmox gestuurd", not changes())

print("--- D. instellen: wat er naar Proxmox gaat")
OPTS["crs"] = "ha=static,toekomst=ja"
r = call("PUT", "/api/balance", OVER, OK)
ch = changes()
check("aanzetten lukt", r[0] == 200 and r[1]["crs"]["ha-auto-rebalance"] is True and r[1]["crs"]["ha-auto-rebalance-threshold"] == 25, detail(r) if r[0] != 200 else "")
check("precies één aanpassing in Datacenter > Opties, met de onbekende sleutel erbij", ch == [("PUT", "cluster/options", {"crs": "ha=dynamic,ha-auto-rebalance=1,ha-auto-rebalance-threshold=25,ha-auto-rebalance-margin=10,ha-auto-rebalance-hold-duration=3,ha-auto-rebalance-method=bruteforce,toekomst=ja"})], str(ch))
r = call("PUT", "/api/balance", OVER, OK)
check("hetzelfde nog eens: niets naar Proxmox", r[0] == 200 and not changes())
r = call("PUT", "/api/balance", OVER, {**OK, "auto": False, "mode": "static", "rebalance_on_start": True})
check("uitzetten: de fijnafstelling gaat weg, starten op de beste node blijft", OPTS.get("crs") == "ha=static,ha-rebalance-on-start=1,toekomst=ja", OPTS.get("crs"))
changes()
OPTS["crs"] = "ha=dynamic"
r = call("PUT", "/api/balance", OVER, {**OK, "auto": False, "mode": "basic"})
check("terug naar alles standaard: de instelling gaat weg", changes() == [("PUT", "cluster/options", {"delete": "crs"})] and "crs" not in OPTS)
OPTS["crs"] = "ha=basic,bad-key=1"
r = call("PUT", "/api/balance", OVER, OK)
check("weigert Proxmox, dan komt dat terug als foutmelding", r[0] == 400 and detail(r).startswith("Proxmox weigerde de instelling"), detail(r))
OPTS.pop("crs")
changes()
ev = [e for e in main.state.events(0) if e.get("kind") == "balance"]
check("in het logboek: aangezet, aangepast en uitgezet, met wie", [e["result"] for e in ev][:3] == ["loadbalancer aangezet", "instellingen van de loadbalancer aangepast", "loadbalancer uitgezet"]
      and all(e.get("user") == "over" for e in ev), str([e["result"] for e in ev]))

print("--- E. het tijdvenster voor containers")
now = dt.datetime.now(main.REPORT_TZ)
mins = now.hour * 60 + now.minute
CLOSED = {"window_from": hhmm(mins + 120), "window_to": hhmm(mins + 180)}
HA_RES["ct:102"]["auto-rebalance"] = 0          # in Proxmox al met de hand uitgezet
r = call("PUT", "/api/balance", OVER, {**OK, "window": True, **CLOSED})
ch = changes()
puts = sorted((c[1].rsplit("/", 1)[1], c[2].get("auto-rebalance")) for c in ch if c[1].startswith("cluster/ha/resources/"))
check("venster dicht: de containers die meededen gaan uit, de VM niet", puts == [("ct:101", 0), ("ct:103", 0), ("ct:105", 0)], str(puts))
g = {x["sid"]: x for x in r[1]["guests"]}
check("wat de gebruiker koos blijft zichtbaar: 102 doet niet mee, 101 en 103 wel (buiten het venster)", g["ct:102"]["takes_part"] is False and g["ct:101"]["takes_part"] and g["ct:103"]["takes_part"] and g["ct:101"]["flag"] is False and g["vm:300"]["window"] is False)
check("de keuze voor 102 is overgenomen in de tool", main.balance_config()["pinned"] == ["ct:102"] and r[1]["window"]["open"] is False)
inside = now.replace(hour=(mins + 150) // 60 % 24, minute=(mins + 150) % 60)
changed, failed = main.balance_sync(Fake(W), main.balance_config(), inside)
check("venster open: 101, 103 en 105 doen weer mee, 102 niet", sorted(changed) == [("ct:101", True), ("ct:103", True), ("ct:105", True)] and not failed and HA_RES["ct:102"]["auto-rebalance"] == 0, str(changed))
changes()
check("nog eens: niets te doen", main.balance_sync(Fake(W), main.balance_config(), inside) == ([], []) and not changes())
changed, failed = main.balance_sync(Fake(W), main.balance_config())
check("weer buiten het venster: alles weer uit", sorted(changed) == [("ct:101", False), ("ct:103", False), ("ct:105", False)], str(changed))
changes()
r = call("PUT", "/api/balance/guest/ct:102", OVER, {"auto": True})
ch = changes()
check("102 mag weer meedoen: buiten het venster blijft hij in Proxmox uit", r[0] == 200 and ch == [("PUT", "cluster/ha/resources/ct:102", {"auto-rebalance": 0})] and main.balance_config()["pinned"] == [], str(ch))
r = call("PUT", "/api/balance/guest/vm:300", OVER, {"auto": False})
check("een VM regelt het venster niet: direct uit in Proxmox", r[0] == 200 and changes() == [("PUT", "cluster/ha/resources/vm:300", {"auto-rebalance": 0})] and {x["sid"]: x for x in r[1]["guests"]}["vm:300"]["takes_part"] is False)
for path, who, code in (("ct:104", OVER, 404), ("xx:1", OVER, 400), ("ct:101", READER, 403), ("ct:101", STOR, 403)):
    check(f"meedoen van {path} als {'lezer' if who is READER else 'opslag' if who is STOR else 'overzicht'}: {code}", call("PUT", f"/api/balance/guest/{path}", who, {"auto": True})[0] == code)
check("zonder Origin geweigerd", call("PUT", "/api/balance/guest/ct:101", OVER, {"auto": True}, origin=None)[0] == 403)
check("niets naar Proxmox gestuurd bij de weigeringen", not changes())
r = call("PUT", "/api/balance", OVER, {**OK, "window": False, **CLOSED})
puts = sorted((c[1].rsplit("/", 1)[1], c[2].get("auto-rebalance")) for c in changes() if c[1].startswith("cluster/ha/resources/"))
check("venster uit: de containers doen weer mee zoals gekozen (alle vier), de VM blijft uit", puts == [("ct:101", 1), ("ct:102", 1), ("ct:103", 1), ("ct:105", 1)] and HA_RES["vm:300"]["auto-rebalance"] == 0, str(puts))

print("--- F. als Proxmox weigert: aandachtspunt, en weer weg als het lukt")
r = call("PUT", "/api/balance", OVER, {**OK, "window": True, **CLOSED})
changes()
for sid in ("ct:101", "ct:102", "ct:103", "ct:105"):
    HA_RES[sid]["auto-rebalance"] = 1
FAIL_PUT.add("ct:103")
changed, failed = main.balance_sync(Fake(W), main.balance_config())
main.bal_note(changed, failed, "tijdvenster")
err = main.state.load().get("balance_error") or {}
check("een weigering wordt onthouden, de andere gaan door", sorted(s for s, _ in changed) == ["ct:101", "ct:102", "ct:105"] and err.get("who") == ["ct:103"], json.dumps(err))
check("het aandachtspunt hoort bij het tabblad HA en staat standaard op oranje", main.ALERTS["balance_failed"] == ("ha", "level", "warning"))
found = []
try:
    found = [i for i in main.gather_issues(Fake(W)) if i["code"] == "balance_failed"]
except Exception as exc:  # noqa: BLE001 - de nagebootste omgeving kent niet alles wat gather_issues leest
    found = None
    print("     (gather_issues niet helemaal na te bootsen:", type(exc).__name__, str(exc)[:80], ")")
if found is not None:
    check("bij de aandachtspunten: wie het betreft", len(found) == 1 and found[0]["tab"] == "ha" and found[0]["who"] == ["ct:103"] and found[0]["level"] == "warning", json.dumps(found))
r = call("GET", "/api/balance", READER)
check("ook op het tabblad te zien", (r[1].get("error") or {}).get("who") == ["ct:103"])
FAIL_PUT.clear()
changed, failed = main.balance_sync(Fake(W), main.balance_config())
main.bal_note(changed, failed, "tijdvenster")
check("lukt het weer, dan is het aandachtspunt weg", "balance_error" not in main.state.load() and changed == [("ct:103", False)], str(changed))
ev = [e["result"] for e in main.state.events(0) if e.get("kind") == "balance"]
check("het venster schrijft het in het logboek", "buiten het tijdvenster: containers doen niet mee aan het verdelen" in ev, str(ev[-4:]))
r = call("PUT", "/api/balance", OVER, {**OK, "auto": False, "mode": "basic", "window": False, **CLOSED})
changes()

print("--- G. de pagina en de rechten")
page = (main.STATIC / "index.html").read_text(encoding="utf-8") if hasattr(main, "STATIC") else open("/tmp/mt-v210/app/static/index.html", encoding="utf-8").read()
check("subtabbladen op HA, het venster van de loadbalancer, de bibliotheek achter een knop", 'id="hatabs"' in page and 'id="lbdlg"' in page and 'id="libdlg"' in page and 'id="lib-open"' in page and 'id="lib"' not in page)
routes = {(m, r.path): r for r in main.app.routes if isinstance(r, APIRoute) for m in r.methods}
check("de drie adressen bestaan", all(k in routes for k in (("GET", "/api/balance"), ("PUT", "/api/balance"), ("PUT", "/api/balance/guest/{sid}"))))
check("de lus voor het tijdvenster start met de dienst", "balance_loop" in main.start_background.__code__.co_names)

TRIPPED = [x for x in TRIPPED if not (x[0] == "agent" and tuple(x[1][1:]) == ("info", "cts"))]
check("het echte cluster is niet aangeraakt", not TRIPPED, str(TRIPPED))
print()
print("ALLES GOED" if not FAILED else f"FOUT ({len(FAILED)}): {FAILED}")
