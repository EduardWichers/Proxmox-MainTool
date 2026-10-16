"""Tests version 1.2 of the backend in-process on the tool container, from a copy in /tmp with its own state folder:
setting up HA (readiness, rules, shutdown policy, disarm for maintenance) and setting up Ceph (monitors, managers, OSDs, pools, flags, first setup).
Everything runs against a stand-in cluster that only writes down what it is asked to do; nothing real is changed."""
import asyncio, base64, datetime as dt, hashlib, hmac, json, os, secrets, subprocess, sys, tempfile, time, urllib.parse
for line in open("/etc/maintool/maintool.env", encoding="utf-8"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ[k.strip()] = v.strip()
os.environ["STATE_DIRECTORY"] = "/tmp/mt-v212/state"
sys.path.insert(0, "/tmp/mt-v212/app")
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

VERSION = {"version": "9.2.21"}
NODES = ["n1", "n2", "n3", "n4"]
ONLINE = {"n1", "n2", "n3", "n4"}
FENCING = {"armed-state": "armed"}
RULES = [{"rule": "web-db", "type": "resource-affinity", "resources": "ct:101,ct:102", "affinity": "positive", "digest": "a" * 40},
         {"rule": "liefst-n1", "type": "node-affinity", "resources": "ct:101", "nodes": "n1:2,n2", "strict": 1, "comment": "oud", "digest": "b" * 40}]
RULES_OK = [True]
HA_RES = [{"sid": "ct:101", "state": "started"}, {"sid": "ct:102", "state": "started"}, {"sid": "ct:103", "state": "started"}, {"sid": "vm:300", "state": "started"}]
GUESTS = [{"vmid": 101, "name": "web", "node": "n1", "type": "lxc", "status": "running"}, {"vmid": 102, "name": "db", "node": "n1", "type": "lxc", "status": "running"},
          {"vmid": 103, "name": "lokaal", "node": "n2", "type": "lxc", "status": "running"}, {"vmid": 300, "name": "win", "node": "n2", "type": "qemu", "status": "running"},
          {"vmid": 104, "name": "los", "node": "n3", "type": "lxc", "status": "stopped"}]
CEPHST = {n: "ok" for n in NODES}
MONS = [{"name": n, "host": n, "state": "running", "quorum": 1, "addr": f"10.0.0.{i}:6789/0", "ceph_version_short": "19.2.6"} for i, n in enumerate(["n1", "n2", "n3"], 1)]
MGRS = [{"name": "n1", "host": "n1", "state": "active"}, {"name": "n2", "host": "n2", "state": "standby"}]
OSDS = [{"id": 0, "name": "osd.0", "host": "n1", "status": "up", "in": 1}, {"id": 1, "name": "osd.1", "host": "n2", "status": "up", "in": 1},
        {"id": 2, "name": "osd.2", "host": "n3", "status": "up", "in": 1}]
POOLS = [{"pool_name": ".mgr", "size": 3, "min_size": 2, "pg_num": 1, "pg_autoscale_mode": "on", "application_metadata": {"mgr": {}}, "bytes_used": 1, "percent_used": 0.0},
         {"pool_name": "ceph", "size": 3, "min_size": 2, "pg_num": 32, "pg_autoscale_mode": "on", "application_metadata": {"rbd": {}}, "bytes_used": 9, "percent_used": 0.18},
         {"pool_name": "leeg", "size": 3, "min_size": 2, "pg_num": 32, "pg_autoscale_mode": "warn", "application_metadata": {"rbd": {}}, "bytes_used": 0, "percent_used": 0.0}]
FLAGS = {f: 0 for f in ("nobackfill", "nodeep-scrub", "nodown", "noin", "noout", "norebalance", "norecover", "noscrub", "notieragent", "noup", "pause")}
STORAGE = [{"storage": "ceph", "type": "rbd", "pool": "ceph", "content": "images,rootdir"}, {"storage": "leeg", "type": "rbd", "pool": "leeg", "content": "images"},
           {"storage": "local", "type": "dir", "content": "iso"}]
CONTENT = {"ceph": [{"volid": "ceph:vm-101-disk-0"}], "leeg": []}
SAFE = {("osd", "0", "stop"): {"safe": True}, ("osd", "2", "destroy"): {"safe": False, "status": "OSD(s) 2 have 33 pgs currently mapped to them."},
        ("mon", "n3", "stop"): {"safe": True, "status": "quorum should be preserved"}, ("mon", "n2", "stop"): {"safe": False, "status": "would lose quorum"}}
DISKS = {"n3": [{"devpath": "/dev/sda", "used": "LVM", "osdid": 2, "type": "ssd", "size": 256 * 2**30}, {"devpath": "/dev/sdb", "type": "ssd", "size": 512 * 2**30, "model": "Samsung SSD"}],
         "n4": [{"devpath": "/dev/sdc", "type": "hdd", "size": 2 * 2**40}]}


def tree():
    def host(n):
        return {"type": "host", "name": n, "children": [{"type": "osd", "id": str(o["id"]), "name": o["name"], "host": n, "status": o["status"], "in": o["in"],   # als tekst, zoals Proxmox
                                                           "device_class": "ssd", "bytes_used": 10, "total_space": 100} for o in OSDS if o["host"] == n]}
    return {"root": {"type": "root", "children": [host(n) for n in NODES]}}


def ceph_status(node):
    def get(kw):
        st = CEPHST[node]
        if st == "ok":
            return {"health": {"status": "HEALTH_OK", "checks": {}}, "pgmap": {}, "osdmap": {}}
        raise ResourceException(500, "Internal Server Error", st)
    return get


_orig = W.call


def world(method, path, kw):
    if method != "GET":
        W.changes.append((method, path, dict(kw)))
        if path.endswith("/ceph/init"):
            for n in CEPHST:
                if CEPHST[n] != "binary not installed: /usr/bin/ceph-mon":
                    CEPHST[n] = "rados_connect failed - No such file or directory"
            return None
        if "/ceph/" in path or path.endswith("/ceph/osd"):
            return f"UPID:{path.split('/')[1]}:9:ceph::root@pam:"
        return None
    if path.endswith("/ceph/cmd-safety"):
        return SAFE.get((kw.get("service"), str(kw.get("id")), kw.get("action")), {"safe": True})
    if path == "cluster/ha/rules":
        if not RULES_OK[0]:
            raise ResourceException(501, "Not Implemented", "Method 'GET /cluster/ha/rules' not implemented")
        return [dict(r) for r in RULES]
    return _orig(method, path, kw)


W.call = world
W.table.update({
    "version": lambda kw: dict(VERSION),
    "nodes": lambda kw: [{"node": n, "status": "online" if n in ONLINE else "offline"} for n in NODES],
    "cluster/status": lambda kw: [{"type": "cluster", "quorate": 1, "nodes": len(NODES)}] + [{"type": "node", "name": n, "online": int(n in ONLINE)} for n in NODES],
    "cluster/ha/status/current": lambda kw: [{"type": "quorum", "quorate": 1}, {"type": "master", "node": "n1", "status": "n1 (active, Thu Oct 15 00:19:34 2026)"},
                                             {"type": "fencing", "id": "fencing", **FENCING}] + [
                                            {"type": "lrm", "node": n, "status": f"{n} (active, watchdog active, Thu)"} for n in ("n1", "n2", "n3")],
    "cluster/ha/resources": lambda kw: [dict(r) for r in HA_RES],
    "cluster/options": {},
    "cluster/resources": lambda kw: [{"storage": "ceph", "shared": 1, "content": "images,rootdir"}, {"storage": "local", "shared": 0, "content": "iso"}]
                                    if kw.get("type") == "storage" else [dict(g) for g in GUESTS],
    "nodes/n1/lxc/101/config": {"rootfs": "ceph:vm-101-disk-0,size=8G"}, "nodes/n1/lxc/102/config": {"rootfs": "ceph:vm-102-disk-0,size=8G"},
    "nodes/n2/lxc/103/config": {"rootfs": "local-lvm:vm-103-disk-0,size=8G"}, "nodes/n2/qemu/300/config": {"scsi0": "ceph:vm-300-disk-0"},
    **{f"nodes/{n}/ceph/status": ceph_status(n) for n in NODES},
    **{f"nodes/{n}/ceph/mon": lambda kw: [dict(m) for m in MONS] for n in NODES},
    **{f"nodes/{n}/ceph/mgr": lambda kw: [dict(m) for m in MGRS] for n in NODES},
    **{f"nodes/{n}/ceph/osd": lambda kw: tree() for n in NODES},
    **{f"nodes/{n}/ceph/pool": lambda kw: [dict(p) for p in POOLS] for n in NODES},
    **{f"nodes/{n}/ceph/cfg/value": {"global": {"public-network": "10.0.0.0/24", "cluster-network": "10.0.1.0/24"}} for n in NODES},
    **{f"nodes/{n}/disks/list": (lambda n: lambda kw: [dict(d) for d in DISKS.get(n, [])])(n) for n in NODES},
    **{f"nodes/{n}/storage/{s}/content": (lambda s: lambda kw: list(CONTENT.get(s, [])))(s) for n in NODES for s in ("ceph", "leeg")},
    "cluster/ceph/flags": lambda kw: [{"name": f, "value": v} for f, v in FLAGS.items()],
    "cluster/ceph/metadata": {"node": {n: {"version": {"str": "19.2.6"}} for n in ("n1", "n2", "n3")}},
    "storage": lambda kw: [dict(s) for s in STORAGE],
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


def codes(cases, method, url_of, who):
    """[(body, verwachte code)] -> de gevallen die een andere code gaven."""
    out = []
    for body, code in cases:
        got = call(method, url_of(body) if callable(url_of) else url_of, who, body)
        if got[0] != code:
            out.append((str(body)[:80], code, got[0], detail(got)))
    return out


print("--- A. HA: gereedheid bekijken")
r = call("GET", "/api/ha-setup", READER)
x = r[1] if r[0] == 200 else {}
check("iedereen die is ingelogd ziet HA instellen", r[0] == 200, detail(r) if r[0] != 200 else "")
c = {k["code"]: k for k in x.get("checks", [])}
check("vier nodes met meerderheid: in orde", c["nodes"]["level"] == "ok" and c["nodes"]["count"] == 4 and c["quorum"]["level"] == "ok")
check("gedeelde opslag voor guests gevonden (ceph, niet local)", c["shared"]["level"] == "ok" and c["shared"]["names"] == ["ceph"])
check("de HA-manager en de bewaking", c["manager"]["level"] == "ok" and c["manager"]["node"] == "n1" and c["watchdog"]["level"] == "ok" and len(c["watchdog"]["nodes"]) == 3)
check("HA staat aan (armed)", c["fencing"]["level"] == "ok" and x.get("fencing") == "armed")
check("guests in HA en daarbuiten, en wie een lokale schijf heeft", c["guests"]["count"] == 4 and c["guests"]["not_ha"] == 1 and c["local"]["level"] == "warn" and c["local"]["who"] == ["ct:103"])
rules = {r["rule"]: r for r in x.get("rules", [])}
check("de regels uitgepakt: samen, en voorkeur met prioriteit en strikt", rules["web-db"]["affinity"] == "positive" and rules["web-db"]["resources"] == ["ct:101", "ct:102"]
      and rules["liefst-n1"]["nodes"] == [{"node": "n1", "prio": 2}, {"node": "n2", "prio": 0}] and rules["liefst-n1"]["strict"] is True and rules["liefst-n1"]["affinity"] == "positive")
check("standaard bij uitzetten: hangt ervan af; tijdelijk uitschakelen kan (9.2)", x.get("policy") == "conditional" and x.get("supported_arm") is True and x.get("rules_supported") is True)
check("bekijken verandert niets", not changes())
VERSION["version"] = "8.4.1"
RULES_OK[0] = False
x = call("GET", "/api/ha-setup", READER)[1]
check("Proxmox 8: geen regels en geen tijdelijk uitschakelen", x["rules_supported"] is False and x["supported_arm"] is False and x["rules"] == [])
VERSION["version"] = "9.2.21"
RULES_OK[0] = True

print("--- B. HA: bij uitzetten van een node")
for who, label in ((READER, "alleen lezen"), (STOR, "rol Opslag")):
    check(f"{label}: geweigerd", call("PUT", "/api/ha-setup", who, {"shutdown_policy": "migrate"})[0] == 403)
check("zonder Origin geweigerd", call("PUT", "/api/ha-setup", OVER, {"shutdown_policy": "migrate"}, origin=None)[0] == 403)
check("onbekende keuze geweigerd", call("PUT", "/api/ha-setup", OVER, {"shutdown_policy": "weg"})[0] == 400 and not changes())
r = call("PUT", "/api/ha-setup", OVER, {"shutdown_policy": "migrate"})
check("eerst verhuizen: naar Datacenter > Opties", r[0] == 200 and changes() == [("PUT", "cluster/options", {"ha": "shutdown_policy=migrate"})])

print("--- C. HA tijdelijk uitschakelen voor onderhoud")
check("onbekende keuze voor de guests geweigerd", call("POST", "/api/ha-setup/disarm", OVER, {"mode": "weg"})[0] == 400)
check("alleen lezen mag het niet", call("POST", "/api/ha-setup/disarm", READER, {"mode": "freeze"})[0] == 403)
check("weer aanzetten terwijl hij aan staat: geweigerd", call("POST", "/api/ha-setup/arm", OVER)[0] == 409)
VERSION["version"] = "9.1.4"
check("op Proxmox 9.1 geweigerd", call("POST", "/api/ha-setup/disarm", OVER, {"mode": "freeze"})[0] == 409)
VERSION["version"] = "9.2.21"
check("niets naar Proxmox gestuurd", not changes())
r = call("POST", "/api/ha-setup/disarm", OVER, {"mode": "freeze"})
check("uitschakelen: disarm-ha met de gekozen manier", r[0] == 200 and changes() == [("POST", "cluster/ha/status/disarm-ha", {"resource-mode": "freeze"})])
FENCING["armed-state"] = "disarmed"
check("nog eens uitschakelen: geweigerd", call("POST", "/api/ha-setup/disarm", OVER, {"mode": "ignore"})[0] == 409)
try:
    found = [i for i in main.gather_issues(Fake(W)) if i["code"] == "ha_disarmed"]
except Exception as exc:  # noqa: BLE001
    found = None
    print("     (gather_issues niet helemaal na te bootsen:", type(exc).__name__, str(exc)[:80], ")")
if found is not None:
    check("zolang HA uit staat: aandachtspunt op het tabblad HA", len(found) == 1 and found[0]["tab"] == "ha" and found[0]["level"] == "warning", json.dumps(found))
x = call("GET", "/api/ha-setup", READER)[1]
check("en de gereedheid meldt het", {k["code"]: k for k in x["checks"]}["fencing"]["level"] == "warn")
r = call("POST", "/api/ha-setup/arm", OVER)
check("weer aanzetten: arm-ha", r[0] == 200 and changes() == [("POST", "cluster/ha/status/arm-ha", {})])
FENCING["armed-state"] = "armed"

print("--- D. HA-regels")
OK = {"rule": "voorkeur-n2", "type": "node-affinity", "resources": ["ct:103", "vm:300"], "nodes": [{"node": "n2", "prio": 2}, {"node": "n3", "prio": 0}],
      "strict": True, "affinity": "positive", "disabled": False, "comment": "dicht bij de NAS"}
r = call("POST", "/api/ha-rules", OVER, OK)
check("voorkeur voor nodes toevoegen", r[0] == 200 and changes() == [("POST", "cluster/ha/rules", {"rule": "voorkeur-n2", "type": "node-affinity", "resources": "ct:103,vm:300",
      "disable": 0, "nodes": "n2:2,n3", "strict": 1, "affinity": "positive", "comment": "dicht bij de NAS"})], detail(r) if r[0] != 200 else "")
bad = [({**OK, "rule": "1verkeerd"}, 400), ({**OK, "rule": "x"}, 400), ({**OK, "rule": "web-db"}, 409), ({**OK, "type": "groep"}, 400),
       ({**OK, "affinity": "half"}, 400), ({**OK, "resources": ["ct:104"]}, 400), ({**OK, "resources": ["ct:9x"]}, 400), ({**OK, "resources": []}, 400),
       ({**OK, "nodes": []}, 400), ({**OK, "nodes": [{"node": "n9", "prio": 0}]}, 400), ({**OK, "nodes": [{"node": "n2", "prio": 1001}]}, 400),
       ({**OK, "affinity": "negative", "nodes": [{"node": n, "prio": 0} for n in NODES]}, 400), ({**OK, "comment": "twee\nregels"}, 400),
       ({**OK, "type": "resource-affinity", "resources": ["ct:101"]}, 400),
       ({**OK, "nodes": [{"node": "n2", "prio": "2"}]}, 422)]
wrong = codes(bad, "POST", "/api/ha-rules", OVER)
check(f"{len(bad)} ongeldige regels geweigerd met de juiste code", not wrong, str(wrong)[:400])
check("niets naar Proxmox gestuurd bij de weigeringen", not changes())
r = call("POST", "/api/ha-rules", OVER, {**OK, "rule": "apart", "type": "resource-affinity", "affinity": "negative", "resources": ["ct:101", "ct:102", "ct:101"], "nodes": [], "comment": ""})
check("niet samen op één node: dubbele guest één keer, geen nodes of strikt mee", r[0] == 200 and changes() == [("POST", "cluster/ha/rules", {"rule": "apart", "type": "resource-affinity",
      "resources": "ct:101,ct:102", "disable": 0, "affinity": "negative"})], detail(r) if r[0] != 200 else "")
r = call("POST", "/api/ha-rules", OVER, {**OK, "rule": "teveel", "type": "resource-affinity", "affinity": "negative", "resources": ["ct:101", "ct:102", "ct:103", "vm:300"], "nodes": []})
check("vier guests apart op vier nodes kan nog", r[0] == 200)
changes()
NODES.pop()
r = call("POST", "/api/ha-rules", OVER, {**OK, "rule": "teveel2", "type": "resource-affinity", "affinity": "negative", "resources": ["ct:101", "ct:102", "ct:103", "vm:300"], "nodes": []})
check("vier guests apart op drie nodes: geweigerd", r[0] == 400 and "3 nodes" in detail(r), detail(r))
NODES.append("n4")
r = call("PUT", "/api/ha-rules/liefst-n1", OVER, {**OK, "rule": "liefst-n1", "resources": ["ct:101"], "nodes": [{"node": "n3", "prio": 1}], "strict": False, "comment": "", "digest": "b" * 40})
check("aanpassen: opmerking leeg = weg, digest mee", r[0] == 200 and changes() == [("PUT", "cluster/ha/rules/liefst-n1", {"type": "node-affinity", "resources": "ct:101", "disable": 0,
      "nodes": "n3:1", "strict": 0, "affinity": "positive", "delete": "comment", "digest": "b" * 40})], detail(r) if r[0] != 200 else "")
check("de soort wijzigen: geweigerd", call("PUT", "/api/ha-rules/web-db", OVER, {**OK, "rule": "web-db"})[0] == 400)
check("andere naam in het adres dan in de inhoud: geweigerd", call("PUT", "/api/ha-rules/web-db", OVER, {**OK, "rule": "anders", "type": "resource-affinity"})[0] == 400)
check("een regel die niet bestaat aanpassen: 404", call("PUT", "/api/ha-rules/bestaat-niet", OVER, {**OK, "rule": "bestaat-niet"})[0] == 404)
check("verwijderen van een onbekende regel: 404", call("DELETE", "/api/ha-rules/bestaat-niet", OVER)[0] == 404)
check("alleen lezen mag geen regels verwijderen", call("DELETE", "/api/ha-rules/web-db", READER)[0] == 403)
check("niets naar Proxmox gestuurd", not changes())
r = call("DELETE", "/api/ha-rules/web-db", OVER)
check("verwijderen", r[0] == 200 and changes() == [("DELETE", "cluster/ha/rules/web-db", {})])
RULES_OK[0] = False
r = call("POST", "/api/ha-rules", OVER, {**OK, "rule": "op-pve8"})
check("Proxmox 8 (geen regels): duidelijke weigering", r[0] == 409 and "HA-groepen" in detail(r), detail(r))
RULES_OK[0] = True
ev = [e["result"] for e in main.state.events(0) if e.get("kind") == "ha"]
check("alles in het logboek", ev.count("HA-regel toegevoegd") == 3 and "HA-regel aangepast" in ev and "HA-regel verwijderd" in ev and "HA uitgeschakeld voor onderhoud" in ev
      and "HA weer ingeschakeld" in ev and "HA-instelling aangepast" in ev, str(ev))

print("--- E. Ceph: bekijken")
r = call("GET", "/api/ceph/setup", READER)
x = r[1] if r[0] == 200 else {}
check("iedereen die is ingelogd ziet Ceph instellen", r[0] == 200, detail(r) if r[0] != 200 else "")
check("ingericht, gelezen via de eerste node, gezond, met netwerken en versies", x.get("configured") and x.get("node") == "n1" and x.get("health") == "HEALTH_OK"
      and x.get("networks") == {"public": "10.0.0.0/24", "cluster": "10.0.1.0/24"} and x.get("versions", {}).get("n2") == "19.2.6")
check("monitors, managers en OSD's", [m["name"] for m in x["mons"]] == ["n1", "n2", "n3"] and [m["state"] for m in x["mgrs"]] == ["active", "standby"]
      and [(o["id"], o["host"], o["up"], o["in"]) for o in x["osds"]] == [(0, "n1", True, True), (1, "n2", True, True), (2, "n3", True, True)])
pools = {p["name"]: p for p in x["pools"]}
check("pools: die van Ceph zelf herkend, met de opslag in Proxmox", pools[".mgr"]["system"] and not pools["ceph"]["system"] and pools["ceph"]["storages"] == ["ceph"]
      and pools["ceph"]["application"] == ["rbd"] and [p["name"] for p in x["pools"]][-1] == ".mgr", json.dumps(list(pools)))
free = {n["node"]: n["free"] for n in x["nodes"]}
check("alleen ongebruikte schijven zijn vrij", free["n3"] == [{"dev": "/dev/sdb", "size": 512 * 2**30, "type": "ssd", "model": "Samsung SSD"}] and free["n1"] == [] and free["n4"][0]["dev"] == "/dev/sdc")
check("vlaggen: alles uit, en welke de tool mag zetten (geen pause)", x["flags"]["noout"] is False and "pause" not in x["flags_allowed"] and "noout" in x["flags_allowed"])
check("bekijken verandert niets", not changes())

print("--- F. Ceph: vlaggen")
for who, label in ((READER, "alleen lezen"), (OVER, "rol Overzicht")):
    check(f"{label}: geweigerd", call("PUT", "/api/ceph/flags", who, {"flag": "noout", "value": True})[0] == 403)
check("pause zet de tool niet", call("PUT", "/api/ceph/flags", STOR, {"flag": "pause", "value": True})[0] == 400 and not changes())
r = call("PUT", "/api/ceph/flags", STOR, {"flag": "noout", "value": True})
check("noout aanzetten", r[0] == 200 and changes() == [("PUT", "cluster/ceph/flags/noout", {"value": 1})])

print("--- G. Ceph: OSD's")
url = lambda b: f"/api/ceph/osd/{b['id']}/{b['act']}"  # noqa: E731
check("onbekende handeling: 400", call("POST", "/api/ceph/osd/0/weg", STOR, {"node": "n1"})[0] == 400)
check("OSD op een andere node: 404", call("POST", "/api/ceph/osd/0/out", STOR, {"node": "n2"})[0] == 404)
check("node niet online: 400", call("POST", "/api/ceph/osd/0/out", STOR, {"node": "n9"})[0] == 400)
check("al in gebruik: in geweigerd", call("POST", "/api/ceph/osd/0/in", STOR, {"node": "n1"})[0] == 409)
check("draait al: start geweigerd", call("POST", "/api/ceph/osd/0/start", STOR, {"node": "n1"})[0] == 409)
check("rol Overzicht mag het niet", call("POST", "/api/ceph/osd/0/out", OVER, {"node": "n1"})[0] == 403)
check("niets naar Proxmox gestuurd", not changes())
r = call("POST", "/api/ceph/osd/0/out", STOR, {"node": "n1"})
check("uit gebruik: er blijven 2 nodes over, genoeg voor minimaal 2", r[0] == 200 and changes() == [("POST", "nodes/n1/ceph/osd/0/out", {})])
OSDS[1]["in"] = 0
r = call("POST", "/api/ceph/osd/0/out", STOR, {"node": "n1"})
check("nog een eruit terwijl er al één uit is: te weinig nodes over", r[0] == 409 and "minstens 2" in detail(r), detail(r))
r = call("POST", "/api/ceph/osd/1/in", STOR, {"node": "n2"})
check("weer in gebruik", r[0] == 200 and changes() == [("POST", "nodes/n2/ceph/osd/1/in", {})])
OSDS[1]["in"] = 1
r = call("POST", "/api/ceph/osd/0/stop", STOR, {"node": "n1"})
check("stoppen als Ceph zegt dat het veilig is", r[0] == 200 and changes() == [("POST", "nodes/n1/ceph/stop", {"service": "osd.0"})])
SAFE[("osd", "1", "stop")] = {"safe": False, "status": "1 PGs are already too degraded"}
r = call("POST", "/api/ceph/osd/1/stop", STOR, {"node": "n2"})
check("stoppen als Ceph het afraadt: geweigerd met de reden van Ceph", r[0] == 409 and "too degraded" in detail(r) and not changes(), detail(r))
r = call("GET", "/api/ceph/safety?service=osd&ident=1&action=stop", READER)
check("de veiligheidsvraag zelf (alleen lezen)", r[0] == 200 and r[1] == {"safe": False, "status": "1 PGs are already too degraded"})
check("ongeldige veiligheidsvraag: 400", call("GET", "/api/ceph/safety?service=osd&ident=../x&action=stop", READER)[0] == 400)
check("verwijderen terwijl hij draait: geweigerd", call("DELETE", "/api/ceph/osd/2?node=n3", STOR)[0] == 409)
OSDS[2].update(status="down", **{"in": 0})
r = call("DELETE", "/api/ceph/osd/2?node=n3", STOR)
check("gestopt en uit gebruik, maar Ceph zegt nee: geweigerd", r[0] == 409 and "33 pgs" in detail(r) and not changes(), detail(r))
SAFE[("osd", "2", "destroy")] = {"safe": True}
r = call("DELETE", "/api/ceph/osd/2?node=n3", STOR)
check("veilig: verwijderen en de schijf wissen", r[0] == 200 and changes() == [("DELETE", "nodes/n3/ceph/osd/2", {"cleanup": 1})] and r[1]["upid"].startswith("UPID:n3"))
OSDS[2].update(status="up", **{"in": 1})
check("een schijf die niet vrij is: geweigerd", call("POST", "/api/ceph/osd", STOR, {"node": "n3", "dev": "/dev/sda"})[0] == 409)
check("een schijf die niet bestaat: geweigerd", call("POST", "/api/ceph/osd", STOR, {"node": "n3", "dev": "/dev/sdz"})[0] == 409)
check("onbekende soort: 400", call("POST", "/api/ceph/osd", STOR, {"node": "n3", "dev": "/dev/sdb", "device_class": "flash"})[0] == 400)
CEPHST["n4"] = "binary not installed: /usr/bin/ceph-mon"
check("op een node zonder Ceph: geweigerd", call("POST", "/api/ceph/osd", STOR, {"node": "n4", "dev": "/dev/sdc"})[0] == 409)
check("niets naar Proxmox gestuurd", not changes())
r = call("POST", "/api/ceph/osd", STOR, {"node": "n3", "dev": "/dev/sdb", "device_class": "ssd"})
check("van een vrije schijf een OSD maken", r[0] == 200 and changes() == [("POST", "nodes/n3/ceph/osd", {"dev": "/dev/sdb", "encrypted": 0, "crush-device-class": "ssd"})])

print("--- H. Ceph: monitors en managers")
check("op een node met monitor: geweigerd", call("POST", "/api/ceph/mon", STOR, {"node": "n1"})[0] == 409)
check("op een node zonder Ceph-pakketten: geweigerd", call("POST", "/api/ceph/mon", STOR, {"node": "n4"})[0] == 409)
CEPHST["n4"] = "ok"
r = call("POST", "/api/ceph/mon", STOR, {"node": "n4"})
check("monitor toevoegen op n4", r[0] == 200 and changes() == [("POST", "nodes/n4/ceph/mon/n4", {})])
r = call("DELETE", "/api/ceph/mon/n2?node=n2", STOR)
check("monitor weg terwijl Ceph zegt dat de meerderheid weg zou zijn: geweigerd", r[0] == 409 and "quorum" in detail(r), detail(r))
check("monitor op een andere node dan opgegeven: 404", call("DELETE", "/api/ceph/mon/n3?node=n1", STOR)[0] == 404)
r = call("DELETE", "/api/ceph/mon/n3?node=n3", STOR)
check("monitor verwijderen als het veilig is", r[0] == 200 and changes() == [("DELETE", "nodes/n3/ceph/mon/n3", {})])
saved = list(MONS)
MONS[:] = MONS[:1]
check("de laatste monitor: geweigerd", call("DELETE", "/api/ceph/mon/n1?node=n1", STOR)[0] == 409)
MONS[:] = saved
check("manager op een node die er al een heeft: geweigerd", call("POST", "/api/ceph/mgr", STOR, {"node": "n2"})[0] == 409)
r = call("POST", "/api/ceph/mgr", STOR, {"node": "n3"})
check("manager toevoegen op n3", r[0] == 200 and changes() == [("POST", "nodes/n3/ceph/mgr/n3", {})])
saved = list(MGRS)
MGRS[:] = MGRS[:1]
check("de laatste manager: geweigerd", call("DELETE", "/api/ceph/mgr/n1?node=n1", STOR)[0] == 409)
MGRS[:] = saved
r = call("DELETE", "/api/ceph/mgr/n2?node=n2", STOR)
check("een manager die klaarstaat verwijderen", r[0] == 200 and changes() == [("DELETE", "nodes/n2/ceph/mgr/n2", {})])
check("rol Overzicht mag geen monitor toevoegen", call("POST", "/api/ceph/mon", OVER, {"node": "n4"})[0] == 403)

print("--- I. Ceph: pools")
P = {"name": "nieuw", "size": 3, "min_size": 2, "autoscale": "on", "application": "rbd", "add_storage": True}
bad = [({**P, "name": ".geheim"}, 400), ({**P, "name": "met spatie"}, 400), ({**P, "size": 8}, 400), ({**P, "size": 1, "min_size": 1}, 400),
       ({**P, "min_size": 4}, 400), ({**P, "min_size": 0}, 400), ({**P, "autoscale": "soms"}, 400), ({**P, "application": "nfs"}, 400),
       ({**P, "size": 5}, 400), ({**P, "name": "ceph"}, 409), ({**P, "name": "local"}, 409), ({**P, "size": "3"}, 422)]
wrong = codes(bad, "POST", "/api/ceph/pool", STOR)
check(f"{len(bad)} ongeldige pools geweigerd met de juiste code", not wrong, str(wrong)[:400])
check("niets naar Proxmox gestuurd", not changes())
r = call("POST", "/api/ceph/pool", STOR, P)
check("pool aanmaken, meteen als opslag", r[0] == 200 and changes() == [("POST", "nodes/n1/ceph/pool", {"name": "nieuw", "size": 3, "min_size": 2, "pg_autoscale_mode": "on",
      "application": "rbd", "add_storages": 1})], detail(r) if r[0] != 200 else "")
r = call("POST", "/api/ceph/pool", STOR, {**P, "name": "obj", "application": "rgw"})
check("een rgw-pool krijgt geen opslag in Proxmox", r[0] == 200 and changes()[0][2]["add_storages"] == 0)
check("een pool van Ceph zelf aanpassen: geweigerd", call("PUT", "/api/ceph/pool/.mgr", STOR, {"size": 3, "min_size": 2, "autoscale": "on"})[0] in (400, 404))
check("een pool die niet bestaat aanpassen: 404", call("PUT", "/api/ceph/pool/weg", STOR, {"size": 3, "min_size": 2, "autoscale": "on"})[0] == 404)
r = call("PUT", "/api/ceph/pool/ceph", STOR, {"size": 3, "min_size": 2, "autoscale": "warn"})
check("pool aanpassen", r[0] == 200 and changes() == [("PUT", "nodes/n1/ceph/pool/ceph", {"size": 3, "min_size": 2, "pg_autoscale_mode": "warn"})])
r = call("DELETE", "/api/ceph/pool/ceph", STOR)
check("pool met schijven erop: niet verwijderen", r[0] == 409 and "1 schijven" in detail(r) and not changes(), detail(r))
check("pool van Ceph zelf: niet verwijderen", call("DELETE", "/api/ceph/pool/.mgr", STOR)[0] in (400, 404) and not changes())
r = call("DELETE", "/api/ceph/pool/leeg", STOR)
check("lege pool verwijderen, met zijn opslag", r[0] == 200 and changes() == [("DELETE", "nodes/n1/ceph/pool/leeg", {"remove_storages": 1})])
check("alleen lezen mag geen pool aanmaken", call("POST", "/api/ceph/pool", READER, P)[0] == 403)
check("zonder Origin geweigerd", call("DELETE", "/api/ceph/pool/leeg", STOR, origin=None)[0] == 403)

print("--- J. Ceph opbouwen op een cluster zonder Ceph")
for n in NODES:
    CEPHST[n] = "rados_connect failed - No such file or directory"
CEPHST["n3"] = "binary not installed: /usr/bin/ceph-mon"
x = call("GET", "/api/ceph/setup", READER)[1]
check("nog niet ingericht: per node wat er staat", x["configured"] is False and {n["node"]: n["ceph"] for n in x["nodes"]} == {"n1": "unconfigured", "n2": "unconfigured", "n3": "absent", "n4": "unconfigured"})
check("ongeldig netwerk: 400", call("POST", "/api/ceph/init", STOR, {"node": "n1", "network": "10.0.0.0"})[0] == 400 and call("POST", "/api/ceph/init", STOR, {"node": "n1", "network": "geen"})[0] == 400)
check("op een node zonder pakketten: geweigerd", call("POST", "/api/ceph/init", STOR, {"node": "n3", "network": "10.0.0.0/24"})[0] == 409)
check("niets naar Proxmox gestuurd", not changes())
r = call("POST", "/api/ceph/init", STOR, {"node": "n1", "network": "10.0.0.0/24", "cluster_network": "10.0.1.0/24"})
check("inrichten", r[0] == 200 and changes() == [("POST", "nodes/n1/ceph/init", {"network": "10.0.0.0/24", "cluster-network": "10.0.1.0/24"})], detail(r) if r[0] != 200 else "")
r = call("POST", "/api/ceph/mon", STOR, {"node": "n1"})
check("de eerste monitor kan meteen daarna", r[0] == 200 and changes() == [("POST", "nodes/n1/ceph/mon/n1", {})], detail(r) if r[0] != 200 else "")
CEPHST["n1"] = "ok"
check("nog eens inrichten als Ceph draait: geweigerd", call("POST", "/api/ceph/init", STOR, {"node": "n2", "network": "10.0.0.0/24"})[0] == 409)
ev = [e["result"] for e in main.state.events(0) if e.get("kind") == "ceph"]
check("alles in het logboek", {"vlag aangezet", "OSD uit gebruik genomen", "OSD gestopt", "OSD verwijderd", "OSD aangemaakt", "monitor toegevoegd", "monitor verwijderd",
                                "manager toegevoegd", "manager verwijderd", "pool aangemaakt", "pool aangepast", "pool verwijderd", "Ceph ingericht"} <= set(ev), str(sorted(set(ev))))

print("--- K. de pagina en de rechten")
page = open("/tmp/mt-v212/app/static/index.html", encoding="utf-8").read()
check("de steeksleutels en vensters staan in de pagina", 'id="ha-setup"' in page and 'id="hasetdlg"' in page and 'id="harudlg"' in page and 'id="cephdlg"' in page and 'id="cpooldlg"' in page and 'id="ceph-open"' in page)
check("het aandachtspunt voor HA uit staat bij tabblad HA", main.ALERTS["ha_disarmed"] == ("ha", "level", "warning"))
r = call("PUT", "/api/ha-setup", OVER, {"shutdown_policy": "weg"}, cookies={"maintool_lang": "de"})
check("meldingen in de taal van de pagina", detail(r) == "Unbekannte Wahl für das Herunterfahren eines Nodes", detail(r))

TRIPPED = [x for x in TRIPPED if not (x[0] == "agent" and tuple(x[1][1:]) == ("info", "cts"))]
check("het echte cluster is niet aangeraakt", not TRIPPED, str(TRIPPED))
print()
print("ALLES GOED" if not FAILED else f"FOUT ({len(FAILED)}): {FAILED}")
