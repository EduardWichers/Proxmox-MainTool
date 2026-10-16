"""Tests version 1.9 of the backend in-process on the tool container, from a copy in /tmp with its own state folder:
view only through Cloudflare, a backup before updates and release upgrades, and automatic updates on a schedule.
Everything runs against a stand-in cluster and a stand-in node agent that only write down what they are asked to do;
nothing on the real cluster or the nodes is changed. No secrets are used or shown."""
import asyncio, base64, datetime as dt, hashlib, hmac, json, os, secrets, subprocess, sys, tempfile, time, urllib.parse
for line in open("/etc/maintool/maintool.env", encoding="utf-8"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ[k.strip()] = v.strip()
os.environ["STATE_DIRECTORY"] = "/tmp/mt-v19/state"
sys.path.insert(0, "/tmp/mt-v19/app")
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
AGENT = {"calls": [], "status": {}, "start": "started", "fail": False}


def fake_agent(ip, *words, timeout=30):
    if words[:1] in (("info",), ("refresh",)):   # de bewaker van de updates (start al bij het inladen); alleen lezen
        return ""
    AGENT["calls"].append((ip, words))
    if words[0] == "status":
        return AGENT["status"].get(words[1:], "state=finished exit=0") + "\nlog"
    if words[0] in ("upgrade", "release"):
        AGENT["status"][words[1:]] = "state=finished exit=100" if AGENT["fail"] else "state=finished exit=0"
        return AGENT["start"]
    if words[0] == "ping":
        return "maintool-agent 3 x"
    return ""


main.agent = fake_agent
main.ssh_ready = lambda: True
REAL_SLEEP = time.sleep
main.time.sleep = lambda s: REAL_SLEEP(0.001)   # wachten op taken is in deze test meteen klaar
TASKS = {}
GiB = 2 ** 30
W.table.update({
    "cluster/resources": [{"vmid": 201, "node": "n1", "type": "lxc", "name": "web", "status": "running"},
                          {"vmid": 202, "node": "n1", "type": "lxc", "name": "db", "status": "running"},
                          {"vmid": 203, "node": "n1", "type": "lxc", "name": "slot", "status": "running"},
                          {"vmid": 204, "node": "n1", "type": "lxc", "name": "uit", "status": "stopped"},
                          {"vmid": 205, "node": "n1", "type": "lxc", "name": "kaal", "status": "running"},
                          {"vmid": 300, "node": "n1", "type": "qemu", "name": "vm", "status": "running"}],
    "nodes": [{"node": "n1", "status": "online"}, {"node": "n2", "status": "online"}],
    "cluster/status": [{"type": "cluster", "quorate": 1}, {"type": "node", "name": "n1", "ip": "10.9.0.1"}, {"type": "node", "name": "n2", "ip": "10.9.0.2"}],
    "storage": [{"storage": "nas", "content": "backup,iso", "shared": 1, "type": "nfs"}, {"storage": "lokaal", "content": "images", "type": "dir"}],
    "nodes/n1/storage/nas/content": [{"vmid": 201, "ctime": 1790000000, "volid": "nas:backup/x", "size": 5}],
    "nodes/n1/ceph/status": {"osdmap": {"num_up_osds": 3, "num_osds": 3}, "pgmap": {"pgs_by_state": [{"state_name": "active+clean", "count": 100}]}},
    "nodes/n1/lxc/201/config": {"hostname": "web"}, "nodes/n1/lxc/202/config": {"hostname": "db"}, "nodes/n1/lxc/203/config": {"hostname": "slot", "lock": "backup"},
    "nodes/n1/lxc/205/config": {"hostname": "kaal"},
    "nodes/n1/lxc/201/snapshot": [{"name": "auto_update_20260101_0300"}, {"name": "auto_update_20260108_0300"}, {"name": "eigen_snapshot"}, {"name": "current"}],
    "nodes/n1/lxc/202/snapshot": [{"name": "current"}], "nodes/n1/lxc/205/snapshot": [{"name": "current"}],
    "cluster/resources?storage": []})
_orig_call = W.call


def call_with_tasks(method, path, kw):
    if path == "cluster/resources" and kw.get("type") == "storage":
        return [{"storage": "nas", "status": "available", "disk": 10 * GiB, "maxdisk": 100 * GiB}]
    if method == "POST" and (path.endswith("/vzdump") or path.endswith("/snapshot")):
        W.changes.append((method, path, kw))
        name = "vzdump" if path.endswith("/vzdump") else "snap"
        upid = f"UPID:n1:{len(TASKS):04d}:{name}"
        TASKS[upid] = W.answers.get(("RESULT", name), "OK")
        return upid
    if method == "DELETE" and "/snapshot/" in path:
        W.changes.append((method, path, kw))
        upid = f"UPID:n1:{len(TASKS):04d}:del"
        TASKS[upid] = "OK"
        return upid
    if method == "GET" and "/tasks/" in path and path.endswith("/status"):
        upid = path.split("/tasks/")[1].rsplit("/status", 1)[0]
        return {"status": "stopped", "exitstatus": TASKS.get(upid, "OK")}
    return _orig_call(method, path, kw)


W.call = call_with_tasks
main.updates.start = lambda lists=True: False
main.updates.busy = False
main.updates.info = {"nodes": {"n1": {"updates": 4}, "n2": {"updates": 0}}, "guests": {"201": {"updates": 3, "os": "Debian 12"}, "202": {"updates": 0},
                     "203": {"updates": 2}, "204": {"updates": 1}, "205": {"updates": 5}}, "checked": 1, "error": None, "ssh": True}
main.login_guard.failures.clear()
ROOT = session_of(call("POST", "/api/login", body={"username": main.APP_USER, "password": main.APP_PASSWORD})[2])
PW = secrets.token_urlsafe(18)
for name, roles in (("over", ["overview"]), ("lezer", []), ("opslag", ["storage"])):
    call("POST", "/api/users", ROOT, {"name": name, "roles": roles, "password": PW})
OVER = session_of(call("POST", "/api/login", body={"username": "over", "password": PW})[2])
READER = session_of(call("POST", "/api/login", body={"username": "lezer", "password": PW})[2])
STOR = session_of(call("POST", "/api/login", body={"username": "opslag", "password": PW})[2])
CF = {"Cf-Ray": "8abc-AMS", "Cf-Connecting-Ip": "198.51.100.77"}

print("--- A. via Cloudflare: alleen bekijken")
r = call("GET", "/", ROOT, origin=None)
check("zonder Cloudflare: geen vlag, alle rechten in de pagina", 'data-cf=""' in r[1] and 'data-can="admin overview' in r[1] and 'data-view=""' in r[1])
r = call("GET", "/", ROOT, origin=None, headers=CF)
check("via Cloudflare: vlag aan, nog niets gekozen, rechten nog in de pagina", 'data-cf="1"' in r[1] and 'data-cfmode="ask"' in r[1] and 'data-view=""' in r[1] and 'data-rights="1"' in r[1])
r = call("POST", "/api/viewonly", ROOT, {"on": True}, headers=CF)
line = next((x for x in r[2] if x.startswith(main.VIEW_COOKIE)), "")
check("kiezen voor alleen bekijken: cookie tot het sluiten van de browser, HttpOnly en Secure", r[0] == 200 and cookie_of(r[2], main.VIEW_COOKIE) == "1"
      and "Max-Age" not in line and "HttpOnly" in line and "Secure" in line, line)
VO = {main.VIEW_COOKIE: "1"}
r = call("GET", "/", ROOT, origin=None, headers=CF, cookies=VO)
check("de pagina krijgt dan geen rechten mee", 'data-can=""' in r[1] and 'data-view="1"' in r[1] and 'data-rights="1"' in r[1])
me = call("GET", "/api/me", ROOT, headers=CF, cookies=VO)[1]
check("wie ben ik: geen rechten, alleen bekijken (zelf gekozen)", me["can"] == [] and me["view_only"] == "chosen" and me["via_cloudflare"] is True)
W.changes.clear()
AGENT["calls"].clear()
for label, method, path, body in [("guest bewerken", "PUT", "/api/guest/n1/lxc/201/config", {"memory": 1024}), ("update starten", "POST", "/api/upgrade/n1/201", {}),
                                  ("gebruikers bekijken (beheerder)", "GET", "/api/users", None), ("drempels", "PUT", "/api/alerts", {"alerts": {}}),
                                  ("automatisch bijwerken instellen", "PUT", "/api/autoupdate", {"enabled": False}),
                                  ("back-up maken", "POST", "/api/backup/run", {"vmids": [201], "storage": "nas", "mode": "snapshot"})]:
    r = call(method, path, ROOT, body, headers=CF, cookies=VO)
    check(f"alleen bekijken: {label} geweigerd met uitleg", r[0] == 403 and "Volledig gebruiken" in detail(r), f"{r[0]} {detail(r)}")
check("en er is niets naar het cluster of een node gestuurd", W.changes == [] and AGENT["calls"] == [], json.dumps(AGENT["calls"]))
check("kijken mag wel", call("GET", "/api/autoupdate", ROOT, headers=CF, cookies=VO)[0] == 200 and call("GET", "/api/report/status", ROOT, headers=CF, cookies=VO)[0] == 200)
check("eigen instellingen (taal, dashboard) mogen wel", call("PUT", "/api/settings", ROOT, {"language": "nl"}, headers=CF, cookies=VO)[0] == 200)
check("hetzelfde cookie zonder Cloudflare (eigen netwerk): alles mag", call("GET", "/api/users", ROOT, cookies=VO)[0] == 200)


def ws_close(cookie, headers):
    hdrs = [(b"host", HOST.encode()), (b"origin", f"https://{HOST}".encode()),
            (b"cookie", f"{main.SESSION_COOKIE}={cookie}; {main.VIEW_COOKIE}=1".encode())] + [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    scope = {"type": "websocket", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1", "scheme": "wss", "path": "/api/console/n1/201",
             "raw_path": b"/api/console/n1/201", "query_string": b"", "root_path": "", "headers": hdrs, "client": ("203.0.113.7", 1), "server": (HOST, 443), "subprotocols": []}
    sent, asked = [], []

    async def receive():
        if not asked:
            asked.append(1)
            return {"type": "websocket.connect"}
        return {"type": "websocket.disconnect", "code": 1006}

    async def send(m):
        sent.append(m)
    asyncio.run(main.app(scope, receive, send))
    return next((m.get("code") for m in sent if m["type"] == "websocket.close"), "open")


check("de console is dicht bij alleen bekijken (4403)", ws_close(ROOT, CF) == 4403)
r = call("POST", "/api/viewonly", ROOT, {"on": False}, headers=CF, cookies=VO)
check("terug naar volledig gebruiken", r[0] == 200 and cookie_of(r[2], main.VIEW_COOKIE) == "0")
check("met de keuze volledig: de beheerder komt weer door de bewaker", call("GET", "/api/users", ROOT, headers=CF, cookies={main.VIEW_COOKIE: "0"})[0] == 200)
check("de keuze zonder Cloudflare: 400", call("POST", "/api/viewonly", ROOT, {"on": True})[0] == 400)
r = call("PUT", "/api/policy", ROOT, {"cloudflare": "readonly"})
check("beheerder stelt in: via Cloudflare altijd alleen bekijken", r[0] == 200 and {k: r[1].get(k) for k in ("min_password", "cloudflare")} == {"min_password": 12, "cloudflare": "readonly"}, json.dumps(r[1]))   # sinds 1.2.1 ook de sessies
check("dan geldt het ook zonder keuze, ook voor de beheerder", call("GET", "/api/users", ROOT, headers=CF)[0] == 403
      and "eigen netwerk" in detail(call("PUT", "/api/alerts", ROOT, {"alerts": {}}, headers=CF)))
check("het cookie '0' omzeilt dat niet", call("GET", "/api/users", ROOT, headers=CF, cookies={main.VIEW_COOKIE: "0"})[0] == 403)
check("volledig gebruiken kiezen wordt dan geweigerd", call("POST", "/api/viewonly", ROOT, {"on": False}, headers=CF)[0] == 403)
r = call("GET", "/", ROOT, origin=None, headers=CF)
check("de pagina: modus readonly, alleen bekijken", 'data-cfmode="readonly"' in r[1] and 'data-view="1"' in r[1] and 'data-can=""' in r[1])
check("in het eigen netwerk werkt alles gewoon", call("GET", "/api/users", ROOT)[0] == 200)
r = call("PUT", "/api/policy", ROOT, {"cloudflare": "off"})
check("niets vragen: via Cloudflare alles zoals altijd, ook met het cookie", r[0] == 200 and call("GET", "/api/users", ROOT, headers=CF, cookies=VO)[0] == 200)
for label, body in [("onbekende keuze", {"cloudflare": "soms"}), ("leeg verzoek", {}), ("lengte 7", {"min_password": 7})]:
    check(f"beleid geweigerd: {label}", call("PUT", "/api/policy", ROOT, body)[0] == 400)
check("beleid: alleen beheerders (ook lezen)", call("GET", "/api/policy", OVER)[0] == 403 and call("PUT", "/api/policy", OVER, {"cloudflare": "ask"})[0] == 403)
check("de minimale lengte kan nog los worden ingesteld", {k: call("PUT", "/api/policy", ROOT, {"min_password": 14})[1].get(k) for k in ("min_password", "cloudflare")} == {"min_password": 14, "cloudflare": "off"})
call("PUT", "/api/policy", ROOT, {"min_password": 12, "cloudflare": "ask"})

print("--- B. eerst een back-up, dan bijwerken")
r = call("GET", "/api/backupfirst/n1/201", READER)
check("venster: de back-upopslag en de laatste back-up", r[0] == 200 and [s["storage"] for s in r[1]["storages"]] == ["nas"] and r[1]["last"]["ctime"] == 1790000000, json.dumps(r[1])[:200])


def wait_prep(key):
    for _ in range(500):
        p = main.prep_status(*key)
        if not p or p["state"] == "failed":
            return p
        REAL_SLEEP(0.01)
    return main.prep_status(*key)


W.changes.clear()
AGENT["calls"].clear()
AGENT["status"].clear()
r = call("POST", "/api/upgrade/n1/201", OVER, {"backup": "vzdump", "storage": "nas", "mode": "snapshot"})
check("update met volledige back-up vooraf: meteen 'preparing'", r[0] == 200 and r[1] == {"state": "preparing"}, json.dumps(r[1]))
p = wait_prep(("n1", "201"))
vz = [x for x in W.changes if x[1] == "nodes/n1/vzdump"]
check("de back-up van alleen deze container naar de gekozen opslag, daarna de update", p is None and vz and vz[0][2]["vmid"] == "201" and vz[0][2]["storage"] == "nas"
      and vz[0][2]["mode"] == "snapshot" and ("10.9.0.1", ("upgrade", "ct", "201")) in AGENT["calls"], json.dumps(W.changes)[:300])
check("de update is pas na de back-up gestart", [x[1][0] for x in AGENT["calls"]][-1] == "upgrade")
W.changes.clear()
AGENT["calls"].clear()
W.answers[("RESULT", "vzdump")] = "job errors"
r = call("POST", "/api/upgrade/n1/202", OVER, {"backup": "vzdump", "storage": "nas"})
p = wait_prep(("n1", "202"))
check("mislukte back-up: de update start NIET, met de reden", p and p["state"] == "failed" and not any(x[1][0] == "upgrade" for x in AGENT["calls"]) and "job errors" in p["error"], json.dumps(p))
st = call("GET", "/api/upgrade/n1/202", OVER)[1]
check("het venster van de update toont 'failed'", st["state"] == "failed" and "niet gestart" in st["log"], json.dumps(st))
st = call("GET", "/api/upgrade/n1/202", OVER, cookies={"maintool_lang": "en"})[1]
check("en in het Engels", "was not started" in st["log"], st["log"])
ev = [e for e in main.state.events(0) if e.get("target") == "202"]
check("de mislukte back-up staat in het logboek", ev and "back-up vooraf mislukt" in ev[-1]["result"], json.dumps(ev[-1:]))
W.answers[("RESULT", "vzdump")] = "OK"
W.changes.clear()
AGENT["calls"].clear()
r = call("POST", "/api/upgrade/n1/202", OVER, {"backup": "snapshot"})
wait_prep(("n1", "202"))
snaps = [x for x in W.changes if x[1] == "nodes/n1/lxc/202/snapshot"]
check("met alleen een snapshot: snapshot voor_update_..., dan de update", snaps and snaps[0][2]["snapname"].startswith("voor_update_") and ("10.9.0.1", ("upgrade", "ct", "202")) in AGENT["calls"])
check("na een gelukte poging is de oude fout weg", call("GET", "/api/upgrade/n1/202", OVER)[1]["state"] == "finished")
W.changes.clear()
AGENT["calls"].clear()
r = call("POST", "/api/upgrade/n1/201", OVER, {"backup": "none"})
check("zonder back-up: meteen gestart, niets naar het cluster", r[0] == 200 and r[1]["state"] == "started" and not [x for x in W.changes if x[0] == "POST"])
check("zonder body (zoals vroeger): ook meteen gestart", call("POST", "/api/upgrade/n1/201", OVER)[1]["state"] == "started")
for label, path, body, code, who in [
        ("node met back-up", "/api/upgrade/n1/node", {"backup": "vzdump", "storage": "nas"}, 400, OVER),
        ("onbekende keuze", "/api/upgrade/n1/201", {"backup": "alles"}, 400, OVER),
        ("opslag die geen back-ups kan", "/api/upgrade/n1/201", {"backup": "vzdump", "storage": "lokaal"}, 400, OVER),
        ("geen opslag", "/api/upgrade/n1/201", {"backup": "vzdump"}, 400, OVER),
        ("rare modus", "/api/upgrade/n1/201", {"backup": "vzdump", "storage": "nas", "mode": "snel"}, 400, OVER),
        ("door de lezer", "/api/upgrade/n1/201", {"backup": "vzdump", "storage": "nas"}, 403, READER),
        ("door de opslagbeheerder", "/api/upgrade/n1/201", {"backup": "none"}, 403, STOR)]:
    W.changes.clear()
    AGENT["calls"].clear()
    r = call("POST", path, who, body)
    check(f"geweigerd: {label} ({code})", r[0] == code and not [x for x in W.changes if x[0] == "POST"] and not any(x[1][0] == "upgrade" for x in AGENT["calls"]), f"{r[0]} {detail(r)}")
W.changes.clear()
AGENT["calls"].clear()
r = call("POST", "/api/release/n1/201", OVER, {"backup": "vzdump", "storage": "nas"})
wait_prep(("n1", "201"))
kinds = [x[1] for x in W.changes if x[0] == "POST"]
check("release-upgrade met back-up: eerst de back-up, dan de vaste snapshot, dan de upgrade",
      r[1]["state"] == "preparing" and kinds == ["nodes/n1/vzdump", "nodes/n1/lxc/201/snapshot"] and ("10.9.0.1", ("release", "ct", "201")) in AGENT["calls"], json.dumps(kinds))
W.changes.clear()
AGENT["calls"].clear()
r = call("POST", "/api/release/n1/201", OVER, {"backup": "snapshot"})
check("release-upgrade met alleen de vaste snapshot: zoals voorheen", r[0] == 200 and r[1]["snapshot"].startswith("voor_release_") and ("10.9.0.1", ("release", "ct", "201")) in AGENT["calls"])

print("--- C. automatisch bijwerken")
TZ = main.REPORT_TZ
at = lambda *a: main.dt.datetime(*a, tzinfo=TZ)  # noqa: E731
base = main.autoupdate_config()
check("standaard uit", base["enabled"] is False and main.autoupdate_due({}, base, at(2026, 10, 18, 3, 5)) is None)
on = {**base, "enabled": True, "frequency": "weekly", "day": 6, "time": "03:00"}
check("om 03:05 op zondag: nu", main.autoupdate_due({}, on, at(2026, 10, 18, 3, 5)) == at(2026, 10, 18, 3, 0))
check("na drie uur niet meer alsnog", main.autoupdate_due({}, on, at(2026, 10, 18, 6, 30)) is None)
check("al gedraaid: niet nog eens", main.autoupdate_due({"autoupdate_ran": at(2026, 10, 18, 3, 1).timestamp()}, on, at(2026, 10, 18, 3, 5)) is None)
check("planning daarna gewijzigd: niet alsnog", main.autoupdate_due({"autoupdate_config_at": at(2026, 10, 18, 3, 2).timestamp()}, on, at(2026, 10, 18, 3, 5)) is None)
for label, body in [("onbekende frequentie", {"frequency": "hourly"}), ("dag 9", {"day": 9}), ("tijd 3:00", {"time": "3:00"}), ("lijst leeg", {"cts": "list", "ct_list": []}),
                    ("niets gekozen", {"enabled": True, "cts": "none", "nodes": False}), ("rare back-up", {"backup": "alles"}),
                    ("opslag fout", {"backup": "vzdump", "storage": "lokaal"}), ("VMID te klein", {"cts": "list", "ct_list": [5]}), ("dag als true", {"day": True})]:
    r = call("PUT", "/api/autoupdate", OVER, {"enabled": False, **body})
    check(f"geweigerd: {label}", r[0] in (400, 422), f"{r[0]} {detail(r)}")
check("instellen mag niet voor de lezer of de opslagbeheerder", call("PUT", "/api/autoupdate", READER, {"enabled": False})[0] == 403
      and call("PUT", "/api/autoupdate", STOR, {"enabled": False})[0] == 403)
r = call("PUT", "/api/autoupdate", OVER, {"enabled": True, "frequency": "weekly", "day": 6, "time": "03:00", "cts": "list",
                                          "ct_list": [201, 202, 203, 204, 205, 999], "nodes": True, "backup": "snapshot"})
check("instellen: aan, gekozen containers en de nodes, met snapshot", r[0] == 200 and r[1]["config"]["enabled"] and r[1]["next"], detail(r) or "")
W.changes.clear()
AGENT["calls"].clear()
AGENT["status"].clear()
main.run_autoupdate(main.autoupdate_config(), "met de hand")
res = {x["target"]: (x["code"], x["ok"]) for x in main.state.load()["autoupdate_last"]["results"]}
check("201 met 3 updates: gelukt", res.get("CT 201 web") == ("done", True), json.dumps(res))
check("202 zonder updates: al bijgewerkt", res.get("CT 202 db") == ("uptodate", None))
check("203 vergrendeld: overgeslagen", res.get("CT 203 slot") == ("locked", None))
check("204 staat uit: overgeslagen", res.get("CT 204 uit") == ("off", None))
check("205 gelukt", res.get("CT 205 kaal") == ("done", True))
check("de VM wordt niet aangeraakt", not any("/qemu/" in x[1] for x in W.changes) and not any(x[1][1:] == ("ct", "300") for x in AGENT["calls"]))
check("node n1 met 4 updates bijgewerkt, n2 had er geen", res.get("node n1") == ("nodedone", True) and res.get("node n2") == ("uptodate", None), json.dumps(res))
upg = [x[1] for x in AGENT["calls"] if x[1][0] == "upgrade"]
check("volgorde: containers één voor één, dan de nodes", upg == [("upgrade", "ct", "201"), ("upgrade", "ct", "205"), ("upgrade", "node")], str(upg))
snaps = [x for x in W.changes if x[0] == "POST" and x[1].endswith("/snapshot")]
check("voor elke bijgewerkte container eerst een snapshot auto_update_...", [x[1] for x in snaps] == ["nodes/n1/lxc/201/snapshot", "nodes/n1/lxc/205/snapshot"]
      and all(x[2]["snapname"].startswith("auto_update_") for x in snaps))
check("geen herstart van een node", not any(x[1][0] == "reboot" for x in AGENT["calls"]) and not [x for x in W.changes if "reboot" in x[1]])
dels = [x[1] for x in W.changes if x[0] == "DELETE"]
check("de oude automatische snapshots zijn opgeruimd, de eigen snapshot blijft", sorted(dels) == ["nodes/n1/lxc/201/snapshot/auto_update_20260101_0300",
      "nodes/n1/lxc/201/snapshot/auto_update_20260108_0300"], str(dels))
ev = [e for e in main.state.events(0) if e.get("by") == "automatisch"]
check("het logboek: gelukt per container en node", {(e["target"], e["result"]) for e in ev} >= {("201", "gelukt"), ("205", "gelukt"), ("node", "gelukt")}, json.dumps(ev)[:300])
AGENT["calls"].clear()
W.changes.clear()
AGENT["fail"] = True
W.table["nodes"] = [{"node": "n1", "status": "online"}, {"node": "n2", "status": "offline"}]
main.run_autoupdate(main.autoupdate_config(), "met de hand")
res = {x["target"]: (x["code"], x["ok"], x.get("detail")) for x in main.state.load()["autoupdate_last"]["results"]}
check("een mislukte update komt als mislukt binnen, met de code", res.get("CT 201 web", ("",))[:2] == ("failed", False) and res["CT 201 web"][2] == "100", json.dumps(res))
check("na een mislukte update wordt de vorige snapshot niet opgeruimd", not [x for x in W.changes if x[0] == "DELETE"])
check("een node offline: de nodes worden overgeslagen, met de reden", res.get("node n1", ("",))[0] == "blocked" and "n2 is niet online" in res["node n1"][2], json.dumps(res.get("node n1")))
check("en er is geen node bijgewerkt", not any(x[1] == ("upgrade", "node") for x in AGENT["calls"]))
main.issues.at = 0
W.table.setdefault("nodes/n1/disks/list", [])
try:
    items = main.issues.get(wait=True)
except Exception as err:  # noqa: BLE001
    items = []
    print("     aandachtspunten:", err)
check("aandachtspunt: automatisch bijwerken mislukt (oranje, Overzicht)", any(i["code"] == "autoupdate_failed" and i["level"] == "warning" and i["tab"] == "overview" for i in items),
      json.dumps([i["code"] for i in items]))
AGENT["fail"] = False
W.table["nodes"] = [{"node": "n1", "status": "online"}, {"node": "n2", "status": "online"}]
W.answers[("RESULT", "snap")] = "snapshot failed"
AGENT["calls"].clear()
main.run_autoupdate(main.autoupdate_config(), "met de hand")
res = {x["target"]: (x["code"], x["ok"]) for x in main.state.load()["autoupdate_last"]["results"]}
check("mislukte snapshot vooraf: die container wordt niet bijgewerkt", res.get("CT 201 web") == ("backupfail", False)
      and ("10.9.0.1", ("upgrade", "ct", "201")) not in AGENT["calls"], json.dumps(res))
W.answers[("RESULT", "snap")] = "OK"
main.AUTO["busy"] = True
check("terwijl er een ronde loopt: nog een ronde geweigerd", call("POST", "/api/autoupdate/run", OVER)[0] == 409 and main.run_autoupdate(main.autoupdate_config()) is False)
main.AUTO["busy"] = False
r = call("GET", "/api/autoupdate", READER)
check("de status is voor iedereen te zien, met de laatste ronde", r[0] == 200 and r[1]["last"]["why"] == "met de hand" and len(r[1]["last"]["results"]) >= 5)
TRIPPED = [x for x in TRIPPED if not (x[0] == "agent" and tuple(x[1][1:]) == ("info", "cts"))]
check("het echte cluster en de echte nodes zijn niet aangeraakt", not TRIPPED, str(TRIPPED))

print()
print("ALLES GOED" if not FAILED else f"FOUT ({len(FAILED)}): {FAILED}")
