"""Tests version 1.0.4 of the backend in-process on the tool container, from a copy in /tmp with its own state folder:
node settings (the wrench next to a node) and the backup log. Everything runs against a stand-in cluster that only
writes down what it is asked to do; nothing on the real cluster is changed."""
import asyncio, base64, datetime as dt, hashlib, hmac, json, os, secrets, subprocess, sys, tempfile, time, urllib.parse
for line in open("/etc/maintool/maintool.env", encoding="utf-8"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ[k.strip()] = v.strip()
os.environ["STATE_DIRECTORY"] = "/tmp/mt-v204/state"
sys.path.insert(0, "/tmp/mt-v204/app")
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
REPOS = {"files": [{"path": "/etc/apt/sources.list.d/pve-enterprise.sources", "repositories": [{"Types": ["deb"], "URIs": ["https://enterprise.proxmox.com/debian/pve"], "Suites": ["trixie"], "Components": ["pve-enterprise"], "Enabled": 0}]},
                   {"path": "/etc/apt/sources.list.d/pve-no-subscription.sources", "repositories": [{"Types": ["deb"], "URIs": ["http://download.proxmox.com/debian/pve/"], "Suites": ["trixie"], "Components": ["pve-no-subscription"], "Enabled": 1, "Comment": " mijn bron\n"}]}],
         "infos": [{"kind": "warning", "path": "/etc/apt/sources.list.d/pve-enterprise.sources", "index": 0, "message": "old suite"}, {"kind": "origin", "path": "x", "index": 0, "message": "Proxmox"}],
         "standard-repos": [{"handle": "enterprise", "name": "Enterprise", "status": 0}, {"handle": "no-subscription", "name": "No-Subscription", "status": 1}, {"handle": "test", "name": "Test"}], "digest": "d"}
TASKS = {"n1": [{"upid": "UPID:n1:1:vzdump::root@pam:", "type": "vzdump", "id": "", "user": "root@pam", "starttime": NOW - 86400, "endtime": NOW - 86400 + 120, "status": "OK"},
                {"upid": "UPID:n1:2:vzdump:110:maintool@pve!webtool:", "type": "vzdump", "id": "110", "user": main.PVE_USER, "starttime": NOW - 7200, "endtime": NOW - 7100, "status": "OK"},
                {"upid": "UPID:n1:3:vzdump::maintool@pve!webtool:", "type": "vzdump", "id": "", "user": main.PVE_USER, "starttime": NOW - 3600, "endtime": None, "status": None}],
         "n2": [{"upid": "UPID:n2:4:vzdump::root@pam:", "type": "vzdump", "id": "", "user": "root@pam", "starttime": NOW - 86400 + 3, "endtime": NOW - 86400 + 200, "status": "job errors"},
                {"upid": "UPID:n2:5:vzdump:104:Eduard@pve:", "type": "vzdump", "id": "104", "user": "Eduard@pve", "starttime": NOW - 5 * 86400, "endtime": NOW - 5 * 86400 + 30, "status": "WARNINGS: 1"},
                {"upid": "UPID:n2:6:vzdump::root@pam:", "type": "vzdump", "id": "", "user": "root@pam", "starttime": NOW - 60 * 86400, "endtime": NOW - 60 * 86400 + 10, "status": "OK"}]}
LOGS = {"UPID:n1:1:vzdump::root@pam:": ["INFO: starting new backup job: vzdump 101 110 --mode snapshot --storage nas --notes-template '{{guestname}}'", "INFO: Finished Backup of VM 101 (00:00:20)"],
        "UPID:n1:2:vzdump:110:maintool@pve!webtool:": ["INFO: starting new backup job: vzdump 110 --mode snapshot --storage nas"],
        "UPID:n1:3:vzdump::maintool@pve!webtool:": ["INFO: starting new backup job: vzdump 101 --mode snapshot --storage nas"],
        "UPID:n2:4:vzdump::root@pam:": ["INFO: starting new backup job: vzdump 104 105 --mode snapshot --storage nas", "INFO: Finished Backup of VM 104 (00:01:00)",
                                         "ERROR: Backup of VM 105 failed - unable to create temporary directory", "INFO: Backup job finished with errors"],
        "UPID:n2:5:vzdump:104:Eduard@pve:": ["INFO: starting new backup job: vzdump 104 --storage nas --mode stop", "WARN: something"],
        "UPID:n2:6:vzdump::root@pam:": ["INFO: starting new backup job: vzdump 101 --storage nas"]}
JOBS = [{"id": "backup-web", "comment": "Websites", "storage": "nas", "mode": "snapshot", "vmid": "101,104,105,110", "schedule": "02:00", "enabled": 1, "next-run": NOW + 3600},
        {"id": "backup-alles", "comment": "Alles", "storage": "nas2", "all": 1, "schedule": "sun 03:00", "enabled": 0}]


def tasks_get(node):
    def get(kw):
        out = [t for t in TASKS[node] if t["starttime"] >= kw.get("since", 0)]
        W.changes.append(("TASKS", node, kw.get("typefilter"), kw.get("source")))
        return out
    return get


_orig = W.call


def world(method, path, kw):
    m = re.match(r"nodes/(n\d)/tasks/(.+)/log$", path)
    if method == "GET" and m:
        lines = LOGS.get(m.group(2), [])[kw.get("start", 0):kw.get("start", 0) + kw.get("limit", 50)]
        return [{"n": i + 1, "t": line} for i, line in enumerate(lines)]
    if method != "GET":
        W.changes.append((method, path, dict(kw)))
        if W.fail:
            raise W.fail
        if path.endswith("/vzdump"):
            return f"UPID:{path.split('/')[1]}:9:vzdump::maintool@pve!webtool:"
        return None
    return _orig(method, path, kw)


import re  # noqa: E402
W.call = world
W.table.update({
    "nodes": [{"node": "n1", "status": "online"}, {"node": "n2", "status": "online"}, {"node": "n3", "status": "offline"}],
    "nodes/n1/config": {"description": "Rack links", "wakeonlan": "mac=AA:BB:CC:DD:EE:FF", "startall-onboot-delay": 30},
    "nodes/n1/dns": {"search": "thuis.lan", "dns1": "192.168.1.1"}, "nodes/n1/time": {"timezone": "Europe/Amsterdam"},
    "nodes/n1/apt/repositories": REPOS, "nodes/n1/subscription": {"status": "notfound"},
    "nodes/n1/tasks": tasks_get("n1"), "nodes/n2/tasks": tasks_get("n2"),
    "cluster/backup": JOBS,
    "cluster/backup/backup-web": JOBS[0],
    "cluster/resources": lambda kw: [{"storage": "nas", "shared": 1, "type": "storage"}] if kw.get("type") == "storage" else
        [{"vmid": 101, "name": "web", "node": "n1", "type": "lxc"}, {"vmid": 104, "name": "db", "node": "n2", "type": "lxc"},
         {"vmid": 105, "name": "foto", "node": "n2", "type": "lxc"}, {"vmid": 110, "name": "tunnel", "node": "n1", "type": "lxc"}],
    "storage": [{"storage": "nas", "content": "backup", "shared": 1, "type": "nfs"}],
})
main.login_guard.failures.clear()
ROOT = session_of(call("POST", "/api/login", body={"username": main.APP_USER, "password": main.APP_PASSWORD})[2])
PW = secrets.token_urlsafe(18)
for name, roles in (("over", ["overview"]), ("lezer", []), ("bk", ["backups"])):
    call("POST", "/api/users", ROOT, {"name": name, "roles": roles, "password": PW})
OVER, READER, BK = (session_of(call("POST", "/api/login", body={"username": n, "password": PW})[2]) for n in ("over", "lezer", "bk"))
check("inloggen van de testgebruikers", all([ROOT, OVER, READER, BK]))


def changes():
    out = [c for c in W.changes if c[0] != "TASKS"]
    W.changes.clear()
    return out


print("--- A. instellingen van een node bekijken")
r = call("GET", "/api/node/n1/settings", READER)
d = r[1] if r[0] == 200 else {}
check("iedereen die is ingelogd ziet ze", r[0] == 200, detail(r) if r[0] != 200 else "")
check("notitie, Wake-on-LAN (zonder mac=), wachttijd, tijdzone, DNS, abonnement", (d.get("description"), d.get("wakeonlan"), d.get("startall_delay"), d.get("timezone"), d.get("dns"), d.get("subscription"))
      == ("Rack links", "AA:BB:CC:DD:EE:FF", 30, "Europe/Amsterdam", {"search": "thuis.lan", "dns1": "192.168.1.1", "dns2": "", "dns3": ""}, "notfound"), json.dumps(d)[:300])
rp = d.get("repos") or {}
check("pakketbronnen per regel, met de opmerking zonder witruimte, en alleen de waarschuwingen van Proxmox",
      [(x["path"].rsplit("/", 1)[1], x["index"], x["enabled"], x["comment"]) for x in rp.get("repos", [])] == [("pve-enterprise.sources", 0, False, None), ("pve-no-subscription.sources", 0, True, "mijn bron")]
      and rp.get("warnings") == [{"path": "/etc/apt/sources.list.d/pve-enterprise.sources", "index": 0, "message": "old suite"}] and [s["handle"] for s in rp.get("standard", [])] == ["enterprise", "no-subscription", "test"])
check("ongeldige nodenaam: 400, zonder sessie: 401", call("GET", "/api/node/n_1/settings", READER)[0] == 400 and call("GET", "/api/node/n1/settings")[0] == 401)
check("bekijken verandert niets", not changes())

print("--- B. aanpassen: wie, en de controles")
OK = {"description": "Nieuw"}
for who, label in ((READER, "alleen lezen"), (BK, "rol Back-ups")):
    check(f"{label}: geweigerd", call("PUT", "/api/node/n1/settings", who, OK)[0] == 403)
check("vanaf een andere website of zonder Origin: geweigerd", call("PUT", "/api/node/n1/settings", OVER, OK, origin="https://kwaad.example")[0] == 403
      and call("PUT", "/api/node/n1/settings", OVER, OK, origin=None)[0] == 403)
check("via Cloudflare in alleen bekijken: geweigerd", call("PUT", "/api/node/n1/settings", OVER, OK, headers={"Cf-Ray": "x"}, cookies={main.VIEW_COOKIE: "1"})[0] == 403)
bad = [({}, 400), ({"timezone": "Mars/Olympus Mons"}, 400), ({"timezone": "../etc"}, 400), ({"startall_delay": 301}, 400), ({"startall_delay": True}, 422), ({"startall_delay": "30"}, 422),
       ({"wakeonlan": "geen-mac"}, 400), ({"dns": {"search": "thuis.lan", "dns1": ""}}, 400), ({"dns": {"search": "thuis.lan", "dns1": "999.1.1.1"}}, 400),
       ({"dns": {"search": "kwaad;rm", "dns1": "1.1.1.1"}}, 400), ({"description": "a\x00b"}, 400), ({"repos": [{"path": "/etc/passwd", "index": 0, "enabled": True}]}, 400),
       ({"repos": [{"path": "/etc/apt/sources.list.d/pve-enterprise.sources", "index": 5, "enabled": True}]}, 409), ({"add_repo": "no-subscription"}, 400), ({"add_repo": "bestaatniet"}, 400)]
wrong = [(b, code, call("PUT", "/api/node/n1/settings", OVER, b)[0]) for b, code in bad if call("PUT", "/api/node/n1/settings", OVER, b)[0] != code]
check(f"{len(bad)} ongeldige verzoeken geweigerd met de juiste code", not wrong, str(wrong))
check("een node die niet online is: 409", call("PUT", "/api/node/n3/settings", OVER, OK)[0] == 409)
check("na al die weigeringen is er niets naar Proxmox gestuurd", not changes())

print("--- C. aanpassen: wat er naar Proxmox gaat")
r = call("PUT", "/api/node/n1/settings", OVER, {"description": "Rack rechts", "startall_delay": 0, "wakeonlan": "AA:BB:CC:DD:EE:01"})
check("algemeen: één keer config, MAC in kleine letters", r[0] == 200 and changes() == [("PUT", "nodes/n1/config", {"description": "Rack rechts", "startall-onboot-delay": 0, "wakeonlan": "aa:bb:cc:dd:ee:01"})], json.dumps(r[1]))
r = call("PUT", "/api/node/n1/settings", OVER, {"description": "  ", "startall_delay": -1, "wakeonlan": ""})
check("leeg maken: weg met delete", r[0] == 200 and changes() == [("PUT", "nodes/n1/config", {"delete": "description,startall-onboot-delay,wakeonlan"})])
r = call("PUT", "/api/node/n1/settings", ROOT, {"timezone": "Europe/Brussels", "dns": {"search": "thuis.lan", "dns1": "1.1.1.1", "dns2": "", "dns3": "2606:4700:4700::1111"}})
check("tijdzone en DNS (lege tweede weg, IPv6 mag)", r[0] == 200 and changes() == [("PUT", "nodes/n1/time", {"timezone": "Europe/Brussels"}),
      ("PUT", "nodes/n1/dns", {"search": "thuis.lan", "dns1": "1.1.1.1", "dns3": "2606:4700:4700::1111"})] and r[1]["changed"] == ["dns", "timezone"])
r = call("PUT", "/api/node/n1/settings", OVER, {"repos": [{"path": "/etc/apt/sources.list.d/pve-enterprise.sources", "index": 0, "enabled": True},
                                                         {"path": "/etc/apt/sources.list.d/pve-no-subscription.sources", "index": 0, "enabled": True}], "add_repo": "test"})
check("pakketbronnen: alleen wat echt verandert, plus de standaardbron", r[0] == 200 and changes() == [("POST", "nodes/n1/apt/repositories", {"path": "/etc/apt/sources.list.d/pve-enterprise.sources", "index": 0, "enabled": 1}),
      ("PUT", "nodes/n1/apt/repositories", {"handle": "test"})], json.dumps(r[1]))
ev = [e for e in main.state.events(0) if e.get("kind") == "nodecfg"]
check("in het logboek: welke node en wie", len(ev) == 4 and {(e["node"], e["user"]) for e in ev} == {("n1", "over"), ("n1", main.APP_USER)}, json.dumps(ev)[:200])
W.fail = ResourceException(500, "Internal Server Error", "kapot")
before = len(main.state.events(0))
r = call("PUT", "/api/node/n1/settings", OVER, {"timezone": "UTC"})
check("een weigering van Proxmox komt door en wordt niet als gelukt gelogd", r[0] == 500 and "kapot" in detail(r) and len(main.state.events(0)) == before)
W.fail = None
changes()

print("--- D. het logboek van de back-ups")
r = call("GET", "/api/backup/log?days=30", READER)
x = r[1] if r[0] == 200 else {}
check("iedereen die is ingelogd ziet het; zonder sessie niet", r[0] == 200 and call("GET", "/api/backup/log")[0] == 401, detail(r) if r[0] != 200 else "")
runs = {rr["upid"].split(":")[2]: rr for rr in x.get("runs", [])}
check("de rondes van de laatste 30 dagen, nieuwste eerst, ook een lopende; niet die van 60 dagen terug", list(runs) == ["3", "2", "4", "1", "5"], str(list(runs)))
check("guests en opslag uit het log, met namen", runs["1"]["vmids"] == [101, 110] and runs["1"]["names"] == {"101": "web", "110": "tunnel"} and runs["1"]["storage"] == "nas" and runs["1"]["mode"] == "snapshot")
check("een ronde van Proxmox zelf (root@pam) hoort bij het passende schema", runs["1"]["job"] == "backup-web" and runs["1"]["job_name"] == "Websites" and runs["4"]["job"] == "backup-web")
check("een losse back-up via de tool hoort bij geen schema, ook al passen de guests", runs["2"]["job"] is None and runs["2"]["user"] == main.PVE_USER and x.get("tool_user") == main.PVE_USER)
check("een back-up door iemand anders in Proxmox: los", runs["5"]["job"] is None and runs["5"]["level"] == "warning")
check("afloop: gelukt, bezig, mislukt", (runs["1"]["level"], runs["3"]["level"], runs["4"]["level"]) == ("ok", "running", "error"))
check("bij een mislukte ronde: welke guest en waarom, en wat wel lukte", runs["4"]["failed"] == [{"vmid": 105, "name": "foto", "reason": "unable to create temporary directory"}] and runs["4"]["done"] == [104])
check("van een gelukte ronde wordt niet het hele log gelezen", runs["1"]["done"] is None and runs["1"]["failed"] == [])
jobs = {j["id"]: j for j in x.get("jobs", [])}
check("per schema: laatste keer, de slechtste afloop van die ronde (over beide nodes), aantal en volgende keer",
      jobs["backup-web"]["last"] == NOW - 86400 + 3 and jobs["backup-web"]["last_level"] == "error" and jobs["backup-web"]["runs"] == 1 and jobs["backup-web"]["bad_runs"] == 1
      and jobs["backup-web"]["next_run"] == NOW + 3600, json.dumps(jobs.get("backup-web")))
check("een schema zonder rondes en uitgeschakeld", jobs["backup-alles"]["last"] is None and jobs["backup-alles"]["enabled"] is False and jobs["backup-alles"]["runs"] == 0)
check("een node die niet online is staat erbij", x.get("offline") == ["n3"])
check("vraagt de taken van alle online nodes op, ook lopende", {(c[1], c[2], c[3]) for c in W.changes if c[0] == "TASKS"} == {("n1", "vzdump", "all"), ("n2", "vzdump", "all")})
r = call("GET", "/api/backup/log?days=7", READER)
check("7 dagen: de ronde van 5 dagen geleden telt mee, die van 60 dagen niet", [rr["upid"].split(":")[2] for rr in r[1]["runs"]] == ["3", "2", "4", "1", "5"])
r = call("GET", "/api/backup/log?days=3", READER)
check("een ander aantal dagen wordt 30", r[1]["days"] == 30)
check("bekijken verandert niets", not changes())

print("--- E. 'nu uitvoeren' via de tool wordt onthouden")
r = call("POST", "/api/backup/jobs/backup-web/run", BK)
check("schema nu uitvoeren met de rol Back-ups", r[0] == 200 and len(r[1]["tasks"]) == 2, detail(r) or "")
started = main.state.load().get("job_upids") or {}
check("de taken van die ronde staan bij het schema", set(started.values()) == {"backup-web"} and len(started) == 2, json.dumps(started))
TASKS["n1"].insert(0, {"upid": "UPID:n1:9:vzdump::maintool@pve!webtool:", "type": "vzdump", "id": "", "user": main.PVE_USER, "starttime": NOW - 10, "endtime": NOW - 5, "status": "OK"})
LOGS["UPID:n1:9:vzdump::maintool@pve!webtool:"] = ["INFO: starting new backup job: vzdump 101 110 --mode snapshot --storage nas"]
r = call("GET", "/api/backup/log", READER)
check("zo'n ronde staat in het logboek bij het schema, niet als los", next(rr for rr in r[1]["runs"] if rr["upid"].startswith("UPID:n1:9"))["job"] == "backup-web")
changes()

TRIPPED = [x for x in TRIPPED if not (x[0] == "agent" and tuple(x[1][1:]) == ("info", "cts"))]
check("het echte cluster is niet aangeraakt", not TRIPPED, str(TRIPPED))
print()
print("ALLES GOED" if not FAILED else f"FOUT ({len(FAILED)}): {FAILED}")
