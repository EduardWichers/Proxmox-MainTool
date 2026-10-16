"""Tests version 1.4 of the backend in-process on the tool container, from a copy in /tmp with its own state folder:
a node that does not answer through the API (seen on another cluster: the whole page gave errors), more than one
schedule for automatic updates, tags of guests, the log of one node and the topology. Everything runs against a
stand-in cluster; nothing real is changed and no real password or token is used."""
import asyncio, base64, datetime as dt, hashlib, hmac, json, os, secrets, subprocess, sys, tempfile, time, urllib.parse
for line in open("/etc/maintool/maintool.env", encoding="utf-8"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ[k.strip()] = v.strip()
os.environ["STATE_DIRECTORY"] = "/tmp/mt-v140/state"
sys.path.insert(0, "/tmp/mt-v140/app")
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
main.agent = lambda ip, *words, **k: ("maintool-agent 3 pve1" if words[:1] == ("ping",) else "") if words[:1] in (("info",), ("refresh",), ("ping",)) else TRIPPED.append(("agent", words)) or ""   # de nagebootste agent: alleen versie en lezen
main.updates.start = lambda lists=True: False
main.updates.busy = False
W.table.update({"nodes": [{"node": "pve1", "status": "online"}], "cluster/resources": [], "cluster/status": [], "cluster/ha/status/current": []})



def login(name, pw, **extra):
    r = call("POST", "/api/login", body={"username": name, "password": pw, **extra})
    return r, session_of(r[2])


main.login_guard.failures.clear()
r, ROOT = login(main.APP_USER, main.APP_PASSWORD)
PW = secrets.token_urlsafe(18)
call("POST", "/api/users", ROOT, {"name": "lezer", "roles": [], "password": PW})
READER = login("lezer", PW)[1]
check("uitgangssituatie: twee sessies", all([ROOT, READER]))
ReadTimeout = main.requests.ReadTimeout
COUNT = {}


def counted(name, value):
    def f(kw):
        COUNT[name] = COUNT.get(name, 0) + 1
        if isinstance(value, BaseException):
            raise value
        return value(kw) if callable(value) else value
    return f


def stuck(kw):
    COUNT["stuck"] = COUNT.get("stuck", 0) + 1
    raise ReadTimeout("Read timed out. (read timeout=10)")


NODES = [{"node": "pve1", "status": "online", "uptime": 4000, "maxmem": 8 * 2**30, "mem": 2**30, "maxdisk": 100, "disk": 10, "maxcpu": 4},
         {"node": "pve2", "status": "online", "uptime": 5000, "maxmem": 8 * 2**30, "mem": 2**30, "maxdisk": 100, "disk": 10, "maxcpu": 4}]
GUESTS = [{"vmid": 101, "type": "lxc", "node": "pve1", "status": "running", "name": "web", "tags": "web;Prod"},
          {"vmid": 201, "type": "lxc", "node": "pve2", "status": "running", "name": "db", "tags": ""},
          {"vmid": 202, "type": "qemu", "node": "pve2", "status": "stopped", "name": "vm"},
          {"vmid": 900, "type": "lxc", "node": "pve1", "status": "stopped", "name": "tpl", "template": 1}]
STATUS = [{"type": "cluster", "quorate": 1}, {"type": "node", "name": "pve1", "ip": "192.168.30.1", "online": 1},
          {"type": "node", "name": "pve2", "ip": "192.168.30.117", "online": 1}]


def world():
    W.table.clear()
    W.changes.clear()
    COUNT.clear()
    main.node_trouble.clear()
    W.table.update({
        "nodes": NODES, "cluster/status": STATUS, "cluster/ha/status/current": [], "cluster/log": [], "storage": [],
        "cluster/resources": lambda kw: {"node": NODES, "vm": GUESTS, "storage": []}.get(kw.get("type"), NODES + GUESTS),
        "nodes/pve1/lxc/101/snapshot": counted("snap101", [{"name": "voor"}, {"name": "current"}]),
        "nodes/pve2/lxc/201/snapshot": stuck, "nodes/pve2/qemu/202/snapshot": stuck,
        "nodes/pve1/status": {"cpu": 0.1, "memory": {"used": 1, "total": 2}, "uptime": 4000},
        "nodes/pve1/lxc": [{"vmid": 101, "status": "running", "cpu": 0.1, "mem": 1, "maxmem": 2, "uptime": 9, "netin": 1000, "netout": 500, "diskread": 7, "diskwrite": 8}],
        "nodes/pve1/qemu": [], "nodes/pve2/status": stuck, "nodes/pve2/lxc": stuck, "nodes/pve2/qemu": stuck,
        "nodes/pve1/version": {"version": "9.2"}, "nodes/pve2/version": stuck})


main.issues.items, main.issues.at = [], time.time() + 3600   # het overzicht wacht niet op de aandachtspunten

# ================================================================ A. een node die via de API niet antwoordt
print("--- A. een node die via de API niet antwoordt")
world()
t0 = time.monotonic()
r = call("GET", "/api/overview", ROOT)
check("overzicht: 200 in plaats van 500", r[0] == 200, str(r[0]) + " " + str(detail(r))[:120])
ov = r[1] if r[0] == 200 else {}
check("de snapshots van de node die wel antwoordt staan erin", ov.get("snapshots", {}).get("101") == 1 or ov.get("snapshots", {}).get(101) == 1, str(ov.get("snapshots")))
check("die van de vastgelopen node zijn leeg (None)", (ov.get("snapshots") or {}).get("201", "x") is None or (ov.get("snapshots") or {}).get(201, "x") is None)
check("de vastgelopen node staat in node_trouble, met zijn adres in het cluster", (ov.get("node_trouble") or {}).get("pve2", {}).get("ip") == "192.168.30.117", str(ov.get("node_trouble")))
check("de node die wel antwoordt niet", "pve1" not in (ov.get("node_trouble") or {}))
COUNT.clear()
r = call("GET", "/api/overview", ROOT)
check("daarna wordt de vastgelopen node overgeslagen: geen nieuwe vraag aan hem", r[0] == 200 and not COUNT.get("stuck"), str(COUNT))
r = call("GET", "/api/live", ROOT)
check("live: 200, alleen de node die antwoordt", r[0] == 200 and set(r[1]["nodes"]) == {"pve1"}, str(r[0]) + " " + str(r[1])[:160])
check("live: de tellers van netwerk en schijf voor de topologie", r[0] == 200 and r[1]["guests"]["101"].get("netin") == 1000 and r[1]["guests"]["101"].get("diskwrite") == 8)
main.node_trouble.clear()
items = main.pve.run(main.gather_issues)
nu = [i for i in items if i["code"] == "node_unreachable"]
check("aandachtspunt: node antwoordt niet via de API (rood, Overzicht), met het adres", len(nu) == 1 and nu[0]["node"] == "pve2" and nu[0]["ip"] == "192.168.30.117"
      and nu[0]["level"] == "error" and nu[0]["tab"] == "overview", str(nu))
check("en geen vals alarm voor pve1", not any(i["code"] == "node_unreachable" and i["node"] == "pve1" for i in items))
# opnieuw nakijken op de achtergrond: de node antwoordt weer
main.node_trouble.failed("pve2", "timeout")
W.table["nodes/pve2/version"] = {"version": "9.2"}
real_api = main.pve.api
main.pve.api = Fake(W)
main.node_trouble._probe("pve2")
check("de draad die opnieuw nakijkt haalt de node eruit zodra hij weer antwoordt", "pve2" not in main.node_trouble.current())
W.table["nodes/pve2/version"] = stuck
main.node_trouble.failed("pve2", "timeout")
main.node_trouble._probe("pve2")
check("antwoordt hij nog niet, dan blijft hij erin", "pve2" in main.node_trouble.current())
main.pve.api = real_api
main.node_trouble.clear()
W.table["nodes/pve2/version"] = counted("v2", ResourceException(595, "Errors during connection establishment, proxy handshake", "No route to host"))
check("Proxmox meldt 595 (geen route naar de node): ook dat telt als niet antwoorden", main.pve.run(lambda api: main.node_answers(api, "pve2")) is False and "pve2" in main.node_trouble.current())
main.node_trouble.clear()
W.table["nodes/pve2/version"] = counted("v2", ResourceException(500, "fout van de node zelf", ""))
check("een gewone foutmelding van de node zelf telt als antwoord", main.pve.run(lambda api: main.node_answers(api, "pve2")) is True and "pve2" not in main.node_trouble.current())
try:
    main.on_node("pve1", lambda: (_ for _ in ()).throw(ResourceException(403, "geen recht", "")))
    check("on_node geeft een 403 door", False)
except ResourceException as e:
    check("on_node geeft een 403 door", e.status_code == 403)
main.node_trouble.failed("pve2", "timeout")
check("overslaan geldt per node", main.node_trouble.skip("pve2") and not main.node_trouble.skip("pve1"))
main.node_trouble.clear()
check("na overschakelen naar een andere host begint de lijst opnieuw", main.node_trouble.current() == {})

# ================================================================ B. meer schema's voor automatisch bijwerken
print("--- B. meer schema's voor automatisch bijwerken")
world()
main.state.change(lambda d: [d.pop(k, None) for k in list(d) if k.startswith("autoupdate")])
r = call("GET", "/api/autoupdate", ROOT)
check("zonder iets bewaard: geen schema's, de standaard uit", r[0] == 200 and r[1]["schedules"] == [] and r[1]["config"]["enabled"] is False and r[1]["max"] == 20, str(r[1])[:200])
# zoals een installatie van voor 1.4 het heeft bewaard
OLD = {"enabled": True, "frequency": "weekly", "day": 6, "monthday": 1, "time": "03:00", "parity": 0, "cts": "list", "ct_list": [101],
       "nodes": False, "backup": "snapshot", "storage": None, "mode": "snapshot"}
LAST = {"started": 1, "finished": int(time.time()) - 3600, "why": "schema", "results": [{"target": "CT 101 web", "code": "failed", "ok": False, "n": 2, "detail": "100"}]}
main.state.change(lambda d: d.update(autoupdate=OLD, autoupdate_ran=12345, autoupdate_config_at=11, autoupdate_last=LAST))
r = call("GET", "/api/autoupdate", ROOT)
s = r[1]["schedules"]
check("het schema van voor 1.4 is vanzelf het eerste (s1), met zijn laatste ronde", len(s) == 1 and s[0]["id"] == "s1" and s[0]["ct_list"] == [101]
      and s[0]["enabled"] and s[0]["last"] == LAST and s[0]["config_at"] == 11, str(s)[:300])
check("de oude velden voor de pagina van voor 1.4 zijn er nog (config, next, last)", r[1]["config"]["id"] == "s1" and "next" in r[1] and r[1]["last"] == LAST)
check("aandachtspunt van de laatste ronde werkt ook met de oude vorm", any(i["code"] == "autoupdate_failed" for i in main.pve.run(main.gather_issues)))
cfg = main.autoupdate_config()
REPORT_TZ = main.REPORT_TZ
at = lambda *a: main.dt.datetime(*a, tzinfo=REPORT_TZ)  # noqa: E731
check("de oude 'al gedraaid' telt nog voor s1", main.autoupdate_due({"autoupdate_ran": at(2026, 10, 18, 3, 1).timestamp()}, {**cfg, "config_at": 0}, at(2026, 10, 18, 3, 5)) is None
      and main.autoupdate_due({}, {**cfg, "config_at": 0}, at(2026, 10, 18, 3, 5)) == at(2026, 10, 18, 3, 0))
body = {"enabled": True, "name": "Websites 's nachts", "frequency": "daily", "day": 0, "monthday": 1, "time": "02:15", "cts": "list", "ct_list": [101, 201],
        "nodes": False, "backup": "snapshot", "storage": None, "mode": "snapshot"}
r = call("POST", "/api/autoupdate/schedules", ROOT, body)
sid = r[1].get("id") if r[0] == 200 else None
check("nieuw schema: een eigen id", r[0] == 200 and sid and main.AUTO_ID_RE.match(sid) and sid != "s1", str(r[0]) + " " + str(detail(r)))
saved = main.state.load()
check("bewaard in de nieuwe vorm; het oude schema is meegekomen", [c["id"] for c in saved["autoupdate_schedules"]] == ["s1", sid]
      and saved["autoupdate_ran_by"].get("s1") == 12345 and saved["autoupdate_last_by"].get("s1") == LAST)
check("het eerste schema staat ook nog op de oude plek (terug naar een oudere versie)", saved["autoupdate"]["ct_list"] == [101] and "id" not in saved["autoupdate"])
check("de naam is bewaard, de tijd van de wijziging ook", next(c for c in saved["autoupdate_schedules"] if c["id"] == sid)["name"] == "Websites 's nachts"
      and next(c for c in saved["autoupdate_schedules"] if c["id"] == sid)["config_at"] > time.time() - 60)
for label, change, code in (("naam met <", {"name": "<b>"}, 400), ("lijst zonder containers", {"ct_list": []}, 400), ("rare tijd", {"time": "25:00"}, 400),
                            ("niets bij te werken", {"cts": "none", "nodes": False}, 400), ("onbekende back-up", {"backup": "alles"}, 400)):
    check(f"nieuw schema geweigerd: {label}", call("POST", "/api/autoupdate/schedules", ROOT, {**body, **change})[0] == code)
r = call("PUT", f"/api/autoupdate/schedules/{sid}", ROOT, {**body, "time": "04:30", "enabled": False})
check("schema bewerken", r[0] == 200 and next(c for c in r[1]["schedules"] if c["id"] == sid)["time"] == "04:30" and len(r[1]["schedules"]) == 2)
check("onbekend schema: 404, rare naam: 400", call("PUT", "/api/autoupdate/schedules/s999", ROOT, body)[0] == 404
      and call("PUT", "/api/autoupdate/schedules/x%2F..", ROOT, body)[0] in (400, 404))
r = call("PUT", "/api/autoupdate", ROOT, {**OLD, "time": "05:00"})
check("PUT /api/autoupdate (zoals voor 1.4) past het eerste schema aan en laat de rest staan", r[0] == 200 and r[1]["schedules"][0]["id"] == "s1"
      and r[1]["schedules"][0]["time"] == "05:00" and len(r[1]["schedules"]) == 2)
for label, method, path, b in (("nieuw", "POST", "/api/autoupdate/schedules", body), ("bewerken", "PUT", f"/api/autoupdate/schedules/{sid}", body),
                               ("verwijderen", "DELETE", f"/api/autoupdate/schedules/{sid}", None), ("nu uitvoeren", "POST", f"/api/autoupdate/schedules/{sid}/run", None)):
    check(f"de lezer mag niet: {label}", call(method, path, READER, b)[0] == 403)
# de planner: twee schema's tegelijk aan de beurt -> het eerste moment eerst, daarna het andere
now = main.dt.datetime.now(REPORT_TZ)
early, late = (now - main.dt.timedelta(minutes=20)).strftime("%H:%M"), (now - main.dt.timedelta(minutes=5)).strftime("%H:%M")
if now.hour == 0 and now.minute < 25:
    early, late = "00:01", "00:02"   # vlak na middernacht: allebei vandaag
main.state.change(lambda d: d.update(autoupdate_schedules=[
    {**main.auto_clean(OLD, "s1"), "frequency": "daily", "time": late, "enabled": True},
    {**main.auto_clean({**body, "time": early}, sid), "enabled": True}], autoupdate_ran_by={}, autoupdate_last_by={}))
ran, real_sleep, real_run = [], main.time.sleep, main.run_autoupdate
ticks = {"n": 0}


class Stop(BaseException):
    pass


def fake_sleep(s):
    ticks["n"] += 1
    if ticks["n"] > 2:
        raise Stop()


main.time.sleep = fake_sleep
main.run_autoupdate = lambda cfg, why="schema": ran.append(cfg["id"]) or True
try:
    main.autoupdate_loop()
except Stop:
    pass
finally:
    main.time.sleep, main.run_autoupdate = real_sleep, real_run
check("planner: allebei aan de beurt, het vroegste moment eerst, daarna het andere", ran == [sid, "s1"], str(ran))
by = main.state.load().get("autoupdate_ran_by") or {}
check("planner: per schema bewaard wanneer het draaide", set(by) == {"s1", sid})
# de uitkomst per schema
main.run_autoupdate = real_run
real_ssh = main.ssh_ready
main.ssh_ready = lambda: False
main.run_autoupdate({**main.auto_clean(body, sid)}, "met de hand")
main.ssh_ready = real_ssh
saved = main.state.load()
check("de laatste ronde staat bij het schema en ook als laatste van allemaal", saved["autoupdate_last_by"][sid]["id"] == sid and saved["autoupdate_last"]["id"] == sid
      and saved["autoupdate_last_by"][sid]["results"][0]["code"] == "nossh")
main.state.change(lambda d: d.update(autoupdate_last_by={"s1": LAST, sid: {"finished": int(time.time()), "results": [{"target": "CT 201 db", "ok": True}]}}))
nu = [i for i in main.pve.run(main.gather_issues) if i["code"] == "autoupdate_failed"]
check("aandachtspunt: per schema de laatste ronde (de mislukte van s1 telt)", len(nu) == 1 and nu[0]["who"] == ["CT 101 web"], str(nu))
main.state.change(lambda d: d.update(autoupdate_last_by={"s1": {**LAST, "finished": int(time.time()) - 8 * 86400}}))
check("ouder dan een week telt niet meer", not any(i["code"] == "autoupdate_failed" for i in main.pve.run(main.gather_issues)))
main.AUTO.update(busy=True, id=sid)
check("verwijderen terwijl het schema draait: 409", call("DELETE", f"/api/autoupdate/schedules/{sid}", ROOT)[0] == 409)
check("nu uitvoeren terwijl er al een ronde loopt: 409", call("POST", f"/api/autoupdate/schedules/{sid}/run", ROOT)[0] == 409)
main.AUTO.update(busy=False, id=None)
r = call("DELETE", f"/api/autoupdate/schedules/{sid}", ROOT)
check("schema verwijderd, met zijn gegevens", r[0] == 200 and [c["id"] for c in r[1]["schedules"]] == ["s1"] and sid not in (main.state.load().get("autoupdate_ran_by") or {}))
check("al verwijderd: 404", call("DELETE", f"/api/autoupdate/schedules/{sid}", ROOT)[0] == 404)
main.state.change(lambda d: d.update(autoupdate_schedules=[main.auto_clean({**body, "name": f"s{i}"}, f"s{i:x}") for i in range(1, 21)]))
check("hooguit 20 schema's", call("POST", "/api/autoupdate/schedules", ROOT, body)[0] == 409)
check("in het Engels", detail(call("POST", "/api/autoupdate/schedules", ROOT, body, cookies={main.LANG_COOKIE: "en"})) == "There can be at most 20 schedules")

# ================================================================ C. labels (tags)
print("--- C. labels")
check("tag_list: zoals Proxmox ze opslaat, zonder dubbele", main.tag_list("web;Prod, prod  db") == ["web", "Prod", "db"] and main.tag_list(None) == [])
cfg = {"hostname": "web", "cores": 1, "memory": 512, "swap": 512, "tags": "web;prod", "digest": "d"}
lim = {"cores": 4, "memory": 4096}
plan = main.edit_plan("lxc", cfg, main.GuestEdit(tags=["web", "prod", "db"]), lim, False)
check("label erbij", plan.get("tags") == "web;prod;db" and "delete" not in plan, str(plan))
plan = main.edit_plan("lxc", cfg, main.GuestEdit(tags=[]), lim, False)
check("alle labels weg: delete tags", plan.get("delete") == "tags" and "tags" not in plan, str(plan))
try:
    main.edit_plan("lxc", cfg, main.GuestEdit(tags=["web", "prod"]), lim, False)
    check("dezelfde labels: niets gewijzigd", False)
except HTTPException as e:
    check("dezelfde labels: niets gewijzigd", e.status_code == 400 and "niets gewijzigd" in e.detail)
check("spaties scheiden labels, zoals in Proxmox", main.edit_plan("lxc", cfg, main.GuestEdit(tags=["web prod db"]), lim, False).get("tags") == "web;prod;db")
for bad in ("-web", "x" * 65, "ä", "<b>", "a/b"):
    try:
        main.edit_plan("lxc", cfg, main.GuestEdit(tags=[bad]), lim, False)
        check(f"ongeldig label geweigerd: {bad[:12]}", False)
    except HTTPException as e:
        check(f"ongeldig label geweigerd: {bad[:12]}", e.status_code == 400)
check("dubbele (hoofdletters) worden er één", main.edit_plan("lxc", cfg, main.GuestEdit(tags=["web", "WEB", "db"]), lim, False).get("tags") == "web;db")
own = {**cfg, "tags": "maintool"}
try:
    main.edit_plan("lxc", own, main.GuestEdit(tags=["prod"]), lim, True)
    check("eigen container: het label maintool blijft", False)
except HTTPException as e:
    check("eigen container: het label maintool blijft", e.status_code == 409)
check("eigen container: een label erbij mag wel", main.edit_plan("lxc", own, main.GuestEdit(tags=["maintool", "infra"]), lim, True).get("tags") == "maintool;infra")
check("de instellingen tonen de labels", main.guest_settings("lxc", cfg)["tags"] == ["web", "prod"])
W.table["cluster/options"] = {"tag-style": "color-map=prod:ff0000:FFFFFF;test:00FF00;kapot:xyz;<x>:FF0000,ordering=config,shape=circle"}
main.TAG_STYLE["at"] = -1e9
check("kleuren uit Proxmox (Tag Style): alleen geldige, in hoofdletters", main.pve.run(main.tag_colors) == {"prod": ["FF0000", "FFFFFF"], "test": ["00FF00", None]},
      str(main.TAG_STYLE))
W.table["cluster/options"] = {}
check("die worden hooguit eens per 5 minuten gelezen", main.pve.run(main.tag_colors) == {"prod": ["FF0000", "FFFFFF"], "test": ["00FF00", None]})
world()
r = call("GET", "/api/overview", ROOT)
check("het overzicht geeft de kleuren mee", r[0] == 200 and "tag_style" in r[1])
W.table.update({"nodes/pve1/lxc/101/config": {"hostname": "web", "cores": 1, "memory": 512, "swap": 512, "tags": "web;Prod", "digest": "d"},
                "nodes/pve1/status": {"cpuinfo": {"cpus": 4}, "memory": {"total": 4 * 2**30}}})
r = call("PUT", "/api/guest/pve1/lxc/101/config", ROOT, {"tags": ["web", "Prod", "db"], "digest": "d"})
check("labels via de pagina: naar Proxmox als a;b;c", r[0] == 200 and W.changes and W.changes[-1][2].get("tags") == "web;Prod;db", str(W.changes[-1:]) + str(detail(r)))
check("de lezer mag geen labels wijzigen", call("PUT", "/api/guest/pve1/lxc/101/config", READER, {"tags": ["x"]})[0] == 403)

# ================================================================ D. logboek van één node
print("--- D. logboek van één node")
world()
CUR = "s=828b28305f5f4a6a9f761817aa04da66;i=f9969;b=62ecbd7934b04f0a9008b20ec;m=1;t=2;x=3"
LINES = [CUR] + [f"Oct 16 14:{i // 60:02d}:{i % 60:02d} pve1 pveproxy[12]: regel {i}" for i in range(6000)] + [CUR]
ASKED = []
W.table["nodes/pve1/journal"] = lambda kw: ASKED.append(kw) or LINES
r = call("GET", "/api/node/pve1/journal?period=1h", READER)
check("systeemlog: ook voor wie alleen mag lezen", r[0] == 200, str(r[0]))
j = r[1] if r[0] == 200 else {}
check("de cursors van de journal zijn geen logregels", not any(x.startswith("s=") for x in j.get("lines", [])))
check("hooguit 5000, de nieuwste, met het totaal erbij", len(j.get("lines", [])) == 5000 and j["lines"][-1].endswith("regel 5999") and j["total"] == 6000 and j["truncated"])
check("periode: since = nu - een uur", ASKED and abs(ASKED[-1].get("since", 0) - (time.time() - 3600)) < 30 and "lastentries" not in ASKED[-1], str(ASKED[-1:]))
call("GET", "/api/node/pve1/journal?period=last", READER)
check("de laatste regels: lastentries, geen since (dat kan Proxmox niet samen)", ASKED[-1] == {"lastentries": 5000}, str(ASKED[-1:]))
check("onbekende periode: 400; onbekende node: 404; rare naam: 400", call("GET", "/api/node/pve1/journal?period=1j", READER)[0] == 400
      and call("GET", "/api/node/pve9/journal", READER)[0] == 404 and call("GET", "/api/node/pv%20e/journal", READER)[0] == 400)
NODES[1]["status"] = "offline"
check("node niet online: 409", call("GET", "/api/node/pve2/journal", READER)[0] == 409)
NODES[1]["status"] = "online"
W.table["nodes/pve2/journal"] = stuck
r = call("GET", "/api/node/pve2/journal", READER)
check("node die niet antwoordt: 503 met wat je eraan doet (geen 401!)", r[0] == 503 and "/etc/hosts" in detail(r), str(r[0]) + " " + str(detail(r)))
r = call("GET", "/api/node/pve2/journal", READER, cookies={main.LANG_COOKIE: "de"})
check("... ook in het Duits", "antwortet nicht" in str(detail(r)), str(detail(r)))
check("zonder inloggen: 401", call("GET", "/api/node/pve1/journal")[0] == 401)
main.node_trouble.clear()
main.state.event("update", "gelukt", node="pve1", target="node", name="", by="admin")
main.state.event("update", "mislukt (code 100)", node="pve2", target="201", name="db", by="admin")
W.table.update({
    "nodes/pve1/services": [{"name": "pveproxy", "desc": "PVE API Proxy Server", "state": "running", "active-state": "active", "unit-state": "enabled"},
                            {"name": "chrony", "desc": "NTP", "state": "dead", "active-state": "inactive", "unit-state": "enabled"}],
    "nodes/pve1/tasks": lambda kw: ([{"upid": "U:fout", "type": "vzdump", "id": "101", "user": "root@pam", "starttime": 50, "endtime": 60, "status": "job errors"}]
                                    if kw.get("errors") else
                                    [{"upid": "U:1", "type": "vzstart", "id": "101", "user": "root@pam", "starttime": 100, "endtime": 101, "status": "OK"},
                                     {"upid": "U:2", "type": "vncproxy", "id": "", "user": "root@pam", "starttime": 200, "status": None}]),
    "cluster/log": [{"time": 1, "node": "pve1", "pri": 3, "tag": "pvedaemon", "user": "root@pam", "msg": "authentication failure"},
                    {"time": 2, "node": "pve2", "pri": 6, "tag": "pvedaemon", "user": "root@pam", "msg": "van een andere node"}]})
r = call("GET", "/api/node/pve1/logbook", READER)
b = r[1] if r[0] == 200 else {}
check("logboek: diensten (op naam)", r[0] == 200 and [s["name"] for s in b.get("services", [])] == ["chrony", "pveproxy"], str(r[0]) + str(detail(r)))
check("logboek: taken, nieuwste eerst, ook een oudere mislukte", [x["upid"] for x in b.get("tasks", [])] == ["U:2", "U:1", "U:fout"]
      and [x["level"] for x in b["tasks"]] == ["running", "info", "error"] and b["tasks"][2]["status"] == "job errors")
check("logboek: alleen de clusterlog van deze node", [e["msg"] for e in b.get("cluster", [])] == ["authentication failure"])
check("logboek: alleen wat de tool op deze node deed", [e["result"] for e in b.get("tool", [])] == ["gelukt"])
check("logboek: het adres in het cluster en de uptime", b.get("ip") == "192.168.30.1" and b.get("uptime") == 4000)

# ================================================================ E. topologie
print("--- E. topologie")
world()
W.table.update({
    "storage": [{"storage": "ceph", "type": "rbd", "shared": 1, "content": "images,rootdir", "pool": "rbd"},
                {"storage": "local", "type": "dir", "content": "iso"}, {"storage": "nas", "type": "nfs", "shared": 1, "server": "192.168.30.50", "export": "/pve", "content": "backup"},
                {"storage": "uit", "type": "nfs", "shared": 1, "disable": 1, "server": "x", "export": "/y"}],
    "nodes/pve1/network": [{"iface": "vmbr0", "type": "bridge", "cidr": "192.168.30.1/24", "gateway": "192.168.30.254", "bridge_ports": "eno1", "bridge_vlan_aware": 1},
                           {"iface": "eno1", "type": "eth"}, {"iface": "vmbr1", "type": "OVSBridge", "ovs_ports": "eno2"}],
    "nodes/pve1/lxc/101/config": counted("cfg101", {"net0": "name=eth0,bridge=vmbr0,tag=20,ip=dhcp", "rootfs": "ceph:vm-101-disk-0,size=8G",
                                                     "mp0": "nas:101/disk.raw,mp=/data", "mp1": "/mnt/host,mp=/host"}),
    "nodes/pve1/rrddata": [{"time": 1, "netin": 100.4, "netout": 50.6}, {"time": 2}],
    "nodes/pve1/ceph/status": {"health": {"status": "HEALTH_OK"}, "pgmap": {"write_bytes_sec": 4096}}})
W.table["nodes/pve2/network"] = stuck
r = call("GET", "/api/topology", READER)
d = r[1] if r[0] == 200 else {}
check("topologie: 200, ook met een node die niet antwoordt", r[0] == 200, str(r[0]) + " " + str(detail(r))[:160])
g101 = next((g for g in d.get("guests", []) if g["vmid"] == 101), {})
check("guest: bridge en VLAN", g101.get("nets") == [{"key": "net0", "bridge": "vmbr0", "tag": 20}], str(g101))
check("guest: de opslag van zijn schijven (geen map van de node)", g101.get("stores") == ["ceph", "nas"], str(g101))
check("geen sjablonen", not any(g["vmid"] == 900 for g in d.get("guests", [])))
check("bridges van een node (ook OVS), met de gateway", [b["iface"] for b in d["nodes"][0]["bridges"]] == ["vmbr0", "vmbr1"] and d.get("gateway") == "192.168.30.254"
      and d["nodes"][0]["bridges"][0]["vlan_aware"] is True)
check("gedeelde opslag; lokale en uitgezette niet", [s["storage"] for s in d.get("storages", [])] == ["ceph", "nas"] and d["storages"][1]["target"] == "192.168.30.50:/pve")
check("stroom van de node uit de RRD (de laatste rij met cijfers)", d.get("rates", {}).get("pve1") == {"in": 100, "out": 51, "time": 1}, str(d.get("rates")))
check("Ceph: lezen en schrijven van het cluster", d.get("ceph") == {"health": "HEALTH_OK", "read": 0, "write": 4096, "recovery": 0}, str(d.get("ceph")))
check("de node die niet antwoordt staat in trouble, zonder stroom", "pve2" in d.get("trouble", []) and "pve2" not in d.get("rates", {}))
COUNT.clear()
call("GET", "/api/topology", READER)
check("de opbouw wordt hooguit eens per minuut gelezen (niet elke keer de configuratie)", not COUNT.get("cfg101"), str(COUNT))
main.TOPO["at"] = -1e9
call("GET", "/api/topology", READER)
check("... en na een minuut wel opnieuw", COUNT.get("cfg101") == 1)

# ================================================================ F. Tool bijwerken met de ZIP van GitHub (1.4.1)
print("--- F. de ZIP van GitHub in één keer aanleveren")
import io as _io, tarfile as _tar, zipfile as _zip  # noqa: E402


class UpReq:   # zoals de pagina het bestand stuurt: de inhoud van het verzoek is het bestand zelf
    def __init__(self, body=b""):
        self.cookies, self.client, self._body = {}, type("C", (), {"host": "test"})(), body
        self.headers = {"origin": f"https://{HOST}", "host": HOST, "content-length": str(len(body))}

    async def stream(self):
        for i in range(0, len(self._body), 65536):
            yield self._body[i:i + 65536]


def upload(data: bytes) -> dict:
    return asyncio.run(main.selfupdate_upload(UpReq(data), main.APP_USER))


def zipped(files: dict) -> bytes:
    buf = _io.BytesIO()
    with _zip.ZipFile(buf, "w", _zip.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def tarred(files: dict) -> bytes:
    buf = _io.BytesIO()
    with _tar.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            info = _tar.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, _io.BytesIO(data))
    return buf.getvalue()


BUILT = main.Path("/tmp/mt-v140/setup.sh")   # het gebouwde setup-bestand van deze versie (de testronde zet het hier neer)
TEMPLATE = b'#!/usr/bin/env bash\n# Proxmox Maintool - setup file (version @VERSION@)\nVERSION="@VERSION@"\n'
REST = {"Proxmox-MainTool-1.4.1/README.md": b"# Proxmox Maintool\n", "Proxmox-MainTool-1.4.1/app/main.py": b"print()\n",
        "Proxmox-MainTool-1.4.1/setup/maintool-setup.template.sh": TEMPLATE}
if not main.UPDATER.is_file() or not BUILT.is_file():
    check("de echte controle van het bijwerkprogramma is te gebruiken (bijwerkprogramma en gebouwd bestand)", False, f"{main.UPDATER} {BUILT}")
else:
    setup = BUILT.read_bytes()
    loose = upload(setup)
    check("los setup-bestand: zoals altijd goedgekeurd", loose.get("ok") is True and "from_archive" not in loose, str({k: loose.get(k) for k in ("ok", "code", "version")}))
    v = upload(zipped({**REST, "Proxmox-MainTool-1.4.1/maintool-setup.sh": setup}))
    check("de ZIP van GitHub in één keer: het setup-bestand eruit gehaald en goedgekeurd", v.get("ok") is True and v.get("version") == loose.get("version")
          and v.get("from_archive") == "Proxmox-MainTool-1.4.1/maintool-setup.sh", str({k: v.get(k) for k in ("ok", "code", "version", "from_archive")}))
    check("klaar om te installeren staat precies het setup-bestand, niet de ZIP", main.UPDATE_FILE.read_bytes() == setup and v.get("sha256") == loose.get("sha256"))
    v = upload(tarred({**REST, "Proxmox-MainTool-1.4.1/maintool-setup.sh": setup}))
    check("de tar.gz van GitHub ook", v.get("ok") is True and v.get("from_archive") == "Proxmox-MainTool-1.4.1/maintool-setup.sh", str({k: v.get(k) for k in ("ok", "code")}))
    v = upload(zipped({"maintool-setup.sh": setup}))
    check("een ZIP met alleen het setup-bestand", v.get("ok") is True and v.get("from_archive") == "maintool-setup.sh")
    v = upload(zipped({**REST, "Proxmox-MainTool-1.4.1/maintool-setup.sh": setup[:-5000]}))
    check("beschadigd setup-bestand in de ZIP: geweigerd door dezelfde controle", v.get("ok") is False and v.get("code") in ("damaged", "bad_content"), str(v.get("code")))
main.UPDATE_FILE.unlink(missing_ok=True)
for label, data, code in (("ZIP van versie 1.4 of ouder (alleen het sjabloon in setup/)", zipped({"Proxmox-MainTool-1.4/setup/maintool-setup.sh": TEMPLATE, "Proxmox-MainTool-1.4/README.md": b"x"}), "archive_old"),
                          ("tar.gz van versie 1.4 of ouder", tarred({"Proxmox-MainTool-1.4/setup/maintool-setup.sh": TEMPLATE}), "archive_old"),
                          ("ZIP zonder setup-bestand", zipped({"foto.jpg": b"\xff\xd8"}), "archive_empty"),
                          ("ZIP met twee setup-bestanden", zipped({"a/maintool-setup.sh": b"#!", "b/maintool-setup.sh": b"#!"}), "archive_empty"),
                          ("kapotte ZIP", b"PK\x03\x04" + b"rommel" * 100, "damaged"),
                          ("kapotte tar.gz", b"\x1f\x8b" + b"rommel" * 100, "damaged"),
                          ("setup-bestand in de ZIP groter dan 20 MB", zipped({"x/maintool-setup.sh": b"\0" * (main.UPDATE_MAX + 10)}), "too_big")):
    v = upload(data)
    check(f"geweigerd met een eigen melding: {label}", v == {"ok": False, "code": code} and not main.UPDATE_FILE.exists(), str(v))
v = upload(TEMPLATE + b"echo nog geen tool\n")
check("het sjabloon uit setup/ los aangeleverd: melding 'source'", v.get("ok") is False and v.get("code") == "source", str(v.get("code")))
v = upload(b"print('main.py')\n")
check("een ander bestand: gewoon 'geen setup-bestand'", v.get("ok") is False and v.get("code") == "not_a_package", str(v.get("code")))
check("na een weigering blijft er niets klaarstaan", not main.UPDATE_FILE.exists())
page = main.INDEX.read_text(encoding="utf-8")
check("de pagina heeft een tekst voor elke nieuwe melding", all(f"{c}:" in page for c in ("archive_old", "archive_empty", "source")))

check("het echte cluster is niet aangeraakt", not TRIPPED, str(TRIPPED))
print()
print("ALLES GOED" if not FAILED else f"FOUT ({len(FAILED)}): {FAILED}")
