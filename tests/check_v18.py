"""Tests version 1.8 of the backend in-process on the tool container, from a copy in /tmp with its own state folder:
the IP settings of a guest (edit dialog) and VM/CT tiles on the dashboard. Everything that changes something runs
against a stand-in cluster that only writes down what it is asked to do; the real cluster is only read (every real
guest's network configuration must come back unchanged). No secrets are used or shown."""
import asyncio, base64, datetime as dt, hashlib, hmac, json, os, secrets, subprocess, sys, tempfile, time, urllib.parse
for line in open("/etc/maintool/maintool.env", encoding="utf-8"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ[k.strip()] = v.strip()
os.environ["STATE_DIRECTORY"] = "/tmp/mt-v18/state"
sys.path.insert(0, "/tmp/mt-v18/app")
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
NI = main.NicIp


def plan_reason(kind, **kw):
    try:
        return main.ip_plan(kind, "net0", NI(**kw))
    except HTTPException as e:
        return "FOUT: " + e.detail


print("--- A. IP-instellingen nakijken")
check("vast adres wordt netjes geschreven", plan_reason("lxc", ip="192.168.30.050/24".replace("050", "50"), gw="192.168.30.1") == {"ip": "192.168.30.50/24", "gw": "192.168.30.1", "ip6": "", "gw6": ""})
check("DHCP en automatisch IPv6", plan_reason("lxc", ip="dhcp", ip6="auto") == {"ip": "dhcp", "gw": "", "ip6": "auto", "gw6": ""})
check("handmatig mag bij een container", plan_reason("lxc", ip="manual", ip6="manual")["ip"] == "manual")
check("IPv6 vast met gateway (ook link-local)", plan_reason("lxc", ip6="2001:DB8::50/64", gw6="fe80::1") == {"ip": "", "gw": "", "ip6": "2001:db8::50/64", "gw6": "fe80::1"})
check("/32 met een gateway buiten het netwerk mag", plan_reason("lxc", ip="203.0.113.7/32", gw="198.51.100.1")["gw"] == "198.51.100.1")
for label, kind, kw, want in [
        ("zonder voorvoegsel", "lxc", {"ip": "192.168.30.50"}, "adres/voorvoegsel"),
        ("onzin", "lxc", {"ip": "192.168.300.1/24"}, "adres/voorvoegsel"),
        ("voorvoegsel 33", "lxc", {"ip": "192.168.1.5/33"}, "adres/voorvoegsel"),
        ("het netwerkadres", "lxc", {"ip": "192.168.1.0/24"}, "broadcastadres"),
        ("het broadcastadres", "lxc", {"ip": "192.168.1.255/24"}, "broadcastadres"),
        ("loopback", "lxc", {"ip": "127.0.0.5/8"}, "kan niet voor een guest"),
        ("multicast", "lxc", {"ip": "224.0.0.5/24"}, "kan niet voor een guest"),
        ("gateway buiten het netwerk", "lxc", {"ip": "192.168.1.5/24", "gw": "10.0.0.1"}, "ligt niet in het netwerk 192.168.1.0/24"),
        ("gateway gelijk aan het adres", "lxc", {"ip": "192.168.1.5/24", "gw": "192.168.1.5"}, "hetzelfde"),
        ("gateway bij DHCP", "lxc", {"ip": "dhcp", "gw": "192.168.1.1"}, "alleen bij een vast"),
        ("ongeldige gateway", "lxc", {"ip": "192.168.1.5/24", "gw": "192.168.1"}, "Ongeldige gateway"),
        ("IPv6 zonder voorvoegsel", "lxc", {"ip6": "2001:db8::5"}, "adres/voorvoegsel"),
        ("IPv6-gateway zonder vast IPv6-adres", "lxc", {"ip6": "auto", "gw6": "fe80::1"}, "alleen bij een vast"),
        ("handmatig bij een VM", "qemu", {"ip": "manual"}, "adres/voorvoegsel"),
        ("IPv6 handmatig bij een VM", "qemu", {"ip6": "manual"}, "adres/voorvoegsel")]:
    r = plan_reason(kind, **kw)
    check(f"geweigerd: {label}", isinstance(r, str) and want in r, str(r))

LINE = "name=eth0,bridge=vmbr0,firewall=1,gw=192.168.30.1,hwaddr=BC:24:11:AA:BB:CC,ip=192.168.30.56/24,ip6=auto,rate=50,tag=20,type=veth"
same = {"ip": "192.168.30.56/24", "gw": "192.168.30.1", "ip6": "auto", "gw6": ""}
check("een regel met dezelfde instellingen blijft letterlijk gelijk", main.ct_net_line(LINE, same) == LINE)
new = main.ct_net_line(LINE, {"ip": "192.168.30.71/24", "gw": "192.168.30.1", "ip6": "", "gw6": ""})
check("een nieuw adres verandert alleen ip (op zijn plek) en haalt ip6 weg; MAC, VLAN, firewall en de rest blijven",
      new == "name=eth0,bridge=vmbr0,firewall=1,gw=192.168.30.1,hwaddr=BC:24:11:AA:BB:CC,ip=192.168.30.71/24,rate=50,tag=20,type=veth", new)
new = main.ct_net_line("name=eth0,bridge=vmbr0,hwaddr=BC:24:11:AA:BB:CC,ip=dhcp,type=veth", {"ip": "192.168.30.71/24", "gw": "192.168.30.1", "ip6": "2001:db8::7/64", "gw6": ""})
check("wat er nog niet stond komt erachter", new == "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:AA:BB:CC,ip=192.168.30.71/24,type=veth,gw=192.168.30.1,ip6=2001:db8::7/64", new)
check("DNS: drie servers, IPv4 en IPv6, komma's of spaties", main.dns_plan("1.1.1.1, 9.9.9.9 2606:4700::1111", "thuis.lan") == ("1.1.1.1 9.9.9.9 2606:4700::1111", "thuis.lan"))
check("DNS leeg = zoals de node", main.dns_plan("", "") == ("", ""))
for label, ns, sd in [("vier servers", "1.1.1.1 2.2.2.2 3.3.3.3 4.4.4.4", None), ("naam in plaats van adres", "dns.google", None), ("zoekdomein met spatie-teken", None, "thuis lan!")]:
    try:
        main.dns_plan(ns, sd)
        check(f"geweigerd: {label}", False)
    except HTTPException as e:
        check(f"geweigerd: {label}", e.status_code == 400, e.detail)

print("--- B. via het venster van de steeksleutel (nagebootst cluster)")
GiB = 2 ** 30
CT = {"hostname": "proef", "cores": 2, "memory": 1024, "swap": 512, "digest": "d1", "rootfs": "ceph-pool:vm-901-disk-0,size=8G", "nameserver": "192.168.30.1",
      "net0": LINE, "net1": "name=eth1,bridge=vmbr1,hwaddr=BC:24:11:00:00:01,ip=10.10.0.5/24,type=veth"}
VMCI = {"name": "vmci", "cores": 2, "memory": 2048, "digest": "e1", "scsi0": "ceph-pool:vm-902-disk-0,size=32G", "ide2": "ceph-pool:vm-902-cloudinit,media=cdrom",
        "net0": "virtio=BC:24:11:00:00:02,bridge=vmbr0", "ipconfig0": "ip=dhcp"}
VMNO = {"name": "vmkaal", "cores": 2, "memory": 2048, "digest": "f1", "scsi0": "ceph-pool:vm-903-disk-0,size=32G", "net0": "virtio=BC:24:11:00:00:03,bridge=vmbr0"}
OWN = {"hostname": main.socket.gethostname(), "cores": 1, "memory": 512, "digest": "o1", "net0": "name=eth0,bridge=vmbr0,ip=192.168.30.202/24,gw=192.168.30.1"}
OTHER = {"hostname": "ander", "net0": "name=eth0,bridge=vmbr0,ip=192.168.30.253/24"}
W.table.update({
    "cluster/resources": [{"vmid": 901, "node": "n1", "type": "lxc", "name": "proef", "status": "running"},
                          {"vmid": 902, "node": "n1", "type": "qemu", "name": "vmci", "status": "running"},
                          {"vmid": 903, "node": "n1", "type": "qemu", "name": "vmkaal", "status": "stopped"},
                          {"vmid": 904, "node": "n1", "type": "lxc", "name": main.socket.gethostname(), "status": "running"},
                          {"vmid": 905, "node": "n1", "type": "lxc", "name": "ander", "status": "running"}],
    "nodes/n1/status": {"cpuinfo": {"cpus": 8}, "memory": {"total": 16 * GiB}},
    "nodes/n1/lxc/901/config": lambda kw: dict(CT), "nodes/n1/qemu/902/config": lambda kw: dict(VMCI), "nodes/n1/qemu/903/config": lambda kw: dict(VMNO),
    "nodes/n1/lxc/904/config": lambda kw: dict(OWN), "nodes/n1/lxc/905/config": lambda kw: dict(OTHER),
    "nodes/n1/storage/ceph-pool/status": {"avail": 100 * GiB}, "nodes/n1/qemu/902/pending": [{"key": "ipconfig0", "value": "ip=192.168.30.80/24", "pending": "x"}],
    "cluster/status": [{"type": "node", "name": "n1", "ip": "192.168.30.1"}]})
main.login_guard.failures.clear()
ROOT = session_of(call("POST", "/api/login", body={"username": main.APP_USER, "password": main.APP_PASSWORD})[2])
PW = secrets.token_urlsafe(18)
call("POST", "/api/users", ROOT, {"name": "netwerk", "roles": ["network"], "password": PW})
NETW = session_of(call("POST", "/api/login", body={"username": "netwerk", "password": PW})[2])
r = call("GET", "/api/guest/n1/lxc/901/config", ROOT)
check("het venster krijgt de netwerkkaarten met hun IP-instellingen en DNS", r[0] == 200 and [n["key"] for n in r[1]["nets"]] == ["net0", "net1"]
      and r[1]["nets"][0] | {} == {"key": "net0", "name": "eth0", "bridge": "vmbr0", "tag": 20, "ip": "192.168.30.56/24", "gw": "192.168.30.1", "ip6": "auto", "gw6": ""}
      and r[1]["nameserver"] == "192.168.30.1" and r[1]["cloudinit"] is False, json.dumps(r[1].get("nets"))[:200])
check("VM met cloud-init: cloudinit waar, adres uit ipconfig0", call("GET", "/api/guest/n1/qemu/902/config", ROOT)[1]["cloudinit"] is True
      and call("GET", "/api/guest/n1/qemu/902/config", ROOT)[1]["nets"][0]["ip"] == "dhcp")
check("VM zonder cloud-init: cloudinit onwaar", call("GET", "/api/guest/n1/qemu/903/config", ROOT)[1]["cloudinit"] is False)
W.changes.clear()
cur0 = {"ip": "192.168.30.56/24", "gw": "192.168.30.1", "ip6": "auto", "gw6": ""}
r = call("PUT", "/api/guest/n1/lxc/901/config", ROOT, {"nets": {"net0": cur0}, "nameserver": "192.168.30.1", "digest": "d1"})
check("dezelfde instellingen opnieuw: niets gewijzigd, niets naar het cluster", r[0] == 400 and W.changes == [], detail(r))
r = call("PUT", "/api/guest/n1/lxc/901/config", ROOT, {"nets": {"net0": {**cur0, "ip": "192.168.30.71/24"}}, "digest": "d1"})
sent = W.changes[-1][2] if W.changes else {}
check("CT: nieuw adres -> alleen net0, met de rest van de regel ongemoeid, en het controlegetal",
      r[0] == 200 and set(sent) == {"net0", "digest"} and sent["net0"] == LINE.replace("192.168.30.56", "192.168.30.71") and sent["digest"] == "d1", json.dumps(sent))
check("het antwoord noemt net0 als gewijzigd", r[1].get("changed") == ["net0"], json.dumps(r[1]))
W.changes.clear()
r = call("PUT", "/api/guest/n1/lxc/901/config", ROOT, {"nets": {"net0": {**cur0, "ip": "192.168.30.253/24"}}})
check("adres van een andere guest: 409 met wie, niets gestuurd", r[0] == 409 and "905 ander" in detail(r) and W.changes == [], detail(r))
r = call("PUT", "/api/guest/n1/lxc/901/config", ROOT, {"nets": {"net0": {**cur0, "ip": "192.168.30.1/24", "gw": ""}}})
check("adres van een node: 409", r[0] == 409 and "node n1" in detail(r) and W.changes == [], detail(r))
r = call("PUT", "/api/guest/n1/lxc/901/config", ROOT, {"nets": {"net1": {"ip": "192.168.30.56/24", "gw": "", "ip6": "", "gw6": ""}}})
check("twee kaarten met hetzelfde adres: 400", r[0] == 400 and "hetzelfde adres" in detail(r) and W.changes == [], detail(r))
r = call("PUT", "/api/guest/n1/lxc/901/config", ROOT, {"nets": {"net7": cur0}})
check("netwerkkaart die er niet is: 400", r[0] == 400 and W.changes == [])
r = call("PUT", "/api/guest/n1/lxc/901/config", ROOT, {"nets": {"eth0": cur0}})
check("rare naam van een kaart: 400", r[0] == 400 and W.changes == [])
r = call("PUT", "/api/guest/n1/lxc/901/config", ROOT, {"nameserver": "", "searchdomain": "thuis.lan"})
sent = W.changes[-1][2] if W.changes else {}
check("DNS leeg = weghalen, zoekdomein zetten", r[0] == 200 and sent.get("searchdomain") == "thuis.lan" and sent.get("delete") == "nameserver"
      and sorted(r[1]["changed"]) == ["nameserver", "searchdomain"], json.dumps(sent))
W.changes.clear()
r = call("PUT", "/api/guest/n1/lxc/904/config", ROOT, {"nets": {"net0": {"ip": "192.168.30.99/24", "gw": "192.168.30.1", "ip6": "", "gw6": ""}}})
check("eigen container: IP wijzigen geweigerd", r[0] == 409 and "eigen container" in detail(r) and W.changes == [], detail(r))
r = call("PUT", "/api/guest/n1/lxc/904/config", ROOT, {"nameserver": "9.9.9.9"})
check("eigen container: DNS wijzigen ook geweigerd", r[0] == 409 and W.changes == [])
r = call("PUT", "/api/guest/n1/qemu/903/config", ROOT, {"nets": {"net0": {"ip": "192.168.30.81/24", "gw": "", "ip6": "", "gw6": ""}}})
check("VM zonder cloud-init: geweigerd met uitleg", r[0] == 409 and "cloud-init" in detail(r) and W.changes == [], detail(r))
r = call("PUT", "/api/guest/n1/qemu/902/config", ROOT, {"nets": {"net0": {"ip": "192.168.30.80/24", "gw": "192.168.30.1", "ip6": "", "gw6": ""}}})
sent = W.changes[-1][2] if W.changes else {}
check("VM met cloud-init: ipconfig0 wordt ip=...,gw=...; net0 zelf blijft; geldt na herstart",
      r[0] == 200 and sent.get("ipconfig0") == "ip=192.168.30.80/24,gw=192.168.30.1" and "net0" not in sent and r[1]["pending"] == ["ipconfig0"], json.dumps(r[1]))
r = call("PUT", "/api/guest/n1/qemu/902/config", ROOT, {"nets": {"net0": {"ip": "", "gw": "", "ip6": "", "gw6": ""}}})
sent = W.changes[-1][2] if W.changes else {}
check("VM: alles leeg haalt ipconfig0 weg", r[0] == 200 and sent.get("delete") == "ipconfig0", json.dumps(sent))
W.changes.clear()
r = call("PUT", "/api/guest/n1/lxc/901/config", NETW, {"nets": {"net0": {**cur0, "ip": "192.168.30.72/24"}}})
check("een netwerkbeheerder zonder overzichtsrol mag dit venster niet", r[0] == 403 and W.changes == [])
r = call("PUT", "/api/guest/n1/lxc/901/config", ROOT, {"nets": {"net0": {**cur0, "ip": "192.168.30.72/24"}}}, origin="https://kwaad.example")
check("vanaf een andere website geweigerd", r[0] == 403 and W.changes == [])
r = call("PUT", "/api/guest/n1/lxc/901/config", ROOT, {"nets": {"net0": {**cur0, "ip": "x" * 70}}})
check("te lang veld: 422", r[0] == 422)
r = call("PUT", "/api/guest/n1/lxc/901/config", ROOT, {"name": "proef2", "nets": {"net0": {**cur0, "gw": "10.1.1.1"}}})
check("een fout in het netwerk houdt de rest ook tegen (niets half opgeslagen)", r[0] == 400 and W.changes == [], detail(r))

print("--- C. tegels voor VM's en CT's op het dashboard")
dash = {"layout": [{"id": "guest:101", "x": 0, "y": 0, "w": 8, "h": 5}, {"id": "nums", "x": 8, "y": 0, "w": 6, "h": 6}], "hidden": ["guest:102"], "live": 5, "history": 60, "fit": False}
r = call("PUT", "/api/settings", ROOT, {"dashboard": dash})
check("tegel guest:101 wordt bewaard", r[0] == 200 and r[1]["dashboard"]["layout"][0]["id"] == "guest:101", detail(r) or "")
for bad in ("guest:abc", "guest:", "guest:1234567890", "guest:-1"):
    r = call("PUT", "/api/settings", ROOT, {"dashboard": {**dash, "layout": [{"id": bad, "x": 0, "y": 0, "w": 8, "h": 5}]}})
    check(f"geweigerd: tegel {bad}", r[0] == 400)
TRIPPED = [x for x in TRIPPED if not (x[0] == "agent" and tuple(x[1][1:]) == ("info", "cts"))]   # de bewaker van de updates (alleen lezen, tegengehouden)
check("niets heeft het echte cluster of een node bereikt", not TRIPPED, str(TRIPPED))

print("--- D. het echte cluster, alleen lezen: elke netwerkregel komt ongewijzigd terug")
main.pve.run, main.pve.connect = REAL_RUN, REAL_CONNECT


def all_configs(api):
    out = []
    for g in api.cluster.resources.get(type="vm"):
        if not g.get("template"):
            out.append((g, main.guest(api, g["node"], g["type"], g["vmid"]).config.get()))
    return out


configs = main.pve.run(all_configs)
nics, same_lines = 0, True
for g, cfg in configs:
    ipset = main.guest_ip_settings(g["type"], cfg)
    for n in ipset["nets"]:
        nics += 1
        if g["type"] == "lxc" and main.ct_net_line(cfg[n["key"]], {p: n[p] for p in main.IP_PARTS}) != cfg[n["key"]]:
            same_lines = False
            print("     anders:", g["vmid"], n["key"])
    body = main.GuestEdit(nets={n["key"]: main.NicIp(**{p: n[p] for p in main.IP_PARTS}) for n in ipset["nets"]})
    try:
        extra = main.ip_changes(g["type"], cfg, body, False, {}, [])
        unchanged = extra == {}
    except HTTPException as e:
        unchanged = False
        print("     fout:", g["vmid"], e.detail)
    if not unchanged:
        same_lines = False
check(f"alle {nics} netwerkkaarten van {len(configs)} echte guests: de huidige instellingen geven geen enkele wijziging", same_lines and nics > 0)
print("     bv. " + ", ".join(f"{g['vmid']} {n['key']} {n['ip'] or '-'}" for g, cfg in configs[:4] for n in main.guest_ip_settings(g['type'], cfg)['nets'][:1]))

print()
print("ALLES GOED" if not FAILED else f"FOUT ({len(FAILED)}): {FAILED}")
