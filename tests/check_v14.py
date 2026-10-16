"""Tests version 1.4 of the backend (tabs Netwerken and Events) in-process on the tool container, from a copy in /tmp
with its own state folder. Nothing on the cluster's network is created, applied or removed:

Part A checks the rules for new VLANs against made-up situations (pure functions that change nothing).
Part B runs the changing addresses against a stand-in cluster that only records what it is asked to do, with the real
       connection replaced by a tripwire.
Part C only reads from the real cluster (network overview, events), and sends two requests that are built to be
       refused before anything could be sent to Proxmox. No secrets are printed."""
import asyncio, json, os, secrets, sys, time
for line in open("/etc/maintool/maintool.env", encoding="utf-8"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ[k.strip()] = v.strip()
os.environ["STATE_DIRECTORY"] = "/tmp/mt-v14/state"
sys.path.insert(0, "/tmp/mt-v14/app")
import main  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from proxmoxer.core import ResourceException  # noqa: E402

FAILED = []


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


def call(method, path, cookie=None, body=None, origin=f"https://{HOST}"):
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
    try:
        return start["status"], json.loads(raw)
    except ValueError:
        return start["status"], raw.decode("utf-8", "replace")


def detail(reply):
    return reply[1].get("detail") if isinstance(reply[1], dict) else str(reply[1])[:80]


print("versie:", main.VERSION, "| eigen map voor de test:", main.STATE_DIR)
waited = 0
while main.updates.busy and waited < 300:
    time.sleep(2)
    waited += 2

# ================================================================== deel A: de regels, tegen verzonnen situaties
print("\n--- deel A: regels voor nieuwe VLAN's (verandert niets)")


def iface(name, kind, cidr=None, **more):
    return {"iface": name, "type": kind, "active": True, "autostart": True, "cidr": cidr, "cidr6": None, "gateway": None, "gateway6": None,
            "ports": None, "vlan_aware": False, "vlan_id": None, "vlan_raw": None, "bond_mode": None, "mtu": None, "comment": None, **more}


def node(*extra, pending=None):
    return {"ifaces": [iface("vmbr0", "bridge", "192.168.30.1/24", ports="eno1"), iface("eno1", "eth"), *extra], "pending": pending,
            "dns": {"search": None, "servers": []}}


EMPTY = {"zones": [], "vnets": [], "pending": False}
NET = {"nodes": {"n1": node(), "n2": node(), "n3": node()}, "sdn": EMPTY}
V, L = main.VnetIn, main.VlanIn
plan = main.vnet_plan(NET, V(name=" Gasten ", tag=20, bridge="vmbr0", alias="Gasten wifi"))
check("eerste VLAN: er komt een zone bij voor deze bridge, daarna het VNet", plan == {"name": "gasten", "tag": 20, "alias": "Gasten wifi", "zone": "vlans",
      "new_zone": {"zone": "vlans", "type": "vlan", "bridge": "vmbr0"}}, json.dumps(plan))
HAVE = {"nodes": NET["nodes"], "sdn": {"zones": [{"zone": "vlans", "type": "vlan", "bridge": "vmbr0", "state": None}],
        "vnets": [{"vnet": "gasten", "zone": "vlans", "tag": 20, "alias": None, "state": None, "status": {}}], "pending": False}}
plan = main.vnet_plan(HAVE, V(name="iot", tag=30, bridge="vmbr0"))
check("volgend VLAN op dezelfde bridge: de bestaande zone wordt hergebruikt", plan["zone"] == "vlans" and plan["new_zone"] is None and plan["alias"] == "")
for label, net, body, code in [
        ("naam met hoofdletters en streepje", NET, V(name="Mijn-Net", tag=20, bridge="vmbr0"), 400),
        ("naam van één teken", NET, V(name="a", tag=20, bridge="vmbr0"), 400),
        ("naam langer dan 8 tekens", NET, V(name="veeltelang", tag=20, bridge="vmbr0"), 400),
        ("naam die met een cijfer begint", NET, V(name="20net", tag=20, bridge="vmbr0"), 400),
        ("VLAN-nummer 0", NET, V(name="gasten", tag=0, bridge="vmbr0"), 400),
        ("VLAN-nummer 4095", NET, V(name="gasten", tag=4095, bridge="vmbr0"), 400),
        ("omschrijving met vreemde tekens", NET, V(name="gasten", tag=20, bridge="vmbr0", alias="x; rm -rf /"), 400),
        ("bridge die niet bestaat", NET, V(name="gasten", tag=20, bridge="vmbr9"), 400),
        ("bridge met vreemde tekens", NET, V(name="gasten", tag=20, bridge="vmbr0;x"), 400),
        ("een netwerkkaart in plaats van een bridge", NET, V(name="gasten", tag=20, bridge="eno1"), 400),
        ("bridge die op één node ontbreekt", {"nodes": {**NET["nodes"], "n3": {"ifaces": [iface("eno1", "eth")], "pending": None, "dns": {}}}, "sdn": EMPTY}, V(name="gasten", tag=20, bridge="vmbr0"), 400),
        ("een node die geen antwoord gaf", {"nodes": {**NET["nodes"], "n3": None}, "sdn": EMPTY}, V(name="gasten", tag=20, bridge="vmbr0"), 409),
        ("cluster zonder SDN", {"nodes": NET["nodes"], "sdn": None}, V(name="gasten", tag=20, bridge="vmbr0"), 409),
        ("naam die al een VLAN is", HAVE, V(name="gasten", tag=21, bridge="vmbr0"), 409),
        ("naam die al een interface is", NET, V(name="vmbr0", tag=21, bridge="vmbr0"), 409),
        ("naam die al een zone is", HAVE, V(name="vlans", tag=21, bridge="vmbr0"), 409),
        ("VLAN-nummer dat op deze bridge al bestaat", HAVE, V(name="dubbel", tag=20, bridge="vmbr0"), 409)]:
    e = refused(main.vnet_plan, net, body)
    check(f"VLAN voor guests geweigerd: {label}", e is not None and e.status_code == code, getattr(e, "detail", "NIET GEWEIGERD"))
full = {"nodes": NET["nodes"], "sdn": {"zones": [{"zone": z, "type": "simple", "bridge": None, "state": None} for z in ["vlans"] + [f"vlans{i}" for i in range(2, 10)]], "vnets": [], "pending": False}}
e = refused(main.vnet_plan, full, V(name="gasten", tag=20, bridge="vmbr0")); check("geen vrije naam meer voor een zone: geweigerd", e and e.status_code == 409, getattr(e, "detail", ""))
taken = {"nodes": NET["nodes"], "sdn": {"zones": [{"zone": "vlans", "type": "simple", "bridge": None, "state": None}], "vnets": [], "pending": False}}
check("de naam 'vlans' is al een andere soort zone: de nieuwe heet vlans2", main.vnet_plan(taken, V(name="gasten", tag=20, bridge="vmbr0"))["new_zone"]["zone"] == "vlans2")

params = main.vlan_plan(node(), L(node="n1", device="vmbr0", tag=20, cidr="192.168.20.5/24", comment="Opslagnet"))
check("VLAN-interface met adres", params == {"iface": "vmbr0.20", "type": "vlan", "autostart": 1, "cidr": "192.168.20.5/24", "comments": "Opslagnet"}, json.dumps(params))
check("VLAN-interface zonder adres en opmerking", main.vlan_plan(node(), L(node="n1", device="eno1", tag=4094)) == {"iface": "eno1.4094", "type": "vlan", "autostart": 1})
check("er gaat nooit een gateway mee", "gateway" not in params)
for label, net, body, code in [
        ("node gaf geen antwoord", None, L(node="n1", device="vmbr0", tag=20), 409),
        ("er staan al wijzigingen klaar", node(pending="--- a\n+++ b"), L(node="n1", device="vmbr0", tag=20), 409),
        ("VLAN-nummer 0", node(), L(node="n1", device="vmbr0", tag=0), 400),
        ("VLAN-nummer 5000", node(), L(node="n1", device="vmbr0", tag=5000), 400),
        ("onderliggende interface bestaat niet", node(), L(node="n1", device="vmbr7", tag=20), 400),
        ("onderliggende interface is zelf een VLAN", node(iface("vmbr0.5", "vlan", vlan_id=5, vlan_raw="vmbr0")), L(node="n1", device="vmbr0.5", tag=20), 400),
        ("naam wordt te lang", node(iface("eenlangenaam1", "eth")), L(node="n1", device="eenlangenaam1", tag=20), 400),
        ("VLAN bestaat al (zelfde naam)", node(iface("vmbr0.20", "vlan", vlan_id=20, vlan_raw="vmbr0")), L(node="n1", device="vmbr0", tag=20), 409),
        ("VLAN bestaat al (andere naam, zelfde nummer en ondergrond)", node(iface("vlan20", "vlan", vlan_id=20, vlan_raw="vmbr0")), L(node="n1", device="vmbr0", tag=20), 409),
        ("adres zonder /", node(), L(node="n1", device="vmbr0", tag=20, cidr="192.168.20.5"), 400),
        ("adres is geen adres", node(), L(node="n1", device="vmbr0", tag=20, cidr="hallo/24"), 400),
        ("IPv6-adres", node(), L(node="n1", device="vmbr0", tag=20, cidr="fd00::5/64"), 400),
        ("het netwerkadres zelf", node(), L(node="n1", device="vmbr0", tag=20, cidr="192.168.20.0/24"), 400),
        ("het broadcastadres", node(), L(node="n1", device="vmbr0", tag=20, cidr="192.168.20.255/24"), 400),
        ("/31", node(), L(node="n1", device="vmbr0", tag=20, cidr="192.168.20.5/31"), 400),
        ("adres in het netwerk dat de node al heeft", node(), L(node="n1", device="vmbr0", tag=20, cidr="192.168.30.77/24"), 409),
        ("groter netwerk dat het bestaande omvat", node(), L(node="n1", device="vmbr0", tag=20, cidr="192.168.0.5/16"), 409),
        ("opmerking met vreemde tekens", node(), L(node="n1", device="vmbr0", tag=20, comment="a\nb"), 400)]:
    e = refused(main.vlan_plan, net, body)
    check(f"VLAN-interface geweigerd: {label}", e is not None and e.status_code == code, getattr(e, "detail", "NIET GEWEIGERD"))

# ================================================================== deel B: de wijzigende adressen tegen een nagebootst cluster
print("\n--- deel B: wijzigen tegen een nagebootst cluster dat alleen opschrijft wat het gevraagd wordt")
TRIPPED = []
REAL_RUN, REAL_CONNECT = main.pve.run, main.pve.connect


class World:
    """A stand-in cluster: answers reads from a table and writes down every change it is asked to make."""
    def __init__(self):
        self.nodes = {"n1": node(), "n2": node(), "n3": node()}
        self.offline, self.zones, self.vnets, self.changes, self.guests = set(), [], [], [], {}
        self.store = {"session": self, "base_url": "https://nagebootst/api2/json"}

    def request(self, method, url, timeout=None):   # the raw request for pending changes
        name = url.split("/nodes/")[1].split("/")[0]
        world = self
        return type("R", (), {"status_code": 200, "json": lambda s: {"data": [], "changes": world.nodes[name]["pending"]}})()

    def call(self, method, path, kw):
        parts = path.split("/")
        if method != "GET":
            self.changes.append((method, path, kw))
            if path == "cluster/sdn":
                return "UPID:n2:0000AAAA:0000BBBB:65000000:reloadnetworkall::maintool@pve!x:"
            if method == "PUT" and path.endswith("/network"):
                return f"UPID:{parts[1]}:0000AAAA:0000BBBB:65000000:srvreload:networking:maintool@pve!x:"
            return None
        if path == "nodes":
            return [{"node": n, "status": "offline" if n in self.offline else "online"} for n in self.nodes]
        if path == "cluster/sdn/zones":
            return self.zones
        if path == "cluster/sdn/vnets":
            return self.vnets
        if path == "cluster/resources":
            return [{"vmid": v, "type": "lxc", "node": "n1", "name": f"g{v}", "status": "stopped"} for v in self.guests]
        if len(parts) == 3 and parts[0] == "nodes" and parts[2] == "network":
            return [{"iface": i["iface"], "type": i["type"], "cidr": i["cidr"], "active": 1, "vlan-id": i["vlan_id"], "vlan-raw-device": i["vlan_raw"]}
                    for i in self.nodes[parts[1]]["ifaces"]]
        if len(parts) == 3 and parts[0] == "nodes" and parts[2] == "dns":
            return {}
        if len(parts) == 5 and parts[2] == "lxc" and parts[4] == "config":
            return {"net0": self.guests[int(parts[3])]}
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


W = World()
main.pve.run = lambda fn: fn(Fake(W))
main.pve.connect = lambda *a, **k: TRIPPED.append("verbinden") or (_ for _ in ()).throw(AssertionError("echte verbinding"))
ROOT = main.make_token(main.APP_USER)   # signed with the key of this test copy only
r = call("POST", "/api/users", ROOT, {"name": "lezer", "role": "readonly", "password": "Proef-" + secrets.token_urlsafe(12)})
READER = main.make_token("lezer")
check("proefgebruiker 'lezer' (alleen lezen) in de testkopie", r[0] == 200 and main.read_token(READER) == "lezer")

CHANGING = [("POST", "/api/network/vnet", {"name": "gasten", "tag": 20, "bridge": "vmbr0"}), ("DELETE", "/api/network/vnet/gasten", None),
            ("POST", "/api/network/sdn/apply", None), ("POST", "/api/network/vlan", {"node": "n1", "device": "vmbr0", "tag": 20}),
            ("POST", "/api/network/node/n1/apply", None), ("DELETE", "/api/network/node/n1/pending", None)]
for method, path, body in CHANGING:
    a, b, c = call(method, path, None, body), call(method, path, READER, body), call(method, path, ROOT, body, origin="https://kwaad.example")
    check(f"{method} {path}: zonder sessie 401, lezer 403, andere website 403", (a[0], b[0], c[0]) == (401, 403, 403), f"{a[0]} {b[0]} {c[0]}")
check("na al die weigeringen is het nagebootste cluster niets gevraagd te veranderen", W.changes == [], str(W.changes))
check("de lezer mag de netwerkgegevens wel bekijken", call("GET", "/api/network", READER)[0] == 200)

r = call("POST", "/api/network/vnet", ROOT, {"name": "gasten", "tag": 20, "bridge": "vmbr0", "alias": "Gasten wifi"})
check("VLAN voor guests: eerst de zone, dan het VNet, en NIET toepassen", r[0] == 200 and W.changes == [
    ("POST", "cluster/sdn/zones", {"zone": "vlans", "type": "vlan", "bridge": "vmbr0"}),
    ("POST", "cluster/sdn/vnets", {"vnet": "gasten", "zone": "vlans", "tag": 20, "alias": "Gasten wifi"})], f"{r[1]} {W.changes}")
check("het antwoord zegt wat er is klaargezet", r[1] == {"ok": True, "vnet": "gasten", "zone": "vlans", "tag": 20, "zone_created": True})
W.zones, W.vnets, W.changes = [{"zone": "vlans", "type": "vlan", "state": "new", "pending": {"bridge": "vmbr0"}}], [{"vnet": "gasten", "type": "vnet", "state": "new", "pending": {"zone": "vlans", "tag": 20}}], []
r = call("POST", "/api/network/vnet", ROOT, {"name": "iot", "tag": 30, "bridge": "vmbr0"})
check("tweede VLAN: alleen het VNet, in de zone die nog klaarstaat", r[0] == 200 and W.changes == [("POST", "cluster/sdn/vnets", {"vnet": "iot", "zone": "vlans", "tag": 30})], str(W.changes))
W.changes = []
r = call("POST", "/api/network/vnet", ROOT, {"name": "dubbel", "tag": 20, "bridge": "vmbr0"})
check("zelfde VLAN-nummer nog een keer: geweigerd, niets gevraagd", r[0] == 409 and W.changes == [], detail(r))
W.offline = {"n3"}
r = call("POST", "/api/network/vnet", ROOT, {"name": "later", "tag": 40, "bridge": "vmbr0"})
check("een node staat uit: geen netwerkwijziging", r[0] == 409 and W.changes == [], detail(r))
r = call("POST", "/api/network/sdn/apply", ROOT); check("een node staat uit: ook niet toepassen", r[0] == 409 and W.changes == [], detail(r))
W.offline = set()
overview = call("GET", "/api/network", ROOT)[1]
check("het overzicht toont wat klaarstaat", overview["sdn"]["pending"] is True and overview["sdn"]["vnets"][0] == {"vnet": "gasten", "zone": "vlans", "tag": 20, "alias": None, "state": "new", "status": {}}
      and overview["sdn"]["zones"][0] == {"zone": "vlans", "type": "vlan", "bridge": "vmbr0", "state": "new"}, json.dumps(overview["sdn"]))
r = call("POST", "/api/network/sdn/apply", ROOT)
check("toepassen: één opdracht aan het cluster, antwoord is de taak en de node waar hij loopt", r[0] == 200 and W.changes == [("PUT", "cluster/sdn", {})] and r[1]["node"] == "n2" and r[1]["upid"].startswith("UPID:n2:"), str(r[1]))
W.zones, W.vnets, W.changes = [{"zone": "vlans", "type": "vlan", "bridge": "vmbr0"}], [{"vnet": "gasten", "type": "vnet", "zone": "vlans", "tag": 20}], []
r = call("POST", "/api/network/sdn/apply", ROOT); check("niets klaar: toepassen geweigerd, niets gevraagd", r[0] == 409 and W.changes == [], detail(r))
W.guests = {105: "name=eth0,bridge=gasten,ip=dhcp", 106: "name=eth0,bridge=vmbr0,tag=20"}
r = call("DELETE", "/api/network/vnet/gasten", ROOT); check("VLAN nog in gebruik door een guest: verwijderen geweigerd", r[0] == 409 and "105" in detail(r) and "106" not in detail(r) and W.changes == [], detail(r))
r = call("DELETE", "/api/network/vnet/bestaat0", ROOT); check("onbekend VLAN verwijderen geweigerd", r[0] == 404 and W.changes == [], detail(r))
r = call("DELETE", "/api/network/vnet/Fout-Naam", ROOT); check("ongeldige naam bij verwijderen geweigerd", r[0] == 400 and W.changes == [])
W.guests = {106: "name=eth0,bridge=vmbr0,tag=20"}
r = call("DELETE", "/api/network/vnet/gasten", ROOT); check("ongebruikt VLAN: verwijderen wordt klaargezet (nog niet toegepast)", r[0] == 200 and W.changes == [("DELETE", "cluster/sdn/vnets/gasten", {})], str(W.changes))

W.changes = []
r = call("POST", "/api/network/vlan", ROOT, {"node": "n1", "device": "vmbr0", "tag": 20, "cidr": "192.168.20.5/24", "comment": "Opslagnet"})
check("VLAN-interface: één opdracht aan die ene node, en NIET toepassen", r[0] == 200 and r[1] == {"ok": True, "node": "n1", "iface": "vmbr0.20"} and W.changes == [
    ("POST", "nodes/n1/network", {"iface": "vmbr0.20", "type": "vlan", "autostart": 1, "cidr": "192.168.20.5/24", "comments": "Opslagnet"})], str(W.changes))
W.changes = []
r = call("POST", "/api/network/vlan", ROOT, {"node": "n9", "device": "vmbr0", "tag": 20}); check("onbekende node geweigerd", r[0] == 409 and W.changes == [], detail(r))
r = call("POST", "/api/network/vlan", ROOT, {"node": "n 1;", "device": "vmbr0", "tag": 20}); check("ongeldige nodenaam geweigerd", r[0] == 400 and W.changes == [])
r = call("POST", "/api/network/vlan", ROOT, {"node": "n1", "device": "vmbr0", "tag": 20, "cidr": "192.168.30.9/24"}); check("adres in het eigen netwerk van de node geweigerd", r[0] == 409 and W.changes == [], detail(r))
r = call("POST", "/api/network/node/n1/apply", ROOT); check("niets klaar op de node: toepassen geweigerd", r[0] == 409 and W.changes == [], detail(r))
r = call("DELETE", "/api/network/node/n1/pending", ROOT); check("niets klaar op de node: terugdraaien geweigerd", r[0] == 409 and W.changes == [])
W.nodes["n1"]["pending"] = "--- /etc/network/interfaces\n+++ /etc/network/interfaces.new\n+auto vmbr0.20\n"
r = call("POST", "/api/network/vlan", ROOT, {"node": "n1", "device": "vmbr0", "tag": 30}); check("er staat al iets klaar: geen tweede wijziging erbovenop", r[0] == 409 and W.changes == [], detail(r))
check("het overzicht toont de klaarstaande wijziging van de node", "vmbr0.20" in (call("GET", "/api/network", ROOT)[1]["nodes"]["n1"]["pending"] or ""))
r = call("POST", "/api/network/node/n1/apply", ROOT); check("toepassen op de node: één opdracht, antwoord is de taak", r[0] == 200 and W.changes == [("PUT", "nodes/n1/network", {})] and r[1]["node"] == "n1" and r[1]["upid"].startswith("UPID:n1:"))
W.changes = []
r = call("DELETE", "/api/network/node/n1/pending", ROOT); check("terugdraaien op de node: één opdracht", r[0] == 200 and W.changes == [("DELETE", "nodes/n1/network", {})])
r = call("POST", "/api/network/node/n2/apply", ROOT); check("een andere node waar niets klaarstaat blijft met rust", r[0] == 409 and len(W.changes) == 1)
check("STRUIKELDRAAD: in deel B is de echte verbinding niet gebruikt", not TRIPPED, str(TRIPPED))
main.pve.run, main.pve.connect = REAL_RUN, REAL_CONNECT

# ================================================================== deel C: alleen lezen van het echte cluster
print("\n--- deel C: als 'lezer' kijken naar het echte cluster")
r = call("GET", "/api/network", READER)
check("netwerkoverzicht", r[0] == 200 and {"nodes", "sdn", "guests", "cluster"} <= set(r[1]), "" if r[0] == 200 else detail(r))
N = r[1]
for name, n in N["nodes"].items():
    print(f"     {name}: DNS {n['dns']} | klaarstaand: {'ja' if n['pending'] else 'nee'}")
    for i in n["ifaces"]:
        print(f"       {i['iface']:<12} {i['type']:<8} {'actief' if i['active'] else 'niet actief':<11} {i['cidr'] or '-':<19} gw={i['gateway'] or '-'} poorten={i['ports'] or '-'} vlan-bewust={i['vlan_aware']}")
check("elke node gaf interfaces, met minstens één bridge met een adres", all(n and any(i["type"] == "bridge" and i["cidr"] for i in n["ifaces"]) for n in N["nodes"].values()))
print("     SDN:", json.dumps(N["sdn"]))
print("     cluster:", json.dumps(N["cluster"]))
for g in N["guests"]:
    print(f"       {g['vmid']} {str(g['name']):<20} {str(g['node']):<9} {str(g['ifname']):<5} {g['bridge']} vlan={g['tag']} ip={g['ip']} nu={g['live']} fw={g['firewall']}")
check("van elke guest zijn de netwerkkaarten gevonden", len({g["vmid"] for g in N["guests"]}) >= 8 and all(g["bridge"] and g["mac"] for g in N["guests"]))
check("het clusternetwerk is bekend", bool(N["cluster"]["links"]) and all(x["addrs"] for x in N["cluster"]["links"]))

real = {"nodes": N["nodes"], "sdn": N["sdn"]}
bridge = next(i["iface"] for i in next(iter(N["nodes"].values()))["ifaces"] if i["type"] == "bridge")
plan = main.vnet_plan(real, V(name="proef20", tag=20, bridge=bridge))
check("plan voor een VLAN op het echte cluster (alleen uitgerekend, niets verstuurd)", plan["name"] == "proef20" and plan["zone"], json.dumps(plan))
first = next(iter(N["nodes"]))
params = main.vlan_plan(N["nodes"][first], L(node=first, device=bridge, tag=20, cidr="10.123.45.6/24"))
check("plan voor een VLAN-interface op een echte node (alleen uitgerekend)", params["iface"] == f"{bridge}.20", json.dumps(params))
own = next(i["cidr"] for i in N["nodes"][first]["ifaces"] if i["cidr"])
e = refused(main.vlan_plan, N["nodes"][first], L(node=first, device=bridge, tag=20, cidr=own.rsplit(".", 1)[0] + ".250/" + own.split("/")[1]))
check("een adres in het eigen netwerk van de echte node wordt geweigerd", e is not None and e.status_code == 409, getattr(e, "detail", ""))

ROOT_REAL = main.make_token(main.APP_USER)
before = json.dumps(call("GET", "/api/network", READER)[1]["sdn"])
r = call("POST", "/api/network/vnet", ROOT_REAL, {"name": "Fout Naam!", "tag": 20, "bridge": bridge})
check("echt cluster: aanvraag met een ongeldige naam strandt vóór er iets verstuurd wordt", r[0] == 400, detail(r))
r = call("POST", "/api/network/vlan", ROOT_REAL, {"node": first, "device": bridge, "tag": 0})
check("echt cluster: VLAN-interface met nummer 0 strandt vóór er iets verstuurd wordt", r[0] in (400, 409), detail(r))
after = call("GET", "/api/network", READER)[1]
check("daarna is er op het echte cluster niets veranderd en staat er niets klaar", json.dumps(after["sdn"]) == before and not any(n["pending"] for n in after["nodes"].values()) and not after["sdn"]["pending"])

for days in (1, 7, 30):
    t0 = time.time()
    r = call("GET", f"/api/events?days={days}", READER)
    E = r[1]
    check(f"events over {days} dag(en)", r[0] == 200 and E["days"] == days and isinstance(E["events"], list), f"{len(E['events'])} regels in {time.time() - t0:.1f} s, afgekapt={E['truncated']}")
check("een onzinnige periode valt terug op 7 dagen", call("GET", "/api/events?days=9999", READER)[1]["days"] == 7)
E = call("GET", "/api/events?days=7", READER)[1]
print("     aandachtspunten nu:", json.dumps(E["now"]))
by = {}
for e in E["events"]:
    by[(e["source"], e["level"])] = by.get((e["source"], e["level"]), 0) + 1
print("     verdeling:", {f"{k[0]}/{k[1]}": v for k, v in sorted(by.items())})
print("     soorten taken:", sorted({str(e["type"]) for e in E["events"] if e["source"] == "task"}))
for e in E["events"][:4] + [x for x in E["events"] if x["level"] == "error"][:4]:
    print(f"       {time.strftime('%d-%m %H:%M', time.localtime(e['time']))} {str(e['node']):<9} {e['source']:<5} {e['level']:<7} {str(e['type']):<12} id={str(e['id']):<5} {e['user']} | {e['text']}")
check("gebeurtenissen staan van nieuw naar oud en vallen binnen de periode", all(a["time"] >= b["time"] for a, b in zip(E["events"], E["events"][1:])) and all(e["time"] >= E["since"] for e in E["events"]))
check("consolesessies en de echo van taken in het clusterlog zijn weggelaten", not any(e["type"] in main.NOISE for e in E["events"]) and not any(e["source"] == "log" and main.TASK_ECHO_RE.match(e["text"] or "") for e in E["events"]))
check("elke taak heeft een verwijzing waarmee het log is op te vragen", all(e["upid"] and e["upid"].startswith("UPID:") for e in E["events"] if e["source"] == "task"))
check("mislukte taken hebben de foutmelding erbij", all(e["text"] for e in E["events"] if e["source"] == "task" and e["level"] == "error"))
task = next((e for e in E["events"] if e["source"] == "task"), None)
if task:
    r = call("GET", f"/api/task/{task['node']}/{task['upid']}/log", READER)
    check("het log van een taak is op te vragen", r[0] == 200 and "log" in r[1], f"{len(r[1].get('log', ''))} tekens")

print("\n" + ("ALLES GOED" if not FAILED else f"{len(FAILED)} FOUT: " + "; ".join(FAILED)))
