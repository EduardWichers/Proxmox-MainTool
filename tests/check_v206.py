"""Tests version 1.0.6 of the backend in-process on the tool container, from a copy in /tmp with its own state folder:
the library of ISOs and container templates, browsing a storage, and free IDs and the node CPU when creating a guest.
Everything runs against a stand-in cluster that only writes down what it is asked to do; nothing real is changed."""
import asyncio, base64, datetime as dt, hashlib, hmac, json, os, secrets, subprocess, sys, tempfile, time, urllib.parse
for line in open("/etc/maintool/maintool.env", encoding="utf-8"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ[k.strip()] = v.strip()
os.environ["STATE_DIRECTORY"] = "/tmp/mt-v206/state"
sys.path.insert(0, "/tmp/mt-v206/app")
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
READS = []
STORES = {"n1": [{"storage": "nas", "type": "nfs", "content": "iso,vztmpl,backup", "shared": 1, "active": 1, "enabled": 1, "avail": 9 * 2**40},
                 {"storage": "local", "type": "dir", "content": "iso,vztmpl,backup", "shared": 0, "active": 1, "enabled": 1, "avail": 50 * 2**30},
                 {"storage": "ceph", "type": "rbd", "content": "images,rootdir", "shared": 1, "active": 1, "enabled": 1, "avail": 2**40}],
          "n2": [{"storage": "nas", "type": "nfs", "content": "iso,vztmpl,backup", "shared": 1, "active": 1, "enabled": 1, "avail": 9 * 2**40},
                 {"storage": "local", "type": "dir", "content": "iso,vztmpl,backup", "shared": 0, "active": 1, "enabled": 1, "avail": 40 * 2**30},
                 {"storage": "ceph", "type": "rbd", "content": "images,rootdir", "shared": 1, "active": 1, "enabled": 1, "avail": 2**40}]}
CONTENT = {("n1", "nas"): [{"volid": "nas:iso/debian-13.iso", "content": "iso", "size": 790000000, "ctime": 1790000000, "format": "iso"},
                           {"volid": "nas:backup/vzdump-lxc-101-2026_10_11-18_53_10.tar.zst", "content": "backup", "size": 5, "ctime": 1790000001, "vmid": 101, "notes": "web", "protected": 1}],
           ("n2", "nas"): [{"volid": "nas:iso/debian-13.iso", "content": "iso", "size": 790000000, "ctime": 1790000000}],
           ("n1", "local"): [{"volid": "local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst", "content": "vztmpl", "size": 126000000, "ctime": 1751738856}],
           ("n2", "local"): [{"volid": "local:vztmpl/alpine-3.22-default_20250617_amd64.tar.xz", "content": "vztmpl", "size": 3000000, "ctime": 1751996131}]}


def content(node, storage):
    def get(kw):
        READS.append((node, storage, kw.get("content")))
        items = CONTENT.get((node, storage), [])
        return [i for i in items if not kw.get("content") or i["content"] == kw["content"]]
    return get


_orig = W.call


def world(method, path, kw):
    if method != "GET":
        W.changes.append((method, path, dict(kw)))
        if path.endswith("download-url") or path.endswith("aplinfo"):
            return f"UPID:{path.split('/')[1]}:1:x::maintool@pve!webtool:"
        if "/content/" in path and method == "DELETE":
            return f"UPID:{path.split('/')[1]}:2:imgdel::maintool@pve!webtool:"
        return None
    return _orig(method, path, kw)


W.call = world
W.table.update({
    "nodes": [{"node": "n1", "status": "online"}, {"node": "n2", "status": "online"}, {"node": "n3", "status": "offline"}],
    "nodes/n1/storage": STORES["n1"], "nodes/n2/storage": STORES["n2"],
    **{f"nodes/{n}/storage/{s}/content": content(n, s) for n in ("n1", "n2") for s in ("nas", "local", "ceph")},
    "nodes/n1/aplinfo": [{"template": "debian-13-standard_13.6-1_amd64.tar.zst", "section": "system", "package": "debian-13-standard", "version": "13.6-1", "headline": "Debian 13", "os": "debian-13"},
                         {"template": "debian-12-turnkey-nextcloud_18.1-1_amd64.tar.gz", "section": "turnkeylinux", "headline": "TurnKey Nextcloud"},
                         {"template": "iets-raars.tar.gz", "section": "onbekend"}],
    "nodes/n2/aplinfo": [{"template": "debian-13-standard_13.6-1_amd64.tar.zst", "section": "system", "package": "debian-13-standard", "version": "13.6-1"}],
    "cluster/resources": lambda kw: [{"vmid": 101, "name": "web", "node": "n1", "type": "lxc", "status": "running"}, {"vmid": 300, "name": "vm", "node": "n2", "type": "qemu", "status": "stopped"},
                                     {"vmid": 111, "name": "elf", "node": "n1", "type": "lxc", "status": "stopped"}],
    "nodes/n2/qemu/300/config": {"ide2": "nas:iso/debian-13.iso,media=cdrom", "scsi0": "ceph:vm-300-disk-0,size=32G"},
    "cluster/nextid": "110",
    "nodes/n1/status": {"cpuinfo": {"cpus": 16, "cores": 4, "sockets": 2, "model": "Intel Core i7"}},
    "nodes/n1/network": [{"iface": "vmbr0", "active": 1}],
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


print("--- A. de bibliotheek")
READS.clear()
r = call("GET", "/api/library", READER)
x = r[1] if r[0] == 200 else {}
check("iedereen die is ingelogd ziet de bibliotheek", r[0] == 200, detail(r) if r[0] != 200 else "")
items = {(i["volid"], i["node"]): i for i in x.get("items", [])}
check("gedeelde opslag één keer gelezen, lokale op elke node; Ceph (geen ISO's) niet", sorted(READS) == sorted([("n1", "nas", "iso"), ("n1", "nas", "vztmpl"), ("n1", "local", "iso"), ("n1", "local", "vztmpl"), ("n2", "local", "iso"), ("n2", "local", "vztmpl")]), str(sorted(READS)))
iso = items.get(("nas:iso/debian-13.iso", "n1"), {})
check("de ISO op gedeelde opslag: op alle nodes te gebruiken, met de VM die hem gebruikt", iso.get("nodes") == ["n1", "n2"] and iso.get("shared") and iso.get("used_by") == [{"vmid": 300, "name": "vm"}], json.dumps(iso))
check("de sjablonen op lokale opslag: elk alleen op zijn eigen node", items[("local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst", "n1")]["nodes"] == ["n1"] and items[("local:vztmpl/alpine-3.22-default_20250617_amd64.tar.xz", "n2")]["nodes"] == ["n2"])
check("geen back-ups of schijven in de bibliotheek", all(i["content"] in ("iso", "vztmpl") for i in x.get("items", [])))
stores = {s["storage"]: s for s in x.get("stores", [])}
check("waar iets bij kan: nas (gedeeld, eerst) en local per node met wat er mag", list(stores) == ["nas", "local"] and stores["local"]["nodes"] == ["n1", "n2"] and stores["nas"]["content"] == ["iso", "vztmpl"], json.dumps(x.get("stores"))[:300])
check("de sjablonen die Proxmox aanbiedt (systeem eerst, onbekende soorten niet)", [a["template"] for a in x.get("offered", [])] == ["debian-13-standard_13.6-1_amd64.tar.zst", "debian-12-turnkey-nextcloud_18.1-1_amd64.tar.gz"])
check("bekijken verandert niets", not changes())

print("--- B. een ISO laten downloaden")
OK = {"node": "n1", "storage": "nas", "url": "https://cdimage.debian.org/debian-13.2.iso", "filename": "debian-13.2.iso", "algorithm": "sha256", "checksum": "a" * 64}
for who, label in ((READER, "alleen lezen"), (OVER, "rol Overzicht")):
    check(f"{label}: geweigerd", call("POST", "/api/library/iso", who, OK)[0] == 403)
check("zonder Origin geweigerd", call("POST", "/api/library/iso", STOR, OK, origin=None)[0] == 403)
bad = [({**OK, "url": "ftp://x/a.iso"}, 400), ({**OK, "url": "https://x/a b.iso"}, 400), ({**OK, "url": "https:///a.iso"}, 400), ({**OK, "filename": "../etc.iso"}, 400),
       ({**OK, "filename": "film.mkv"}, 400), ({**OK, "checksum": "a" * 63}, 400), ({**OK, "algorithm": "crc32"}, 400), ({**OK, "algorithm": ""}, 400),
       ({**OK, "storage": "ceph"}, 400), ({**OK, "storage": "weg"}, 400), ({**OK, "node": "n3"}, 400), ({**OK, "filename": "debian-13.iso"}, 409)]
wrong = [(b.get("url")[-12:], b.get("filename"), b.get("storage"), code, call("POST", "/api/library/iso", STOR, b)[0]) for b, code in bad if call("POST", "/api/library/iso", STOR, b)[0] != code]
check(f"{len(bad)} ongeldige verzoeken geweigerd met de juiste code", not wrong, str(wrong))
check("niets naar Proxmox gestuurd", not changes())
r = call("POST", "/api/library/iso", STOR, OK)
check("downloaden met de rol Opslag: precies dit naar Proxmox", r[0] == 200 and changes() == [("POST", "nodes/n1/storage/nas/download-url", {"url": OK["url"], "filename": "debian-13.2.iso", "content": "iso",
      "checksum": "a" * 64, "checksum-algorithm": "sha256"})] and r[1]["volid"] == "nas:iso/debian-13.2.iso", json.dumps(r[1]))
r = call("POST", "/api/library/iso", ROOT, {**OK, "node": "n1", "storage": "local", "algorithm": "", "checksum": ""})
check("zonder controlesom, naar lokale opslag", r[0] == 200 and changes() == [("POST", "nodes/n1/storage/local/download-url", {"url": OK["url"], "filename": "debian-13.2.iso", "content": "iso"})])

print("--- C. een sjabloon ophalen")
check("niet in de lijst van Proxmox: 400", call("POST", "/api/library/template", STOR, {"node": "n1", "storage": "nas", "template": "nep.tar.gz"})[0] == 400)
check("staat er al: 409", call("POST", "/api/library/template", STOR, {"node": "n1", "storage": "local", "template": "debian-12-standard_12.7-1_amd64.tar.zst"})[0] in (400, 409))
check("op opslag zonder sjablonen: 400", call("POST", "/api/library/template", STOR, {"node": "n1", "storage": "ceph", "template": "debian-13-standard_13.6-1_amd64.tar.zst"})[0] == 400)
check("niets naar Proxmox", not changes())
r = call("POST", "/api/library/template", STOR, {"node": "n1", "storage": "nas", "template": "debian-12-turnkey-nextcloud_18.1-1_amd64.tar.gz"})
check("ophalen naar gedeelde opslag", r[0] == 200 and changes() == [("POST", "nodes/n1/aplinfo", {"storage": "nas", "template": "debian-12-turnkey-nextcloud_18.1-1_amd64.tar.gz"})])

print("--- D. verwijderen")
check("ongeldig bestand: 400", call("DELETE", "/api/library?node=n1&volid=nas:backup/vzdump-x.tar.zst", STOR)[0] == 400 and call("DELETE", "/api/library?node=n1&volid=../x", STOR)[0] == 400)
r = call("DELETE", "/api/library?node=n1&volid=nas:iso/debian-13.iso", STOR)
check("een ISO in de cd-speler van een VM: geweigerd, met welke VM", r[0] == 409 and "300" in detail(r), detail(r))
check("staat er niet: 404", call("DELETE", "/api/library?node=n1&volid=nas:iso/weg.iso", STOR)[0] == 404)
check("alleen lezen: 403", call("DELETE", "/api/library?node=n1&volid=local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst", READER)[0] == 403)
check("niets naar Proxmox", not changes())
r = call("DELETE", "/api/library?node=n1&volid=local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst", STOR)
check("een sjabloon verwijderen", r[0] == 200 and changes() == [("DELETE", "nodes/n1/storage/local/content/local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst", {})] and r[1]["upid"])
ev = [e for e in main.state.events(0) if e.get("kind") == "library"]
check("in het logboek: download, sjabloon, verwijderen, met wie", [e["result"] for e in ev] == ["ISO downloaden gestart", "ISO downloaden gestart", "sjabloon ophalen gestart", "sjabloon verwijderd"]
      and {e["user"] for e in ev} == {"opslag", main.APP_USER}, json.dumps(ev)[:200])

print("--- E. bladeren door een opslag")
r = call("GET", "/api/storage/nas/content", READER)
x = r[1] if r[0] == 200 else {}
check("alles op een opslag, op soort, met de guest erbij", r[0] == 200 and [i["content"] for i in x["items"]] == ["iso", "backup"] and x["items"][1]["guest"] == "web" and x["items"][1]["protected"] is True
      and x["shared"] and x["nodes"] == ["n1", "n2"] and x["node"] == "n1", json.dumps(x)[:300])
r = call("GET", "/api/storage/local/content?node=n2", READER)
check("een lokale opslag op de gekozen node", r[0] == 200 and r[1]["node"] == "n2" and [i["file"] for i in r[1]["items"]] == ["alpine-3.22-default_20250617_amd64.tar.xz"])
check("onbekende opslag: 404, ongeldige naam: 400", call("GET", "/api/storage/weg/content", READER)[0] == 404 and call("GET", "/api/storage/a;b/content", READER)[0] == 400)
check("zonder sessie: 401", call("GET", "/api/storage/nas/content")[0] == 401)

print("--- F. nieuwe guest: vrije ID's, de processor, wat elders staat")
r = call("GET", "/api/create/options?node=n1", OVER)
o = r[1] if r[0] == 200 else {}
check("vrije ID's vanaf nextid, bezette overgeslagen", o.get("free_ids") == [110, 112, 113, 114, 115, 116, 117, 118, 119, 120], str(o.get("free_ids")))
check("bezette ID's met hun naam", o.get("used_ids") == {"101": "web", "300": "vm", "111": "elf"})
check("de processor van de node: kernen (alle sockets) en threads", o.get("cpu") == {"threads": 16, "cores": 8, "model": "Intel Core i7"}, json.dumps(o.get("cpu")))
check("sjablonen die alleen op een andere node staan", o.get("templates_elsewhere") == [{"volid": "local:vztmpl/alpine-3.22-default_20250617_amd64.tar.xz", "file": "alpine-3.22-default_20250617_amd64.tar.xz", "nodes": ["n2"]}], json.dumps(o.get("templates_elsewhere")))
CONTENT[("n2", "local")].append({"volid": "local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst", "content": "vztmpl", "size": 126000000, "ctime": 1751738856})
CONTENT[("n3x", "x")] = []
o2 = call("GET", "/api/create/options?node=n1", OVER)[1]
check("een sjabloon dat hier ook staat telt niet als elders", [x["file"] for x in o2["templates_elsewhere"]] == ["alpine-3.22-default_20250617_amd64.tar.xz"], json.dumps(o2["templates_elsewhere"]))
CONTENT[("n2", "local")].pop()
check("geen ISO elders (die op nas is overal), en de grootte erbij", o.get("isos_elsewhere") == [] and o.get("media_info", {}).get("nas:iso/debian-13.iso", {}).get("size") == 790000000)
check("alleen lezen mag de keuzes niet ophalen", call("GET", "/api/create/options", READER)[0] == 403)
check("niets veranderd", not changes())

TRIPPED = [x for x in TRIPPED if not (x[0] == "agent" and tuple(x[1][1:]) == ("info", "cts"))]
check("het echte cluster is niet aangeraakt", not TRIPPED, str(TRIPPED))
print()
print("ALLES GOED" if not FAILED else f"FOUT ({len(FAILED)}): {FAILED}")
