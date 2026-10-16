#!/usr/bin/env python3
"""Tests voor updater/maintool-updater. Draait zonder bijzondere rechten in een tijdelijke map (de updater krijgt
via MAINTOOL_UPDATER_ROOT een nagebootst systeem) en raakt het echte systeem niet.

    python3 test.py PAD/NAAR/maintool-setup.sh PAD/NAAR/maintool-updater
"""
import base64
import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

SETUP, UPDATER = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
assert os.geteuid() != 0, "draai deze tests niet als root"
MARKER = b"\n__PAYLOAD__\n"
passed = failed = 0


def check(label, ok, extra=""):
    global passed, failed
    if ok:
        passed += 1
        if os.environ.get("QUIET") != "1":
            print(f"  ok    {label}")
    else:
        failed += 1
        print(f"  FOUT  {label} {extra}")


# ---------------------------------------------------------------- pakketten maken

RAW = SETUP.read_bytes()
HEAD = RAW[:RAW.find(MARKER)]
ORIGINAL = {}
with tarfile.open(fileobj=io.BytesIO(gzip.decompress(base64.b64decode(RAW[RAW.find(MARKER) + len(MARKER):]))), mode="r:") as _tar:
    for _m in _tar:
        if _m.isreg():
            ORIGINAL[_m.name.removeprefix("./")] = _tar.extractfile(_m).read()


def sums(files):
    return "".join(f"{hashlib.sha256(c).hexdigest()}  ./{n}\n" for n, c in sorted(files.items()) if n != "SHA256SUMS").encode()


def package(change=None, *, resum=True, extra_members=(), head=HEAD, raw_tar=None, trailer=b"", version=None):
    """Een setup-bestand op basis van het echte, met wijzigingen. change krijgt de bestanden (naam -> inhoud)."""
    files = dict(ORIGINAL)
    if version:
        files["app/VERSION"] = (version + "\n").encode()
    if change:
        change(files)
    if resum and "SHA256SUMS" in files:
        files["SHA256SUMS"] = sums(files)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, content in sorted(files.items()):
            info = tarfile.TarInfo("./" + name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
        for info, content in extra_members:
            tar.addfile(info, io.BytesIO(content) if content is not None else None)
    tar_bytes = raw_tar if raw_tar is not None else buf.getvalue()
    return head + MARKER + base64.encodebytes(gzip.compress(tar_bytes) + trailer)


def member(name, kind=tarfile.REGTYPE, content=b"x", link=""):
    info = tarfile.TarInfo(name)
    info.type, info.linkname = kind, link
    info.size = len(content) if kind == tarfile.REGTYPE else 0
    return info, (content if kind == tarfile.REGTYPE else None)


# ---------------------------------------------------------------- nagebootst systeem

class Box:
    def __init__(self, installed="1.0"):
        self.root = Path(tempfile.mkdtemp(prefix="mt-upd-"))
        r = self.root
        for d in ("opt/maintool", "var/lib/maintool/update", "usr/local/lib/maintool", "run", "var/log", "etc/maintool"):
            (r / d).mkdir(parents=True)
        for name, content in ORIGINAL.items():
            if name.startswith("app/") or name in ("selftest.py", "LICENSE", "README.md", "THIRD-PARTY.md"):
                path = r / "opt/maintool" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
        (r / "opt/maintool/app/VERSION").write_text(installed + "\n")
        (r / "opt/maintool/app/stale.txt").write_text("bestand uit een oudere versie\n")
        system = ("requirements.txt", "maintool.service", "install.sh", "updater/maintool-updater",
                  "updater/maintool-update.service", "updater/maintool-update.path", "node/maintool-agent")
        (r / "usr/local/lib/maintool/baseline.sums").write_text(
            "".join(f"{hashlib.sha256(ORIGINAL[n]).hexdigest()}  {n}\n" for n in system))
        (r / "restart.sh").write_text(f"""#!/bin/sh
echo restart >> {r}/restarts
if grep -q BROKEN {r}/opt/maintool/app/main.py 2>/dev/null; then : > {r}/health; else cp {r}/opt/maintool/app/VERSION {r}/health; fi
""")
        self.env = {"PATH": "/usr/bin:/bin", "MAINTOOL_UPDATER_ROOT": str(r),
                    "MAINTOOL_UPDATER_RESTART": f"sh {r}/restart.sh", "MAINTOOL_UPDATER_HEALTH": str(r / "health")}
        self.upload = r / "var/lib/maintool/update/upload.bin"
        self.trigger = r / "var/lib/maintool/update/apply"
        self.result = r / "var/lib/maintool-update/result.json"
        self.app = r / "opt/maintool/app"

    def check(self, data: bytes, name="pakket.sh"):
        path = self.root / name
        path.write_bytes(data)
        p = subprocess.run([sys.executable, str(UPDATER), "check", str(path)], env=self.env, capture_output=True, text=True, timeout=120)
        try:
            out = json.loads(p.stdout)
        except ValueError:
            out = {"ok": None, "raw": p.stdout[-300:] + p.stderr[-300:]}
        out["rc"] = p.returncode
        return out

    def apply(self, data, sha=None, trigger=True):
        if data is not None:
            self.upload.write_bytes(data)
        if trigger:
            self.trigger.write_text(json.dumps({"sha256": sha if sha is not None else hashlib.sha256(data).hexdigest()}))
        p = subprocess.run([sys.executable, str(UPDATER), "apply"], env=self.env, capture_output=True, text=True, timeout=180)
        try:
            res = json.loads(self.result.read_text())
        except (OSError, ValueError):
            res = None
        return p.returncode, res, p.stderr

    def version(self):
        return (self.app / "VERSION").read_text().strip()

    def fingerprint(self):
        """Vingerafdruk van alles wat geïnstalleerd is, om te zien of er iets veranderd is."""
        h = hashlib.sha256()
        for path in sorted((self.root / "opt").rglob("*")) + sorted((self.root / "usr").rglob("*")):
            h.update(str(path.relative_to(self.root)).encode())
            if path.is_file():
                h.update(path.read_bytes())
        return h.hexdigest()

    def leftovers(self):
        home = self.root / "opt/maintool"
        return [p.name for p in home.iterdir() if p.name.startswith("app.")] + [p.name for p in (self.upload, self.trigger) if p.exists() or p.is_symlink()]

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


def put(name, content):
    return lambda files: files.__setitem__(name, content)


def drop(name):
    return lambda files: files.pop(name)


# ---------------------------------------------------------------- 1. controleren (verandert niets)
print("--- controleren")
box = Box()
before = box.fingerprint()

r = box.check(package(version="1.2"))
check("nieuwer pakket goedgekeurd", r.get("ok") is True and r["version"] == "1.2" and r["current"] == "1.0" and r["warnings"] == [] and r["rc"] == 0, str(r))
check("vingerafdruk van het hele bestand meegegeven", len(r.get("sha256", "")) == 64 and r.get("size", 0) > 100000)
r = box.check(RAW)
check("het echte, ongewijzigde setup-bestand goedgekeurd", r.get("ok") is True and r["version"] == ORIGINAL["app/VERSION"].decode().strip() and r["sha256"] == hashlib.sha256(RAW).hexdigest(), str(r))
r = box.check(package(version="1.0"))
check("zelfde versie: goedgekeurd met opmerking", r.get("ok") is True and r["warnings"] == ["same_version"], str(r))
r = box.check(package(version="0.9"))
check("oudere versie geweigerd", r.get("ok") is False and r["code"] == "older", str(r))
r = box.check(package(put("node/maintool-agent", b"#!/bin/bash\n# nieuwer hulpscript\n"), version="1.2"))
check("ander hulpscript voor de nodes: goedgekeurd met opmerking", r.get("ok") is True and r["warnings"] == ["agent_changed"], str(r))
r = box.check(package(put("app/static/extra.js", b"// nieuw bestand\n"), version="1.2"))
check("nieuw bestand binnen app/ toegestaan", r.get("ok") is True and r["files"] == len(ORIGINAL) + 1, str(r))

REFUSED = [
    ("leeg bestand", b"", "not_a_package"),
    ("willekeurige bytes", os.urandom(5000), "not_a_package"),
    ("een webpagina", b"<!doctype html><html><body>Proxmox Maintool</body></html>\n", "not_a_package"),
    ("een ander shellscript met dezelfde scheidingsregel", b"#!/bin/sh\necho hoi\n" + MARKER + b"aGFsbG8=\n", "not_a_package"),
    ("kop zonder de naam van de tool", package(head=b"#!/usr/bin/env bash\n# iets anders\n", version="1.2"), "not_a_package"),
    ("afgebroken (laatste 2000 tekens weg)", package(version="1.2")[:-2000], "damaged"),
    ("ingepakt deel is geen base64", HEAD + MARKER + b"dit is geen base64 !!! ###\n", "damaged"),
    ("ingepakt deel is geen gzip", HEAD + MARKER + base64.encodebytes(b"geen gzip" * 50), "damaged"),
    ("gzip met rommel erin in plaats van een archief", package(raw_tar=os.urandom(4096)), "damaged"),
    ("extra gegevens achter het archief", package(version="1.2", trailer=b"EXTRA"), "damaged"),
    ("bestand veranderd zonder nieuwe vingerafdruk", package(put("app/main.py", ORIGINAL["app/main.py"] + b"\n# x\n"), resum=False, version=None), "damaged"),
    ("vingerafdruk voor een bestand dat ontbreekt", package(lambda f: (f.__setitem__("SHA256SUMS", sums(f) + b"0" * 64 + b"  ./app/spook.py\n")), resum=False), "damaged"),
    ("bestand zonder vingerafdruk", package(lambda f: (f.__setitem__("SHA256SUMS", sums(f)), f.__setitem__("app/static/los.js", b"x")), resum=False), "damaged"),
    ("main.py ontbreekt", package(drop("app/main.py"), version="1.2"), "bad_content"),
    ("SHA256SUMS ontbreekt", package(drop("SHA256SUMS"), version="1.2"), "bad_content"),
    ("selftest.py ontbreekt", package(drop("selftest.py"), version="1.2"), "bad_content"),
    ("main.py is geen geldig Python", package(put("app/main.py", b"def kapot(:\n  pass\n"), version="1.2"), "bad_content"),
    ("main.py met een nul-byte", package(put("app/main.py", b"x = 1\x00\n"), version="1.2"), "bad_content"),
    ("inlogscherm zonder versieregel", package(put("app/static/login.html", b"<html>geen versie</html>"), version="1.2"), "bad_content"),
    ("ongeldig versienummer", package(version="1.x"), "bad_content"),
    ("versienummer met een opdracht erin", package(version="1.2; rm -rf /"), "bad_content"),
    ("onverwacht bestand naast de tool", package(put("extra.sh", b"#!/bin/sh\n"), version="1.2"), "bad_content"),
    ("pad dat de map uit wil (../)", package(extra_members=[member("../../etc/cron.d/kwaad")], version="1.2"), "bad_content"),
    ("pad dat via app/ de map uit wil", package(extra_members=[member("app/../../kwaad")], version="1.2"), "bad_content"),
    ("absoluut pad", package(extra_members=[member("/etc/passwd")], version="1.2"), "bad_content"),
    ("verborgen bestand in app/", package(extra_members=[member("app/.verborgen")], version="1.2"), "bad_content"),
    ("symbolische koppeling", package(extra_members=[member("app/static/link", tarfile.SYMTYPE, link="/etc/shadow")], version="1.2"), "bad_content"),
    ("harde koppeling", package(extra_members=[member("app/static/hard", tarfile.LNKTYPE, link="app/main.py")], version="1.2"), "bad_content"),
    ("apparaatbestand", package(extra_members=[member("app/static/dev", tarfile.CHRTYPE)], version="1.2"), "bad_content"),
    ("named pipe", package(extra_members=[member("app/static/fifo", tarfile.FIFOTYPE)], version="1.2"), "bad_content"),
    ("dubbel bestand in het archief", package(extra_members=[member("./app/main.py", content=b"x = 1\n")], version="1.2"), "bad_content"),
    ("onverwachte map", package(extra_members=[member("geheim", tarfile.DIRTYPE)], version="1.2"), "bad_content"),
    ("andere Python-pakketten nodig (requirements)", package(put("requirements.txt", ORIGINAL["requirements.txt"] + b"kwaad==1.0\n"), version="1.2"), "needs_setup"),
    ("andere systemd-dienst", package(put("maintool.service", ORIGINAL["maintool.service"] + b"# x\n"), version="1.2"), "needs_setup"),
    ("ander installatiescript", package(put("install.sh", ORIGINAL["install.sh"] + b"# x\n"), version="1.2"), "needs_setup"),
    ("andere updater", package(put("updater/maintool-updater", ORIGINAL["updater/maintool-updater"] + b"# x\n"), version="1.2"), "needs_setup"),
    ("ander startsein voor de updater", package(put("updater/maintool-update.path", b"[Path]\nPathExists=/tmp/x\n"), version="1.2"), "needs_setup"),
    ("te veel bestanden", package(lambda f: f.update({f"app/static/f{i}.js": b"x" for i in range(250)}), version="1.2"), "bad_content"),
    ("één bestand te groot (9 MB)", package(put("app/static/groot.js", b"a" * (9 * 2**20)), version="1.2"), "too_big"),
    ("uitgepakt te groot (pakt uit tot 70 MB)", package(lambda f: f.update({f"app/static/b{i}.js": b"\0" * (7 * 2**20) for i in range(10)}), version="1.2"), "too_big"),
    ("bestand zelf te groot (21 MB)", HEAD + MARKER + base64.encodebytes(os.urandom(16 * 2**20)), "too_big"),
]
for label, data, code in REFUSED:
    r = box.check(data)
    check(f"geweigerd: {label}", r.get("ok") is False and r.get("code") == code and r["rc"] == 1, f"-> {r.get('code')} {r.get('detail', r.get('raw', ''))[:120]}")

link = box.root / "koppeling.sh"
(box.root / "echt.sh").write_bytes(package(version="1.2"))
link.symlink_to(box.root / "echt.sh")
p = subprocess.run([sys.executable, str(UPDATER), "check", str(link)], env=box.env, capture_output=True, text=True)
check("geweigerd: een koppeling in plaats van een bestand", json.loads(p.stdout).get("code") == "no_file", p.stdout[:200])
p = subprocess.run([sys.executable, str(UPDATER), "check", str(box.root / "bestaat-niet")], env=box.env, capture_output=True, text=True)
check("geweigerd: bestand bestaat niet", json.loads(p.stdout).get("code") == "no_file", p.stdout[:200])
(box.root / "usr/local/lib/maintool/baseline.sums").rename(box.root / "weg.sums")
r = box.check(package(version="1.2"))
check("geweigerd: geen gegevens over de huidige installatie", r.get("code") == "needs_setup", str(r))
(box.root / "weg.sums").rename(box.root / "usr/local/lib/maintool/baseline.sums")
check("controleren heeft niets aan de installatie veranderd", box.fingerprint() == before)
check("controleren laat geen startsein of uitkomst achter", not box.trigger.exists() and not box.result.exists())
box.close()

# ---------------------------------------------------------------- 2. installeren
print("--- installeren")
box = Box()
new = package(lambda f: f.__setitem__("README.md", b"nieuwe uitleg\n"), version="1.2")
rc, res, err = box.apply(new)
check("geslaagd: afsluitcode en uitkomst", rc == 0 and res and res["ok"] and res["version"] == "1.2" and res["previous"] == "1.0", f"{rc} {res} {err[-200:]}")
check("nieuwe versie staat er", box.version() == "1.2" and (box.app / "main.py").read_bytes() == ORIGINAL["app/main.py"])
check("bestand uit de oude versie is weg (map helemaal vervangen)", not (box.app / "stale.txt").exists())
check("documentatie vervangen", (box.root / "opt/maintool/README.md").read_bytes() == b"nieuwe uitleg\n")
check("tool één keer herstart en hij antwoordt met de nieuwe versie", (box.root / "restarts").read_text().count("restart") == 1 and (box.root / "health").read_text().strip() == "1.2")
backups = sorted((box.root / "var/lib/maintool-backup").iterdir())
check("kopie van de oude versie bewaard", len(backups) == 1 and backups[0].name.endswith("-v1.0") and (backups[0] / "app/VERSION").read_text().strip() == "1.0" and (backups[0] / "app/stale.txt").exists() and (backups[0] / "README.md").read_bytes() == ORIGINAL["README.md"])
check("niets achtergebleven (tussenmappen, bestand, startsein)", box.leftovers() == [], str(box.leftovers()))
check("logboek geschreven", "uitkomst" in (box.root / "var/log/maintool-update.log").read_text())

rc, res, err = box.apply(package(version="1.2"))
check("zelfde versie opnieuw installeren kan", rc == 0 and res["ok"] and res["warnings"] == ["same_version"], f"{rc} {res}")
for v in ("1.3", "1.4", "1.5"):
    box.apply(package(version=v))
check("na vijf keer bijwerken: versie 1.5, drie kopieën bewaard", box.version() == "1.5" and len(list((box.root / "var/lib/maintool-backup").iterdir())) == 3)
box.close()

print("--- mislukte en geweigerde installaties")
box = Box()
before = box.fingerprint()
broken = package(put("app/main.py", ORIGINAL["app/main.py"] + b"\n# BROKEN: deze versie start niet\n"), version="1.2")
check("(proefpakket komt wel door de controle)", box.check(broken).get("ok") is True)
rc, res, err = box.apply(broken)
check("nieuwe versie start niet: gemeld", rc == 1 and res and res["ok"] is False and res["code"] == "not_starting" and res["restored"] is True, f"{rc} {res} {err[-200:]}")
check("oude versie staat er weer, precies zoals eerst", box.version() == "1.0" and box.fingerprint() == before)
check("tool draait weer op de oude versie (twee keer herstart)", (box.root / "health").read_text().strip() == "1.0" and (box.root / "restarts").read_text().count("restart") == 2)
check("niets achtergebleven", box.leftovers() == [], str(box.leftovers()))

rc, res, err = box.apply(package(version="1.2"), sha="0" * 64)
check("ander bestand dan bevestigd: geweigerd", rc == 1 and res["code"] == "changed" and box.fingerprint() == before and box.leftovers() == [], f"{rc} {res}")
rc, res, err = box.apply(package(version="0.5"))
check("ouder pakket bij installeren alsnog geweigerd", rc == 1 and res["code"] == "older" and box.fingerprint() == before and box.leftovers() == [], f"{rc} {res}")
rc, res, err = box.apply(package(extra_members=[member("../../kwaad")], version="1.2"))
check("pakket met een pad naar buiten bij installeren geweigerd", rc == 1 and res["code"] == "bad_content" and box.fingerprint() == before and not (box.root.parent / "kwaad").exists(), f"{rc} {res}")
rc, res, err = box.apply(package(put("requirements.txt", b"kwaad\n"), version="1.2"))
check("pakket dat dieper ingrijpt bij installeren geweigerd", rc == 1 and res["code"] == "needs_setup" and box.fingerprint() == before, f"{rc} {res}")
restarts = (box.root / "restarts").read_text().count("restart")
check("bij een weigering wordt de tool niet herstart", restarts == 2)

box.result.unlink()
box.upload.write_bytes(package(version="1.2"))
box.trigger.write_text("geen json")
rc, res, err = box.apply(None, trigger=False)
check("onleesbaar startsein: genegeerd en opgeruimd", rc == 0 and res is None and not box.trigger.exists() and box.fingerprint() == before, f"{rc} {res}")
secret = box.root / "geheim.txt"
secret.write_text('{"sha256": "x"}')
box.trigger.symlink_to(secret)
rc, res, err = box.apply(None, trigger=False)
check("startsein is een koppeling: niet gevolgd, alleen de koppeling weg", rc == 0 and res is None and not box.trigger.is_symlink() and secret.exists(), f"{rc} {res}")
box.upload.unlink(missing_ok=True)
(box.root / "echt.sh").write_bytes(package(version="1.2"))
box.upload.symlink_to(box.root / "echt.sh")
box.trigger.write_text(json.dumps({"sha256": hashlib.sha256(package(version="1.2")).hexdigest()}))
rc, res, err = box.apply(None, trigger=False)
check("aangeleverd bestand is een koppeling: geweigerd", rc == 1 and res["code"] == "no_file" and box.fingerprint() == before and (box.root / "echt.sh").exists(), f"{rc} {res}")
box.trigger.write_text(json.dumps({"sha256": "0" * 64}))
rc, res, err = box.apply(None, trigger=False)
check("startsein zonder bestand: geweigerd", rc == 1 and res["code"] == "no_file" and box.fingerprint() == before, f"{rc} {res}")

import fcntl
lock = open(box.root / "run/maintool-update.lock", "w")
fcntl.flock(lock, fcntl.LOCK_EX)
box.result.unlink(missing_ok=True)
rc, res, err = box.apply(package(version="1.2"))
check("er loopt al een installatie: tweede doet niets", rc == 0 and res is None and box.version() == "1.0", f"{rc} {res}")
lock.close()
box.trigger.unlink(missing_ok=True)
box.upload.unlink(missing_ok=True)

env = {k: v for k, v in box.env.items() if not k.startswith("MAINTOOL_")}
p = subprocess.run([sys.executable, str(UPDATER), "apply"], env=env, capture_output=True, text=True)
check("installeren zonder root (buiten de test) weigert", p.returncode == 2 and "root" in p.stderr, p.stderr[:200])
p = subprocess.run([sys.executable, str(UPDATER), "onzin"], env=env, capture_output=True, text=True)
check("onbekende opdracht: uitleg", p.returncode == 2 and "maintool-updater check" in p.stderr, p.stderr[:200])
box.close()

print(f"\n=== {passed} geslaagd, {failed} mislukt ===")
sys.exit(1 if failed else 0)
