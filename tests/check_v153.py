"""Tests version 1.5.3: the Python packages with fixed versions and checksums, install.sh (side by side, root-owned,
put back when the new version does not start; tested in depth by tests/install/test.sh), the stricter service, and
above all that a running 1.5.2 offers this version through the node: the page itself may not install it, because it
changes install.sh, the service and the package list. Uses the built setup file next to this folder (bash build.sh)
and the 1.5.2 files from git. Nothing is installed and nothing goes out over the network."""
import base64, io, json, os, re, shutil, subprocess, sys, tarfile, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parent
FAILED = []


def check(label, ok, extra=""):
    if not ok:
        FAILED.append(label)
    print(f"{'OK  ' if ok else 'FOUT'} {label} {extra}")


def git(*args):
    return subprocess.run(["git", "-c", "safe.directory=*", *args], cwd=SRC, capture_output=True, check=True).stdout


SETUP = SRC / "maintool-setup.sh"
data = SETUP.read_bytes()
payload = tarfile.open(fileobj=io.BytesIO(base64.b64decode(data.split(b"\n__PAYLOAD__\n", 1)[1])), mode="r:gz")
pkg = {m.name.lstrip("./"): payload.extractfile(m).read() for m in payload.getmembers() if m.isfile()}
version = pkg["app/VERSION"].decode().strip()
check("het gebouwde setup-bestand is van deze versie", version == (SRC / "app" / "VERSION").read_text().strip(), version)

# ================================================================ A. pakketlijst
print("--- A. Python-pakketten")
lock = pkg["requirements.txt"].decode()
reqs = re.findall(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\;]+)", lock, re.M)
blocks = re.split(r"\n(?=[A-Za-z0-9])", lock.split("\n", 2)[2] if lock.startswith("#") else lock)
check("elk pakket met een vaste versie", len(reqs) >= 15 and all(v for _, v in reqs), str(len(reqs)))
check("... en met minstens één controlesom", all("--hash=sha256:" in b for b in blocks if b.strip() and not b.startswith("#")))
names = {n.lower().replace("_", "-") for n, _ in reqs}
for need in ("fastapi", "starlette", "pydantic", "pydantic-core", "uvicorn", "uvloop", "httptools", "websockets", "proxmoxer", "requests", "urllib3"):
    check(f"in de lijst: {need}", need in names)
top = [l.split("#")[0].strip() for l in (SRC / "requirements.in").read_text().splitlines() if l.split("#")[0].strip()]
check("alles uit requirements.in staat erin", all(t.lower() in names for t in top), str(top))
check("geen watchfiles of PyYAML meer (alleen nodig voor uvicorn --reload en YAML-instellingen)", not names & {"watchfiles", "pyyaml", "python-dotenv"})

# ================================================================ B. install.sh en de dienst
print("--- B. install.sh en de dienst")
inst = pkg["install.sh"].decode()
check("install.sh: geldige bash", subprocess.run(["bash", "-n"], input=inst.encode()).returncode == 0)
check("pip alleen met controlesommen en kant-en-klare pakketten", "--require-hashes --only-binary :all:" in inst
      and all("--require-hashes" in l for l in inst.splitlines() if re.search(r"bin/pip\"? install", l)))
check("alles onder /opt/maintool van root", 'chown -R root:root "$APP_DIR"' in inst and "chown -R maintool" not in inst)
check("bij bijwerken: nakijken en anders terugzetten (exitcode 3 of 4)", "healthy" in inst and "put_back" in inst and "exit 3" in inst and "exit 4" in inst)
unit = pkg["maintool.service"].decode()
for line in ("UMask=0077", "StateDirectoryMode=0700", "--limit-concurrency 200", "ProtectSystem=strict", "NoNewPrivileges=true"):
    check(f"maintool.service: {line}", line in unit)
d = Path(tempfile.mkdtemp())
(d / "maintool.service").write_bytes(pkg["maintool.service"])
r = subprocess.run(["systemd-analyze", "verify", str(d / "maintool.service")], capture_output=True, text=True,
                   env={**os.environ, "SYSTEMD_UNIT_PATH": f"{d}:"})
bad = [l for l in (r.stdout + r.stderr).splitlines() if l.strip() and not re.search(r"executable|resolve|EnvironmentFile|WorkingDirectory|not found", l, re.I)]
check("systemd kent elke regel van de dienst", not bad, str(bad[:2]))
shutil.rmtree(d)
check("het setup-bestand kan zonder vragen bijwerken (UNATTENDED=1)", re.search(rb"^UNATTENDED=1\b", data[:20000], re.M) is not None)
check("... en meldt een teruggezette versie", b"install_back" in data and b"install_broken" in data)
check("met de hand in een terminal: verder op de achtergrond, maar niet nog eens als het al een dienst is",
      b'systemd-run --quiet --collect --unit="$unit" /bin/bash "$self"' in data and b"INVOCATION_ID" in data)

# ================================================================ C. vanaf 1.5.2: niet via de pagina, wel via de node
print("--- C. een draaiende 1.5.2 en deze versie")
root = Path(tempfile.mkdtemp(prefix="mt-v153-"))
(root / "opt/maintool/app").mkdir(parents=True)
(root / "opt/maintool/app/VERSION").write_text("1.5.2\n")
(root / "usr/local/lib/maintool").mkdir(parents=True)
OLD = "15b269e"
names_sys = ["requirements.txt", "maintool.service", "install.sh", "updater/maintool-updater", "updater/maintool-update.service",
             "updater/maintool-update.path", "node/maintool-agent"]
import hashlib  # noqa: E402
(root / "usr/local/lib/maintool/baseline.sums").write_text("".join(f"{hashlib.sha256(git('show', f'{OLD}:{n}')).hexdigest()}  {n}\n" for n in names_sys))
updater = root / "maintool-updater-1.5.2"
updater.write_bytes(git("show", f"{OLD}:updater/maintool-updater"))
r = subprocess.run([sys.executable, "-I", str(updater), "check", str(SETUP)], capture_output=True, text=True,
                   env={**os.environ, "MAINTOOL_UPDATER_ROOT": str(root)})
verdict = json.loads(r.stdout or "{}")
check("het bijwerkprogramma van 1.5.2 weigert deze versie via de pagina (needs_setup)", verdict.get("code") == "needs_setup", str(verdict))
check("... om de pakketlijst, de dienst en install.sh", all(x in verdict.get("detail", "") for x in ("requirements.txt", "maintool.service", "install.sh")), verdict.get("detail", ""))
check("... maar niet om het bijwerkprogramma of het hulpscript", "maintool-updater" not in verdict.get("detail", "") and "maintool-agent" not in verdict.get("detail", ""))
shutil.rmtree(root)

copy = Path(tempfile.mkdtemp(prefix="mt-v153-app-"))
shutil.copytree(SRC / "app", copy / "app")
os.environ.update({"PVE_HOSTS": "192.0.2.1", "PVE_TOKEN_VALUE": "test-only", "APP_PASSWORD": "test-only-x", "STATE_DIRECTORY": str(copy / "state")})
(copy / "state").mkdir()
import proxmoxer  # noqa: E402

proxmoxer.ProxmoxAPI = lambda *a, **k: (_ for _ in ()).throw(AssertionError("geen echte verbinding met Proxmox in deze test"))
sys.path.insert(0, str(copy / "app"))
import main  # noqa: E402
import socket  # noqa: E402

main.VERSION = "1.5.2"
main.UPDATE_DIR.mkdir(parents=True, exist_ok=True)
shutil.copyfile(SETUP, main.UPDATE_FILE)
main.pve.run = lambda fn: fn(type("A", (), {"cluster": type("C", (), {"resources": type("R", (), {"get": staticmethod(lambda **k: [
    {"vmid": 110, "type": "lxc", "node": "pve2", "status": "running", "name": socket.gethostname(), "tags": "maintool"}])})})}))
plan = main.node_update_plan()
check("een draaiende 1.5.2 biedt deze versie aan via de node", plan.get("possible") and plan.get("version") == version and plan.get("node") == "pve2"
      and plan.get("sha256") == hashlib.sha256(data).hexdigest(), str(plan))
shutil.rmtree(copy)

print()
print("ALLES GOED" if not FAILED else f"FOUT ({len(FAILED)}): {FAILED}")
sys.exit(1 if FAILED else 0)
