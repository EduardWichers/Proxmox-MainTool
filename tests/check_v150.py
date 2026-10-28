"""Tests version 1.5 of the backend in-process, from a copy in /tmp with its own state folder: looking on GitHub for a
newer version (tags, ETag, errors), the status for the page, Don't remind me per user, fetching a version from GitHub
into the same check as an uploaded file, and switching it all off. GitHub and the cluster are stand-ins; nothing goes
out over the network and nothing real is changed. Runs on the tool container (with its maintool.env) and elsewhere
(then with test settings)."""
import asyncio, hashlib, io, json, os, secrets, shutil, sys, time, zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
COPY = Path("/tmp/mt-v150")
shutil.rmtree(COPY, ignore_errors=True)
shutil.copytree(HERE.parent / "app", COPY / "app")
if os.path.isfile("/etc/maintool/maintool.env"):
    for line in open("/etc/maintool/maintool.env", encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ[k.strip()] = v.strip()
else:
    os.environ.update({"PVE_HOSTS": "192.0.2.1", "PVE_TOKEN_VALUE": "test-only", "APP_PASSWORD": "test-" + secrets.token_hex(8)})
os.environ["STATE_DIRECTORY"] = str(COPY / "state")
os.environ.pop("UPDATE_REPO", None)
(COPY / "state").mkdir(parents=True)

import proxmoxer  # noqa: E402

proxmoxer.ProxmoxAPI = lambda *a, **k: (_ for _ in ()).throw(AssertionError("geen echte verbinding met Proxmox in deze test"))
sys.path.insert(0, str(COPY / "app"))
import main  # noqa: E402
import requests  # noqa: E402

FAILED = []


def check(label, ok, extra=""):
    if not ok:
        FAILED.append(label)
    print(f"{'OK  ' if ok else 'FOUT'} {label} {extra}")


HOST = "tool.example"


def call(method, path, cookie=None, body=None, origin=f"https://{HOST}", raw=None):
    """Een verzoek recht in de applicatie. Geeft (status, inhoud, set-cookie-regels)."""
    route, _, query = path.partition("?")
    hdrs = [(b"host", HOST.encode())]
    if origin:
        hdrs.append((b"origin", origin.encode()))
    if cookie:
        hdrs.append((b"cookie", f"{main.SESSION_COOKIE}={cookie}".encode()))
    data = raw if raw is not None else (b"" if body is None else json.dumps(body).encode())
    if body is not None:
        hdrs.append((b"content-type", b"application/json"))
    if body is not None or raw is not None:
        hdrs.append((b"content-length", str(len(data)).encode()))
    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1", "method": method,
             "scheme": "https", "path": route, "raw_path": route.encode(), "query_string": query.encode(), "root_path": "",
             "headers": hdrs, "client": ("203.0.113.7", 40000), "server": (HOST, 443)}
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
    out = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    try:
        parsed = json.loads(out)
    except ValueError:
        parsed = out.decode("utf-8", "replace")
    return start["status"], parsed, [v.decode() for k, v in start["headers"] if k == b"set-cookie"]


def session_of(setc):
    return next((c.split(";")[0].split("=", 1)[1] for c in setc if c.startswith(main.SESSION_COOKIE + "=") and "Max-Age=0" not in c), None)


# ---------------------------------------------------------------- nagebootst GitHub: alles wat de tool vraagt komt hier
SHA_OLD, SHA_NEW = "a" * 40, "b" * 40
GH = {}
ASKED = []


class Reply:
    def __init__(self, status, payload=None, headers=None, url="", body=b""):
        self.status_code, self._payload, self.headers, self.url, self._body = status, payload, headers or {}, url, body

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload

    def iter_content(self, size):
        for i in range(0, len(self._body), size):
            yield self._body[i:i + size]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def fake_get(url, headers=None, timeout=None, stream=False, **kw):
    headers = headers or {}
    ASKED.append(url)
    if GH.get("raise"):
        raise GH["raise"]
    api = f"{main.GITHUB_API}/repos/{main.UPDATE_REPO}"
    if url == f"{api}/tags?per_page=100":
        if GH.get("tags_status", 200) != 200:
            return Reply(GH["tags_status"])
        if GH.get("etag") and headers.get("If-None-Match") == GH["etag"]:
            return Reply(304)
        return Reply(200, GH.get("tags"), {"ETag": GH.get("etag") or ""})
    if url.startswith(f"{api}/commits/"):
        sha = url.rsplit("/", 1)[1]
        return Reply(200, {"commit": {"message": GH.get("messages", {}).get(sha, "")}}) if sha in GH.get("messages", {}) else Reply(404)
    if url.startswith(f"{main.GITHUB_SITE}/{main.UPDATE_REPO}/archive/refs/tags/"):
        z = GH.get("zip", {})
        return Reply(z.get("status", 200), headers=z.get("headers", {}), url=z.get("url", "https://codeload.github.com/x.zip"), body=z.get("body", b""))
    raise AssertionError(f"onverwachte vraag naar buiten: {url}")


main.requests.get = fake_get
requests.get = fake_get


def tags(*names):
    return [{"name": n, "commit": {"sha": SHA_NEW if n == "v1.10" else SHA_OLD}, "zipball_url": "x"} for n in names]


def setup_file(version):
    return f'#!/usr/bin/env bash\nVERSION="{version}"\n# nagebootst setup-bestand\n'.encode() + b"\0" * 2000


def zipped(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def fake_update_check():
    """Het oordeel van het bijwerkprogramma, nagebootst: de versie staat in het setup-bestand."""
    data = main.UPDATE_FILE.read_bytes()
    if not data.startswith(b"#!/usr/bin/env bash\nVERSION="):
        return {"ok": False, "code": "not_a_package"}
    version = data.split(b'"')[1].decode()
    return {"ok": True, "version": version, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "warnings": []}


main.update_check = fake_update_check

# ---------------------------------------------------------------- inloggen: de beheerder en iemand die alleen leest
main.login_guard.reset()
ROOT = session_of(call("POST", "/api/login", body={"username": main.APP_USER, "password": main.APP_PASSWORD})[2])
PW = secrets.token_urlsafe(18)
call("POST", "/api/users", ROOT, {"name": "lezer", "roles": [], "password": PW})
READER = session_of(call("POST", "/api/login", body={"username": "lezer", "password": PW})[2])
check("uitgangssituatie: twee sessies", all([ROOT, READER]))
check("de tool kijkt standaard in zijn eigen repository", main.UPDATE_REPO == "EduardWichers/Proxmox-MainTool", main.UPDATE_REPO)

# ================================================================ A. versienummers
print("--- A. versienummers")
check("1.4.1 en v1.5", main.version_key("1.4.1") == (1, 4, 1) and main.version_key("v1.5") == (1, 5, 0))
check("1.10 is nieuwer dan 1.9 (geen tekstvergelijking)", main.version_key("v1.10") > main.version_key("v1.9"))
check("1.5 en 1.5.0 zijn gelijk", main.version_key("1.5") == main.version_key("v1.5.0"))
check("geen versie: rc, nightly, leeg, onzin", all(main.version_key(x) is None for x in ("v1.5-rc1", "nightly", "", None, "1", "v1.2.3.4", "1.x")))

# ================================================================ B. wat er nieuw is
print("--- B. de toelichting uit het commitbericht")
msg = ("Proxmox Maintool 1.10\n\n- Eerste punt dat over\n  twee regels loopt.\n- Tweede punt.\n\n"
       "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n")
check("zonder titel en Co-Authored-By, afgebroken regels aan elkaar",
      main.release_notes(msg) == "- Eerste punt dat over twee regels loopt.\n- Tweede punt.", repr(main.release_notes(msg)))
check("hooguit NOTES_MAX tekens", len(main.release_notes("t\n" + "x" * 9000)) == main.NOTES_MAX)

# ================================================================ C. kijken op GitHub
print("--- C. kijken op GitHub")
v = call("GET", "/api/selfupdate/status", ROOT)[1]["github"]
check("nog niet gekeken: aan, geen versie, niet nieuwer", v["enabled"] and v["latest"] is None and not v["newer"] and v["checked"] is None, str(v))
GH.update(tags=tags("v1.4.1", "v1.5", "v1.9", "v1.10", "v2.0-rc1", "nightly"), etag='"e1"',
          messages={SHA_NEW: msg, SHA_OLD: "Oud\n\n- iets\n"})
ASKED.clear()
g = main.github_check()
check("de hoogste echte versie (1.10, niet 1.9 of 2.0-rc1)", g.get("tag") == "v1.10" and g.get("version") == "1.10" and g.get("error") is None, str(g))
check("toelichting van die versie opgehaald", g.get("notes", "").startswith("- Eerste punt"), str(g.get("notes"))[:60])
check("ETag bewaard", g.get("etag") == '"e1"')
v = call("GET", "/api/selfupdate/status", ROOT)[1]["github"]
check("status: nieuwer dan wat hier draait, met toelichting", v["newer"] and v["latest"] == "1.10" and v["notes"] and v["checked"], str({k: v[k] for k in ("newer", "latest", "checked")}))
ASKED.clear()
before = main.github_saved()["checked"]
time.sleep(1.1)
g = main.github_check()
check("niets veranderd: 304, versie blijft, geen nieuwe vraag naar de commit", g.get("version") == "1.10" and g.get("checked", 0) > before
      and not any("/commits/" in u for u in ASKED) and len(ASKED) == 1, str(ASKED))
ASKED.clear()
g = main.github_check(manual=True)
check("Opnieuw kijken vlak erna: het vorige antwoord, GitHub niet gevraagd", not ASKED and g.get("version") == "1.10")
for label, setup, code in (("repository niet gevonden of niet openbaar (404)", {"tags_status": 404}, "not_found"),
                           ("te veel vragen (403)", {"tags_status": 403}, "rate_limited"),
                           ("te veel vragen (429)", {"tags_status": 429}, "rate_limited"),
                           ("geen verbinding", {"raise": requests.ConnectionError("weg")}, "unreachable"),
                           ("antwoord is geen JSON", {"tags": ValueError("rommel"), "etag": None}, "bad_answer"),
                           ("andere fout (500)", {"tags_status": 500}, "bad_answer")):
    saved = dict(GH)
    GH.update(setup)
    g = main.github_check()
    check(f"fout: {label} -> {code}, de laatst bekende versie blijft", g.get("error") == code and g.get("version") == "1.10", str(g.get("error")))
    GH.clear()
    GH.update(saved)
GH.update(tags=[{"name": "v1.11", "commit": {"sha": "geen-sha"}}], etag='"e2"')
g = main.github_check()
check("tag met een onzinnige commit: bad_answer, 1.10 blijft", g.get("error") == "bad_answer" and g.get("version") == "1.10")
check("... en de ETag van dat antwoord wordt niet bewaard (anders zou het nooit opnieuw gelezen worden)", g.get("etag") == '"e1"', str(g.get("etag")))
GH.update(tags=tags("v1.4.1", "v1.10"), etag='"e3"')
g = main.github_check()
check("daarna weer gewoon: fout weg", g.get("error") is None and g.get("version") == "1.10")
GH.update(tags=[], etag='"e4"')
g = main.github_check()
check("geen enkele versie op GitHub: geen nieuwere", g.get("version") is None and not call("GET", "/api/selfupdate/status", ROOT)[1]["github"]["newer"])
GH.update(tags=tags("v1.4.1", "v1.5"), etag='"e5"')
g = main.github_check()
v = call("GET", "/api/selfupdate/status", ROOT)[1]["github"]
check(f"de nieuwste op GitHub is wat hier draait ({main.VERSION}): niet nieuwer, geen toelichting", not v["newer"] and v["notes"] is None and v["latest"] == "1.5")
GH.update(tags=tags("v1.4.1", "v1.5", "v1.10"), etag='"e6"')
main.github_check()

# ================================================================ D. Herinner mij niet, per gebruiker
print("--- D. Herinner mij niet")
r = call("PUT", "/api/settings", ROOT, {"update_dismissed": "1.10"})
check("bewaard bij de beheerder", r[0] == 200 and r[1].get("update_dismissed") == "1.10", str(r[:2]))
check("status geeft het terug", call("GET", "/api/selfupdate/status", ROOT)[1]["github"]["dismissed"] == "1.10")
check("geldt niet voor een andere gebruiker", call("GET", "/api/selfupdate/status", READER)[1]["github"]["dismissed"] is None)
check("andere instellingen blijven staan", call("PUT", "/api/settings", ROOT, {"background": "#112233"})[1].get("update_dismissed") == "1.10")
check("onzin wordt geweigerd", call("PUT", "/api/settings", ROOT, {"update_dismissed": "1.5; echo"})[0] == 422)

# ================================================================ E. nu meteen kijken
print("--- E. Opnieuw kijken")
check("alleen voor beheerders", call("POST", "/api/selfupdate/check", READER)[0] == 403)
check("niet vanaf een andere site", call("POST", "/api/selfupdate/check", ROOT, origin="https://elders.example")[0] == 403)
ASKED.clear()
main.state.change(lambda d: d["github"].update(tried=0))
r = call("POST", "/api/selfupdate/check", ROOT)
check("beheerder: kijkt en geeft de status terug", r[0] == 200 and r[1]["github"]["latest"] == "1.10" and len(ASKED) == 1, str(r[0]))

# ================================================================ F. een versie van GitHub halen
print("--- F. versie van GitHub halen en controleren")
REPO_ZIP = "Proxmox-MainTool-1.10/"
GOOD = zipped({REPO_ZIP + "maintool-setup.sh": setup_file("1.10"), REPO_ZIP + "README.md": b"# uitleg\n",
               REPO_ZIP + "docs/screenshots/en/overview.webp": b"RIFF" + b"\0" * 100})
main.UPDATER = COPY / "no-updater"
r = call("POST", "/api/selfupdate/github", ROOT, {"version": "1.10"})
check("zonder bijwerkprogramma: geweigerd zoals een upload", r[0] == 409, str(r[1]))
main.UPDATER = COPY / "maintool-updater"
main.UPDATER.write_text("# nagebootst\n")
check("alleen voor beheerders", call("POST", "/api/selfupdate/github", READER, {"version": "1.10"})[0] == 403)
r = call("POST", "/api/selfupdate/github", ROOT, {"version": "9.9"})
check("een versie die niet (meer) op GitHub staat: 409", r[0] == 409, str(r[1]))
check("een ongeldig versienummer: 422", call("POST", "/api/selfupdate/github", ROOT, {"version": "../x"})[0] == 422)
for label, z, code in (("de ZIP bestaat niet (404)", {"status": 404}, "github_not_found"),
                       ("doorgestuurd naar een andere site", {"body": GOOD, "url": "https://elders.example/x.zip"}, "github_unreachable"),
                       ("te groot volgens GitHub", {"body": GOOD, "headers": {"content-length": str(main.UPDATE_MAX + 1)}}, "too_big"),
                       ("te groot tijdens het ophalen", {"body": b"\0" * (main.UPDATE_MAX + 70000)}, "too_big"),
                       ("ZIP zonder setup-bestand", {"body": zipped({REPO_ZIP + "README.md": b"x"})}, "archive_empty"),
                       ("setup-bestand niet opnieuw gebouwd (versie 1.4.1 in de ZIP van 1.10)",
                        {"body": zipped({REPO_ZIP + "maintool-setup.sh": setup_file("1.4.1")})}, "github_mismatch")):
    GH["zip"] = z
    r = call("POST", "/api/selfupdate/github", ROOT, {"version": "1.10"})
    left = sorted(p.name for p in main.UPDATE_DIR.iterdir()) if main.UPDATE_DIR.exists() else []
    check(f"{label} -> {code}, niets blijft klaarstaan", r[0] == 200 and r[1].get("ok") is False and r[1].get("code") == code and not left,
          f"{r[1]} {left}")
GH["raise"] = requests.ConnectionError("weg")
r = call("POST", "/api/selfupdate/github", ROOT, {"version": "1.10"})
GH.pop("raise")
check("GitHub onbereikbaar -> github_unreachable", r[1] == {"ok": False, "code": "github_unreachable"}, str(r[1]))
r = call("POST", "/api/selfupdate/github", ROOT, {"version": "1.10"})
check("de mismatch noemt beide versies", r[1].get("version") == "1.4.1" and r[1].get("wanted") == "1.10", str(r[1]))
GH["zip"] = {"body": GOOD}
ASKED.clear()
r = call("POST", "/api/selfupdate/github", ROOT, {"version": "1.10"})
check("goede ZIP: zelfde oordeel als bij een upload, met waar hij vandaan kwam",
      r[0] == 200 and r[1].get("ok") is True and r[1].get("version") == "1.10" and r[1].get("from_github") == "v1.10"
      and r[1].get("from_archive") == REPO_ZIP + "maintool-setup.sh", str(r[1]))
check("de ZIP van precies die tag", ASKED == [f"{main.GITHUB_SITE}/{main.UPDATE_REPO}/archive/refs/tags/v1.10.zip"], str(ASKED))
check("het setup-bestand staat klaar voor de stap met het wachtwoord", main.UPDATE_FILE.read_bytes() == setup_file("1.10"))
r = call("POST", "/api/selfupdate/apply", ROOT, {"password": "fout", "sha256": "0" * 64})
check("installeren vraagt nog steeds het wachtwoord", r[0] == 403, str(r[1]))
main.login_guard.reset()
main.UPDATE_FILE.unlink(missing_ok=True)

# ================================================================ G. een bestand zelf aanleveren werkt nog net zo
print("--- G. zelf een bestand aanleveren")
r = call("POST", "/api/selfupdate/upload", ROOT, raw=GOOD)
check("de ZIP van GitHub zelf aangeleverd", r[0] == 200 and r[1].get("ok") is True and r[1].get("from_archive") == REPO_ZIP + "maintool-setup.sh"
      and "from_github" not in r[1], str(r[1]))
r = call("POST", "/api/selfupdate/upload", ROOT, raw=b"print('main.py')\n")
check("een ander bestand: nog steeds 'geen setup-bestand'", r[1] == {"ok": False, "code": "not_a_package"} and not main.UPDATE_FILE.exists(), str(r[1]))

# ================================================================ H. uitgezet
print("--- H. UPDATE_REPO leeg")
main.UPDATE_REPO = ""
v = call("GET", "/api/selfupdate/status", ROOT)[1]["github"]
check("status: uit, en dus nooit 'nieuwer'", v["enabled"] is False and v["newer"] is False and v["latest"] is None, str(v))
check("Opnieuw kijken: 409", call("POST", "/api/selfupdate/check", ROOT)[0] == 409)
check("van GitHub halen: 409", call("POST", "/api/selfupdate/github", ROOT, {"version": "1.10"})[0] == 409)
main.UPDATE_REPO = "EduardWichers/Proxmox-MainTool"
check("een onzinnige UPDATE_REPO wordt niet gebruikt", not main.REPO_RE.match("x/y z") and not main.REPO_RE.match("../etc") and main.REPO_RE.match("ander/fork-1"))

# ================================================================ I. pagina en vertalingen
print("--- I. pagina en vertalingen")
page = main.INDEX.read_text(encoding="utf-8")
check("de pagina heeft een tekst voor elke nieuwe code", all(c in page for c in ("github_unreachable:", "github_not_found:", '"github_mismatch"')))
check("... en voor elke fout bij het kijken", all(f"{c}:" in page for c in ("unreachable", "not_found", "rate_limited", "bad_answer")))
check("menu, regel onder Tool bijwerken en de melding staan in de pagina", all(x in page for x in ('id="su-new"', 'id="sundlg"', 'id="sun-never"', "#menu.update")))
for nl in ("Zoeken naar nieuwe versies staat uit (UPDATE_REPO in maintool.env)", "Deze versie staat niet (meer) op GitHub; kijk opnieuw"):
    check(f"melding vertaald: {nl[:40]}…", main.translate(nl, "en") != nl and main.translate(nl, "de") != nl)

check("niets anders naar buiten dan het nagebootste GitHub", all(u.startswith(("https://api.github.com/", "https://github.com/")) for u in ASKED))
print()
print("ALLES GOED" if not FAILED else f"FOUT ({len(FAILED)}): {FAILED}")
sys.exit(1 if FAILED else 0)
