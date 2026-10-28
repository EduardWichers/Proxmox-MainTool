"""Tests version 1.5.2 of the backend in-process, from a copy in /tmp with its own state folder: the security fixes from
the check of 28 October 2026. The brake on logging in (per name and address, no lock-out for everyone, attempts counted
before the password check), the gate in front of every request (origin of changing requests, size of requests, security
headers), the __Host- cookies, security keys for users without a password, OpenID Connect, ISO downloads from internal
addresses and the small fixes. Proxmox, Cloudflare and OpenID are stand-ins; nothing goes out over the network. Runs on
the tool container (with its maintool.env) and elsewhere (then with test settings)."""
import asyncio, base64, hashlib, json, os, re, secrets, shutil, sys, threading, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
COPY = Path("/tmp/mt-v152")
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
(COPY / "state").mkdir(parents=True)

import proxmoxer  # noqa: E402

proxmoxer.ProxmoxAPI = lambda *a, **k: (_ for _ in ()).throw(AssertionError("geen echte verbinding met Proxmox in deze test"))
sys.path.insert(0, str(COPY / "app"))
import main  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.routing import APIRoute  # noqa: E402

FAILED = []


def check(label, ok, extra=""):
    if not ok:
        FAILED.append(label)
    print(f"{'OK  ' if ok else 'FOUT'} {label} {extra}")


HOST = "tool.example"
ORIGIN = f"https://{HOST}"
GATE_MSG = "Dit verzoek komt niet van de pagina van de tool"


def call(method, path, cookie=None, body=None, origin=ORIGIN, client="203.0.113.7", headers=(), raw=None, chunks=None,
         cookie_name=None):
    """Eén verzoek aan de app. raw: de body als bytes (met Content-Length); chunks: de body in stukken zonder lengte."""
    route, _, query = path.partition("?")
    hdrs = [(b"host", HOST.encode())]
    if origin:
        hdrs.append((b"origin", origin.encode()))
    if cookie:
        hdrs.append((b"cookie", f"{cookie_name or main.SESSION_COOKIE}={cookie}".encode()))
    for k, v in headers:
        hdrs.append((k.encode(), v.encode() if isinstance(v, str) else v))
    if chunks is not None:
        parts = list(chunks)
        hdrs.append((b"content-type", b"application/json"))
    else:
        data = raw if raw is not None else (b"" if body is None else json.dumps(body).encode())
        if body is not None or raw is not None:
            hdrs += [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode())]
        parts = [data]
    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1", "method": method,
             "scheme": "https", "path": route, "raw_path": route.encode(), "query_string": query.encode(), "root_path": "",
             "headers": hdrs, "client": (client, 40000), "server": (HOST, 443)}
    sent, given = [], {"n": 0}

    async def receive():
        i = given["n"]
        given["n"] += 1
        if i < len(parts):
            return {"type": "http.request", "body": parts[i], "more_body": i < len(parts) - 1}
        await asyncio.sleep(0)
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
    head = {}
    for k, v in start["headers"]:
        head.setdefault(k.decode().lower(), []).append(v.decode("latin-1"))
    return start["status"], parsed, head.get("set-cookie", []), head, given["n"]


def session_of(setc):
    return next((c.split(";")[0].split("=", 1)[1] for c in setc if c.startswith(main.SESSION_COOKIE + "=") and "Max-Age=0" not in c), None)


def detail(r):
    return r[1].get("detail") if isinstance(r[1], dict) else str(r[1])[:120]


def login(name, password, client="203.0.113.7", headers=()):
    return call("POST", "/api/login", body={"username": name, "password": password}, client=client, headers=headers)


def token(user, since=None, expires=None, remember=False):
    """Een sessie zoals de tool hem maakt, met een zelfgekozen inlogtijd of einde."""
    if expires is None:
        return main.make_token(user, remember, since)
    data = {"u": user, "e": int(expires), "g": (main.account(user) or {}).get("gen", 0), "t": int(since or time.time())}
    payload = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
    return f"{payload}.{main.sign(payload)}"


main.login_guard.reset()
ROOT = session_of(login(main.APP_USER, main.APP_PASSWORD)[2])
PW = secrets.token_urlsafe(18)
for name, roles in (("lezer", []), ("opslag", ["storage"]), ("beheer", ["admin"])):
    call("POST", "/api/users", ROOT, {"name": name, "roles": roles, "password": PW})
READER = session_of(login("lezer", PW)[2])
STORE = session_of(login("opslag", PW)[2])
check("uitgangssituatie: beheerder, lezer en opslag ingelogd", all([ROOT, READER, STORE]))

# ================================================================ A. cookies (M11)
print("--- A. cookies")
r = login(main.APP_USER, main.APP_PASSWORD)
cookie = next((c for c in r[2] if c.startswith("__Host-maintool_session=")), "")
check("de sessie heet nu __Host-maintool_session", bool(cookie), str(r[2]))
low = cookie.lower()
check("... met Secure, HttpOnly, Path=/ en SameSite=lax, zonder Domain",
      "secure" in low and "httponly" in low and "path=/" in low and "samesite=lax" in low and "domain=" not in low, cookie)
check("bij inloggen wordt het oude cookie maintool_session opgeruimd",
      any(c.startswith("maintool_session=") and "Max-Age=0" in c for c in r[2]), str(r[2]))
r = call("GET", "/api/me", token(main.APP_USER), cookie_name="maintool_session")
check("het oude cookie (maintool_session) geldt niet meer, ook met een geldige sessie erin", r[0] == 401, str(r[0]))
check("het nieuwe cookie geldt", call("GET", "/api/me", ROOT)[0] == 200)
r = call("GET", "/api/me", headers=[("cookie", "__Host-maintool_session=abc.éé".encode("utf-8"))])
check("een cookie met vreemde tekens geeft 401, geen 500", r[0] == 401, str(r[0]))
r = call("POST", "/api/logout", ROOT)
gone = [c for c in r[2] if c.startswith("__Host-maintool_session=")]
check("uitloggen haalt het cookie weg, met Secure (anders negeert de browser het bij __Host-)",
      gone and "Max-Age=0" in gone[0] and "secure" in gone[0].lower() and "path=/" in gone[0].lower(), str(gone))
nosso = [c for c in r[2] if c.startswith("__Host-maintool_nosso=")]
check("... en zet __Host-maintool_nosso (niet vanzelf weer binnen via Cloudflare)", nosso and "secure" in nosso[0].lower(), str(r[2]))
check("de andere cookies van de tool hebben ook __Host-", main.VIEW_COOKIE.startswith("__Host-") and main.OIDC_COOKIE.startswith("__Host-")
      and main.NOSSO_COOKIE.startswith("__Host-"))
ROOT = session_of(login(main.APP_USER, main.APP_PASSWORD)[2])

# ================================================================ B. herkomst van wijzigende verzoeken (M3)
print("--- B. herkomst")


def sample_path(path):
    def fill(m):
        name = m.group(1).split(":")[0]
        return {"node": "pve1", "vmid": "100", "kind": "qemu", "action": "start", "target": "node", "name": "x",
                "job": "backup-1", "snap": "s1", "upid": "UPID:x"}.get(name, "x")
    return re.sub(r"\{([^}]+)\}", fill, path)


routes = [(m, r.path) for r in main.app.routes if isinstance(r, APIRoute) and r.path.startswith("/api/")
          for m in sorted(r.methods) if m not in ("GET", "HEAD")]
missing, cross = [], []
for method, path in routes:
    r = call(method, sample_path(path), ROOT, body={}, origin=None)
    if r[0] != 403 or detail(r) != GATE_MSG:
        missing.append(f"{method} {path} -> {r[0]}")
    r = call(method, sample_path(path), ROOT, body={}, origin="https://andere-app." + HOST)
    if r[0] != 403 or detail(r) != GATE_MSG:
        cross.append(f"{method} {path} -> {r[0]}")
check(f"alle {len(routes)} wijzigende adressen weigeren een verzoek zonder Origin", not missing and len(routes) > 100, str(missing[:5]))
check("... en een verzoek van een andere site onder hetzelfde domein", not cross, str(cross[:5]))
for path in ("/api/node/{node}/reboot", "/api/guest/{node}/{kind}/{vmid}/status/{action}", "/api/backup/run", "/api/logout", "/api/login",
             "/api/settings", "/api/report/send", "/api/updates/check"):
    check(f"onder meer {path}", any(p == path for m, p in routes), str([p for m, p in routes if "status" in p][:3]))
r = call("POST", "/api/logout", ROOT, origin="null")
check("Origin: null (bijvoorbeeld uit een sandbox) telt niet als de eigen pagina", r[0] == 403, str(r[0]))
r = call("POST", "/api/logout", ROOT, origin="https://[::1")
check("een kapotte Origin geeft 403, geen 500", r[0] == 403, str(r[0]))
r = call("GET", "/api/me", ROOT, origin=None)
check("lezen (GET) kan zonder Origin, zoals voorheen", r[0] == 200, str(r[0]))
r = call("POST", "/api/login", body={"username": "x", "password": "y"}, origin=None, headers=[("cookie", "maintool_lang=de")])
check("de weigering is vertaald", r[0] == 403 and detail(r) == main.translate(GATE_MSG, "de") != GATE_MSG, detail(r))
r = login("lezer", PW)
check("met de juiste Origin: gewoon inloggen", r[0] == 200, str(r[0]))

# ================================================================ C. grootte van verzoeken (M4)
print("--- C. grootte")
r = call("PUT", "/api/policy", raw=b"{" + b" " * 100_000 + b"}")
check("100 KB zonder in te loggen: 413 nog vóór het inlezen", r[0] == 413 and r[4] == 0, f"{r[0]} gelezen={r[4]}")
r = call("PUT", "/api/policy", chunks=[b'{"a":"' + b"x" * 16_000] * 6 + [b'"}'])
check("... ook zonder lengte (in stukken): 413 en niet alles ingelezen", r[0] == 413 and r[4] <= 6, f"{r[0]} stukken={r[4]}")
r = call("PUT", "/api/policy", ROOT, raw=json.dumps({"min_password": 12}).encode())
check("een gewoon verzoek komt er door", r[0] != 413, str(r[0]))
r = call("POST", "/api/selfupdate/upload", raw=b"x" * 200_000)
check("de update-upload heeft een eigen grens: geen 413 van de poort", r[0] != 413, str(r[0]))
r = call("POST", "/api/login", body={"username": ["geheim" * 50], "password": "x"})
check("een foutmelding (422) stuurt de ingestuurde waarde niet terug", r[0] == 422 and "geheim" not in json.dumps(r[1])
      and all(set(d) <= {"type", "loc", "msg"} for d in r[1]["detail"]), json.dumps(r[1])[:160])
held = [main.HASH_SLOTS.acquire() for _ in range(4)]
main.HASH_WAIT, before = 0.2, main.login_guard.fails.get(("a", "198.51.100.90"))
r = login(main.APP_USER, "fout", client="198.51.100.90")
for _ in held:
    main.HASH_SLOTS.release()
main.HASH_WAIT = 20
check("hooguit vier wachtwoordcontroles tegelijk; anders 503 'te druk'", r[0] == 503, f"{r[0]} {detail(r)}")
check("... en dat telt niet als mislukte poging", not main.login_guard.fails.get(("a", "198.51.100.90")), str(before))

# ================================================================ D. beveiligingsheaders (M11)
print("--- D. headers")
r = call("GET", "/login")
csp = (r[3].get("content-security-policy") or [""])[0]
page = r[1] if isinstance(r[1], str) else ""
want = ["'sha256-" + base64.b64encode(hashlib.sha256(s.encode()).digest()).decode() + "'" for s in re.findall(r"<script>(.*?)</script>", page, re.S)]
check("inlogpagina: CSP met de vingerafdruk van elk script in de pagina", len(want) == 2 and all(w in csp for w in want), csp[:120])
for part in ("object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'", "default-src 'self'", f"wss://{HOST}"):
    check(f"... met {part}", part in csp)
check("... zonder unsafe-inline voor scripts", "script-src 'self' 'sha256-" in csp and "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0])
for k, v in (("x-content-type-options", "nosniff"), ("x-frame-options", "DENY"), ("referrer-policy", "same-origin"),
             ("cross-origin-opener-policy", "same-origin")):
    check(f"inlogpagina: {k}: {v}", r[3].get(k) == [v], str(r[3].get(k)))
r = call("GET", "/", ROOT)
csp = (r[3].get("content-security-policy") or [""])[0]
page = r[1] if isinstance(r[1], str) else ""
want = ["'sha256-" + base64.b64encode(hashlib.sha256(s.encode()).digest()).decode() + "'" for s in re.findall(r"<script>(.*?)</script>", page, re.S)]
check("de tool zelf: CSP met de vingerafdruk van elk script", len(want) == 2 and all(w in csp for w in want), csp[:100])
check("... en niet te bewaren door de browser", r[3].get("cache-control") == ["no-store"], str(r[3].get("cache-control")))
check("de vingerafdruk past bij elke gebruiker (gegevens staan niet in de scripts)", "{{" not in "".join(re.findall(r"<script>(.*?)</script>", page, re.S)))
r = call("GET", "/api/me", ROOT)
check("/api/: Cache-Control: no-store", r[3].get("cache-control") == ["no-store"], str(r[3].get("cache-control")))
check("/api/: strenge CSP en nosniff", "default-src 'none'" in r[3].get("content-security-policy", [""])[0] and r[3].get("x-content-type-options") == ["nosniff"])
check("geen HSTS (een eigen certificaat in het eigen netwerk zou dan niet meer te openen zijn)", "strict-transport-security" not in r[3])
r = call("GET", "/login", headers=[("host", "evil;script-src *")])
check("een rare Host komt niet in de CSP", "evil" not in (r[3].get("content-security-policy") or [""])[0])

# ================================================================ E. rem op inloggen (M1, M2)
print("--- E. rem op inloggen")
main.login_guard.reset()
CHECKS = []
real_check = main.check_login
main.check_login = lambda u, p: CHECKS.append(u) or real_check(u, p)
A = "198.51.100.10"
statuses = []
for round_ in range(3):
    for _ in range(4):
        statuses.append(login(main.APP_USER, "fout", client=A)[0])
    login("lezer", PW, client=A)
tries = sum(1 for u in CHECKS if u == main.APP_USER)
check("eigen inlog tussendoor wist de fouten op een ander account niet meer (oude omweg)", tries == 5 and statuses.count(429) == 7, f"{tries} {statuses}")

main.login_guard.reset()
CHECKS.clear()
results = []


def one():
    results.append(login(main.APP_USER, "fout", client="198.51.100.11")[0])


threads = [threading.Thread(target=one) for _ in range(40)]
for th in threads:
    th.start()
for th in threads:
    th.join()
check("40 pogingen tegelijk vanaf één adres: er worden er maar 5 echt gecontroleerd", len(CHECKS) == 5 and results.count(401) == 5
      and results.count(429) == 35, f"{len(CHECKS)} {sorted(set(results))}")

main.login_guard.reset()
ok = login(main.APP_USER, main.APP_PASSWORD, client="198.51.100.20")   # dit adres is daarna vertrouwd voor het hoofdaccount
for i in range(10):
    login(main.APP_USER, "fout", client=f"192.0.2.{100 + i}")
r = login(main.APP_USER, "fout", client="192.0.2.200")
check("raden vanaf steeds een ander adres: na 10 fouten is de naam dicht voor nieuwe adressen",
      ok[0] == 200 and r[0] == 429 and "te vaak een verkeerd wachtwoord" in detail(r), f"{r[0]} {detail(r)}")
r = login(main.APP_USER, main.APP_PASSWORD, client="198.51.100.20")
check("... de echte gebruiker komt vanaf zijn vertrouwde adres gewoon binnen", r[0] == 200, f"{r[0]} {detail(r)}")
r = call("POST", "/api/password", session_of(r[2]), {"current": "fout", "new": "x" * 20}, client="198.51.100.20")
check("... en wachtwoord wijzigen zegt daar 'klopt niet', niet 'te veel pogingen'", r[0] == 403, f"{r[0]} {detail(r)}")
r = login("lezer", PW, client="192.0.2.201")
check("geen blokkade voor iedereen meer: een andere gebruiker vanaf een nieuw adres komt binnen", r[0] == 200, f"{r[0]} {detail(r)}")
r = call("POST", "/api/login", body={"username": "Admin ", "password": "fout"}, client="192.0.2.202")
check("de naam telt ongeacht hoofdletters en spaties", r[0] == 429 or main.APP_USER.lower() != "admin", f"{r[0]}")

main.login_guard.reset()
for i in range(25):
    login(f"bestaat-niet-{i}", "fout", client="192.0.2.50")
r = login("lezer", PW, client="192.0.2.51")
check("25 fouten vanaf één adres sluiten alleen dat adres", r[0] == 200 and login("lezer", PW, client="192.0.2.50")[0] == 429)

main.login_guard.reset()
CF = [("cf-connecting-ip", "203.0.113.150"), ("cf-ray", "1")]
for _ in range(5):
    login("lezer", "fout", client="10.0.0.5", headers=CF)
blocked = login("lezer", PW, client="10.0.0.5", headers=CF)[0]
r = login("lezer", PW, client="10.0.0.5", headers=[("cf-connecting-ip", "203.0.113.151"), ("cf-ray", "1")])
check("via Cloudflare telt het echte adres: één gebruiker sluit de anderen niet buiten", blocked == 429 and r[0] == 200, f"{blocked} {r[0]}")

main.login_guard.reset()
main.save_sso({"cloudflare": {"enabled": True, "team": "voorbeeld", "aud": "a" * 64}})
main.verified = lambda *a, **k: (_ for _ in ()).throw(main.JWTError("handtekening"))
for _ in range(30):
    call("GET", "/", headers=[("cf-access-jwt-assertion", "onzin.onzin.onzin")], client="192.0.2.60")
check("een onzin-token van Cloudflare telt niet als mislukte poging", not main.login_guard.fails, str(list(main.login_guard.fails)[:3]))
check("... en het inloggen vanaf dat adres werkt", login("lezer", PW, client="192.0.2.60")[0] == 200)
main.save_sso({})

main.login_guard.reset()
main.pve_ticket = lambda *a, **k: (_ for _ in ()).throw(HTTPException(503, "Geen enkele Proxmox-node bereikbaar om het account te controleren"))
for _ in range(8):
    r = call("POST", "/api/nodeconsole/login", ROOT, {"username": "root", "password": "x"})
check("console: Proxmox onbereikbaar telt niet als mislukte poging", r[0] == 503 and not main.login_guard.fails, str(main.login_guard.fails))
main.pve_ticket = lambda *a, **k: None
for _ in range(6):
    r = call("POST", "/api/nodeconsole/login", ROOT, {"username": "root", "password": "fout"})
check("console: een fout wachtwoord van Proxmox telt wel (na 5: 429)", r[0] == 429, f"{r[0]} {detail(r)}")
main.pve.run = lambda fn: (_ for _ in ()).throw(HTTPException(500, "x"))
main.login_guard.reset()
main.check_login = real_check

# ================================================================ F. beveiligingssleutels zonder wachtwoord (M7)
print("--- F. sleutels zonder wachtwoord")
r = call("POST", "/api/users", ROOT, {"name": "ssoalleen", "roles": [], "sso": {"cloudflare": "sso@example.com"}, "password_login": False})
check("gebruiker die alleen via SSO inlogt", r[0] == 200, f"{r[0]} {detail(r)}")
old = token("ssoalleen", since=int(time.time()) - 600)
r = call("GET", "/api/webauthn", old)
check("zijn inlog van 10 minuten geleden geldt niet als recent", r[0] == 200 and r[1].get("recent") is False and r[1].get("password") is False, str(r[1]))
r = call("POST", "/api/webauthn/register/start", old, {"password": ""})
check("... dan geen sleutel toevoegen", r[0] == 403 and "opnieuw in" in detail(r), f"{r[0]} {detail(r)}")
r = call("PUT", "/api/webauthn", old, {"remove": "x" * 30})
check("... en ook geen verwijderen", r[0] == 403, f"{r[0]} {detail(r)}")
fresh = token("ssoalleen")
r = call("POST", "/api/webauthn/register/start", fresh, {"password": ""})
check("vlak na het inloggen wel", r[0] == 200 and "publicKey" in r[1], f"{r[0]} {detail(r)}")
check("de pagina krijgt te horen dat het nu kan", call("GET", "/api/webauthn", fresh)[1].get("recent") is True)
r = call("POST", "/api/webauthn/register/start", token("lezer", since=int(time.time()) - 86400), {"password": PW})
check("met een wachtwoord blijft het wachtwoord de bevestiging (ook bij een oude inlog)", r[0] == 200, f"{r[0]} {detail(r)}")

KEY = {"id": "A" * 43, "kty": "EC", "x": "B" * 43, "y": "C" * 43, "rp": HOST, "count": 0, "name": "sleutel", "created": 1}
main.save_wa({"ssoalleen": {"handle": "D" * 22, "required": False, "keys": [dict(KEY)]},
              "lezer": {"handle": "E" * 22, "required": False, "keys": [dict(KEY, id="F" * 43)]}})
r = call("PUT", "/api/users/ssoalleen", ROOT, {"sso": {"cloudflare": "sso@example.com", "oidc": "sso@example.com"}})
check("een koppeling erbij: de sleutels blijven", r[0] == 200 and main.wa_user("ssoalleen")["keys"], f"{r[0]} {detail(r)}")
r = call("PUT", "/api/users/ssoalleen", ROOT, {"sso": {"oidc": "sso@example.com"}})
check("een koppeling weg bij een gebruiker zonder wachtwoord: zijn sleutels gaan ook weg", r[0] == 200 and not main.wa_user("ssoalleen")["keys"], f"{r[0]} {detail(r)}")
events = [json.loads(line) for line in (COPY / "state" / "events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
check("... en dat staat in het logboek", any(e.get("kind") == "webauthn" and e.get("name") == "ssoalleen" for e in events))
call("PUT", "/api/users/lezer", ROOT, {"sso": {"cloudflare": "lezer@example.com"}})
r = call("PUT", "/api/users/lezer", ROOT, {"sso": {}})
check("bij een gebruiker met een wachtwoord blijven de sleutels", r[0] == 200 and main.wa_user("lezer")["keys"], f"{r[0]} {detail(r)}")
main.save_wa({})

since = int(time.time()) - 3000
r = call("PUT", "/api/users/beheer", token("beheer", since=since), {"sso": {"cloudflare": "beheer@example.com"}})
r = call("PUT", "/api/users/beheer", token("beheer", since=since), {"sso": {}})
new = session_of(r[2])
check("wie zijn eigen koppeling wijzigt houdt een sessie met de oude inlogtijd", new and main.token_since(new) == since, f"{r[0]} {new and main.token_since(new)}")
main.pve.run = lambda fn: {"history": {}}
r = call("GET", "/api/dashboard", token(main.APP_USER, since=since, expires=time.time() + 60))
new = session_of(r[2])
check("het dashboard verlengt de sessie, met de oude inlogtijd", r[0] == 200 and new and main.token_since(new) == since, f"{r[0]} {new and main.token_since(new)}")
check("een sessie zonder inlogtijd telt niet als recent", main.token_since(main.make_token("lezer", since=0)) == 0)

# ================================================================ G. OpenID Connect (M8)
print("--- G. OpenID Connect")
c_other, c_ms = {"provider": "other"}, {"provider": "microsoft"}
check("een bevestigd adres telt", main.oidc_email(c_other, {"email": "A@x.nl", "email_verified": True}) == "a@x.nl")
check("... ook als tekst 'true'", main.oidc_email(c_other, {"email": "a@x.nl", "email_verified": "true"}) == "a@x.nl")
check("onbevestigd: telt niet", main.oidc_email(c_other, {"email": "a@x.nl", "email_verified": False}) is None)
check("zonder email_verified: telt niet meer", main.oidc_email(c_other, {"email": "a@x.nl"}) is None)
check("Microsoft (geeft nooit email_verified): het adres van de eigen tenant", main.oidc_email(c_ms, {"email": "a@x.nl"}) == "a@x.nl")
check("Microsoft met email_verified false: telt niet", main.oidc_email(c_ms, {"email": "a@x.nl", "email_verified": False}) is None)
users = main.users_state()
main.save_users({**users, "lezer": {**users["lezer"], "sso": {"oidc": "lezer@x.nl", "oidc_sub": "https://idp|123"}}})
check("een vastgelegd account komt binnen, ook met een ander of onbevestigd adres",
      main.oidc_user(c_other, {"iss": "https://idp", "sub": "123", "email": "nieuw@x.nl"}) == ("lezer", None))
check("een ander account met hetzelfde adres: geweigerd",
      main.oidc_user(c_other, {"iss": "https://idp", "sub": "999", "email": "lezer@x.nl", "email_verified": True}) == (None, "mismatch"))
check("een nieuw account zonder bevestigd adres: geweigerd",
      main.oidc_user(c_other, {"iss": "https://idp", "sub": "555", "email": "lezer@x.nl"}) == (None, "noemail"))

# ================================================================ H. ISO van een webadres (M9)
print("--- H. ISO downloaden")
for host, want in (("127.0.0.1", False), ("10.1.2.3", False), ("192.168.1.10", False), ("172.16.5.5", False), ("169.254.169.254", False),
                   ("100.64.0.1", False), ("224.0.0.1", False), ("0.0.0.0", False), ("::1", False), ("fe80::1", False), ("fd00::1", False),
                   ("::ffff:10.0.0.1", False), ("64:ff9b::a00:1", False), ("2002:c0a8:101::1", False), ("localhost", False),
                   ("2130706433", False), ("::7f00:1", False), ("::ffff:0:7f00:1", False), ("fec0::1", False), ("240.0.0.1", False),
                   ("8.8.8.8", True), ("2606:4700:4700::1111", True), ("2a00:1450:4001::1", True), ("naam.invalid", None)):
    check(f"adres {host}: {'openbaar' if want else 'niet te vinden' if want is None else 'eigen netwerk'}", main.public_host(host) is want, str(main.public_host(host)))
ISO = {"node": "pve1", "storage": "local", "filename": "x.iso"}
STARTED = []
main.pve.run = lambda fn: STARTED.append(1) or "UPID:pve1:test"
r = call("POST", "/api/library/iso", STORE, {**ISO, "url": "http://192.168.1.10/x.iso"})
check("rol Opslag: een adres in het eigen netwerk wordt geweigerd", r[0] == 403 and not STARTED, f"{r[0]} {detail(r)}")
r = call("POST", "/api/library/iso", STORE, {**ISO, "url": "http://[::ffff:169.254.169.254]/x.iso"})
check("... ook verpakt in IPv6", r[0] == 403 and not STARTED, f"{r[0]} {detail(r)}")
r = call("POST", "/api/library/iso", STORE, {**ISO, "url": "https://8.8.8.8/x.iso"})
check("rol Opslag: een openbaar adres mag", r[0] == 200 and STARTED, f"{r[0]} {detail(r)}")
STARTED.clear()
r = call("POST", "/api/library/iso", ROOT, {**ISO, "url": "http://192.168.1.10/x.iso"})
check("een beheerder mag een adres in het eigen netwerk", r[0] == 200 and STARTED, f"{r[0]} {detail(r)}")

# ================================================================ I. kleine punten (L5, L6, L11)
print("--- I. kleine punten")
login_page = (COPY / "app" / "static" / "login.html").read_text(encoding="utf-8")
index_page = (COPY / "app" / "static" / "index.html").read_text(encoding="utf-8")
check("inlogformulier verstuurt nooit met GET (wachtwoord in de adresbalk)", '<form id="f" method="post"' in login_page)
check("inlogpagina: foutcode alleen uit de eigen lijst", "hasKey(SSO_CODES, code)" in login_page and "SSO_CODES[code] ||" not in login_page)
check("inlogpagina en tool: vertalen alleen met eigen sleutels", "hasKey(I18N[LANG], s)" in login_page and "hasKey(I18N[LANG], s)" in index_page)
check("labels: kleur alleen uit de eigen lijst", "hasKey(DATA.tag_style, key)" in index_page and "(DATA.tag_style || {})[" not in index_page)


class OsApi:
    def __init__(self, value):
        self.value = value

    def nodes(self, *_):
        return self

    def qemu(self, *_):
        return self

    def agent(self, *_):
        return self

    def get(self):
        return {"result": self.value}


check("guest agent: een OS-naam die geen tekst is telt niet", main.Updates._vm_os(OsApi({"pretty-name": {"x": 1}}), "pve1", 100) is None)
check("... en een rare result ook niet", main.Updates._vm_os(OsApi(["x"]), "pve1", 100) is None)
check("... tekst wordt netjes en kort", main.Updates._vm_os(OsApi({"pretty-name": "Debian\n13 " + "x" * 300}), "pve1", 100) == ("Debian 13 " + "x" * 300)[:120])
for pattern, value in ((main.NODE_RE, "pve1\n"), (main.USER_RE, "lezer\n"), (main.TAG_RE, "prod\n"), (main.EMAIL_RE, "a@x.nl\n"),
                       (main.SSH_KEY_RE, "ssh-ed25519 " + "A" * 68 + "\n"), (main.ACL_PATH_RE, "/vms\n")):
    check(f"geen regeleinde achter een waarde: {value.strip()[:16]!r}", not pattern.match(value) and pattern.match(value.strip()))
for nl in ("Dit verzoek is te groot", main.TOO_MANY_NAME, "De tool is even te druk om het wachtwoord te controleren; probeer het zo opnieuw",
           "Log eerst opnieuw in (via SSO of met een sleutel); daarna kun je vijf minuten lang je sleutels wijzigen",
           "De naam {0} is niet te vinden", "Alleen een beheerder kan een ISO laten downloaden van een adres in het eigen netwerk"):
    text = nl.replace("{0}", "x.nl")
    check(f"melding vertaald: {nl[:40]}…", main.translate(text, "en") != text and main.translate(text, "de") != text)
check("venster sleutels: uitleg en knop voor opnieuw inloggen", 'id="key-old"' in index_page and 'id="key-relogin"' in index_page)

# ================================================================ J. bijwerken via de node
print("--- J. bijwerken via de node")
import socket  # noqa: E402

ME_CT = {"vmid": 110, "type": "lxc", "node": "pve2", "status": "running", "name": socket.gethostname(), "tags": "maintool;infra"}


class ClusterApi:
    def __init__(self, guests):
        self.guests = guests
        self.cluster = self
        self.resources = self

    def get(self, **_):
        return self.guests


main.pve.run = lambda fn: fn(ClusterApi([ME_CT, {"vmid": 111, "type": "lxc", "node": "pve1", "name": "andere", "tags": "maintool"}]))
(COPY / "updater").write_text("stand-in", encoding="utf-8")
main.UPDATER = COPY / "updater"
main.update_check = lambda: {"ok": False, "code": "needs_setup", "detail": "anders dan geïnstalleerd: install.sh", "current": main.VERSION}
main.UPDATE_DIR.mkdir(parents=True, exist_ok=True)


def stage(version="1.5.3", marker=True, extra=b""):
    body = (b'#!/usr/bin/env bash\n# Proxmox Maintool - setup file (version ' + version.encode() + b')\nset -Eeuo pipefail\n\nVERSION="'
            + version.encode() + b'"\nPVE_USER="maintool@pve"\n' + (b"UNATTENDED=1\n" if marker else b"") + b"x" * 50000 + extra)
    main.UPDATE_FILE.write_bytes(body)
    return hashlib.sha256(body).hexdigest()


SHA = stage()
v = asyncio.run(main.judge_update())
plan = v.get("node_update") or {}
check("versie die meer verandert: via de node mogelijk, met node, container en vingerafdruk",
      v.get("code") == "needs_setup" and plan.get("possible") and plan.get("node") == "pve2" and plan.get("ctid") == 110
      and plan.get("version") == "1.5.3" and plan.get("sha256") == SHA, str(v))
check("... en het bestand blijft klaarstaan", main.UPDATE_FILE.is_file())
stage(marker=False)
v = asyncio.run(main.judge_update())
check("een ouder setup-bestand (zonder UNATTENDED=1): niet via de node, bestand weg",
      not v["node_update"]["possible"] and v["node_update"]["why"] == "old_setup" and not main.UPDATE_FILE.exists(), str(v))
stage(version="1.5.1")
v = asyncio.run(main.judge_update())
check("geen nieuwere versie: niet via de node", not v["node_update"]["possible"], str(v))
main.pve.run = lambda fn: fn(ClusterApi([dict(ME_CT), dict(ME_CT, vmid=112)]))
SHA = stage()
v = asyncio.run(main.judge_update())
check("twee containers die op de tool lijken: niet via de node", v["node_update"].get("why") == "no_container", str(v))
main.pve.run = lambda fn: fn(ClusterApi([dict(ME_CT, tags="")]))
SHA = stage()
check("container zonder het label maintool: niet via de node", asyncio.run(main.judge_update())["node_update"].get("why") == "no_container")
main.pve.run = lambda fn: fn(ClusterApi([ME_CT]))
SHA = stage()
asyncio.run(main.judge_update())

r = call("GET", "/api/selfupdate/node", ROOT)
check("de pagina ziet node, container en dat de console nog dicht is", r[0] == 200 and r[1]["possible"] and r[1]["console"] is None, str(r[1]))
check("alleen beheerders", call("GET", "/api/selfupdate/node", token("lezer"))[0] == 403)
r = call("POST", "/api/selfupdate/node", ROOT, {"password": main.APP_PASSWORD, "sha256": SHA})
check("zonder console-inlog: eerst inloggen als root@pam", r[0] == 409 and "root@pam" in detail(r) and "pve2" in detail(r), f"{r[0]} {detail(r)}")
KEY = hashlib.sha256(ROOT.encode()).hexdigest()
main._nodecon[KEY] = {"owner": main.APP_USER, "user": "beheer@pve", "ticket": "PVE:beheer@pve:x", "csrf": "c", "exp": time.time() + 3600}
r = call("POST", "/api/selfupdate/node", ROOT, {"password": main.APP_PASSWORD, "sha256": SHA})
check("console als een ander account dan root@pam: geweigerd", r[0] == 409 and "root@pam" in detail(r), f"{r[0]} {detail(r)}")
main._nodecon[KEY] = {"owner": main.APP_USER, "user": "root@pam", "ticket": "PVE:root@pam:x", "csrf": "c", "exp": time.time() + 3600}
check("met de console als root@pam ziet de pagina dat", call("GET", "/api/selfupdate/node", ROOT)[1]["console"] == "root@pam")
main.login_guard.reset()
r = call("POST", "/api/selfupdate/node", ROOT, {"password": "fout", "sha256": SHA})
check("verkeerd wachtwoord van de tool: geweigerd en geteld", r[0] == 403 and main.login_guard.fails, f"{r[0]} {detail(r)}")
r = call("POST", "/api/selfupdate/node", ROOT, {"password": main.APP_PASSWORD, "sha256": "0" * 64})
check("een andere vingerafdruk dan getoond: geweigerd", r[0] == 409, f"{r[0]} {detail(r)}")
r = call("POST", "/api/selfupdate/node", ROOT, {"password": main.APP_PASSWORD, "sha256": SHA}, origin="https://andere.example")
check("niet van de eigen pagina: geweigerd", r[0] == 403)


class FakeShell:
    """Een nagebootste shell op de node achter termproxy: antwoordt OK op de inlog en reply(regel) op wat er getypt wordt."""

    def __init__(self, reply):
        self.sent, self.reply, self.queue, self.url, self.kw = [], reply, None, None, None

    async def __aenter__(self):
        self.queue = asyncio.Queue()
        return self

    async def __aexit__(self, *exc):
        return False

    async def send(self, message):
        first = not self.sent
        self.sent.append(message)
        if first:
            await self.queue.put("OK")
        elif isinstance(message, bytes) and message.startswith(b"0:"):
            typed = message.split(b":", 2)[2].decode()
            if typed.strip() != "exit":
                for chunk in self.reply(typed):
                    await self.queue.put(chunk)

    async def recv(self):
        return await self.queue.get()


def connect_to(shell):
    def connect(url, **kw):
        shell.url, shell.kw = url, kw
        return shell
    return connect


def started(typed):
    stamp = re.search(r'MAINTOOL-STAR""TED-(\d+)', typed).group(1)
    return [b"\x1b]0;root@pve2: ~\x07root@pve2:~# " + typed.encode().replace(b"\n", b"\r\n"), f"MAINTOOL-STARTED-{stamp}\r\n".encode()]


main.node_termproxy = lambda entry, node: {"host": "192.0.2.1", "port": 5900, "ticket": "PVEVNC:abc", "user": "root@pam"}
SHELL = FakeShell(started)
main.websockets.connect = connect_to(SHELL)
main.login_guard.reset()
r = call("POST", "/api/selfupdate/node", ROOT, {"password": main.APP_PASSWORD, "sha256": SHA})
check("gestart via de node", r[0] == 200 and r[1].get("started") and r[1]["node"] == "pve2" and r[1]["ctid"] == 110 and r[1]["version"] == "1.5.3", f"{r[0]} {r[1]}")
typed = next((m for m in SHELL.sent if isinstance(m, bytes) and m.startswith(b"0:")), b"").split(b":", 2)[-1].decode()
check("ingelogd met het ticket van de console", SHELL.sent[0] == "root@pam:PVEVNC:abc\n" and "pve2/vncwebsocket?port=5900" in SHELL.url
      and SHELL.kw["additional_headers"]["Cookie"] == "PVEAuthCookie=PVE:root@pam:x", str(SHELL.sent[:1]))
check("getypt: het bestand uit de container halen", f"pct pull 110 {main.UPDATE_FILE} " in typed, typed)
check("... de vingerafdruk controleren", f'echo "{SHA}  $f" | sha256sum -c --status' in typed)
check("... en op de achtergrond starten, zonder vragen, in de taal van de pagina",
      "systemd-run --quiet --collect --unit=maintool-update-" in typed and '--lang nl --update 110 --yes' in typed)
check("... in één regel, niet in de geschiedenis van bash, zonder !", typed.startswith(" ") and typed.count("\n") == 1 and "!" not in typed)
check("daarna de shell weer dicht", SHELL.sent[-1] == b"0:5:exit\n", str(SHELL.sent[-1:]))
st = call("GET", "/api/selfupdate/status", ROOT)[1].get("node") or {}
check("de status noemt de lopende update via de node", st.get("version") == "1.5.3" and st.get("node") == "pve2", str(st))
events = [json.loads(line) for line in (COPY / "state" / "events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
check("in het logboek", any(e.get("kind") == "selfupdate" and e.get("name") == "1.5.3" and e.get("node") == "pve2" for e in events))
r = call("POST", "/api/selfupdate/node", ROOT, {"password": main.APP_PASSWORD, "sha256": SHA})
check("niet twee keer tegelijk", r[0] == 409 and "pve2" in detail(r), f"{r[0]} {detail(r)}")
main.NODE_UPDATE_STATE.unlink()

def refused(typed):
    stamp = re.search(r'MAINTOOL-FAIL""ED-(\d+)', typed).group(1)
    return [b"sha256sum: WARNING: 1 computed checksum did NOT match\r\n", f"MAINTOOL-FAILED-{stamp}\r\n".encode()]


SHELL = FakeShell(refused)
main.websockets.connect = connect_to(SHELL)
r = call("POST", "/api/selfupdate/node", ROOT, {"password": main.APP_PASSWORD, "sha256": SHA}, headers=[("cookie", "maintool_lang=de")])
check("mislukt op de node: 502 met wat de node zei", r[0] == 502 and "did NOT match" in detail(r), f"{r[0]} {detail(r)}")
typed = next(m for m in SHELL.sent if isinstance(m, bytes) and m.startswith(b"0:")).decode()
check("... de taal van de pagina gaat mee naar het setup-bestand", "--lang de " in typed)
check("... en er staat niets als lopend genoteerd", not main.NODE_UPDATE_STATE.exists())
SHELL = FakeShell(lambda typed: [])
main.websockets.connect = connect_to(SHELL)
outcome, _ = asyncio.run(main.node_type(main._nodecon[KEY], "pve2", " echo x", "A", "B", timeout=1))
check("geen antwoord van de node: na de wachttijd 'niets'", outcome is None)
for bad in ((5, SHA, "1.5.3", "nl"), (110, "xyz", "1.5.3", "nl"), (110, SHA, "1.5.3; rm -rf /", "nl"), (110, SHA, "1.5.3", "fr")):
    try:
        main.node_update_line(*bad, 1)
        check(f"opdracht met een rare waarde geweigerd: {bad[1:] if bad[0] == 110 else bad[0]}", False)
    except HTTPException:
        check(f"opdracht met een rare waarde geweigerd: {str(bad)[:40]}", True)
check("de pagina: blok, knoppen en wachten op de node", all(x in index_page for x in ('id="su-node"', 'id="su-nodego"', 'id="su-nodelogin"', "function suWaitNode", "ncLogin(suPlan.node")))
for nl in ("Log eerst in op de console van node {0} als root@pam", "Het starten op node {0} is mislukt: {1}",
           "Er loopt al een update via node {0}; wacht tot die klaar is"):
    text = nl.replace("{0}", "pve2").replace("{1}", "x")
    check(f"melding vertaald: {nl[:40]}…", main.translate(text, "en") != text and main.translate(text, "de") != text)
check("versie 1.5.2", main.VERSION == "1.5.2", main.VERSION)

print()
print("ALLES GOED" if not FAILED else f"FOUT ({len(FAILED)}): {FAILED}")
sys.exit(1 if FAILED else 0)
