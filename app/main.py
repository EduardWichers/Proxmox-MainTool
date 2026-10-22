"""
Proxmox Maintool - onderhoudstool voor Proxmox VE (versie: zie het bestand VERSION)
Praat met het Proxmox-cluster via de REST API (API-token), met failover over alle nodes.

(c) 2026 Eduard Wichers - MIT-licentie, gebruik op eigen risico (zie LICENSE).
"""
import asyncio
import base64
import datetime as dt
import hashlib
import hmac
import ipaddress
import html
import json
import os
import re
import secrets
import shlex
import smtplib
import socket
import ssl
import subprocess
import tarfile
import threading
import time
import urllib.parse
import zipfile
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
from email.utils import formataddr
from pathlib import Path
from zoneinfo import ZoneInfo

import requests
import websockets
from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from proxmoxer import ProxmoxAPI
from proxmoxer.core import ResourceException
from pydantic import BaseModel, Field
from requests.adapters import HTTPAdapter

# ---------------------------------------------------------------- configuratie
HOSTS = [h.strip() for h in os.environ.get("PVE_HOSTS", "").split(",") if h.strip()]
PVE_USER = os.environ.get("PVE_USER", "maintool@pve")
TOKEN_NAME = os.environ.get("PVE_TOKEN_NAME", "webtool")
TOKEN_VALUE = os.environ.get("PVE_TOKEN_VALUE", "")
CA_FILE = os.environ.get("PVE_CA_FILE", "").strip()
if CA_FILE:
    VERIFY = CA_FILE
else:
    VERIFY = os.environ.get("PVE_VERIFY_SSL", "true").lower() in ("1", "true", "yes")

APP_USER = os.environ.get("APP_USER", "admin")
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")

# SSH naar de nodes, uitsluitend voor de maintool-agent (zie node/maintool-agent; het setup-bestand zet hem op de nodes).
SSH_KEY = os.environ.get("SSH_KEY_FILE", "/etc/maintool/ssh/id_ed25519")
SSH_KNOWN_HOSTS = os.environ.get("SSH_KNOWN_HOSTS", "/etc/maintool/ssh/known_hosts")



def is_ip(text) -> bool:
    try:
        ipaddress.ip_address(str(text))
        return True
    except ValueError:
        return False


IP_HOSTS = bool(HOSTS) and all(is_ip(h) for h in HOSTS)   # alleen dan is te volgen welke nodes het cluster heeft

if not HOSTS or not TOKEN_VALUE or not APP_PASSWORD:
    raise SystemExit("PVE_HOSTS, PVE_TOKEN_VALUE en APP_PASSWORD moeten gezet zijn (zie maintool.env)")

# ---------------------------------------------------------------- validatie
KINDS = {"qemu", "lxc"}
ACTIONS = {"start", "shutdown", "stop", "reboot"}
NODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]{0,62}$")
SNAP_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_\-]{1,39}$")


def check_target(node: str, kind: str, vmid: int):
    if not NODE_RE.match(node):
        raise HTTPException(400, "Ongeldige nodenaam")
    if kind not in KINDS:
        raise HTTPException(400, "Type moet qemu of lxc zijn")
    if not (100 <= vmid <= 999999999):
        raise HTTPException(400, "Ongeldig VMID")


def check_snap(name: str):
    if not SNAP_RE.match(name) or name == "current":
        raise HTTPException(400, "Snapshotnaam: begint met een letter, 2-40 tekens, alleen letters/cijfers/_/-")


# ---------------------------------------------------------------- authenticatie
# Eigen inlogpagina met een sessiecookie. Het wachtwoordvenster van de browser (HTTP Basic) is hier bewust niet meer:
# het externe adres van de tool zit achter Cloudflare Access en daar toont de browser dat venster niet.
STATE_DIR = Path(os.environ.get("STATE_DIRECTORY", "/var/lib/maintool"))
SESSION_COOKIE = "maintool_session"
SESSION_SECONDS = int(float(os.environ.get("SESSION_HOURS", "12")) * 3600)


def load_session_key() -> bytes:
    """De sleutel waarmee sessies worden ondertekend; blijft bewaard, zodat een herstart niemand uitlogt."""
    path = STATE_DIR / "session.key"
    try:
        if not path.exists():
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(secrets.token_bytes(32))
        key = path.read_bytes()
        if len(key) >= 32:
            return key
    except OSError:
        pass
    return secrets.token_bytes(32)  # geen schrijfbare map: sessies gelden dan tot de volgende herstart


SESSION_KEY = load_session_key()


def sign(payload: str) -> str:
    return hmac.new(SESSION_KEY, payload.encode(), hashlib.sha256).hexdigest()


AUTH_FILE = STATE_DIR / "auth.json"
_auth = {"stamp": None, "data": {}}


def auth_state() -> dict:
    """Het in de tool gewijzigde wachtwoord (alleen als hash) en het volgnummer van de sessies.

    Zonder dit bestand geldt het wachtwoord uit maintool.env; het bestand weggooien zet dat wachtwoord dus terug
    (voor wie het nieuwe vergeten is). Bij elke wijziging gaat het volgnummer omhoog, waardoor alle sessies die
    daarvoor zijn uitgegeven vervallen. Het bestand wordt opnieuw gelezen zodra het verandert."""
    try:
        info = AUTH_FILE.stat()
        stamp = (info.st_mtime_ns, info.st_size)
    except OSError:
        stamp = None
    if stamp != _auth["stamp"]:
        data = {}
        if stamp:
            try:
                loaded = json.loads(AUTH_FILE.read_text(encoding="utf-8"))
                if (isinstance(loaded, dict) and re.fullmatch(r"[0-9a-f]{32}", str(loaded.get("salt")))
                        and re.fullmatch(r"[0-9a-f]{64}", str(loaded.get("hash")))):
                    data = {"salt": loaded["salt"], "hash": loaded["hash"], "gen": int(loaded.get("gen") or 0)}
            except (OSError, ValueError, TypeError):
                pass
        _auth.update(stamp=stamp, data=data)
    return _auth["data"]


def password_hash(password: str, salt: bytes) -> str:
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32).hex()


def password_ok(password: str) -> bool:
    saved = auth_state()
    if saved:
        return hmac.compare_digest(password_hash(password, bytes.fromhex(saved["salt"])), saved["hash"])
    return secrets.compare_digest(password.encode(), APP_PASSWORD.encode())


# Gebruikers. Het hoofdaccount is APP_USER uit maintool.env: altijd beheerder, niet te verwijderen. Alle andere
# gebruikers staan in users.json (alleen een hash van hun wachtwoord) met hun rollen. Kijken mag iedereen die is
# ingelogd; een rol geeft het recht om op één tabblad dingen te doen. "admin" is beheerder van alles, ook van de
# gebruikers en de tool zelf. Geen enkele rol = alleen lezen. De namen van de rollen zijn die van de tabbladen.
USERS_FILE = STATE_DIR / "users.json"
USER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}$")
AREAS = ("overview", "storage", "network", "backups", "events")
MAX_USERS = 50
MIN_PASSWORD_DEFAULT, MIN_PASSWORD_RANGE = 12, (8, 128)


def clean_roles(roles, role=None) -> list:
    """Maakt van wat is opgegeven een nette lijst rollen; None als het niet klopt. role is de oude vorm van vóór 1.6
    ("admin" of "readonly")."""
    if roles is None:
        return {"admin": ["admin"], "readonly": []}.get(role)
    if not isinstance(roles, (list, tuple)) or any(r != "admin" and r not in AREAS for r in roles):
        return None
    return ["admin"] if "admin" in roles else [a for a in AREAS if a in roles]
_users = {"stamp": None, "data": {}}
users_lock = threading.Lock()


def users_state() -> dict:
    """naam -> {roles, salt, hash, gen, created, sso, pw}; wordt opnieuw gelezen zodra het bestand verandert. Wie alleen
    met SSO inlogt heeft een wachtwoord dat niemand kent (pw false); een oudere versie van de tool laat hem dus niet binnen."""
    try:
        info = USERS_FILE.stat()
        stamp = (info.st_mtime_ns, info.st_size)
    except OSError:
        stamp = None
    if stamp != _users["stamp"]:
        data = {}
        if stamp:
            try:
                for name, u in (json.loads(USERS_FILE.read_text(encoding="utf-8")).get("users") or {}).items():
                    roles = clean_roles(u.get("roles"), u.get("role")) if isinstance(u, dict) else None
                    if (USER_RE.match(str(name)) and roles is not None
                            and re.fullmatch(r"[0-9a-f]{32}", str(u.get("salt"))) and re.fullmatch(r"[0-9a-f]{64}", str(u.get("hash")))):
                        data[name] = {"roles": roles, "salt": u["salt"], "hash": u["hash"], "gen": int(u.get("gen") or 0),
                                      "created": int(u.get("created") or 0), "sso": stored_links(u.get("sso")),
                                      "pw": u.get("pw") is not False}   # pw: mag ook met een wachtwoord inloggen
            except (OSError, ValueError, TypeError, AttributeError):
                pass
        _users.update(stamp=stamp, data=data)
    return _users["data"]


def save_users(data: dict):
    tmp = USERS_FILE.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json.dumps({"users": data}))
    os.replace(tmp, USERS_FILE)


def role_name(roles) -> str:
    """De korte aanduiding voor de pagina: admin, readonly (geen enkele rol) of custom (een of meer tabbladen)."""
    return "admin" if "admin" in roles else "custom" if roles else "readonly"


def account(user) -> dict | None:
    """Rollen en sessie-volgnummer van een gebruiker; None als hij niet (meer) bestaat. can = waar hij iets mag doen."""
    if user == APP_USER:
        return {"roles": ["admin"], "role": "admin", "admin": True, "can": ["admin", *AREAS], "gen": auth_state().get("gen", 0), "builtin": True}
    found = users_state().get(user) if isinstance(user, str) else None
    if not found:
        return None
    is_admin = "admin" in found["roles"]
    return {"roles": list(found["roles"]), "role": role_name(found["roles"]), "admin": is_admin,
            "can": ["admin", *AREAS] if is_admin else list(found["roles"]), "gen": found["gen"], "builtin": False}


def check_login(user: str, password: str) -> bool:
    """Klopt dit wachtwoord bij deze gebruiker? Kost voor een onbekende naam evenveel rekentijd als voor een bekende."""
    if secrets.compare_digest(user.encode(), APP_USER.encode()):
        if not auth_state():
            password_hash(password, b"\0" * 16)
        return password_ok(password)
    found = users_state().get(user)
    if not found:
        password_hash(password, b"\0" * 16)
        return False
    return hmac.compare_digest(password_hash(password, bytes.fromhex(found["salt"])), found["hash"]) and found["pw"]


def min_password() -> int:
    """De minimale lengte van een nieuw wachtwoord; de beheerder stelt die in (zie /api/policy)."""
    try:
        n = int((state.load().get("policy") or {}).get("min_password"))
    except (TypeError, ValueError, AttributeError):
        return MIN_PASSWORD_DEFAULT
    return n if MIN_PASSWORD_RANGE[0] <= n <= MIN_PASSWORD_RANGE[1] else MIN_PASSWORD_DEFAULT


def new_password_problem(password: str) -> str | None:
    if len(password) < min_password():
        return f"Het nieuwe wachtwoord moet minstens {min_password()} tekens lang zijn"
    if password != password.strip() or any(ord(c) < 32 or ord(c) == 127 for c in password):
        return "Het nieuwe wachtwoord mag niet met een spatie beginnen of eindigen en geen stuurtekens bevatten"
    return None


IDLE_CHOICES = (0, 15, 30, 60, 120, 240, 480)   # minuten zonder activiteit tot de pagina uitlogt; 0 = nooit
REMEMBER_DAYS = (7, 14, 30, 90)                  # hoe lang "Ingelogd blijven" duurt
SESSION_HOURS_RANGE = (1, 24)                    # hoe lang een gewone sessie hooguit duurt


def session_policy() -> dict:
    """De instellingen voor sessies (de beheerder stelt die in, zie /api/policy), met de standaard waar niets staat."""
    p = state.load().get("policy")
    p = p if isinstance(p, dict) else {}
    whole = lambda v: isinstance(v, int) and not isinstance(v, bool)  # noqa: E731
    hours = p.get("session_hours")
    return {"idle": p["idle"] if whole(p.get("idle")) and p["idle"] in IDLE_CHOICES else 0,
            "remember": p.get("remember") is not False,
            "remember_days": p["remember_days"] if whole(p.get("remember_days")) and p["remember_days"] in REMEMBER_DAYS else 30,
            "session_hours": hours if whole(hours) and SESSION_HOURS_RANGE[0] <= hours <= SESSION_HOURS_RANGE[1]
            else min(max(round(SESSION_SECONDS / 3600), SESSION_HOURS_RANGE[0]), SESSION_HOURS_RANGE[1])}


def make_token(user: str, remember: bool = False) -> str:
    """Een ondertekende sessie. Met remember ("Ingelogd blijven") duurt hij dagen in plaats van uren, en staat dat erin."""
    pol = session_policy()
    life = pol["remember_days"] * 86400 if remember else pol["session_hours"] * 3600
    data = {"u": user, "e": int(time.time()) + life, "g": (account(user) or {}).get("gen", 0)}
    if remember:
        data["r"] = 1
    payload = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
    return f"{payload}.{sign(payload)}"


def token_remembered(token) -> bool:
    """Of deze (geldige) sessie met Ingelogd blijven is gestart."""
    try:
        payload = (token or "").partition(".")[0]
        return bool(json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))).get("r"))
    except (ValueError, TypeError, AttributeError):
        return False


def set_session_cookie(response, user: str, remember: bool = False):
    """Met Ingelogd blijven (als de beheerder dat toestaat) een cookie dat blijft na het sluiten van de browser; anders
    een sessiecookie dat dan verdwijnt (en de sessie zelf verloopt na session_hours). Lax: het cookie gaat niet mee
    met verzoeken die een andere website namens de gebruiker doet."""
    pol = session_policy()
    remember = bool(remember and pol["remember"])
    extra = {"max_age": pol["remember_days"] * 86400} if remember else {}
    response.set_cookie(SESSION_COOKIE, make_token(user, remember), path="/", httponly=True, secure=True, samesite="lax", **extra)


def read_token(token) -> str | None:
    """De gebruiker uit een geldig, niet verlopen sessiecookie; anders None."""
    payload, _, signature = (token or "").partition(".")
    if not signature or not hmac.compare_digest(signature, sign(payload)):
        return None
    try:
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except ValueError:
        return None
    who = account(data.get("u"))
    if not who or data.get("g", 0) != who["gen"]:
        return None  # gebruiker bestaat niet meer, of de sessie is van vóór zijn laatste wachtwoordwijziging
    return data["u"] if data.get("e", 0) > time.time() else None


def auth(request: Request) -> str:
    """Iedere ingelogde gebruiker: kijken mag altijd."""
    user = read_token(request.cookies.get(SESSION_COOKIE))
    if not user:
        raise HTTPException(401, "Niet ingelogd")
    return user


def admin(request: Request) -> str:
    """Alleen beheerders: de gebruikers, het wachtwoordbeleid en het bijwerken van de tool zelf."""
    user = auth(request)
    if not (account(user) or {}).get("admin"):
        raise HTTPException(403, "Hiervoor zijn beheerdersrechten nodig")
    refuse_view_only(request)   # via Cloudflare alleen bekijken (zie "via Cloudflare")
    return user


def need(*areas):
    """Maakt de controle voor wat op een tabblad iets verandert: beheerders mogen het altijd, en verder iedereen met
    de rol van (een van) deze tabbladen."""
    def guard(request: Request) -> str:
        user = auth(request)
        who = account(user) or {}
        if not (who.get("admin") or any(a in who.get("roles", ()) for a in areas)):
            raise HTTPException(403, "Hiervoor heb je niet de juiste rol")
        refuse_view_only(request)
        return user
    guard.areas = areas
    return guard


manage_overview, manage_storage, manage_network, manage_backups, manage_events = (need(a) for a in AREAS)
manage_create = need("overview", "storage")   # de keuzelijsten voor aanmaken dienen beide tabbladen


class LoginGuard:
    """Rem op raden: na 5 mislukte pogingen vanaf één adres (of 20 in totaal) binnen 10 minuten is inloggen dicht."""

    WINDOW, PER_SOURCE, TOTAL = 600, 5, 20

    def __init__(self):
        self.failures = []  # (tijdstip, afzender)
        self.lock = threading.Lock()

    def blocked(self, source: str) -> bool:
        with self.lock:
            self.failures = [f for f in self.failures if f[0] > time.time() - self.WINDOW]
            return len(self.failures) >= self.TOTAL or sum(1 for f in self.failures if f[1] == source) >= self.PER_SOURCE

    def failed(self, source: str):
        with self.lock:
            self.failures.append((time.time(), source))

    def succeeded(self, source: str):
        with self.lock:
            self.failures = [f for f in self.failures if f[1] != source]


login_guard = LoginGuard()


# ---------------------------------------------------------------- Proxmox-verbinding
def cluster_ssl_context(cafile: str) -> ssl.SSLContext:
    """De TLS-instelling voor elke verbinding met de nodes; zie ClusterCAAdapter voor het waarom."""
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return ctx


class ClusterCAAdapter(HTTPAdapter):
    """Verifieert tegen de cluster-CA zonder de strikte RFC 5280-controle van Python 3.13+.

    De CA die Proxmox zelf genereert heeft geen key usage-extensie en wordt daardoor in strikte
    modus geweigerd. Keten, geldigheid en hostnaam/IP worden nog steeds gecontroleerd.
    """

    def __init__(self, cafile: str, **kwargs):
        self._ctx = cluster_ssl_context(cafile)
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self._ctx
        return super().init_poolmanager(*args, **kwargs)


def make_api(host: str, timeout: int = 10) -> ProxmoxAPI:
    api = ProxmoxAPI(host, user=PVE_USER, token_name=TOKEN_NAME,
                     token_value=TOKEN_VALUE, verify_ssl=VERIFY, timeout=timeout)
    if CA_FILE:
        api._store["session"].mount("https://", ClusterCAAdapter(CA_FILE))
    return api


class Cluster:
    """Houdt één API-verbinding open en schakelt over naar een andere node als die wegvalt."""

    def __init__(self):
        self.api = None
        self.host = None
        self.hosts = list(HOSTS) + [h for h in self._saved_hosts() if h not in HOSTS]  # volgt het cluster, zie follow()
        self.followed_at = 0.0
        self.probes = {}        # host -> eigen verbinding, alleen voor de bereikbaarheidscontrole
        self.reachable = {}     # host -> bool
        self.checked_at = 0.0

    def connect(self):
        errors = []
        # Probeer eerst de huidige host niet opnieuw als eerste; begin bij de volgende.
        order = self.hosts
        if self.host in self.hosts:
            i = self.hosts.index(self.host)
            order = self.hosts[i + 1:] + self.hosts[: i + 1]
        for host in order:
            try:
                api = make_api(host)
                api.version.get()
                if host != self.host:
                    node_trouble.clear()   # wat via de vorige host vastliep kan via deze gewoon werken
                self.api, self.host = api, host
                return
            except Exception as e:  # noqa: BLE001
                errors.append(f"{host}: {e.__class__.__name__}")
        self.api = None
        raise HTTPException(503, "Geen enkele Proxmox-node bereikbaar (" + "; ".join(errors) + ")")

    def run(self, fn):
        if self.api is None:
            self.connect()
        try:
            return fn(self.api)
        except (requests.ConnectionError, requests.Timeout):
            self.connect()
            return fn(self.api)
        except ResourceException as e:
            raise HTTPException(e.status_code or 500, f"Proxmox: {e.status_message} {e.content or ''}".strip())

    def _probe(self, host):
        try:
            api = self.probes.get(host) or make_api(host, timeout=3)
            api.version.get()
            self.probes[host] = api
            return True
        except Exception:  # noqa: BLE001
            self.probes.pop(host, None)
            return False

    @staticmethod
    def _saved_hosts() -> list:
        """De adressen van nodes die er na de installatie bij zijn gekomen, zoals follow() ze heeft bewaard."""
        if not IP_HOSTS:
            return []
        try:
            saved = json.loads((STATE_DIR / "state.json").read_text(encoding="utf-8")).get("hosts") or []
            return [h for h in saved if isinstance(h, str) and is_ip(h)][:32]
        except (OSError, ValueError, AttributeError, TypeError):
            return []

    def follow(self):
        """Houdt de lijst van API-adressen gelijk aan de nodes van het cluster: een node die erbij komt wordt
        vanzelf gebruikt (ook als uitwijk), een node die uit het cluster is gehaald valt af.

        Alleen als de ingestelde adressen IP-adressen zijn (namen zijn niet te herleiden tot wat het cluster meldt)
        en alleen als het cluster het adres waarmee de tool nu verbonden is zelf ook noemt: dan staat vast dat het
        dezelfde adressen meldt als de tool gebruikt, en blijft de werkende verbinding hoe dan ook in de lijst.
        Elke node wordt met het certificaat van het cluster gecontroleerd, net als de ingestelde adressen."""
        if self.api is None or not IP_HOSTS:
            return
        try:
            members = [e["ip"] for e in self.api.cluster.status.get() if e.get("type") == "node" and is_ip(e.get("ip"))]
        except Exception:  # noqa: BLE001 - geen antwoord: de lijst blijft zoals hij is
            return
        if self.host not in members or len(members) > 64:
            return
        hosts = [h for h in self.hosts if h in members] + sorted(m for m in members if m not in self.hosts)
        if hosts != self.hosts:
            self.hosts = hosts
            self.probes = {h: c for h, c in self.probes.items() if h in hosts}
            try:
                state.change(lambda d: d.update(hosts=hosts))
            except Exception:  # noqa: BLE001
                pass

    def hosts_status(self):
        """Bereikbaarheid van elk API-adres; hooguit eens per 15 s opnieuw gemeten."""
        if time.monotonic() - self.followed_at > 60:
            self.followed_at = time.monotonic()
            self.follow()
        if time.monotonic() - self.checked_at > 15:
            self.checked_at = time.monotonic()
            hosts = list(self.hosts)
            self.reachable = dict(zip(hosts, POOL.map(self._probe, hosts)))
        return [{"host": h, "ok": self.reachable.get(h, False), "active": h == self.host} for h in self.hosts]


POOL = ThreadPoolExecutor(max_workers=8)
pve = Cluster()


def guest(api, node, kind, vmid):
    return api.nodes(node)(kind)(vmid)


class NodeTrouble:
    """Nodes die het cluster online noemt maar die via de API niet antwoorden.

    Een vraag aan een node gaat via de node waarmee de tool verbonden is; die stuurt hem door naar het adres waaronder
    de node in het cluster bekend staat (Proxmox neemt dat uit /etc/hosts op die node). Klopt dat adres niet, dan wacht
    de doorsturende node tevergeefs en loopt de vraag na 10 s af. Zonder dit gaf zo één node een foutmelding op de hele
    pagina, elke paar seconden opnieuw (gezien op een ander cluster, 1.3.2). Nu wordt die node overgeslagen en melden de
    nodekaart en de aandachtspunten wat er aan de hand is. Of hij weer antwoordt, kijkt een eigen draad eens per minuut
    na; zo wacht geen enkele pagina daar nog op."""
    HOLD = 60

    def __init__(self):
        self.lock = threading.Lock()
        self.bad = {}   # node -> (sinds, wanneer opnieuw nakijken (monotonic), reden)
        self.probing = set()

    def skip(self, node) -> bool:
        with self.lock:
            b = self.bad.get(node)
            if not b:
                return False
            if time.monotonic() >= b[1] and node not in self.probing:
                self.probing.add(node)
                threading.Thread(target=self._probe, args=(node,), daemon=True).start()
            return True

    def _probe(self, node):
        try:
            api = pve.api
            if api is None:
                raise requests.ReadTimeout()
            api.nodes(node).version.get()
            self.answered(node)
        except ResourceException as err:
            (self.failed if (err.status_code or 0) in (595, 596) else self.answered)(node, f"{err.status_code}")
        except Exception:  # noqa: BLE001 - nog steeds geen antwoord: over een minuut opnieuw
            self.failed(node, "timeout")
        finally:
            with self.lock:
                self.probing.discard(node)

    def failed(self, node, why: str):
        with self.lock:
            since = (self.bad.get(node) or (time.time(),))[0]
            self.bad[node] = (since, time.monotonic() + self.HOLD, why)

    def answered(self, node, _why=""):
        with self.lock:
            self.bad.pop(node, None)

    def clear(self):
        with self.lock:
            self.bad.clear()

    def current(self) -> dict:
        with self.lock:
            return {n: {"since": int(b[0]), "why": b[2]} for n, b in self.bad.items()}


node_trouble = NodeTrouble()


def on_node(node, call, default=None):
    """call() is een vraag aan één node. Antwoordt die node niet (de doorsturende node wacht tevergeefs, of meldt dat
    hij hem niet bereikt: Proxmox-code 595/596), dan geeft dit default terug en wordt de node een minuut overgeslagen,
    zodat één node die vastzit de rest van de pagina niet ophoudt. Andere fouten gaan gewoon door naar de aanroeper."""
    if node_trouble.skip(node):
        return default
    try:
        out = call()
    except requests.ReadTimeout:
        node_trouble.failed(node, "timeout")
        return default
    except ResourceException as err:
        if (err.status_code or 0) in (595, 596):
            node_trouble.failed(node, f"{err.status_code} {str(err.status_message or '')[:120]}".strip())
            return default
        raise
    node_trouble.answered(node)
    return out


def node_answers(api, node) -> bool:
    """Antwoordt deze node via de API? Een foutmelding van de node zelf telt als antwoord: dan werkt het doorsturen."""
    def ask():
        api.nodes(node).version.get()
        return True
    try:
        return on_node(node, ask, False)
    except ResourceException:
        return True


def snapshot_count(api, g):
    """Aantal snapshots van een guest; None als zijn node niet antwoordt."""
    try:
        return on_node(g["node"], lambda: sum(1 for s in guest(api, g["node"], g["type"], g["vmid"]).snapshot.get()
                                              if s.get("name") != "current"))
    except ResourceException:
        return None


BUSY_MSG = "Er loopt een update of release-upgrade in deze container; wacht tot die klaar is"


def ct_busy(api, node, vmid) -> bool:
    """Loopt er via de agent een update of release-upgrade in deze CT?

    Afsluiten, migreren of terugzetten breekt die halverwege af en laat de pakketten half bijgewerkt
    achter. Is de agent niet bereikbaar, dan telt dat als 'nee', zodat de gewone knoppen blijven werken.
    """
    if not ssh_ready():
        return False
    try:
        ip = node_ips(api).get(node)
        return bool(ip) and parse_status(agent(ip, "status", "ct", str(vmid), timeout=10))["state"] == "active"
    except HTTPException:
        return False


def ceph_osds(api, node):
    """Alle OSD's uit de CRUSH-boom als platte lijst; leeg als het cluster geen Ceph heeft."""
    try:
        tree = api.nodes(node).ceph.osd.get()
    except ResourceException:
        return []
    osds, todo = [], [tree.get("root") or {}]
    while todo:
        n = todo.pop()
        todo.extend(n.get("children", []))
        if n.get("type") == "osd":
            osds.append({k: n.get(k) for k in ("name", "host", "status", "in", "bytes_used", "total_space")})
    return sorted(osds, key=lambda o: (o.get("host") or "", o.get("name") or ""))


# ---------------------------------------------------------------- app
app = FastAPI(title="Proxmox Maintool", docs_url=None, redoc_url=None, openapi_url=None)
INDEX = Path(__file__).parent / "static" / "index.html"
LOGIN = Path(__file__).parent / "static" / "login.html"
try:
    VERSION = (Path(__file__).parent / "VERSION").read_text(encoding="utf-8").strip()[:20]
except OSError:
    VERSION = "?"


def page(file: Path, user: str = "", request=None) -> str:
    who = (account(user) or {}) if user else {}
    why = view_only(request) if user else None
    choice = request.cookies.get(VIEW_COOKIE) if request is not None and via_cloudflare(request) else None
    return (file.read_text(encoding="utf-8").replace("{{VERSION}}", html.escape(VERSION))
            .replace("{{USER}}", html.escape(user)).replace("{{ROLE}}", who.get("role", "readonly") if user else "")
            .replace("{{CAN}}", "" if why else " ".join(who.get("can", []))).replace("{{MINPW}}", str(min_password()))
            .replace("{{CF}}", "1" if user and request is not None and via_cloudflare(request) else "")
            .replace("{{CFMODE}}", cf_mode() if user else "").replace("{{VIEW}}", "1" if why else "0" if choice == "0" else "")
            .replace("{{RIGHTS}}", "1" if who.get("can") else "")
            .replace("{{IDLE}}", str(session_policy()["idle"]) if user and not (request is not None and token_remembered(request.cookies.get(SESSION_COOKIE))) else "0")
            .replace("{{PW}}", "1" if not user or user == APP_USER or (users_state().get(user) or {}).get("pw", True) else "0"))


# ---------------------------------------------------------------- talen
# De tool is in het Nederlands geschreven; Engels en Duits komen uit vertaaltabellen. De pagina vertaalt haar eigen
# teksten (zie I18N in index.html). De meldingen van deze achterkant staan in de code in het Nederlands en worden pas
# bij het versturen vertaald, aan de hand van het cookie dat de pagina zet. {0} en {1} zijn de wisselende delen.
LANGS = ("nl", "en", "de")
LANG_COOKIE = "maintool_lang"
MESSAGES = {
    "Ongeldige nodenaam": ("Invalid node name", "Ungültiger Node-Name"),
    "Type moet qemu of lxc zijn": ("Type must be qemu or lxc", "Typ muss qemu oder lxc sein"),
    "Ongeldig VMID": ("Invalid VMID", "Ungültige VMID"),
    "Snapshotnaam: begint met een letter, 2-40 tekens, alleen letters/cijfers/_/-":
        ("Snapshot name: starts with a letter, 2-40 characters, only letters/digits/_/-",
         "Snapshot-Name: beginnt mit einem Buchstaben, 2-40 Zeichen, nur Buchstaben/Ziffern/_/-"),
    "Niet ingelogd": ("Not logged in", "Nicht angemeldet"),
    "Geen enkele Proxmox-node bereikbaar ({0})": ("No Proxmox node can be reached ({0})", "Kein Proxmox-Node erreichbar ({0})"),
    "Er loopt een update of release-upgrade in deze container; wacht tot die klaar is":
        ("An update or release upgrade is running in this container; wait until it has finished",
         "In diesem Container läuft ein Update oder Release-Upgrade; warte, bis es fertig ist"),
    "Te veel mislukte pogingen. Probeer het over tien minuten opnieuw.":
        ("Too many failed attempts. Try again in ten minutes.", "Zu viele Fehlversuche. Versuche es in zehn Minuten erneut."),
    "Gebruikersnaam of wachtwoord klopt niet": ("Username or password is incorrect", "Benutzername oder Passwort ist falsch"),
    "Onbekende actie": ("Unknown action", "Unbekannte Aktion"),
    "Ongeldige doel-node": ("Invalid target node", "Ungültiger Ziel-Node"),
    "Onbekend bestand": ("Unknown file", "Unbekannte Datei"),
    "SSH naar de nodes is nog niet ingesteld; draai op een node: bash maintool-setup.sh --update":
        ("SSH to the nodes has not been set up yet; run on a node: bash maintool-setup.sh --update",
         "SSH zu den Nodes ist noch nicht eingerichtet; auf einem Node ausführen: bash maintool-setup.sh --update"),
    "Node reageert niet op tijd via SSH": ("The node does not respond in time over SSH", "Der Node antwortet nicht rechtzeitig über SSH"),
    "Agent: onbekende fout": ("Helper script: unknown error", "Hilfsskript: unbekannter Fehler"),
    "Agent: {0}": ("Helper script: {0}", "Hilfsskript: {0}"),
    "Doel moet 'node' of een CT-nummer zijn": ("Target must be 'node' or a CT number", "Ziel muss 'node' oder eine CT-Nummer sein"),
    "Onbekende node": ("Unknown node", "Unbekannter Node"),
    "Er loopt al een update op {0}; werk één node tegelijk bij":
        ("An update is already running on {0}; update one node at a time", "Auf {0} läuft bereits ein Update; aktualisiere immer nur einen Node"),
    "De agent op de nodes is te oud voor release-upgrades; draai op een node: bash maintool-setup.sh --update":
        ("The helper script on the nodes is too old for release upgrades; run on a node: bash maintool-setup.sh --update",
         "Das Hilfsskript auf den Nodes ist zu alt für Release-Upgrades; auf einem Node ausführen: bash maintool-setup.sh --update"),
    "Snapshot mislukt ({0}); de upgrade is niet gestart":
        ("Snapshot failed ({0}); the upgrade was not started", "Snapshot fehlgeschlagen ({0}); das Upgrade wurde nicht gestartet"),
    "Snapshot duurt te lang; de upgrade is niet gestart":
        ("The snapshot is taking too long; the upgrade was not started", "Der Snapshot dauert zu lange; das Upgrade wurde nicht gestartet"),
    "Deze node is niet online": ("This node is not online", "Dieser Node ist nicht online"),
    "{0} is niet online; met nog een node uit verliest het cluster zijn meerderheid":
        ("{0} is not online; with one more node down the cluster loses its quorum",
         "{0} ist nicht online; fällt ein weiterer Node aus, verliert der Cluster sein Quorum"),
    "niet alle Ceph-schijven (OSD's) zijn actief": ("not all Ceph disks (OSDs) are active", "nicht alle Ceph-Datenträger (OSDs) sind aktiv"),
    "Ceph is nog aan het herstellen ({0})": ("Ceph is still recovering ({0})", "Ceph stellt sich noch wieder her ({0})"),
    "er loopt nog een update op deze node": ("an update is still running on this node", "auf diesem Node läuft noch ein Update"),
    "er loopt nog een update in CT {0} ({1})": ("an update is still running in CT {0} ({1})", "in CT {0} ({1}) läuft noch ein Update"),
    "Herstart geweigerd: {0}": ("Restart refused: {0}", "Neustart verweigert: {0}"),
    "Ongeldige taak": ("Invalid task", "Ungültige Aufgabe"),
    "Geen enkele node is online": ("No node is online", "Kein Node ist online"),
    "Deze opslag is niet beschikbaar voor back-ups": ("This storage is not available for backups", "Dieser Speicher steht für Backups nicht zur Verfügung"),
    "Ongeldig schema": ("Invalid schedule", "Ungültiger Zeitplan"),
    "Onbekende modus": ("Unknown mode", "Unbekannter Modus"),
    "Ongeldig tijdschema": ("Invalid time schedule", "Ungültiges Zeitschema"),
    "Kies minstens één bestaande guest": ("Choose at least one existing guest", "Wähle mindestens einen vorhandenen Gast"),
    "Geen van deze guests staat op een node die online is":
        ("None of these guests is on a node that is online", "Keiner dieser Gäste liegt auf einem Node, der online ist"),
    "Kies minstens één guest en een geldige modus": ("Choose at least one guest and a valid mode", "Wähle mindestens einen Gast und einen gültigen Modus"),
    "Ongeldig back-upbestand": ("Invalid backup file", "Ungültige Backup-Datei"),
    "Ongeldige node of ongeldig ID": ("Invalid node or invalid ID", "Ungültiger Node oder ungültige ID"),
    "ID {0} is al in gebruik": ("ID {0} is already in use", "ID {0} ist bereits vergeben"),
    "ID {0} is een ander soort guest dan deze back-up":
        ("ID {0} is a different kind of guest than this backup", "ID {0} ist eine andere Art von Gast als dieses Backup"),
    "Zet de guest eerst uit; een draaiende guest kan niet worden overschreven":
        ("Shut the guest down first; a running guest cannot be overwritten",
         "Fahre den Gast zuerst herunter; ein laufender Gast kann nicht überschrieben werden"),
    "Er is geen guest met ID {0} om te overschrijven":
        ("There is no guest with ID {0} to overwrite", "Es gibt keinen Gast mit der ID {0} zum Überschreiben"),
    "Op deze opslag mag de schijf van de guest niet staan":
        ("The guest's disk is not allowed on this storage", "Auf diesem Speicher darf die Disk des Gasts nicht liegen"),
    "Kies een opslag voor de schijf van de guest; de oorspronkelijke is er niet meer":
        ("Choose a storage for the guest's disk; the original one no longer exists",
         "Wähle einen Speicher für die Disk des Gasts; der ursprüngliche existiert nicht mehr"),
    "De instelling kon niet bewaard worden": ("The setting could not be saved", "Die Einstellung konnte nicht gespeichert werden"),
    "De catalogus van community-scripts.org is nu niet bereikbaar: {0}":
        ("The community-scripts.org catalogue cannot be reached right now: {0}", "Der Katalog von community-scripts.org ist gerade nicht erreichbar: {0}"),
    "De catalogus van community-scripts.org is nu niet bereikbaar":
        ("The community-scripts.org catalogue cannot be reached right now", "Der Katalog von community-scripts.org ist gerade nicht erreichbar"),
    "Mail is nog niet ingesteld; doe dat op het tabblad Events bij Overzicht per mail":
        ("Mail has not been set up yet; do that on the Events tab under Weekly report",
         "E-Mail ist noch nicht eingerichtet; mach das auf dem Reiter Ereignisse beim Wochenbericht"),
    "De mailserver is niet bereikbaar of weigert de verbinding ({0}); er is niets bewaard":
        ("The mail server cannot be reached or refuses the connection ({0}); nothing was saved",
         "Der Mailserver ist nicht erreichbar oder lehnt die Verbindung ab ({0}); es wurde nichts gespeichert"),
    "Ongeldig adres bij 'Versturen naar': {0}": ("Invalid address in 'Send to': {0}", "Ungültige Adresse bei 'Senden an': {0}"),
    "Vul bij 'Versturen naar' één tot vijf adressen in": ("Enter one to five addresses in 'Send to'", "Trage bei 'Senden an' eine bis fünf Adressen ein"),
    "Vul het wachtwoord in (bij Gmail een app-wachtwoord)": ("Enter the password (for Gmail an app password)", "Trage das Passwort ein (bei Gmail ein App-Passwort)"),
    "Ongeldig wachtwoord: geen stuurtekens, hooguit 200 tekens": ("Invalid password: no control characters, at most 200 characters", "Ungültiges Passwort: keine Steuerzeichen, höchstens 200 Zeichen"),
    "De mailinstellingen konden niet bewaard worden": ("The mail settings could not be saved", "Die E-Mail-Einstellungen konnten nicht gespeichert werden"),
    "Versturen mislukt: {0}": ("Sending failed: {0}", "Senden fehlgeschlagen: {0}"),
    # guests bekijken en verwijderen
    "Deze guest bestaat niet (meer) op deze node": ("This guest does not exist (any more) on this node", "Diesen Gast gibt es auf diesem Node nicht (mehr)"),
    "De naam komt niet overeen met de guest; er is niets verwijderd":
        ("The name does not match the guest; nothing was deleted", "Der Name passt nicht zum Gast; es wurde nichts gelöscht"),
    "De tool kan zijn eigen container niet verwijderen": ("The tool cannot delete its own container", "Das Tool kann seinen eigenen Container nicht löschen"),
    "Zet de guest eerst uit; een draaiende guest wordt niet verwijderd":
        ("Shut the guest down first; a running guest is not deleted", "Fahre den Gast zuerst herunter; ein laufender Gast wird nicht gelöscht"),
    "Deze guest is in Proxmox beschermd tegen verwijderen (Protection staat aan)":
        ("This guest is protected against deletion in Proxmox (Protection is on)", "Dieser Gast ist in Proxmox gegen Löschen geschützt (Protection ist aktiv)"),
    "Deze guest is vergrendeld ({0}); er is niets verwijderd":
        ("This guest is locked ({0}); nothing was deleted", "Dieser Gast ist gesperrt ({0}); es wurde nichts gelöscht"),
    "Een sjabloon wordt hier niet verwijderd; doe dat in Proxmox zelf":
        ("A template is not deleted here; do that in Proxmox itself", "Eine Vorlage wird hier nicht gelöscht; mach das in Proxmox selbst"),
    # netwerken
    "Ongeldige naam: 2-8 tekens, kleine letters en cijfers, beginnend met een letter":
        ("Invalid name: 2-8 characters, lowercase letters and digits, starting with a letter", "Ungültiger Name: 2-8 Zeichen, Kleinbuchstaben und Ziffern, beginnend mit einem Buchstaben"),
    "Het VLAN-nummer moet tussen 1 en 4094 liggen": ("The VLAN number must be between 1 and 4094", "Die VLAN-Nummer muss zwischen 1 und 4094 liegen"),
    "Ongeldige omschrijving: hooguit 60 tekens, alleen letters, cijfers, spaties en . _ - ( )":
        ("Invalid description: at most 60 characters, only letters, digits, spaces and . _ - ( )", "Ungültige Beschreibung: höchstens 60 Zeichen, nur Buchstaben, Ziffern, Leerzeichen und . _ - ( )"),
    "Dit cluster heeft geen SDN (nodig: Proxmox VE 8.1 of nieuwer); maak het VLAN in Proxmox zelf":
        ("This cluster has no SDN (needed: Proxmox VE 8.1 or newer); create the VLAN in Proxmox itself", "Dieser Cluster hat kein SDN (nötig: Proxmox VE 8.1 oder neuer); lege das VLAN in Proxmox selbst an"),
    "Niet alle nodes zijn online; een netwerkwijziging kan nu niet overal worden doorgevoerd":
        ("Not all nodes are online; a network change cannot be carried out everywhere right now", "Nicht alle Nodes sind online; eine Netzwerkänderung kann jetzt nicht überall durchgeführt werden"),
    "Niet elke node gaf zijn netwerkinstellingen; probeer het opnieuw":
        ("Not every node returned its network settings; try again", "Nicht jeder Node hat seine Netzwerkeinstellungen geliefert; versuche es erneut"),
    "Deze bridge bestaat niet op elke node": ("This bridge does not exist on every node", "Diese Bridge gibt es nicht auf jedem Node"),
    "Deze naam is al in gebruik voor een VLAN of een interface": ("This name is already in use for a VLAN or an interface", "Dieser Name wird bereits für ein VLAN oder ein Interface verwendet"),
    "VLAN {0} bestaat al op deze bridge, onder de naam {1}": ("VLAN {0} already exists on this bridge, under the name {1}", "VLAN {0} gibt es auf dieser Bridge bereits, unter dem Namen {1}"),
    "Er zijn te veel VLAN-zones; ruim er eerst een op in Proxmox": ("There are too many VLAN zones; remove one in Proxmox first", "Es gibt zu viele VLAN-Zonen; entferne zuerst eine in Proxmox"),
    "Dit VLAN bestaat niet": ("This VLAN does not exist", "Dieses VLAN gibt es nicht"),
    "Dit VLAN is nog in gebruik door: {0}. Koppel die eerst aan een ander netwerk":
        ("This VLAN is still in use by: {0}. Connect those to another network first", "Dieses VLAN wird noch verwendet von: {0}. Verbinde diese zuerst mit einem anderen Netzwerk"),
    "Er staat niets klaar om toe te passen": ("Nothing is waiting to be applied", "Es steht nichts zum Anwenden bereit"),
    "Deze node gaf zijn netwerkinstellingen niet; probeer het opnieuw": ("This node did not return its network settings; try again", "Dieser Node hat seine Netzwerkeinstellungen nicht geliefert; versuche es erneut"),
    "De netwerkinstellingen van deze node zijn niet op te vragen": ("The network settings of this node cannot be retrieved", "Die Netzwerkeinstellungen dieses Nodes lassen sich nicht abrufen"),
    "Op deze node staan al netwerkwijzigingen klaar; pas die eerst toe of draai ze terug":
        ("Network changes are already waiting on this node; apply them or revert them first", "Auf diesem Node stehen bereits Netzwerkänderungen bereit; wende sie zuerst an oder mache sie rückgängig"),
    "Kies een bridge, bond of netwerkkaart die op deze node bestaat": ("Choose a bridge, bond or network card that exists on this node", "Wähle eine Bridge, einen Bond oder eine Netzwerkkarte, die es auf diesem Node gibt"),
    "De naam van de interface wordt te lang (hooguit 15 tekens)": ("The name of the interface becomes too long (at most 15 characters)", "Der Name des Interface wird zu lang (höchstens 15 Zeichen)"),
    "Dit VLAN bestaat al op deze node": ("This VLAN already exists on this node", "Dieses VLAN gibt es auf diesem Node bereits"),
    "Ongeldig adres; gebruik de vorm 192.168.20.5/24": ("Invalid address; use the form 192.168.20.5/24", "Ungültige Adresse; verwende die Form 192.168.20.5/24"),
    "Dit adres valt in een netwerk dat deze node al heeft ({0}); kies een adres uit het netwerk van het VLAN":
        ("This address lies in a network this node already has ({0}); choose an address from the network of the VLAN", "Diese Adresse liegt in einem Netzwerk, das dieser Node bereits hat ({0}); wähle eine Adresse aus dem Netzwerk des VLANs"),
    # mail voor meer soorten mailservers
    "Ongeldige poort; kies een getal tussen 1 en 65535": ("Invalid port; choose a number between 1 and 65535", "Ungültiger Port; wähle eine Zahl zwischen 1 und 65535"),
    "Ongeldige mailserver; gebruik een naam zoals smtp.gmail.com of een IP-adres": ("Invalid mail server; use a name such as smtp.gmail.com or an IP address", "Ungültiger Mailserver; verwende einen Namen wie smtp.gmail.com oder eine IP-Adresse"),
    "Ongeldige beveiliging van de verbinding": ("Invalid connection security", "Ungültige Verbindungssicherheit"),
    "Ongeldig afzenderadres": ("Invalid sender address", "Ungültige Absenderadresse"),
    "Ongeldige naam van de afzender: hooguit 60 tekens, zonder aanhalingstekens en haakjes":
        ("Invalid sender name: at most 60 characters, without quotation marks and angle brackets", "Ungültiger Absendername: höchstens 60 Zeichen, ohne Anführungszeichen und spitze Klammern"),
    "Ongeldige inlognaam": ("Invalid login name", "Ungültiger Anmeldename"),
    "Zonder versleuteling stuurt de tool geen wachtwoord mee; kies STARTTLS of SSL/TLS, of zet inloggen uit":
        ("Without encryption the tool does not send a password; choose STARTTLS or SSL/TLS, or turn off logging in", "Ohne Verschlüsselung sendet das Tool kein Passwort; wähle STARTTLS oder SSL/TLS, oder schalte die Anmeldung aus"),
    "Bij een andere mailserver of inlognaam hoort het wachtwoord opnieuw; vul het in":
        ("A different mail server or login name needs the password again; enter it", "Bei einem anderen Mailserver oder Anmeldenamen ist das Passwort erneut nötig; trage es ein"),
    "De mailserver weigert de inlog; controleer de inlognaam en het wachtwoord (bij Gmail een app-wachtwoord, niet je gewone)":
        ("The mail server refuses the login; check the login name and the password (for Gmail an app password, not your normal one)",
         "Der Mailserver lehnt die Anmeldung ab; prüfe den Anmeldenamen und das Passwort (bei Gmail ein App-Passwort, nicht dein normales)"),
    "De mailserver ondersteunt deze manier van verbinden of inloggen niet ({0}); er is niets bewaard":
        ("The mail server does not support this way of connecting or logging in ({0}); nothing was saved", "Der Mailserver unterstützt diese Art der Verbindung oder Anmeldung nicht ({0}); es wurde nichts gespeichert"),
    "Het certificaat van de mailserver klopt niet; er is niets bewaard": ("The certificate of the mail server is not valid; nothing was saved", "Das Zertifikat des Mailservers ist nicht gültig; es wurde nichts gespeichert"),
    # aandachtspunten
    "Onbekende trigger: {0}": ("Unknown trigger: {0}", "Unbekannter Auslöser: {0}"),
    "Ongeldige instelling voor {0}": ("Invalid setting for {0}", "Ungültige Einstellung für {0}"),
    "Bij {0} moet de waarde voor oranje lager zijn dan die voor rood": ("For {0} the value for orange must be lower than the one for red", "Bei {0} muss der Wert für Orange niedriger sein als der für Rot"),
    "Ongeldige periode": ("Invalid period", "Ungültiger Zeitraum"),
    # een guest bewerken
    "Deze guest is vergrendeld ({0}); er is niets gewijzigd": ("This guest is locked ({0}); nothing was changed", "Dieser Gast ist gesperrt ({0}); es wurde nichts geändert"),
    "Een sjabloon wordt hier niet gewijzigd; doe dat in Proxmox zelf": ("A template is not changed here; do that in Proxmox itself", "Eine Vorlage wird hier nicht geändert; mach das in Proxmox selbst"),
    "Er is niets gewijzigd": ("Nothing was changed", "Es wurde nichts geändert"),
    "Ongeldige naam: letters, cijfers en streepjes, hooguit 63 tekens": ("Invalid name: letters, digits and hyphens, at most 63 characters", "Ungültiger Name: Buchstaben, Ziffern und Bindestriche, höchstens 63 Zeichen"),
    "De tool wijzigt de naam van zijn eigen container niet": ("The tool does not change the name of its own container", "Das Tool ändert den Namen seines eigenen Containers nicht"),
    "Het aantal cores moet tussen 1 en {0} liggen (zoveel heeft de node)": ("The number of cores must be between 1 and {0} (what the node has)", "Die Anzahl der Kerne muss zwischen 1 und {0} liegen (so viele hat der Node)"),
    "Het geheugen moet tussen {0} en {1} MB liggen": ("The memory must be between {0} and {1} MB", "Der Arbeitsspeicher muss zwischen {0} und {1} MB liegen"),
    "De swap moet tussen 0 en {0} MB liggen": ("The swap must be between 0 and {0} MB", "Der Swap muss zwischen 0 und {0} MB liegen"),
    "Een VM heeft hier geen swap-instelling": ("A VM has no swap setting here", "Eine VM hat hier keine Swap-Einstellung"),
    "Ongeldige notitie: hooguit 2000 tekens, zonder stuurtekens": ("Invalid note: at most 2000 characters, without control characters", "Ungültige Notiz: höchstens 2000 Zeichen, ohne Steuerzeichen"),
    "De instellingen van deze guest zijn intussen door iemand anders gewijzigd; open het venster opnieuw":
        ("The settings of this guest have been changed by someone else in the meantime; open the window again", "Die Einstellungen dieses Gasts wurden inzwischen von jemand anderem geändert; öffne das Fenster erneut"),
    # het netwerk van een guest
    "Deze netwerkkaart bestaat niet bij deze guest": ("This network card does not exist for this guest", "Diese Netzwerkkarte gibt es bei diesem Gast nicht"),
    "Dit netwerk bestaat niet op de node van deze guest": ("This network does not exist on the node of this guest", "Dieses Netzwerk gibt es auf dem Node dieses Gasts nicht"),
    "Een VLAN-netwerk heeft zijn nummer al; kies bij VLAN 'geen'": ("A VLAN network already has its number; choose 'none' for VLAN", "Ein VLAN-Netzwerk hat seine Nummer bereits; wähle bei VLAN 'keine'"),
    "De tool wijzigt het netwerk van zijn eigen container niet": ("The tool does not change the network of its own container", "Das Tool ändert das Netzwerk seines eigenen Containers nicht"),
    # gebruikers en rechten
    "Hiervoor zijn beheerdersrechten nodig": ("This requires administrator rights", "Dafür sind Administratorrechte nötig"),
    "Ongeldige gebruikersnaam: 2-32 tekens, kleine letters, cijfers, punt, streepje":
        ("Invalid username: 2-32 characters, lowercase letters, digits, dot, hyphen", "Ungültiger Benutzername: 2-32 Zeichen, Kleinbuchstaben, Ziffern, Punkt, Bindestrich"),
    "Ongeldige rechten": ("Invalid rights", "Ungültige Rechte"),
    "Deze gebruikersnaam bestaat al": ("This username already exists", "Diesen Benutzernamen gibt es bereits"),
    "Deze gebruiker bestaat niet": ("This user does not exist", "Diesen Benutzer gibt es nicht"),
    "Het hoofdaccount kan hier niet gewijzigd of verwijderd worden": ("The main account cannot be changed or deleted here", "Das Hauptkonto kann hier nicht geändert oder gelöscht werden"),
    "Je kunt je eigen account niet verwijderen of je eigen rechten wijzigen":
        ("You cannot delete your own account or change your own rights", "Du kannst dein eigenes Konto nicht löschen oder deine eigenen Rechte ändern"),
    "Er kunnen niet meer dan 50 gebruikers zijn": ("There cannot be more than 50 users", "Es kann nicht mehr als 50 Benutzer geben"),
    "Er is niets om te wijzigen": ("There is nothing to change", "Es gibt nichts zu ändern"),
    "De gebruikers konden niet bewaard worden": ("The users could not be saved", "Die Benutzer konnten nicht gespeichert werden"),
    # wachtwoord wijzigen
    "Het huidige wachtwoord klopt niet; er is niets gewijzigd": ("The current password is incorrect; nothing was changed", "Das aktuelle Passwort ist falsch; es wurde nichts geändert"),
    "Het nieuwe wachtwoord moet minstens {0} tekens lang zijn": ("The new password must be at least {0} characters long", "Das neue Passwort muss mindestens {0} Zeichen lang sein"),
    "Hiervoor heb je niet de juiste rol": ("You do not have the right role for this", "Dafür hast du nicht die richtige Rolle"),
    "De minimale lengte moet tussen 8 en 128 liggen": ("The minimum length must be between 8 and 128", "Die Mindestlänge muss zwischen 8 und 128 liegen"),
    "Het nieuwe wachtwoord mag niet met een spatie beginnen of eindigen en geen stuurtekens bevatten":
        ("The new password may not start or end with a space and may not contain control characters",
         "Das neue Passwort darf nicht mit einem Leerzeichen beginnen oder enden und keine Steuerzeichen enthalten"),
    "Het nieuwe wachtwoord is gelijk aan het huidige": ("The new password is the same as the current one", "Das neue Passwort ist gleich dem aktuellen"),
    "Het wachtwoord kon niet bewaard worden": ("The password could not be saved", "Das Passwort konnte nicht gespeichert werden"),
    # aanmaken van containers, VM's en opslag
    "Deze node is niet online of bestaat niet": ("This node is not online or does not exist", "Dieser Node ist nicht online oder existiert nicht"),
    "Deze naam is ongeldig: gebruik letters, cijfers en streepjes": ("This name is invalid: use letters, digits and hyphens", "Dieser Name ist ungültig: verwende Buchstaben, Ziffern und Bindestriche"),
    "Deze naam is al de naam van de container van de tool zelf; kies een andere":
        ("This name is already the name of the tool's own container; choose another one", "Dieser Name ist bereits der Name des Containers des Tools selbst; wähle einen anderen"),
    "Dit sjabloon staat niet op een opslag van deze node": ("This template is not on a storage of this node", "Diese Vorlage liegt nicht auf einem Speicher dieses Nodes"),
    "Dit sjabloon staat niet in de lijst van Proxmox": ("This template is not in Proxmox's list", "Diese Vorlage steht nicht in der Liste von Proxmox"),
    "Op deze opslag mogen geen sjablonen staan": ("Templates are not allowed on this storage", "Auf diesem Speicher dürfen keine Vorlagen liegen"),
    "Op deze opslag mag deze schijf niet staan": ("This disk is not allowed on this storage", "Auf diesem Speicher darf diese Disk nicht liegen"),
    "Deze netwerkbrug bestaat niet op deze node": ("This network bridge does not exist on this node", "Diese Netzwerkbrücke gibt es auf diesem Node nicht"),
    "Dit ISO-bestand staat niet op een opslag van deze node": ("This ISO file is not on a storage of this node", "Diese ISO-Datei liegt nicht auf einem Speicher dieses Nodes"),
    "Geef een root-wachtwoord van minstens 8 tekens of een SSH-sleutel op":
        ("Provide a root password of at least 8 characters or an SSH key", "Gib ein Root-Passwort mit mindestens 8 Zeichen oder einen SSH-Schlüssel an"),
    "Dit is geen geldige openbare SSH-sleutel": ("This is not a valid public SSH key", "Das ist kein gültiger öffentlicher SSH-Schlüssel"),
    "Ongeldig IP-adres; gebruik de vorm 192.168.1.50/24": ("Invalid IP address; use the form 192.168.1.50/24", "Ungültige IP-Adresse; verwende die Form 192.168.1.50/24"),
    "De gateway is geen geldig adres in hetzelfde netwerk": ("The gateway is not a valid address in the same network", "Das Gateway ist keine gültige Adresse im selben Netzwerk"),
    "Er bestaat al een opslag met de naam {0}": ("A storage named {0} already exists", "Es gibt bereits einen Speicher mit dem Namen {0}"),
    "Ongeldige naam voor de opslag: begin met een letter; letters, cijfers, punt, streepje": ("Invalid storage name: start with a letter; letters, digits, dot, hyphen", "Ungültiger Speichername: beginne mit einem Buchstaben; Buchstaben, Ziffern, Punkt, Bindestrich"),
    "Ongeldig adres van de server": ("Invalid server address", "Ungültige Serveradresse"),
    "Ongeldige gedeelde map": ("Invalid share", "Ungültige Freigabe"),
    "Kies minstens één soort inhoud": ("Choose at least one kind of content", "Wähle mindestens eine Art von Inhalt"),
    # de tool bijwerken met een bestand
    "Dit verzoek komt niet van de pagina van de tool": ("This request does not come from the tool's own page", "Diese Anfrage kommt nicht von der Seite des Tools"),
    "Bijwerken via de pagina is op deze installatie niet ingeschakeld; draai op een node: bash maintool-setup.sh --update":
        ("Updating through the page is not enabled on this installation; run on a node: bash maintool-setup.sh --update",
         "Aktualisieren über die Seite ist bei dieser Installation nicht aktiviert; auf einem Node ausführen: bash maintool-setup.sh --update"),
    "Er wordt al een update geïnstalleerd": ("An update is already being installed", "Es wird bereits ein Update installiert"),
    "Het bestand is te groot": ("The file is too large", "Die Datei ist zu groß"),
    "Het bestand kon niet worden opgeslagen": ("The file could not be stored", "Die Datei konnte nicht gespeichert werden"),
    "De controle van het bestand is mislukt": ("Checking the file failed", "Die Prüfung der Datei ist fehlgeschlagen"),
    "Het wachtwoord klopt niet; er is niets geïnstalleerd": ("The password is incorrect; nothing was installed", "Das Passwort ist falsch; es wurde nichts installiert"),
    "Er staat geen gecontroleerd bestand klaar; kies het bestand opnieuw":
        ("There is no checked file waiting; choose the file again", "Es liegt keine geprüfte Datei bereit; wähle die Datei erneut"),
    "Het bestand is veranderd sinds de controle; kies het opnieuw":
        ("The file has changed since it was checked; choose it again", "Die Datei hat sich seit der Prüfung geändert; wähle sie erneut"),
    'Proxmox gaf geen bruikbaar antwoord bij het controleren van het account':
        ('Proxmox gave no usable answer when checking the account', 'Proxmox gab bei der Prüfung des Kontos keine brauchbare Antwort'),
    'Geen enkele Proxmox-node bereikbaar om het account te controleren':
        ('No Proxmox node reachable to check the account', 'Kein Proxmox-Node erreichbar, um das Konto zu prüfen'),
    'Inloggen met een Proxmox-account staat uit':
        ('Logging in with a Proxmox account is turned off', 'Die Anmeldung mit einem Proxmox-Konto ist ausgeschaltet'),
    'Dit Proxmox-account gebruikt tweestapsverificatie; daarmee kan de tool nog niet inloggen':
        ('This Proxmox account uses two-factor authentication; the tool cannot log in with that yet', 'Dieses Proxmox-Konto verwendet Zwei-Faktor-Authentifizierung; damit kann sich das Tool noch nicht anmelden'),
    'Inloggen met Cloudflare Access staat uit':
        ('Logging in with Cloudflare Access is turned off', 'Die Anmeldung mit Cloudflare Access ist ausgeschaltet'),
    'Geen geldige inlog van Cloudflare Access gevonden. Open de tool via je Cloudflare-adres; is dat al zo, dan is je account niet aan een gebruiker gekoppeld.':
        ('No valid Cloudflare Access login found. Open the tool through your Cloudflare address; if you already do, your account is not linked to a user.', 'Keine gültige Anmeldung von Cloudflare Access gefunden. Öffne das Tool über deine Cloudflare-Adresse; tust du das schon, ist dein Konto mit keinem Benutzer verknüpft.'),
    'De SSO-instellingen konden niet bewaard worden':
        ('The SSO settings could not be saved', 'Die SSO-Einstellungen konnten nicht gespeichert werden'),
    'Onbekende soort SSO-dienst':
        ('Unknown kind of SSO service', 'Unbekannte Art von SSO-Dienst'),
    'Ongeldige naam op de knop: hooguit 40 tekens, zonder < > " &':
        ('Invalid button name: at most 40 characters, without < > " &', 'Ungültiger Name auf der Schaltfläche: höchstens 40 Zeichen, ohne < > " &'),
    "Vul bij Uitgever het volledige https-adres in, bij Microsoft met je eigen tenant-ID (niet 'common')":
        ("Enter the full https address under Issuer, for Microsoft with your own tenant ID (not 'common')", "Gib bei Aussteller die vollständige https-Adresse ein, bei Microsoft mit deiner eigenen Tenant-ID (nicht 'common')"),
    'Ongeldige client-ID':
        ('Invalid client ID', 'Ungültige Client-ID'),
    'Vul bij Adres van de tool het https-adres in waarop je de tool opent, zonder pad, bijvoorbeeld https://maintool.voorbeeld.nl':
        ('Under Address of the tool, enter the https address where you open the tool, without a path, for example https://maintool.example.com', 'Gib bei Adresse des Tools die https-Adresse ein, unter der du das Tool öffnest, ohne Pfad, zum Beispiel https://maintool.beispiel.de'),
    'Ongeldig client secret':
        ('Invalid client secret', 'Ungültiges Client-Secret'),
    'Vul het client secret in':
        ('Enter the client secret', 'Gib das Client-Secret ein'),
    'De SSO-dienst gaf geen bruikbare instellingen ({0}); controleer het adres bij Uitgever. Er is niets bewaard.':
        ('The SSO service gave no usable settings ({0}); check the address under Issuer. Nothing was saved.', 'Der SSO-Dienst lieferte keine brauchbaren Einstellungen ({0}); prüfe die Adresse bei Aussteller. Es wurde nichts gespeichert.'),
    'Ongeldige teamnaam; dat is het eerste deel van jouwteam.cloudflareaccess.com':
        ('Invalid team name; that is the first part of yourteam.cloudflareaccess.com', 'Ungültiger Teamname; das ist der erste Teil von deinteam.cloudflareaccess.com'),
    'Ongeldige Application Audience (AUD) Tag; die bestaat uit 64 tekens 0-9 en a-f':
        ('Invalid Application Audience (AUD) Tag; it consists of 64 characters 0-9 and a-f', 'Ungültiger Application Audience (AUD) Tag; er besteht aus 64 Zeichen 0-9 und a-f'),
    'De sleutels van dit Cloudflare-team zijn niet op te halen ({0}); er is niets bewaard':
        ('The keys of this Cloudflare team cannot be fetched ({0}); nothing was saved', 'Die Schlüssel dieses Cloudflare-Teams sind nicht abrufbar ({0}); es wurde nichts gespeichert'),
    'Kies een of meer realms die in Proxmox bestaan':
        ('Choose one or more realms that exist in Proxmox', 'Wähle einen oder mehrere Realms, die es in Proxmox gibt'),
    'Ongeldige SSO-koppelingen':
        ('Invalid SSO links', 'Ungültige SSO-Verknüpfungen'),
    'Ongeldige SSO-koppeling bij {0}':
        ('Invalid SSO link for {0}', 'Ungültige SSO-Verknüpfung bei {0}'),
    'Dit account is al gekoppeld aan gebruiker {0}':
        ('This account is already linked to user {0}', 'Dieses Konto ist bereits mit Benutzer {0} verknüpft'),
    'Zonder wachtwoord moet de gebruiker aan minstens één SSO-inlog gekoppeld zijn':
        ('Without a password the user must be linked to at least one SSO login', 'Ohne Passwort muss der Benutzer mit mindestens einer SSO-Anmeldung verknüpft sein'),
    'Geef een wachtwoord op om inloggen met een wachtwoord weer aan te zetten':
        ('Enter a password to turn logging in with a password back on', 'Gib ein Passwort an, um die Anmeldung mit Passwort wieder einzuschalten'),
    'Deze schijf kan hier niet vergroot worden':
        ('This disk cannot be enlarged here', 'Diese Disk kann hier nicht vergrößert werden'),
    'Vergroot met 1 tot 16384 GB':
        ('Enlarge by 1 to 16384 GB', 'Um 1 bis 16384 GB vergrößern'),
    'Op opslag {0} is nog {1} GB vrij; vergroot met minder':
        ('Storage {0} has {1} GB free; enlarge by less', 'Auf Speicher {0} sind noch {1} GB frei; vergrößere um weniger'),
    'Ongeldige keuze bij Hoe vaak':
        ('Invalid choice for How often', 'Ungültige Auswahl bei Wie oft'),
    'Ongeldige dag':
        ('Invalid day', 'Ungültiger Tag'),
    'Kies een dag van de maand van 1 tot en met 28':
        ('Choose a day of the month from 1 to 28', 'Wähle einen Tag des Monats von 1 bis 28'),
    'Ongeldige tijd; gebruik uu:mm, bijvoorbeeld 05:00':
        ('Invalid time; use hh:mm, for example 05:00', 'Ungültige Uhrzeit; verwende hh:mm, zum Beispiel 05:00'),
    'Onbekend onderdeel voor de mail':
        ('Unknown part for the mail', 'Unbekannter Teil für die Mail'),
    'Kies minstens één onderdeel voor de mail':
        ('Choose at least one part for the mail', 'Wähle mindestens einen Teil für die Mail'),
    'Ongeldige indeling van het dashboard':
        ('Invalid dashboard layout', 'Ungültiges Layout des Dashboards'),
    'Ongeldig IPv4-adres bij {0}: gebruik adres/voorvoegsel, bijvoorbeeld 192.168.1.50/24':
        ('Invalid IPv4 address for {0}: use address/prefix, for example 192.168.1.50/24', 'Ungültige IPv4-Adresse bei {0}: verwende Adresse/Präfix, zum Beispiel 192.168.1.50/24'),
    '{0}: het adres {1} kan niet voor een guest':
        ('{0}: the address {1} cannot be used for a guest', '{0}: die Adresse {1} kann für einen Gast nicht verwendet werden'),
    '{0}: {1} is het adres van het netwerk zelf of het broadcastadres':
        ('{0}: {1} is the address of the network itself or the broadcast address', '{0}: {1} ist die Adresse des Netzwerks selbst oder die Broadcast-Adresse'),
    '{0}: een gateway hoort alleen bij een vast IPv4-adres':
        ('{0}: a gateway only belongs with a fixed IPv4 address', '{0}: ein Gateway gehört nur zu einer festen IPv4-Adresse'),
    'Ongeldige gateway bij {0}':
        ('Invalid gateway for {0}', 'Ungültiges Gateway bei {0}'),
    '{0}: de gateway kan niet hetzelfde zijn als het adres':
        ('{0}: the gateway cannot be the same as the address', '{0}: das Gateway kann nicht gleich der Adresse sein'),
    '{0}: de gateway {1} ligt niet in het netwerk {2}':
        ('{0}: the gateway {1} is not in the network {2}', '{0}: das Gateway {1} liegt nicht im Netzwerk {2}'),
    'Ongeldig IPv6-adres bij {0}: gebruik adres/voorvoegsel, bijvoorbeeld 2001:db8::50/64':
        ('Invalid IPv6 address for {0}: use address/prefix, for example 2001:db8::50/64', 'Ungültige IPv6-Adresse bei {0}: verwende Adresse/Präfix, zum Beispiel 2001:db8::50/64'),
    '{0}: een IPv6-gateway hoort alleen bij een vast IPv6-adres':
        ('{0}: an IPv6 gateway only belongs with a fixed IPv6 address', '{0}: ein IPv6-Gateway gehört nur zu einer festen IPv6-Adresse'),
    'Ongeldige IPv6-gateway bij {0}':
        ('Invalid IPv6 gateway for {0}', 'Ungültiges IPv6-Gateway bei {0}'),
    'Vul hooguit drie DNS-servers in':
        ('Enter at most three DNS servers', 'Gib höchstens drei DNS-Server ein'),
    'Ongeldige DNS-server: {0} (vul een IP-adres in)':
        ('Invalid DNS server: {0} (enter an IP address)', 'Ungültiger DNS-Server: {0} (gib eine IP-Adresse ein)'),
    'Ongeldig zoekdomein; bijvoorbeeld thuis.lan':
        ('Invalid search domain; for example home.lan', 'Ungültige Suchdomäne; zum Beispiel heim.lan'),
    'De tool wijzigt het IP-adres van zijn eigen container niet':
        ('The tool does not change the IP address of its own container', 'Das Tool ändert die IP-Adresse seines eigenen Containers nicht'),
    'Bij deze VM stel je het IP-adres in de VM zelf in; zonder cloud-init kan de tool dat niet':
        ('For this VM you set the IP address inside the VM itself; without cloud-init the tool cannot do that', 'Bei dieser VM stellst du die IP-Adresse in der VM selbst ein; ohne cloud-init kann das Tool das nicht'),
    'Twee netwerkkaarten van deze guest kunnen niet hetzelfde adres hebben':
        ('Two network cards of this guest cannot have the same address', 'Zwei Netzwerkkarten dieses Gastes können nicht dieselbe Adresse haben'),
    'Adres {0} ({1}) is al in gebruik bij {2}; kies een ander adres':
        ('Address {0} ({1}) is already in use by {2}; choose another address', 'Adresse {0} ({1}) wird bereits von {2} verwendet; wähle eine andere Adresse'),
    'Via Cloudflare kun je de tool alleen bekijken; wijzigen doe je via het adres in je eigen netwerk':
        ('Through Cloudflare you can only view the tool; make changes through the address in your own network', 'Über Cloudflare kannst du das Tool nur ansehen; Änderungen machst du über die Adresse im eigenen Netzwerk'),
    'Je bekijkt de tool nu alleen; kies bovenaan Volledig gebruiken om iets te wijzigen':
        ('You are only viewing the tool now; choose Full use at the top to change something', 'Du siehst das Tool gerade nur an; wähle oben Voll nutzen, um etwas zu ändern'),
    'Dit geldt alleen als je de tool via Cloudflare opent':
        ('This only applies when you open the tool through Cloudflare', 'Das gilt nur, wenn du das Tool über Cloudflare öffnest'),
    'Ongeldige keuze voor toegang via Cloudflare':
        ('Invalid choice for access through Cloudflare', 'Ungültige Auswahl für den Zugriff über Cloudflare'),
    'Onbekende keuze voor de back-up vooraf':
        ('Unknown choice for the backup beforehand', 'Unbekannte Auswahl für das Backup vorab'),
    'Van een node zelf maakt Proxmox geen back-up; maak back-ups van de guests op die node':
        ('Proxmox does not back up a node itself; make backups of the guests on that node', 'Proxmox sichert einen Node selbst nicht; sichere die Gäste auf diesem Node'),
    'De back-up vooraf is mislukt ({0}); de update is niet gestart':
        ('The backup beforehand failed ({0}); the update was not started', 'Das Backup vorab ist fehlgeschlagen ({0}); das Update wurde nicht gestartet'),
    'De back-up vooraf is mislukt ({0}); de release-upgrade is niet gestart':
        ('The backup beforehand failed ({0}); the release upgrade was not started', 'Das Backup vorab ist fehlgeschlagen ({0}); das Release-Upgrade wurde nicht gestartet'),
    'Back-up vooraf wordt gemaakt…':
        ('Making the backup beforehand…', 'Backup vorab wird erstellt…'),
    'Snapshot vooraf wordt gemaakt…':
        ('Making the snapshot beforehand…', 'Snapshot vorab wird erstellt…'),
    'Ongeldige keuze van de containers':
        ('Invalid choice of containers', 'Ungültige Auswahl der Container'),
    'Kies minstens één container, of kies Alle containers':
        ('Choose at least one container, or choose All containers', 'Wähle mindestens einen Container oder Alle Container'),
    'Kies wat er bijgewerkt moet worden: containers, nodes of allebei':
        ('Choose what should be updated: containers, nodes or both', 'Wähle, was aktualisiert werden soll: Container, Nodes oder beides'),
    'Er loopt al een ronde automatisch bijwerken':
        ('A round of automatic updates is already running', 'Es läuft bereits eine Runde automatischer Updates'),
    'Onbekende HA-toestand':
        ('Unknown HA state', 'Unbekannter HA-Zustand'),
    'Herstarten en verhuizen: 0 tot 10 keer':
        ('Restart and relocate: 0 to 10 times', 'Neustarten und Verschieben: 0 bis 10 Mal'),
    'De opmerking mag geen regeleinden of stuurtekens bevatten':
        ('The comment may not contain line breaks or control characters', 'Der Kommentar darf keine Zeilenumbrüche oder Steuerzeichen enthalten'),
    'Ongeldige HA-naam; verwacht vm:ID of ct:ID':
        ('Invalid HA name; expected vm:ID or ct:ID', 'Ungültiger HA-Name; erwartet vm:ID oder ct:ID'),
    'Deze guest bestaat niet (meer)':
        ('This guest does not exist (any more)', 'Diesen Gast gibt es nicht (mehr)'),
    'Een sjabloon kan niet in HA':
        ('A template cannot be put in HA', 'Eine Vorlage kann nicht in HA aufgenommen werden'),
    'Deze guest staat al in HA':
        ('This guest is already in HA', 'Dieser Gast ist bereits in HA'),
    'Dit is de container van de tool zelf; die zet de tool niet via HA uit':
        ("This is the tool's own container; the tool does not switch it off through HA", 'Das ist der Container des Tools selbst; das Tool schaltet ihn nicht über HA aus'),
    'Er is niets om aan te passen':
        ('There is nothing to change', 'Es gibt nichts zu ändern'),
    'Deze guest staat niet (meer) in HA':
        ('This guest is not (or no longer) in HA', 'Dieser Gast ist nicht (mehr) in HA'),
    'root@pam wijzigt de tool niet; doe dat in Proxmox zelf':
        ('The tool does not change root@pam; do that in Proxmox itself', 'root@pam ändert das Tool nicht; mach das in Proxmox selbst'),
    'Met deze gebruiker werkt de tool zelf; die wijzigt de tool niet':
        ('The tool itself works with this user; the tool does not change it', 'Mit diesem Benutzer arbeitet das Tool selbst; den ändert das Tool nicht'),
    'Deze naam kent de tool niet; wijzig deze gebruiker in Proxmox zelf':
        ('The tool does not know this name; change this user in Proxmox itself', 'Diesen Namen kennt das Tool nicht; ändere diesen Benutzer in Proxmox selbst'),
    'Dan heeft niemand meer volledige beheerrechten in Proxmox (Administrator op /), behalve de tool zelf; er is niets gewijzigd':
        ('Then nobody would have full admin rights in Proxmox any more (Administrator on /), except the tool itself; nothing was changed', 'Dann hätte niemand mehr volle Administratorrechte in Proxmox (Administrator auf /), außer dem Tool selbst; es wurde nichts geändert'),
    'Namen, e-mail en opmerking mogen geen regeleinden of stuurtekens bevatten':
        ('Names, e-mail and comment may not contain line breaks or control characters', 'Namen, E-Mail und Kommentar dürfen keine Zeilenumbrüche oder Steuerzeichen enthalten'),
    'Ongeldig e-mailadres':
        ('Invalid e-mail address', 'Ungültige E-Mail-Adresse'),
    'Ongeldige datum voor verlopen':
        ('Invalid expiry date', 'Ungültiges Ablaufdatum'),
    'Het wachtwoord mag geen regeleinden of stuurtekens bevatten':
        ('The password may not contain line breaks or control characters', 'Das Passwort darf keine Zeilenumbrüche oder Steuerzeichen enthalten'),
    'Het wachtwoord moet {0} tot 64 tekens lang zijn':
        ('The password must be {0} to 64 characters long', 'Das Passwort muss {0} bis 64 Zeichen lang sein'),
    'Onbekende groep: {0}':
        ('Unknown group: {0}', 'Unbekannte Gruppe: {0}'),
    'Onbekende gebruiker: {0}':
        ('Unknown user: {0}', 'Unbekannter Benutzer: {0}'),
    'Ongeldige gebruikersnaam: letters, cijfers, punt, streepje of liggend streepje, tot 64 tekens':
        ('Invalid user name: letters, digits, dot, hyphen or underscore, up to 64 characters', 'Ungültiger Benutzername: Buchstaben, Ziffern, Punkt, Bindestrich oder Unterstrich, bis 64 Zeichen'),
    'Deze realm bestaat niet':
        ('This realm does not exist', 'Diesen Realm gibt es nicht'),
    'Kies een wachtwoord: een gebruiker in realm pve logt daarmee in':
        ('Choose a password: a user in realm pve logs in with it', 'Wähle ein Passwort: ein Benutzer im Realm pve meldet sich damit an'),
    'Een wachtwoord stel je hier alleen in bij realm pve; bij deze realm regelt die het inloggen':
        ('You can only set a password here for realm pve; with this realm, the realm handles logging in', 'Ein Passwort legst du hier nur beim Realm pve fest; bei diesem Realm regelt er die Anmeldung'),
    'Een wachtwoord wijzig je hier alleen bij realm pve; bij deze realm regelt die het inloggen':
        ('You can only change a password here for realm pve; with this realm, the realm handles logging in', 'Ein Passwort änderst du hier nur beim Realm pve; bei diesem Realm regelt er die Anmeldung'),
    'Deze Proxmox-gebruiker bestaat al':
        ('This Proxmox user already exists', 'Diesen Proxmox-Benutzer gibt es bereits'),
    'Deze Proxmox-gebruiker bestaat niet (meer)':
        ('This Proxmox user does not exist (any more)', 'Diesen Proxmox-Benutzer gibt es nicht (mehr)'),
    'Proxmox vraagt hierbij het eigen wachtwoord van wie het wijzigt, en dat heeft de tool niet. Wijzig het wachtwoord in Proxmox zelf (Datacenter, Permissions, Users, Password)':
        ('Proxmox asks for the own password of whoever makes this change, and the tool does not have it. Change the password in Proxmox itself (Datacenter, Permissions, Users, Password)', 'Proxmox verlangt dabei das eigene Passwort dessen, der es ändert, und das hat das Tool nicht. Ändere das Passwort in Proxmox selbst (Rechenzentrum, Berechtigungen, Benutzer, Passwort)'),
    'Ongeldige groepsnaam: letters, cijfers, punt, streepje of liggend streepje, tot 64 tekens':
        ('Invalid group name: letters, digits, dot, hyphen or underscore, up to 64 characters', 'Ungültiger Gruppenname: Buchstaben, Ziffern, Punkt, Bindestrich oder Unterstrich, bis 64 Zeichen'),
    'Deze groep bestaat al':
        ('This group already exists', 'Diese Gruppe gibt es bereits'),
    'Deze groep bestaat niet (meer)':
        ('This group does not exist (any more)', 'Diese Gruppe gibt es nicht (mehr)'),
    'De gebruiker waarmee de tool werkt zit in deze groep; die groep verwijdert de tool niet':
        ('The user the tool works with is in this group; the tool does not delete that group', 'Der Benutzer, mit dem das Tool arbeitet, ist in dieser Gruppe; diese Gruppe löscht das Tool nicht'),
    'De gebruiker waarmee de tool werkt zit in deze groep; de rechten van die groep wijzigt de tool niet':
        ("The user the tool works with is in this group; the tool does not change that group's permissions", 'Der Benutzer, mit dem das Tool arbeitet, ist in dieser Gruppe; die Rechte dieser Gruppe ändert das Tool nicht'),
    'Kies een gebruiker of een groep':
        ('Choose a user or a group', 'Wähle einen Benutzer oder eine Gruppe'),
    'Ongeldige plek voor een recht':
        ('Invalid place for a permission', 'Ungültiger Ort für eine Berechtigung'),
    'Onbekende rol':
        ('Unknown role', 'Unbekannte Rolle'),
    'Dit recht bestaat niet (meer)':
        ('This permission does not exist (any more)', 'Diese Berechtigung gibt es nicht (mehr)'),
    'Ongeldig zoekdomein':
        ('Invalid search domain', 'Ungültige Suchdomäne'),
    'Ongeldig adres van een DNS-server: {0}':
        ('Invalid DNS server address: {0}', 'Ungültige Adresse eines DNS-Servers: {0}'),
    'Vul minstens de eerste DNS-server in':
        ('Fill in at least the first DNS server', 'Gib mindestens den ersten DNS-Server ein'),
    'De notitie bevat een ongeldig teken':
        ('The note contains an invalid character', 'Die Notiz enthält ein ungültiges Zeichen'),
    'Wachttijd voor het starten van de guests: 0 tot 300 seconden':
        ('Delay before starting the guests: 0 to 300 seconds', 'Wartezeit vor dem Start der Gäste: 0 bis 300 Sekunden'),
    'Ongeldig MAC-adres voor Wake-on-LAN':
        ('Invalid MAC address for Wake-on-LAN', 'Ungültige MAC-Adresse für Wake-on-LAN'),
    'Onbekende tijdzone':
        ('Unknown time zone', 'Unbekannte Zeitzone'),
    'Onbekende pakketbron':
        ('Unknown package repository', 'Unbekannte Paketquelle'),
    'Deze node is niet online':
        ('This node is not online', 'Dieser Node ist nicht online'),
    'De pakketbronnen zijn intussen veranderd; open het venster opnieuw':
        ('The package repositories have changed in the meantime; open the window again', 'Die Paketquellen haben sich inzwischen geändert; öffne das Fenster erneut'),
    'Deze standaardbron is onbekend of staat er al':
        ('This standard repository is unknown or already present', 'Diese Standardquelle ist unbekannt oder schon vorhanden'),
    'Ongeldige node of opslag':
        ('Invalid node or storage', 'Ungültiger Node oder Speicher'),
    'Op deze opslag mogen geen ISO-bestanden staan':
        ('ISO files are not allowed on this storage', 'Auf diesem Speicher sind keine ISO-Dateien erlaubt'),
    'Op deze opslag mogen geen sjablonen staan':
        ('Templates are not allowed on this storage', 'Auf diesem Speicher sind keine Vorlagen erlaubt'),
    'Vul een webadres in dat begint met http:// of https://':
        ('Fill in a web address that starts with http:// or https://', 'Gib eine Webadresse ein, die mit http:// oder https:// beginnt'),
    'Bestandsnaam: letters, cijfers, punt, streepje, liggend streepje of plus, eindigend op .iso of .img':
        ('File name: letters, digits, dot, hyphen, underscore or plus, ending in .iso or .img', 'Dateiname: Buchstaben, Ziffern, Punkt, Bindestrich, Unterstrich oder Plus, endend auf .iso oder .img'),
    'De controlesom past niet bij het gekozen soort ({0})':
        ('The checksum does not match the chosen type ({0})', 'Die Prüfsumme passt nicht zur gewählten Art ({0})'),
    'Er staat al een ISO met deze naam op deze opslag':
        ('There already is an ISO with this name on this storage', 'Auf diesem Speicher gibt es bereits eine ISO mit diesem Namen'),
    'Dit sjabloon staat al op deze opslag':
        ('This template is already on this storage', 'Diese Vorlage liegt bereits auf diesem Speicher'),
    'Ongeldig bestand':
        ('Invalid file', 'Ungültige Datei'),
    'Dit bestand staat niet (meer) op deze opslag':
        ('This file is not (or no longer) on this storage', 'Diese Datei liegt nicht (mehr) auf diesem Speicher'),
    'Deze ISO zit nog in de cd-speler van VM {0}; haal hem daar eerst uit':
        ('This ISO is still in the CD drive of VM {0}; remove it there first', 'Diese ISO steckt noch im CD-Laufwerk von VM {0}; entferne sie dort zuerst'),
    'Deze opslag is nu op geen enkele node beschikbaar':
        ('This storage is not available on any node right now', 'Dieser Speicher ist gerade auf keinem Node verfügbar'),
    'Onbekende manier van plaatsen':
        ('Unknown placement mode', 'Unbekannte Art der Platzierung'),
    'Onbekende rekenmethode':
        ('Unknown scoring method', 'Unbekannte Berechnungsmethode'),
    'De loadbalancer werkt alleen als Proxmox naar het gebruik kijkt: kies Dynamisch of Statisch':
        ('The load balancer only works when Proxmox looks at usage: choose Dynamic or Static',
         'Der Loadbalancer funktioniert nur, wenn Proxmox auf die Auslastung achtet: wähle Dynamisch oder Statisch'),
    'De drempel en de verbetering zijn een percentage van 0 tot en met 100':
        ('The threshold and the improvement are a percentage from 0 to 100', 'Schwelle und Verbesserung sind ein Prozentsatz von 0 bis 100'),
    'Wachtrondes: 0 tot en met 60':
        ('Waiting rounds: 0 to 60', 'Warterunden: 0 bis 60'),
    'Het tijdvenster moet een begin en een ander einde hebben':
        ('The time window needs a start and a different end', 'Das Zeitfenster braucht einen Anfang und ein anderes Ende'),
    'De loadbalancer van Proxmox bestaat pas vanaf Proxmox VE 9.2; werk de nodes eerst bij':
        ('The Proxmox load balancer only exists from Proxmox VE 9.2 on; update the nodes first',
         'Den Loadbalancer von Proxmox gibt es erst ab Proxmox VE 9.2; aktualisiere zuerst die Nodes'),
    'Proxmox weigerde de instelling: {0}':
        ('Proxmox refused the setting: {0}', 'Proxmox hat die Einstellung abgelehnt: {0}'),
    'Deze guest staat niet in HA; alleen guests in HA doen mee aan het verdelen':
        ('This guest is not in HA; only guests in HA take part in balancing', 'Dieser Gast ist nicht in HA; nur Gäste in HA nehmen an der Verteilung teil'),
    'Kies een geldige tijd voor uitloggen zonder activiteit':
        ('Choose a valid time for logging out without activity', 'Wähle eine gültige Zeit für das Abmelden ohne Aktivität'),
    'Ingelogd blijven: 7, 14, 30 of 90 dagen':
        ('Stay logged in: 7, 14, 30 or 90 days', 'Angemeldet bleiben: 7, 14, 30 oder 90 Tage'),
    'Een sessie zonder Ingelogd blijven duurt 1 tot en met 24 uur':
        ('A session without Stay logged in lasts 1 to 24 hours', 'Eine Sitzung ohne Angemeldet bleiben dauert 1 bis 24 Stunden'),
    "Het bestand is afgekeurd; er is niets geïnstalleerd": ("The file was rejected; nothing was installed", "Die Datei wurde abgelehnt; es wurde nichts installiert"),
    'Onbekende keuze voor het uitzetten van een node':
        ('Unknown choice for shutting down a node', 'Unbekannte Wahl für das Herunterfahren eines Nodes'),
    'Onbekende keuze voor de guests tijdens het onderhoud':
        ('Unknown choice for the guests during maintenance', 'Unbekannte Wahl für die Gäste während der Wartung'),
    'HA tijdelijk uitschakelen kan pas vanaf Proxmox VE 9.2':
        ('Temporarily disabling HA is only possible from Proxmox VE 9.2 on', 'HA vorübergehend ausschalten geht erst ab Proxmox VE 9.2'),
    'HA staat al uit voor onderhoud':
        ('HA is already off for maintenance', 'HA ist bereits für Wartung ausgeschaltet'),
    'HA staat al aan':
        ('HA is already on', 'HA ist bereits an'),
    'Onbekende soort regel':
        ('Unknown kind of rule', 'Unbekannte Art von Regel'),
    'Onbekende keuze bij samen of apart':
        ('Unknown choice for together or apart', 'Unbekannte Wahl bei zusammen oder getrennt'),
    'Deze guests staan niet in HA: {0}':
        ('These guests are not in HA: {0}', 'Diese Gäste sind nicht in HA: {0}'),
    'Kies minstens één guest':
        ('Choose at least one guest', 'Wähle mindestens einen Gast'),
    'Onbekende node: {0}':
        ('Unknown node: {0}', 'Unbekannter Node: {0}'),
    'Prioriteit: 0 tot en met 1000':
        ('Priority: 0 to 1000', 'Priorität: 0 bis 1000'),
    'Kies minstens één node':
        ('Choose at least one node', 'Wähle mindestens einen Node'),
    "Met 'niet op deze nodes' moet er minstens één node overblijven":
        ("With 'not on these nodes' at least one node must remain", "Mit 'nicht auf diesen Nodes' muss mindestens ein Node übrig bleiben"),
    'Kies minstens twee guests':
        ('Choose at least two guests', 'Wähle mindestens zwei Gäste'),
    'Niet samen op één node kan hier niet: {0} guests en maar {1} nodes':
        ('Not together on one node is not possible here: {0} guests and only {1} nodes', 'Nicht zusammen auf einem Node geht hier nicht: {0} Gäste und nur {1} Nodes'),
    'Deze Proxmox-versie kent geen HA-regels (vanaf Proxmox VE 9); gebruik daar de HA-groepen':
        ('This Proxmox version has no HA rules (from Proxmox VE 9 on); use the HA groups there', 'Diese Proxmox-Version kennt keine HA-Regeln (ab Proxmox VE 9); nutze dort die HA-Gruppen'),
    'Naam van de regel: begint met een letter, 2 tot 63 tekens: letters, cijfers, - en _':
        ('Rule name: starts with a letter, 2 to 63 characters: letters, digits, - and _', 'Name der Regel: beginnt mit einem Buchstaben, 2 bis 63 Zeichen: Buchstaben, Ziffern, - und _'),
    'Er is al een regel met deze naam':
        ('There already is a rule with this name', 'Es gibt bereits eine Regel mit diesem Namen'),
    'Ongeldige naam van de regel':
        ('Invalid rule name', 'Ungültiger Name der Regel'),
    'Deze regel bestaat niet (meer)':
        ('This rule does not exist (any more)', 'Diese Regel existiert nicht (mehr)'),
    'De soort van een regel kun je niet wijzigen; maak een nieuwe regel':
        ('You cannot change the kind of a rule; create a new rule', 'Die Art einer Regel kannst du nicht ändern; lege eine neue Regel an'),
    'Ceph draait nog op geen enkele node':
        ('Ceph is not running on any node yet', 'Ceph läuft noch auf keinem Node'),
    'Ongeldige vraag':
        ('Invalid question', 'Ungültige Anfrage'),
    'Deze vlag zet de tool niet':
        ('The tool does not set this flag', 'Dieses Flag setzt das Tool nicht'),
    'Onbekende handeling':
        ('Unknown action', 'Unbekannte Aktion'),
    'Deze OSD staat niet op deze node':
        ('This OSD is not on this node', 'Dieses OSD ist nicht auf diesem Node'),
    'Deze OSD is al uit gebruik':
        ('This OSD is already out', 'Dieses OSD ist bereits außer Betrieb'),
    "Dan blijven er te weinig nodes met OSD's in gebruik over ({0}); de pools hebben er minstens {1} nodig":
        ('Then too few nodes with OSDs in use would remain ({0}); the pools need at least {1}', 'Dann blieben zu wenige Nodes mit OSDs in Betrieb übrig ({0}); die Pools brauchen mindestens {1}'),
    'Deze OSD is al in gebruik':
        ('This OSD is already in', 'Dieses OSD ist bereits in Betrieb'),
    'Deze OSD draait niet':
        ('This OSD is not running', 'Dieses OSD läuft nicht'),
    'Ceph raadt stoppen nu af: {0}':
        ('Ceph advises against stopping now: {0}', 'Ceph rät jetzt vom Stoppen ab: {0}'),
    'Deze OSD draait al':
        ('This OSD is already running', 'Dieses OSD läuft bereits'),
    'Onbekende soort schijf':
        ('Unknown kind of disk', 'Unbekannte Art von Platte'),
    'Ceph draait niet op deze node; voeg daar eerst Ceph toe':
        ('Ceph is not running on this node; add Ceph there first', 'Ceph läuft nicht auf diesem Node; füge dort zuerst Ceph hinzu'),
    'Deze schijf is niet vrij (in gebruik of niet gevonden)':
        ('This disk is not free (in use or not found)', 'Diese Platte ist nicht frei (belegt oder nicht gefunden)'),
    'Neem de OSD eerst uit gebruik en stop hem; wacht tot Ceph klaar is met verplaatsen':
        ('Take the OSD out and stop it first; wait until Ceph has finished moving data', 'Nimm das OSD zuerst außer Betrieb und stoppe es; warte, bis Ceph mit dem Verschieben fertig ist'),
    'Ceph raadt verwijderen nu af: {0}':
        ('Ceph advises against deleting now: {0}', 'Ceph rät jetzt vom Löschen ab: {0}'),
    'Op deze node staat Ceph niet; installeer het daar eerst':
        ('Ceph is not on this node; install it there first', 'Auf diesem Node ist Ceph nicht; installiere es dort zuerst'),
    'Op deze node draait al een monitor':
        ('A monitor is already running on this node', 'Auf diesem Node läuft bereits ein Monitor'),
    'Ongeldige monitor':
        ('Invalid monitor', 'Ungültiger Monitor'),
    'Deze monitor staat niet op deze node':
        ('This monitor is not on this node', 'Dieser Monitor ist nicht auf diesem Node'),
    'Dit is de laatste monitor; zonder monitor werkt Ceph niet':
        ('This is the last monitor; Ceph does not work without a monitor', 'Das ist der letzte Monitor; ohne Monitor funktioniert Ceph nicht'),
    'Ceph raadt dit nu af: {0}':
        ('Ceph advises against this now: {0}', 'Ceph rät jetzt davon ab: {0}'),
    'Ceph draait niet op deze node; voeg daar eerst een monitor toe':
        ('Ceph is not running on this node; add a monitor there first', 'Ceph läuft nicht auf diesem Node; füge dort zuerst einen Monitor hinzu'),
    'Op deze node draait al een manager':
        ('A manager is already running on this node', 'Auf diesem Node läuft bereits ein Manager'),
    'Ongeldige manager':
        ('Invalid manager', 'Ungültiger Manager'),
    'Deze manager staat niet op deze node':
        ('This manager is not on this node', 'Dieser Manager ist nicht auf diesem Node'),
    'Dit is de laatste manager; zonder manager werkt Ceph niet goed':
        ('This is the last manager; Ceph does not work well without a manager', 'Das ist der letzte Manager; ohne Manager funktioniert Ceph nicht richtig'),
    'Aantal kopieën: 2 tot en met 7':
        ('Number of copies: 2 to 7', 'Anzahl der Kopien: 2 bis 7'),
    'Minimum: 1 tot en met het aantal kopieën':
        ('Minimum: 1 up to the number of copies', 'Minimum: 1 bis zur Anzahl der Kopien'),
    'Onbekende keuze voor het automatisch schalen':
        ('Unknown choice for automatic scaling', 'Unbekannte Wahl für das automatische Skalieren'),
    "{0} kopieën kan niet: er zijn maar {1} nodes met OSD's":
        ('{0} copies is not possible: there are only {1} nodes with OSDs', '{0} Kopien geht nicht: Es gibt nur {1} Nodes mit OSDs'),
    'Naam van de pool: letters, cijfers, - en _, hooguit 63 tekens':
        ('Pool name: letters, digits, - and _, at most 63 characters', 'Name des Pools: Buchstaben, Ziffern, - und _, höchstens 63 Zeichen'),
    'Onbekende toepassing':
        ('Unknown application', 'Unbekannte Anwendung'),
    'Er is al een pool met deze naam':
        ('There already is a pool with this name', 'Es gibt bereits einen Pool mit diesem Namen'),
    'Er is al een opslag met deze naam in Proxmox':
        ('There already is a storage with this name in Proxmox', 'In Proxmox gibt es bereits einen Speicher mit diesem Namen'),
    'Een pool van Ceph zelf (met een punt ervoor) of met een ongeldige naam past de tool niet aan':
        ('The tool does not change a pool of Ceph itself (with a dot in front) or with an invalid name', 'Einen Pool von Ceph selbst (mit einem Punkt davor) oder mit ungültigem Namen ändert das Tool nicht'),
    'Deze pool bestaat niet (meer)':
        ('This pool does not exist (any more)', 'Dieser Pool existiert nicht (mehr)'),
    'Een pool van Ceph zelf (met een punt ervoor) of met een ongeldige naam verwijdert de tool niet':
        ('The tool does not delete a pool of Ceph itself (with a dot in front) or with an invalid name', 'Einen Pool von Ceph selbst (mit einem Punkt davor) oder mit ungültigem Namen löscht das Tool nicht'),
    'Op opslag {0} staan nog {1} schijven; deze pool verwijdert de tool niet':
        ('Storage {0} still holds {1} disks; the tool does not delete this pool', 'Auf Speicher {0} liegen noch {1} Platten; diesen Pool löscht das Tool nicht'),
    'Vul een netwerk in met de netwerkgrootte, bijvoorbeeld 10.10.10.0/24':
        ('Fill in a network with its size, for example 10.10.10.0/24', 'Gib ein Netzwerk mit seiner Größe an, zum Beispiel 10.10.10.0/24'),
    'Ceph is al ingericht':
        ('Ceph has already been set up', 'Ceph ist bereits eingerichtet'),
    'Op deze node staan de Ceph-pakketten nog niet; draai daar eerst pveceph install':
        ('The Ceph packages are not on this node yet; run pveceph install there first', 'Auf diesem Node sind die Ceph-Pakete noch nicht; führe dort zuerst pveceph install aus'),
    'Het antwoord van de beveiligingssleutel klopt niet':
        ('The answer of the security key is not right', 'Die Antwort des Sicherheitsschlüssels stimmt nicht'),
    'De beveiligingssleutel is niet herkend':
        ('The security key was not recognised', 'Der Sicherheitsschlüssel wurde nicht erkannt'),
    'Het aanmelden met de sleutel duurde te lang of is in een ander venster begonnen; probeer het opnieuw':
        ('Signing in with the key took too long or was started in another window; try again', 'Die Anmeldung mit dem Schlüssel hat zu lange gedauert oder wurde in einem anderen Fenster begonnen; versuche es erneut'),
    'Beveiligingssleutels werken alleen als je de tool via een naam opent (bijvoorbeeld je Cloudflare-adres), niet via een IP-adres':
        ('Security keys only work when you open the tool through a name (for example your Cloudflare address), not through an IP address', 'Sicherheitsschlüssel funktionieren nur, wenn du das Tool über einen Namen öffnest (zum Beispiel deine Cloudflare-Adresse), nicht über eine IP-Adresse'),
    'Het wachtwoord klopt niet; er is niets gewijzigd':
        ('The password is not right; nothing has been changed', 'Das Passwort stimmt nicht; es wurde nichts geändert'),
    'Voor deze gebruiker is na het wachtwoord ook de beveiligingssleutel nodig. Die werkt hier niet; open de tool via {0}':
        ('This user also needs the security key after the password. It does not work here; open the tool through {0}', 'Dieser Benutzer braucht nach dem Passwort auch den Sicherheitsschlüssel. Der funktioniert hier nicht; öffne das Tool über {0}'),
    'Er kunnen niet meer dan 10 sleutels per gebruiker zijn':
        ('There cannot be more than 10 keys per user', 'Es kann nicht mehr als 10 Schlüssel pro Benutzer geben'),
    'De sleutels konden niet bewaard worden':
        ('The keys could not be saved', 'Die Schlüssel konnten nicht gespeichert werden'),
    'Deze sleutel gebruikt een soort handtekening die de tool niet kent (alleen ES256 en RS256)':
        ('This key uses a kind of signature the tool does not know (only ES256 and RS256)', 'Dieser Schlüssel verwendet eine Art von Signatur, die das Tool nicht kennt (nur ES256 und RS256)'),
    'Een naam voor de sleutel: hooguit 40 tekens, zonder < > " &':
        ('A name for the key: at most 40 characters, without < > " &', 'Ein Name für den Schlüssel: höchstens 40 Zeichen, ohne < > " &'),
    'Deze sleutel is al toegevoegd':
        ('This key has already been added', 'Dieser Schlüssel wurde bereits hinzugefügt'),
    'Deze sleutel bestaat niet (meer)':
        ('This key does not exist (any more)', 'Dieser Schlüssel existiert nicht (mehr)'),
    'Voeg eerst een beveiligingssleutel toe':
        ('Add a security key first', 'Füge zuerst einen Sicherheitsschlüssel hinzu'),
    'Dit account logt niet met een wachtwoord in; de sleutel na het wachtwoord is dan niet nodig':
        ('This account does not log in with a password; the key after the password is not needed then', 'Dieses Konto meldet sich nicht mit einem Passwort an; der Schlüssel nach dem Passwort ist dann nicht nötig'),
    'Deze gebruiker heeft geen beveiligingssleutels':
        ('This user has no security keys', 'Dieser Benutzer hat keine Sicherheitsschlüssel'),
    'Voor inloggen met alleen de sleutel moet de sleutel je pincode of vingerafdruk vragen':
        ('To log in with only the key, the key has to ask for your PIN or fingerprint', 'Für die Anmeldung nur mit dem Schlüssel muss der Schlüssel deine PIN oder deinen Fingerabdruck abfragen'),
    'Deze beveiligingssleutel meldt een teller die niet klopt (mogelijk een kopie); er is niet ingelogd':
        ('This security key reports a counter that is not right (possibly a copy); you were not logged in', 'Dieser Sicherheitsschlüssel meldet einen Zähler, der nicht stimmt (möglicherweise eine Kopie); es wurde nicht angemeldet'),
    'Log eerst opnieuw in met gebruikersnaam en wachtwoord':
        ('Log in again with user name and password first', 'Melde dich zuerst erneut mit Benutzername und Passwort an'),
    'Ongeldige code':
        ('Invalid code', 'Ungültiger Code'),
    'Vul een gebruiker van de node in (bijvoorbeeld root) en zijn wachtwoord':
        ('Fill in a user of the node (for example root) and its password', 'Gib einen Benutzer des Nodes an (zum Beispiel root) und sein Passwort'),
    'Gebruikersnaam, wachtwoord of code klopt niet':
        ('User name, password or code is not right', 'Benutzername, Passwort oder Code stimmt nicht'),
    'Het inloggen bij Proxmox is verlopen; log opnieuw in voor de console':
        ('The login at Proxmox has expired; log in again for the console', 'Die Anmeldung bei Proxmox ist abgelaufen; melde dich für die Konsole erneut an'),
    'Dit account mag geen console op deze node openen':
        ('This account may not open a console on this node', 'Dieses Konto darf auf diesem Node keine Konsole öffnen'),
    'Proxmox gaf geen console voor deze node':
        ('Proxmox gave no console for this node', 'Proxmox gab keine Konsole für diesen Node'),
    'Log eerst in voor de console':
        ('Log in for the console first', 'Melde dich zuerst für die Konsole an'),
    'Ongeldige naam voor een token: begint met een letter, dan letters, cijfers, punt, streepje of liggend streepje (2 tot 64 tekens)':
        ('Invalid name for a token: starts with a letter, then letters, digits, dot, hyphen or underscore (2 to 64 characters)', 'Ungültiger Name für ein Token: beginnt mit einem Buchstaben, dann Buchstaben, Ziffern, Punkt, Bindestrich oder Unterstrich (2 bis 64 Zeichen)'),
    'Deze gebruiker heeft al een token met die naam':
        ('This user already has a token with that name', 'Dieser Benutzer hat bereits ein Token mit diesem Namen'),
    'Proxmox gaf geen geheim terug voor het nieuwe token':
        ('Proxmox returned no secret for the new token', 'Proxmox gab kein Geheimnis für das neue Token zurück'),
    'Dit token bestaat niet (meer)':
        ('This token does not exist (any more)', 'Dieses Token existiert nicht (mehr)'),
    'Kies een gebruiker, een groep of een token':
        ('Choose a user, a group or a token', 'Wähle einen Benutzer, eine Gruppe oder ein Token'),
    'Ongeldige indeling van de tabellen':
        ('Invalid layout of the tables', 'Ungültige Anordnung der Tabellen'),
    '{0} bestaat niet in Proxmox; een pam-account moet daar bestaan (tabblad Gebruikers) en als Linux-account op de nodes':
        ('{0} does not exist in Proxmox; a pam account has to exist there (Users tab) and as a Linux account on the nodes', '{0} existiert nicht in Proxmox; ein pam-Konto muss dort existieren (Reiter Benutzer) und als Linux-Konto auf den Nodes'),
    '{0} staat in Proxmox uit (Datacenter, Permissions, Users). Zet het account daar aan, of log in met een ander account dat een console mag openen':
        ('{0} is switched off in Proxmox (Datacenter, Permissions, Users). Switch the account on there, or log in with another account that may open a console', '{0} ist in Proxmox ausgeschaltet (Datacenter, Permissions, Users). Schalte das Konto dort ein oder melde dich mit einem anderen Konto an, das eine Konsole öffnen darf'),
    '{0} is in Proxmox verlopen. Verleng het account (tabblad Gebruikers), of log in met een ander account':
        ('{0} has expired in Proxmox. Extend the account (Users tab), or log in with another account', '{0} ist in Proxmox abgelaufen. Verlängere das Konto (Reiter Benutzer) oder melde dich mit einem anderen Konto an'),
    '{0} bestaat niet in Proxmox; maak het account aan op het tabblad Gebruikers, in realm pve':
        ('{0} does not exist in Proxmox; create the account on the Users tab, in realm pve', '{0} existiert nicht in Proxmox; lege das Konto auf dem Reiter Benutzer an, im Realm pve'),
    'Vul een gebruiker van Proxmox in (realm pve) en zijn wachtwoord':
        ('Fill in a Proxmox user (realm pve) and its password', 'Gib einen Benutzer von Proxmox ein (Realm pve) und sein Passwort'),
    'Ongeldige naam: hooguit 40 tekens, zonder < of >':
        ('Invalid name: at most 40 characters, without < or >', 'Ungültiger Name: höchstens 40 Zeichen, ohne < oder >'),
    "Er kunnen hooguit {0} schema's zijn":
        ('There can be at most {0} schedules', 'Es kann höchstens {0} Zeitpläne geben'),
    'Probeer het nog een keer':
        ('Please try again', 'Bitte versuche es noch einmal'),
    'Dit schema bestaat niet (meer)':
        ('This schedule does not exist (any more)', 'Dieser Zeitplan existiert nicht (mehr)'),
    'Dit schema draait nu; verwijder het als de ronde klaar is':
        ('This schedule is running now; remove it when the round is finished', 'Dieser Zeitplan läuft gerade; entferne ihn, wenn die Runde fertig ist'),
    'Deze node is niet online; zijn logboek is nu niet te lezen':
        ('This node is not online; its log cannot be read right now', 'Dieser Node ist nicht online; sein Protokoll lässt sich gerade nicht lesen'),
    '{0} antwoordt niet via de Proxmox-API; meestal staat in /etc/hosts op die node nog een oud adres':
        ('{0} does not answer through the Proxmox API; usually /etc/hosts on that node still holds an old address', '{0} antwortet nicht über die Proxmox-API; meist steht in /etc/hosts auf diesem Node noch eine alte Adresse'),
    'Ongeldig label: begin met een letter, cijfer of _, daarna ook - + of een punt; hooguit 64 tekens en 20 labels':
        ('Invalid tag: start with a letter, digit or _, after that also - + or a dot; at most 64 characters and 20 tags', 'Ungültiger Tag: Beginne mit einem Buchstaben, einer Ziffer oder _, danach auch - + oder ein Punkt; höchstens 64 Zeichen und 20 Tags'),
    'De tool houdt het label maintool op zijn eigen container: daaraan herkent het setup-bestand hem bij bijwerken en verwijderen':
        ('The tool keeps the tag maintool on its own container: that is how the setup file recognises it when updating and removing', 'Das Tool behält den Tag maintool auf seinem eigenen Container: Daran erkennt die Setup-Datei ihn beim Aktualisieren und Entfernen'),
    'Zoeken naar nieuwe versies staat uit (UPDATE_REPO in maintool.env)':
        ('Looking for new versions is switched off (UPDATE_REPO in maintool.env)',
         'Die Suche nach neuen Versionen ist ausgeschaltet (UPDATE_REPO in maintool.env)'),
    'Deze versie staat niet (meer) op GitHub; kijk opnieuw':
        ('This version is not (or no longer) on GitHub; check again', 'Diese Version ist nicht (mehr) auf GitHub; sieh noch einmal nach'),
}
_PATTERNS = [(re.compile("^" + re.escape(nl).replace(r"\{0\}", "(.*?)").replace(r"\{1\}", "(.*?)") + "$", re.S), en, de)
             for nl, (en, de) in MESSAGES.items()]


def lang_of(request) -> str:
    lang = request.cookies.get(LANG_COOKIE, "")
    return lang if lang in LANGS else "nl"


def translate(text, lang: str):
    """Een melding van deze achterkant in de gevraagde taal; onbekende tekst (ook die van Proxmox zelf) blijft staan."""
    if lang == "nl" or not isinstance(text, str):
        return text
    for pattern, en, de in _PATTERNS:
        found = pattern.match(text)
        if found:
            return (en if lang == "en" else de).format(*found.groups())
    return text


@app.exception_handler(HTTPException)
async def translated_error(request: Request, err: HTTPException):
    return JSONResponse({"detail": translate(err.detail, lang_of(request))}, status_code=err.status_code,
                        headers=getattr(err, "headers", None))


def same_origin(request: Request):
    """Een ingrijpend verzoek moet van de pagina van de tool zelf komen: een extra slot naast het SameSite-cookie."""
    origin = request.headers.get("origin")
    if not origin or urllib.parse.urlsplit(origin).netloc != request.headers.get("host"):
        raise HTTPException(403, "Dit verzoek komt niet van de pagina van de tool")


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    user = read_token(request.cookies.get(SESSION_COOKIE))
    if user:
        return page(INDEX, user, request)
    # Via Cloudflare Access heeft de gebruiker al ingelogd: dan meteen binnen (behalve vlak na uitloggen).
    name = None if request.cookies.get(NOSSO_COOKIE) else cloudflare_user(request)
    if not name:
        return RedirectResponse("/login", status_code=303)
    response = HTMLResponse(page(INDEX, name, request))
    start_session(response, name)
    return response


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if read_token(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse("/", status_code=303)
    name = None if request.cookies.get(NOSSO_COOKIE) else cloudflare_user(request)
    if name:
        response = RedirectResponse("/", status_code=303)
        start_session(response, name)
        return response
    return page(LOGIN)


class LoginIn(BaseModel):
    username: str = Field(max_length=100)
    password: str = Field(max_length=300)
    remember: bool = False                           # het vinkje Ingelogd blijven
    method: str = Field("password", max_length=12)   # "password" (eigen wachtwoord) of "proxmox" (Proxmox-account)
    realm: str | None = Field(None, max_length=40)   # bij een Proxmox-account


@app.post("/api/login")
def login(body: LoginIn, request: Request, response: Response):
    source = source_of(request)
    if login_guard.blocked(source):
        raise HTTPException(429, "Te veel mislukte pogingen. Probeer het over tien minuten opnieuw.")
    if body.method == "proxmox":
        name = proxmox_login(body, source)
    else:
        name = body.username.strip()
        if not secrets.compare_digest(name.encode(), APP_USER.encode()):
            name = name.lower()   # de namen van de overige gebruikers zijn in kleine letters
        if not check_login(name, body.password):
            login_guard.failed(source)
            raise HTTPException(401, "Gebruikersnaam of wachtwoord klopt niet")
    if wa_required(name):   # de beveiligingssleutel is voor deze gebruiker verplicht: nog geen sessie
        return wa_second_step(request, name, body.remember)
    login_guard.succeeded(source)
    start_session(response, name, body.remember)
    return {"ok": True}


@app.post("/api/logout")
def logout(request: Request, response: Response):
    with nodecon_lock:
        _nodecon.pop(nodecon_key(request), None)
    response.delete_cookie(SESSION_COOKIE, path="/")
    # Na uitloggen niet vanzelf weer binnen via Cloudflare Access; dat kan dan met de knop op de inlogpagina.
    response.set_cookie(NOSSO_COOKIE, "1", path="/", httponly=True, secure=True, samesite="lax")
    return {"ok": True}


class PasswordIn(BaseModel):
    current: str = Field(max_length=300)
    new: str = Field(max_length=300)


@app.get("/api/me")
def me(request: Request, user: str = Depends(auth)):
    who, why = account(user) or {}, view_only(request)
    return {"user": user, "role": who.get("role", "readonly"), "roles": who.get("roles", []), "can": [] if why else who.get("can", []),
            "view_only": why, "via_cloudflare": via_cloudflare(request),
            "builtin": bool(who.get("builtin")), "min_password": min_password(),
            "password_login": user == APP_USER or (users_state().get(user) or {}).get("pw", True),
            "sso": sorted(m for m in SSO_METHODS if m in links_of(user)),
            "webauthn": {"keys": len(wa_user(user)["keys"]), "required": wa_required(user)}}


@app.post("/api/password")
def change_password(body: PasswordIn, request: Request, response: Response, user: str = Depends(auth)):
    """Wijzigt het eigen wachtwoord. Het nieuwe wordt alleen als hash bewaard; alle andere sessies van deze
    gebruiker vervallen."""
    same_origin(request)
    source = request.client.host if request.client else "?"
    if login_guard.blocked(source):
        raise HTTPException(429, "Te veel mislukte pogingen. Probeer het over tien minuten opnieuw.")
    if not check_login(user, body.current):
        login_guard.failed(source)
        raise HTTPException(403, "Het huidige wachtwoord klopt niet; er is niets gewijzigd")
    problem = new_password_problem(body.new)
    if problem:
        raise HTTPException(400, problem)
    if body.new == body.current:
        raise HTTPException(400, "Het nieuwe wachtwoord is gelijk aan het huidige")
    salt = secrets.token_bytes(16)
    try:
        if user == APP_USER:
            data = {"salt": salt.hex(), "hash": password_hash(body.new, salt), "gen": auth_state().get("gen", 0) + 1,
                    "changed": int(time.time())}
            tmp = AUTH_FILE.with_suffix(".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(json.dumps(data))
            os.replace(tmp, AUTH_FILE)
        else:
            with users_lock:
                everyone = dict(users_state())
                everyone[user] = {**everyone[user], "salt": salt.hex(), "hash": password_hash(body.new, salt),
                                  "gen": everyone[user]["gen"] + 1}
                save_users(everyone)
    except (OSError, KeyError):
        raise HTTPException(500, "Het wachtwoord kon niet bewaard worden")
    # Deze sessie krijgt meteen een nieuw cookie (met Ingelogd blijven als dat zo was); elke andere van deze gebruiker
    # is vanaf nu ongeldig.
    set_session_cookie(response, user, token_remembered(request.cookies.get(SESSION_COOKIE)))
    return {"ok": True}


# ---------------------------------------------------------------- gebruikers beheren (alleen beheerders)
class UserIn(BaseModel):
    name: str = Field(max_length=64)
    roles: list[str] | None = Field(None, max_length=8)
    role: str | None = Field(None, max_length=16)   # oude vorm: "admin" of "readonly"
    password: str | None = Field(None, max_length=300)
    sso: dict | None = None            # {"oidc": mailadres, "cloudflare": mailadres, "proxmox": "gebruiker@realm"}
    password_login: bool = True        # mag ook met een wachtwoord inloggen


class UserChange(BaseModel):
    roles: list[str] | None = Field(None, max_length=8)
    role: str | None = Field(None, max_length=16)
    password: str | None = Field(None, max_length=300)
    sso: dict | None = None
    password_login: bool | None = None


SSO_NAMES = {"oidc": "OpenID Connect", "cloudflare": "Cloudflare Access", "proxmox": "Proxmox-account"}


def links_in(raw, name: str) -> dict:
    """Nagekeken koppelingen uit een verzoek: alleen bekende manieren, geldige waarden, en niet al van een ander."""
    if not isinstance(raw, dict) or any(k not in SSO_METHODS for k in raw):
        raise HTTPException(400, "Ongeldige SSO-koppelingen")
    out = {}
    for method in SSO_METHODS:
        value = raw.get(method)
        value = clean_link(method, value) if value is None or isinstance(value, str) and len(value) <= 255 else None
        if value is None:
            raise HTTPException(400, f"Ongeldige SSO-koppeling bij {SSO_NAMES[method]}")
        if value:
            other = next((n for n in [APP_USER, *users_state()] if n != name and links_of(n).get(method) == value), None)
            if other:
                raise HTTPException(409, f"Dit account is al gekoppeld aan gebruiker {other}")
            out[method] = value
    return out


def user_list() -> list:
    def view(name, roles, builtin, pw=True, created=None):
        links = links_of(name)
        row = {"name": name, "roles": roles, "role": role_name(roles), "builtin": builtin, "password_login": pw,
               "sso": {m: links[m] for m in SSO_METHODS if m in links}, "bound": bool(links.get("oidc_sub")),
               "keys": len(wa_user(name)["keys"]), "key_required": wa_required(name)}
        return row if created is None else {**row, "created": created}
    return [view(APP_USER, ["admin"], True)] + [view(name, u["roles"], False, u["pw"], u["created"]) for name, u in sorted(users_state().items())]


class PolicyIn(BaseModel):
    min_password: int | None = None
    cloudflare: str | None = Field(None, max_length=10)   # ask, readonly of off (zie "via Cloudflare")
    idle: int | None = Field(None, strict=True)            # minuten zonder activiteit tot uitloggen, 0 = nooit
    remember: bool | None = None                           # het vinkje Ingelogd blijven op de inlogpagina
    remember_days: int | None = Field(None, strict=True)
    session_hours: int | None = Field(None, strict=True)   # hoe lang een sessie zonder Ingelogd blijven hooguit duurt


def policy_view() -> dict:
    return {"min_password": min_password(), "cloudflare": cf_mode(), **session_policy(),
            "choices": {"idle": list(IDLE_CHOICES), "remember_days": list(REMEMBER_DAYS), "session_hours": list(SESSION_HOURS_RANGE)}}


@app.get("/api/policy")
def policy_get(_: str = Depends(admin)):
    return policy_view()


@app.put("/api/policy")
def policy_put(body: PolicyIn, request: Request, _: str = Depends(admin)):
    """De minimale lengte voor nieuwe wachtwoorden (bestaande blijven geldig tot ze gewijzigd worden) en wat er gebeurt
    als iemand de tool via Cloudflare opent: vragen, altijd alleen bekijken, of niets."""
    same_origin(request)
    fields = ("min_password", "cloudflare", "idle", "remember", "remember_days", "session_hours")
    if all(getattr(body, k) is None for k in fields):
        raise HTTPException(400, "Er is niets om te wijzigen")
    if body.idle is not None and body.idle not in IDLE_CHOICES:
        raise HTTPException(400, "Kies een geldige tijd voor uitloggen zonder activiteit")
    if body.remember_days is not None and body.remember_days not in REMEMBER_DAYS:
        raise HTTPException(400, "Ingelogd blijven: 7, 14, 30 of 90 dagen")
    if body.session_hours is not None and not SESSION_HOURS_RANGE[0] <= body.session_hours <= SESSION_HOURS_RANGE[1]:
        raise HTTPException(400, "Een sessie zonder Ingelogd blijven duurt 1 tot en met 24 uur")
    if body.min_password is not None and not MIN_PASSWORD_RANGE[0] <= body.min_password <= MIN_PASSWORD_RANGE[1]:
        raise HTTPException(400, "De minimale lengte moet tussen 8 en 128 liggen")
    if body.cloudflare is not None and body.cloudflare not in CF_MODES:
        raise HTTPException(400, "Ongeldige keuze voor toegang via Cloudflare")
    change = {k: getattr(body, k) for k in fields if getattr(body, k) is not None}
    try:
        state.change(lambda d: d.setdefault("policy", {}).update(change))
    except OSError:
        raise HTTPException(500, "De instelling kon niet bewaard worden")
    return policy_view()


@app.get("/api/users")
def users_get(_: str = Depends(admin)):
    return user_list()


@app.post("/api/users")
def users_add(body: UserIn, request: Request, _: str = Depends(admin)):
    same_origin(request)
    name = body.name.strip().lower()
    if not USER_RE.match(name):
        raise HTTPException(400, "Ongeldige gebruikersnaam: 2-32 tekens, kleine letters, cijfers, punt, streepje")
    roles = clean_roles(body.roles, body.role)
    if roles is None:
        raise HTTPException(400, "Ongeldige rechten")
    if body.password_login:
        problem = new_password_problem(body.password or "")
        if problem:
            raise HTTPException(400, problem)
        secret = body.password
    else:
        secret = secrets.token_urlsafe(32)   # een wachtwoord dat niemand kent: inloggen kan alleen via SSO
    salt = secrets.token_bytes(16)
    with users_lock:
        everyone = dict(users_state())
        if name in everyone or name == APP_USER.lower():
            raise HTTPException(409, "Deze gebruikersnaam bestaat al")
        if len(everyone) >= MAX_USERS:
            raise HTTPException(409, "Er kunnen niet meer dan 50 gebruikers zijn")
        links = links_in(body.sso or {}, name)
        if not body.password_login and not links:
            raise HTTPException(400, "Zonder wachtwoord moet de gebruiker aan minstens één SSO-inlog gekoppeld zijn")
        # Het volgnummer begint bij de klok: wordt een naam verwijderd en later opnieuw aangemaakt, dan leeft een
        # oude sessie van de vorige gebruiker met die naam niet weer op.
        everyone[name] = {"roles": roles, "salt": salt.hex(), "hash": password_hash(secret, salt),
                          "gen": int(time.time() * 1000), "created": int(time.time()), "sso": links, "pw": bool(body.password_login)}
        try:
            save_users(everyone)
        except OSError:
            raise HTTPException(500, "De gebruikers konden niet bewaard worden")
    return user_list()


@app.put("/api/users/{name}")
def users_change(name: str, body: UserChange, request: Request, response: Response, actor: str = Depends(admin)):
    """Wijzigt rechten, wachtwoord, SSO-koppelingen en/of of iemand met een wachtwoord mag inloggen. Bij nieuwe rechten,
    een nieuw wachtwoord, een weggehaalde of gewijzigde koppeling, of als inloggen met een wachtwoord uit gaat,
    vervallen de sessies van die gebruiker. Van het hoofdaccount zijn hier alleen de SSO-koppelingen te wijzigen."""
    same_origin(request)
    asked = body.roles is not None or body.role is not None
    if name == APP_USER:
        if asked or body.password is not None or body.password_login is not None:
            raise HTTPException(409, "Het hoofdaccount kan hier niet gewijzigd of verwijderd worden")
        if body.sso is None:
            raise HTTPException(400, "Er is niets om te wijzigen")
        with sso_lock:
            data = dict(sso_state())
            old = stored_links(data.get("builtin"))
            links = links_in(body.sso, name)
            if old.get("oidc_sub") and links.get("oidc") == old.get("oidc"):
                links["oidc_sub"] = old["oidc_sub"]
            data["builtin"] = links
            try:
                save_sso(data)
            except OSError:
                raise HTTPException(500, "De gebruikers konden niet bewaard worden")
        return user_list()
    roles = clean_roles(body.roles, body.role) if asked else None
    if asked and roles is None:
        raise HTTPException(400, "Ongeldige rechten")
    if asked and name == actor:
        raise HTTPException(409, "Je kunt je eigen account niet verwijderen of je eigen rechten wijzigen")
    if not asked and body.password is None and body.sso is None and body.password_login is None:
        raise HTTPException(400, "Er is niets om te wijzigen")
    problem = new_password_problem(body.password) if body.password is not None else None
    if problem:
        raise HTTPException(400, problem)
    with users_lock:
        everyone = dict(users_state())
        if name not in everyone:
            raise HTTPException(404, "Deze gebruiker bestaat niet")
        changed, end = dict(everyone[name]), False
        if asked and roles != changed["roles"]:
            changed["roles"], end = roles, True
        if body.password is not None:
            salt = secrets.token_bytes(16)
            changed.update(salt=salt.hex(), hash=password_hash(body.password, salt))
            end = True
        if body.sso is not None:
            old = dict(changed.get("sso") or {})
            links = links_in(body.sso, name)
            if old.get("oidc_sub") and links.get("oidc") == old.get("oidc"):
                links["oidc_sub"] = old["oidc_sub"]
            end = end or any(old.get(m) and old.get(m) != links.get(m) for m in SSO_METHODS)
            changed["sso"] = links
        if body.password_login is not None and body.password_login != changed["pw"]:
            if body.password_login and body.password is None:
                raise HTTPException(400, "Geef een wachtwoord op om inloggen met een wachtwoord weer aan te zetten")
            changed["pw"] = body.password_login
            end = end or not body.password_login
        if not changed["pw"] and not any(m in (changed.get("sso") or {}) for m in SSO_METHODS):
            raise HTTPException(400, "Zonder wachtwoord moet de gebruiker aan minstens één SSO-inlog gekoppeld zijn")
        if end:
            changed["gen"] += 1
        everyone[name] = changed
        try:
            save_users(everyone)
        except OSError:
            raise HTTPException(500, "De gebruikers konden niet bewaard worden")
    if end and name == actor:
        start_session(response, name, token_remembered(request.cookies.get(SESSION_COOKIE)))   # wie zijn eigen koppelingen wijzigt blijft in deze browser ingelogd
    return user_list()


@app.delete("/api/users/{name}")
def users_delete(name: str, request: Request, actor: str = Depends(admin)):
    same_origin(request)
    if name == APP_USER:
        raise HTTPException(409, "Het hoofdaccount kan hier niet gewijzigd of verwijderd worden")
    if name == actor:
        raise HTTPException(409, "Je kunt je eigen account niet verwijderen of je eigen rechten wijzigen")
    with users_lock:
        everyone = dict(users_state())
        if name not in everyone:
            raise HTTPException(404, "Deze gebruiker bestaat niet")
        del everyone[name]
        try:
            save_users(everyone)
            state.change(lambda d: (d.get("user_settings") or {}).pop(name, None))
            wa_forget(name)
        except OSError:
            raise HTTPException(500, "De gebruikers konden niet bewaard worden")
    return user_list()


# ---------------------------------------------------------------- inloggen met SSO
# Naast het eigen wachtwoord kan de beheerder drie manieren aanzetten (menu, Gebruikers, SSO instellen):
#  - OpenID Connect: Microsoft Entra ID (Azure), Google, Authentik, Keycloak en dergelijke. Code flow met PKCE. Het
#    id-token komt rechtstreeks van de tokenserver (certificaat gecontroleerd) en wordt bovendien op handtekening,
#    uitgever, doelgroep, geldigheid en nonce gecontroleerd.
#  - Cloudflare Access: wie de tool via Cloudflare opent heeft daar al ingelogd; Cloudflare zet dan een ondertekend
#    token in elk verzoek. De tool controleert het met de openbare sleutels van het eigen Cloudflare-team.
#  - Een Proxmox-account: Proxmox controleert zelf gebruikersnaam en wachtwoord (POST /access/ticket); de tool
#    vergeet het ticket meteen weer.
# Alleen wie in de tool aan zo'n inlog is gekoppeld komt binnen, met de rollen van die gebruiker. Er worden nooit
# vanzelf gebruikers aangemaakt. Het client secret staat leesbaar in sso.json (de tool moet het meesturen); dat bestand
# is alleen voor de tool leesbaar en het secret gaat nooit terug naar de pagina.
SSO_FILE = STATE_DIR / "sso.json"
SSO_METHODS = ("oidc", "cloudflare", "proxmox")
OIDC_PROVIDERS = {"microsoft": "Microsoft", "google": "Google", "authentik": "Authentik", "keycloak": "Keycloak", "other": "SSO"}
PVE_USERID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}@[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
PVE_REALM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
CF_TEAM_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
CF_AUD_RE = re.compile(r"^[0-9a-f]{64}$")
PUBLIC_URL_RE = re.compile(r"^https://[A-Za-z0-9]([A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?(:\d{1,5})?$")
OIDC_SECRET_RE = re.compile(r"^[\x21-\x7e]{1,500}$")
OIDC_ID_RE = re.compile(r"^[\x21-\x7e]{1,200}$")
SSO_LABEL_RE = re.compile(r"^[^\x00-\x1f\x7f<>\"&]{1,40}$")
OIDC_COOKIE, NOSSO_COOKIE = "maintool_oidc", "maintool_nosso"
_sso = {"stamp": None, "data": {}}
sso_lock = threading.Lock()


class SSOError(Exception):
    """Iets bij een SSO-dienst klopt niet of is onbereikbaar; de tekst is een korte reden voor het logboek."""


def sso_state() -> dict:
    """Wat in sso.json staat; wordt opnieuw gelezen zodra het bestand verandert."""
    try:
        info = SSO_FILE.stat()
        stamp = (info.st_mtime_ns, info.st_size)
    except OSError:
        stamp = None
    if stamp != _sso["stamp"]:
        data = {}
        if stamp:
            try:
                loaded = json.loads(SSO_FILE.read_text(encoding="utf-8"))
                data = loaded if isinstance(loaded, dict) else {}
            except (OSError, ValueError):
                pass
        _sso.update(stamp=stamp, data=data)
    return _sso["data"]


def save_sso(data: dict):
    tmp = SSO_FILE.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json.dumps(data))
    os.replace(tmp, SSO_FILE)


def sso_conf(method: str) -> dict:
    block = sso_state().get(method)
    return dict(block) if isinstance(block, dict) else {}


def sso_on(method: str) -> bool:
    """Staat deze manier aan en is ze volledig ingesteld?"""
    c = sso_conf(method)
    if c.get("enabled") is not True:
        return False
    if method == "oidc":
        return all(isinstance(c.get(k), str) and c[k] for k in ("issuer", "client_id", "client_secret", "public_url"))
    if method == "cloudflare":
        return bool(CF_TEAM_RE.match(str(c.get("team") or "")) and CF_AUD_RE.match(str(c.get("aud") or "")))
    return bool(sso_realms())


def sso_realms() -> list:
    realms = sso_conf("proxmox").get("realms")
    return [r for r in realms if isinstance(r, str) and PVE_REALM_RE.match(r)][:20] if isinstance(realms, list) else []


def clean_link(method: str, value) -> str | None:
    """Een koppeling netjes gemaakt: een mailadres (OpenID, Cloudflare) of gebruiker@realm (Proxmox). "" is geen
    koppeling; None als het niet klopt."""
    value = str(value or "").strip()
    if not value:
        return ""
    if method in ("oidc", "cloudflare"):
        value = value.lower()
        return value if EMAIL_RE.match(value) else None
    return value if PVE_USERID_RE.match(value) else None


def stored_links(raw) -> dict:
    """De koppelingen zoals ze bewaard zijn (alleen wat klopt), plus het vastgelegde account bij de OpenID-provider."""
    raw = raw if isinstance(raw, dict) else {}
    out = {m: raw[m] for m in SSO_METHODS if isinstance(raw.get(m), str) and raw[m] and clean_link(m, raw[m]) == raw[m]}
    if out.get("oidc") and isinstance(raw.get("oidc_sub"), str) and 0 < len(raw["oidc_sub"]) <= 600:
        out["oidc_sub"] = raw["oidc_sub"]
    return out


def links_of(name: str) -> dict:
    """De SSO-koppelingen van een gebruiker. Die van het hoofdaccount staan in sso.json, de rest in users.json."""
    if name == APP_USER:
        return stored_links(sso_state().get("builtin"))
    return dict((users_state().get(name) or {}).get("sso") or {})


def find_linked(method: str, value) -> str | None:
    """De gebruiker die aan dit account is gekoppeld; None als niemand (of, wat niet hoort te kunnen, meer dan één)."""
    value = clean_link(method, value)
    if not value:
        return None
    hits = [n for n in [APP_USER, *sorted(users_state())] if links_of(n).get(method) == value]
    return hits[0] if len(hits) == 1 else None


def bind_oidc_sub(name: str, key: str) -> bool:
    """Legt bij de eerste inlog via OpenID vast welk account bij de provider bij deze gebruiker hoort (uitgever en
    sub). Daarna komt alleen dat account binnen, ook als een ander account bij de provider later hetzelfde mailadres
    laat zien. Verandert de beheerder het gekoppelde adres, dan begint dit opnieuw."""
    if name == APP_USER:
        with sso_lock:
            data = dict(sso_state())
            links = stored_links(data.get("builtin"))
            if links.get("oidc_sub"):
                return hmac.compare_digest(links["oidc_sub"], key)
            data["builtin"] = {**links, "oidc_sub": key}
            save_sso(data)
            return True
    with users_lock:
        everyone = dict(users_state())
        found = everyone.get(name)
        if not found:
            return False
        links = dict(found.get("sso") or {})
        if links.get("oidc_sub"):
            return hmac.compare_digest(links["oidc_sub"], key)
        everyone[name] = {**found, "sso": {**links, "oidc_sub": key}}
        save_users(everyone)
        return True


def source_of(request) -> str:
    return request.client.host if request.client else "?"


def start_session(response, name: str, remember: bool = False):
    """Geeft deze browser een sessie voor deze gebruiker; met remember (Ingelogd blijven) een die blijft."""
    set_session_cookie(response, name, remember)
    response.delete_cookie(NOSSO_COOKIE, path="/")


# --- ondertekende tokens (JWT). Alleen controleren, nooit maken; RS256 met de openbare sleutels van de dienst, of
# HS256 met het client secret (sommige OpenID-diensten ondertekenen zo).
SHA256_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


class JWTError(Exception):
    pass


def b64url(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def rs256_ok(key: dict, signed: bytes, signature: bytes) -> bool:
    """Controleert een RSA-handtekening (RS256, PKCS#1 v1.5) met een openbare sleutel uit een JWKS. Het hele verwachte
    blok wordt vergeleken, zodat er niets te ontleden en dus niets te misleiden valt. Sleutels onder 2048 bit tellen niet."""
    try:
        n, e = int.from_bytes(b64url(key["n"]), "big"), int.from_bytes(b64url(key["e"]), "big")
    except (KeyError, TypeError, ValueError, AttributeError):
        return False
    size = (n.bit_length() + 7) // 8
    if n.bit_length() < 2048 or e < 3 or e % 2 == 0 or len(signature) != size:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    digest = SHA256_INFO + hashlib.sha256(signed).digest()
    expected = b"\x00\x01" + b"\xff" * (size - len(digest) - 3) + b"\x00" + digest
    return hmac.compare_digest(pow(s, e, n).to_bytes(size, "big"), expected)


def jwt_check(token, keys: list, secret: str | None, issuer: str, audience: str, leeway: int = 60) -> dict:
    """De inhoud van een token als handtekening, uitgever, doelgroep en geldigheid kloppen; anders JWTError. De reden
    "sleutel" betekent: geen passende sleutel, misschien zijn ze net vernieuwd (de aanroeper haalt ze dan opnieuw op)."""
    if not isinstance(token, str) or len(token) > 16384 or token.count(".") != 2:
        raise JWTError("vorm")
    h, p, s = token.split(".")
    try:
        header, claims, signature = json.loads(b64url(h)), json.loads(b64url(p)), b64url(s)
    except ValueError:
        raise JWTError("vorm")
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise JWTError("vorm")
    signed = f"{h}.{p}".encode()
    if header.get("alg") == "RS256":
        usable = [k for k in keys if isinstance(k, dict) and k.get("kty") == "RSA" and k.get("use", "sig") == "sig"
                  and k.get("alg", "RS256") == "RS256"]
        if "kid" in header:
            usable = [k for k in usable if k.get("kid") == header["kid"]]
        elif len(usable) != 1:
            usable = []
        if not usable:
            raise JWTError("sleutel")
        if not any(rs256_ok(k, signed, signature) for k in usable):
            raise JWTError("handtekening")
    elif header.get("alg") == "HS256" and secret:
        if not hmac.compare_digest(hmac.new(secret.encode(), signed, hashlib.sha256).digest(), signature):
            raise JWTError("handtekening")
    else:
        raise JWTError("ondertekening")
    now = time.time()
    if claims.get("iss") != issuer:
        raise JWTError("uitgever")
    aud = claims.get("aud")
    if audience not in (aud if isinstance(aud, list) else [aud]):
        raise JWTError("doelgroep")
    number = lambda v: isinstance(v, (int, float)) and not isinstance(v, bool)  # noqa: E731
    if not number(claims.get("exp")) or claims["exp"] < now - leeway:
        raise JWTError("verlopen")
    for key in ("nbf", "iat"):
        if number(claims.get(key)) and claims[key] > now + leeway:
            raise JWTError("nog niet geldig")
    return claims


def fetch_json(url: str, data: dict | None = None, auth=None) -> dict:
    """JSON van een SSO-dienst: alleen https, certificaat gecontroleerd, geen doorverwijzingen, hooguit 1 MB."""
    if urllib.parse.urlsplit(url).scheme != "https":
        raise SSOError("geen https")
    try:
        r = (requests.post if data is not None else requests.get)(
            url, data=data, auth=auth, timeout=10, allow_redirects=False, stream=True, headers={"Accept": "application/json"})
        body = r.raw.read(1_000_001, decode_content=True)
    except requests.RequestException as err:
        raise SSOError(f"onbereikbaar ({err.__class__.__name__})")
    if len(body) > 1_000_000:
        raise SSOError("antwoord te groot")
    try:
        out = json.loads(body)
    except ValueError:
        raise SSOError(f"geen JSON (HTTP {r.status_code})")
    if r.status_code != 200 or not isinstance(out, dict):
        raise SSOError(f"HTTP {r.status_code} {str(out.get('error') if isinstance(out, dict) else '')[:60]}".strip())
    return out


_jwks, _discovery = {}, {}


def jwks(url: str, force: bool = False) -> list:
    """De openbare sleutels van een dienst; een uur bewaard. force haalt ze opnieuw, maar hooguit eens per minuut."""
    hit = _jwks.get(url)
    if hit and time.time() - hit[0] < (60 if force else 3600):
        return hit[1]
    keys = [k for k in (fetch_json(url).get("keys") or []) if isinstance(k, dict)][:50]
    _jwks[url] = (time.time(), keys)
    return keys


def verified(token, keys_url: str, secret: str | None, issuer: str, audience: str) -> dict:
    for force in (False, True):
        try:
            return jwt_check(token, jwks(keys_url, force), secret, issuer, audience)
        except JWTError as err:
            if str(err) != "sleutel" or force:
                raise


def oidc_discovery(issuer: str, force: bool = False) -> dict:
    """De openbare instellingen van een OpenID-dienst (.well-known/openid-configuration); een uur bewaard."""
    hit = _discovery.get(issuer)
    if hit and not force and time.time() - hit[0] < 3600:
        return hit[1]
    d = fetch_json(issuer.rstrip("/") + "/.well-known/openid-configuration")
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not (isinstance(d.get(key), str) and d[key].startswith("https://")):
            raise SSOError(f"{key} ontbreekt")
    if not isinstance(d.get("issuer"), str) or d["issuer"].rstrip("/") != issuer.rstrip("/"):
        raise SSOError("andere uitgever")
    _discovery[issuer] = (time.time(), d)
    return d


def oidc_redirect_uri(c: dict) -> str:
    return str(c.get("public_url") or "").rstrip("/") + "/api/sso/oidc/callback"


def oidc_exchange(c: dict, d: dict, code: str, verifier: str, nonce: str) -> dict:
    """Ruilt de code in bij de tokenserver en geeft de gecontroleerde inhoud van het id-token terug."""
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": oidc_redirect_uri(c), "code_verifier": verifier,
            "client_id": c["client_id"]}
    methods = d.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"]
    if "client_secret_post" in methods:
        reply = fetch_json(d["token_endpoint"], data={**form, "client_secret": c["client_secret"]})
    else:
        reply = fetch_json(d["token_endpoint"], data=form, auth=(c["client_id"], c["client_secret"]))
    try:
        claims = verified(reply.get("id_token"), d["jwks_uri"], c["client_secret"], d["issuer"], c["client_id"])
    except JWTError as err:
        raise SSOError(f"id-token: {err}")
    if not hmac.compare_digest(str(claims.get("nonce") or ""), nonce):
        raise SSOError("id-token: nonce")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise SSOError("id-token: sub")
    aud = claims.get("aud")
    if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != c["client_id"]:
        raise SSOError("id-token: azp")
    return claims


def oidc_email(c: dict, claims: dict) -> str | None:
    """Het mailadres waarmee de gebruiker wordt opgezocht. Een adres dat de dienst zelf onbevestigd noemt telt niet.
    Microsoft geeft het adres niet altijd als 'email' mee; dan geldt de inlognaam (UPN) van de eigen tenant."""
    if str(claims.get("email_verified")).lower() == "false":
        return None
    email = claims.get("email")
    if not (isinstance(email, str) and EMAIL_RE.match(email)) and c.get("provider") == "microsoft":
        email = claims.get("preferred_username")
    return email.lower() if isinstance(email, str) and EMAIL_RE.match(email) else None


def cf_issuer(team: str) -> str:
    return f"https://{team}.cloudflareaccess.com"


def cloudflare_user(request) -> str | None:
    """De gekoppelde gebruiker bij het Cloudflare Access-token in dit verzoek; None als er geen geldig token is of
    niemand aan dat adres is gekoppeld. Een ongeldig token telt als mislukte inlogpoging."""
    if not sso_on("cloudflare"):
        return None
    token = request.headers.get("cf-access-jwt-assertion") or request.cookies.get("CF_Authorization")
    if not token:
        return None
    source = source_of(request)
    if login_guard.blocked(source):
        return None
    c = sso_conf("cloudflare")
    issuer = cf_issuer(c["team"])
    try:
        claims = verified(token, issuer + "/cdn-cgi/access/certs", None, issuer, c["aud"])
    except (JWTError, SSOError):
        login_guard.failed(source)
        return None
    return find_linked("cloudflare", claims.get("email")) if isinstance(claims.get("email"), str) else None


def pve_ticket(userid: str, password: str, **extra) -> dict | None:
    """Laat Proxmox zelf een gebruikersnaam en wachtwoord controleren. Geeft het antwoord terug (het ticket wordt niet
    bewaard of gebruikt), None bij een verkeerd wachtwoord. Elke node wordt met het certificaat van het cluster
    gecontroleerd, zoals bij de gewone verbinding."""
    session = requests.Session()
    session.verify = VERIFY
    if CA_FILE:
        session.mount("https://", ClusterCAAdapter(CA_FILE))
    hosts = ([pve.host] if pve.host else []) + [h for h in pve.hosts if h != pve.host]
    for host in hosts[:8]:
        address = f"[{host}]" if ":" in host else host
        try:
            r = session.post(f"https://{address}:8006/api2/json/access/ticket", data={"username": userid, "password": password, **extra},
                             timeout=10, allow_redirects=False)
        except requests.RequestException:
            continue
        if r.status_code == 401:
            return None
        try:
            data = (r.json() or {}).get("data")
        except ValueError:
            data = None
        if r.status_code != 200 or not isinstance(data, dict):
            raise HTTPException(502, "Proxmox gaf geen bruikbaar antwoord bij het controleren van het account")
        return data
    raise HTTPException(503, "Geen enkele Proxmox-node bereikbaar om het account te controleren")


def proxmox_login(body, source: str) -> str:
    """Inloggen met een Proxmox-account. Proxmox wordt alleen gevraagd als het account in de tool aan een gebruiker
    is gekoppeld; zo is de tool geen loket om wachtwoorden van andere Proxmox-accounts uit te proberen."""
    if not sso_on("proxmox"):
        raise HTTPException(400, "Inloggen met een Proxmox-account staat uit")
    realm, user = (body.realm or "").strip(), body.username.strip()
    userid = f"{user}@{realm}"
    name = find_linked("proxmox", userid) if realm in sso_realms() and PVE_USERID_RE.match(userid) else None
    if not name or not body.password:
        login_guard.failed(source)
        time.sleep(0.2 + secrets.randbelow(300) / 1000)   # ongeveer zo lang als een echte controle bij Proxmox duurt
        raise HTTPException(401, "Gebruikersnaam of wachtwoord klopt niet")
    data = pve_ticket(userid, body.password)
    if data is None:
        login_guard.failed(source)
        raise HTTPException(401, "Gebruikersnaam of wachtwoord klopt niet")
    if data.get("NeedTFA"):
        raise HTTPException(401, "Dit Proxmox-account gebruikt tweestapsverificatie; daarmee kan de tool nog niet inloggen")
    if find_linked("proxmox", str(data.get("username") or "")) != name:
        login_guard.failed(source)
        raise HTTPException(401, "Gebruikersnaam of wachtwoord klopt niet")
    return name


def proxmox_realms(api) -> list:
    return sorted(({"realm": r["realm"], "type": str(r.get("type") or ""), "comment": str(r.get("comment") or "")[:60]}
                   for r in api.access.domains.get() if isinstance(r.get("realm"), str) and PVE_REALM_RE.match(r["realm"])),
                  key=lambda r: r["realm"])[:20]


# --- de inlogpagina en de terugkeer van de OpenID-dienst
@app.get("/api/sso/options")
def sso_options():
    """Welke inlogknoppen de inlogpagina toont. Openbaar: er staat niets geheims in."""
    o = sso_conf("oidc")
    return {"oidc": {"label": o.get("label") or OIDC_PROVIDERS.get(o.get("provider"), "SSO"), "provider": o.get("provider", "other"),
                     "start": o["public_url"].rstrip("/") + "/api/sso/oidc/start"} if sso_on("oidc") else None,
            "cloudflare": sso_on("cloudflare"),
            "proxmox": {"realms": sso_realms()} if sso_on("proxmox") else None,
            "remember": {"allowed": session_policy()["remember"], "days": session_policy()["remember_days"]},
            "webauthn": any(u["keys"] for u in wa_state().values())}


@app.get("/api/sso/oidc/start")
def oidc_start(request: Request, then: str = "", remember: int = 0):
    if not sso_on("oidc"):
        return RedirectResponse("/login?sso=off", status_code=303)
    c = sso_conf("oidc")
    if request.headers.get("host") != urllib.parse.urlsplit(c["public_url"]).netloc:
        # de terugkeer komt op het openbare adres binnen; het cookie met de controlegegevens moet daar dus ook staan
        query = urllib.parse.urlencode({k: v for k, v in (("then", "sxy" if then == "sxy" else ""), ("remember", "1" if remember else "")) if v})
        return RedirectResponse(c["public_url"].rstrip("/") + "/api/sso/oidc/start" + ("?" + query if query else ""), status_code=303)
    try:
        d = oidc_discovery(c["issuer"])
    except SSOError:
        return RedirectResponse("/login?sso=down", status_code=303)
    verifier = secrets.token_urlsafe(48)
    st = {"s": secrets.token_urlsafe(24), "n": secrets.token_urlsafe(24), "v": verifier, "t": int(time.time()), "x": "sxy" if then == "sxy" else "",
          "k": 1 if remember else 0}   # k: Ingelogd blijven
    payload = base64.urlsafe_b64encode(json.dumps(st).encode()).decode().rstrip("=")
    query = urllib.parse.urlencode({
        "response_type": "code", "client_id": c["client_id"], "redirect_uri": oidc_redirect_uri(c), "scope": "openid email profile",
        "state": st["s"], "nonce": st["n"], "code_challenge_method": "S256",
        "code_challenge": base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")})
    response = RedirectResponse(d["authorization_endpoint"] + ("&" if "?" in d["authorization_endpoint"] else "?") + query, status_code=303)
    response.set_cookie(OIDC_COOKIE, f"{payload}.{sign('oidc:' + payload)}", max_age=600, path="/api/sso/oidc",
                        httponly=True, secure=True, samesite="lax")
    return response


@app.get("/api/sso/oidc/callback")
def oidc_callback(request: Request):
    """Hier komt de browser terug van de OpenID-dienst. Bij elke fout gaat hij naar de inlogpagina met een vaste
    foutcode (nooit tekst van buiten)."""
    q, source = request.query_params, source_of(request)

    def fail(code: str, count: bool = True):
        if count:
            login_guard.failed(source)
        response = RedirectResponse(f"/login?sso={code}", status_code=303)
        response.delete_cookie(OIDC_COOKIE, path="/api/sso/oidc")
        return response
    if login_guard.blocked(source):
        return fail("blocked", False)
    if not sso_on("oidc"):
        return fail("off", False)
    if q.get("error"):
        return fail("denied", False)
    payload, _, signature = (request.cookies.get(OIDC_COOKIE) or "").partition(".")
    try:
        st = json.loads(b64url(payload)) if signature and hmac.compare_digest(signature, sign("oidc:" + payload)) else None
    except ValueError:
        st = None
    if (not isinstance(st, dict) or not isinstance(st.get("t"), int) or time.time() - st["t"] > 600
            or not hmac.compare_digest(str(st.get("s") or ""), q.get("state") or "")):
        return fail("expired")
    code = q.get("code") or ""
    if not code or len(code) > 4096:
        return fail("denied")
    c = sso_conf("oidc")
    try:
        claims = oidc_exchange(c, oidc_discovery(c["issuer"]), code, str(st.get("v")), str(st.get("n")))
    except SSOError:
        return fail("invalid")
    email = oidc_email(c, claims)
    name = find_linked("oidc", email) if email else None
    if not name:
        return fail("unknown" if email else "noemail")
    if not bind_oidc_sub(name, f"{claims['iss']}|{claims['sub']}"):
        return fail("mismatch")
    login_guard.succeeded(source)
    response = RedirectResponse("/#sxy" if st.get("x") == "sxy" else "/", status_code=303)
    response.delete_cookie(OIDC_COOKIE, path="/api/sso/oidc")
    start_session(response, name, st.get("k") == 1)
    return response


@app.post("/api/sso/cloudflare")
def cloudflare_login(request: Request, response: Response, remember: int = 0):
    """De knop "Inloggen met Cloudflare Access" op de inlogpagina (na uitloggen gaat dat niet meer vanzelf)."""
    if not sso_on("cloudflare"):
        raise HTTPException(400, "Inloggen met Cloudflare Access staat uit")
    if login_guard.blocked(source_of(request)):
        raise HTTPException(429, "Te veel mislukte pogingen. Probeer het over tien minuten opnieuw.")
    name = cloudflare_user(request)
    if not name:
        raise HTTPException(401, "Geen geldige inlog van Cloudflare Access gevonden. Open de tool via je Cloudflare-adres; is dat al zo, dan is je account niet aan een gebruiker gekoppeld.")
    start_session(response, name, bool(remember))
    return {"ok": True}


# --- instellen (alleen beheerders)
class OidcIn(BaseModel):
    enabled: bool
    provider: str = Field("other", max_length=12)
    label: str | None = Field(None, max_length=60)
    issuer: str = Field("", max_length=300)
    client_id: str = Field("", max_length=200)
    client_secret: str | None = Field(None, max_length=600)
    public_url: str = Field("", max_length=260)


class CloudflareIn(BaseModel):
    enabled: bool
    team: str = Field("", max_length=120)
    aud: str = Field("", max_length=80)


class ProxmoxSSOIn(BaseModel):
    enabled: bool
    realms: list[str] = Field(default_factory=list, max_length=20)


def sso_view(request: Request) -> dict:
    """Voor het instelvenster. Het client secret gaat nooit terug naar de pagina, alleen of er een is."""
    o, cf = sso_conf("oidc"), sso_conf("cloudflare")
    try:
        realms = pve.run(proxmox_realms)
    except HTTPException:
        realms = []
    return {"oidc": {"enabled": o.get("enabled") is True, "ready": sso_on("oidc"), "provider": o.get("provider") or "microsoft",
                     "label": o.get("label") or "", "issuer": o.get("issuer") or "", "client_id": o.get("client_id") or "",
                     "secret_set": bool(o.get("client_secret")), "public_url": o.get("public_url") or "",
                     "redirect_uri": oidc_redirect_uri(o) if o.get("public_url") else ""},
            "cloudflare": {"enabled": cf.get("enabled") is True, "ready": sso_on("cloudflare"), "team": cf.get("team") or "", "aud": cf.get("aud") or ""},
            "proxmox": {"enabled": sso_conf("proxmox").get("enabled") is True, "ready": sso_on("proxmox"),
                        "realms": sso_realms() if "realms" in sso_conf("proxmox") else ["pam", "pve"], "available": realms},
            "here": "https://" + str(request.headers.get("host") or "")}


def sso_store(method: str, block: dict):
    with sso_lock:
        data = dict(sso_state())
        data[method] = block
        try:
            save_sso(data)
        except OSError:
            raise HTTPException(500, "De SSO-instellingen konden niet bewaard worden")


@app.get("/api/sso")
def sso_get(request: Request, _: str = Depends(admin)):
    return sso_view(request)


@app.put("/api/sso/oidc")
def sso_oidc_put(body: OidcIn, request: Request, _: str = Depends(admin)):
    """Bewaart de OpenID-instellingen. Bij aanzetten haalt de tool eerst de openbare instellingen van de dienst op;
    lukt dat niet of klopt de uitgever niet, dan wordt er niets bewaard. Een bewaard client secret blijft alleen
    gelden als de uitgever en de client-ID gelijk blijven."""
    same_origin(request)
    current = sso_conf("oidc")
    if not body.enabled:
        sso_store("oidc", {**current, "enabled": False})
        return sso_view(request)
    provider = body.provider if body.provider in OIDC_PROVIDERS else None
    if not provider:
        raise HTTPException(400, "Onbekende soort SSO-dienst")
    label = (body.label or "").strip() or OIDC_PROVIDERS[provider]
    if not SSO_LABEL_RE.match(label):
        raise HTTPException(400, "Ongeldige naam op de knop: hooguit 40 tekens, zonder < > \" &")
    issuer = body.issuer.strip()
    if not issuer.startswith("https://") or any(ch.isspace() for ch in issuer) or "{" in issuer or "}" in issuer:
        raise HTTPException(400, "Vul bij Uitgever het volledige https-adres in, bij Microsoft met je eigen tenant-ID (niet 'common')")
    client_id = body.client_id.strip()
    if not OIDC_ID_RE.match(client_id):
        raise HTTPException(400, "Ongeldige client-ID")
    public_url = body.public_url.strip().rstrip("/")
    if not PUBLIC_URL_RE.match(public_url):
        raise HTTPException(400, "Vul bij Adres van de tool het https-adres in waarop je de tool opent, zonder pad, bijvoorbeeld https://maintool.voorbeeld.nl")
    secret = (body.client_secret or "").strip()
    if secret:
        if not OIDC_SECRET_RE.match(secret):
            raise HTTPException(400, "Ongeldig client secret")
    elif current.get("client_secret") and current.get("issuer", "").rstrip("/") == issuer.rstrip("/") and current.get("client_id") == client_id:
        secret = current["client_secret"]
    else:
        raise HTTPException(400, "Vul het client secret in")
    try:
        d = oidc_discovery(issuer, force=True)
    except SSOError as err:
        raise HTTPException(502, f"De SSO-dienst gaf geen bruikbare instellingen ({err}); controleer het adres bij Uitgever. Er is niets bewaard.")
    sso_store("oidc", {"enabled": True, "provider": provider, "label": label, "issuer": d["issuer"], "client_id": client_id,
                       "client_secret": secret, "public_url": public_url})
    return sso_view(request)


@app.put("/api/sso/cloudflare")
def sso_cloudflare_put(body: CloudflareIn, request: Request, _: str = Depends(admin)):
    """Bewaart de Cloudflare Access-instellingen; bij aanzetten moeten de openbare sleutels van het team op te halen zijn."""
    same_origin(request)
    current = sso_conf("cloudflare")
    if not body.enabled:
        sso_store("cloudflare", {**current, "enabled": False})
        return sso_view(request)
    team = body.team.strip().lower().removeprefix("https://").split("/")[0].removesuffix(".cloudflareaccess.com")
    if not CF_TEAM_RE.match(team):
        raise HTTPException(400, "Ongeldige teamnaam; dat is het eerste deel van jouwteam.cloudflareaccess.com")
    aud = body.aud.strip().lower()
    if not CF_AUD_RE.match(aud):
        raise HTTPException(400, "Ongeldige Application Audience (AUD) Tag; die bestaat uit 64 tekens 0-9 en a-f")
    try:
        keys = jwks(cf_issuer(team) + "/cdn-cgi/access/certs", force=True)
    except SSOError as err:
        raise HTTPException(502, f"De sleutels van dit Cloudflare-team zijn niet op te halen ({err}); er is niets bewaard")
    if not any(k.get("kty") == "RSA" for k in keys):
        raise HTTPException(502, "De sleutels van dit Cloudflare-team zijn niet op te halen (geen sleutels); er is niets bewaard")
    sso_store("cloudflare", {"enabled": True, "team": team, "aud": aud})
    return sso_view(request)


@app.put("/api/sso/proxmox")
def sso_proxmox_put(body: ProxmoxSSOIn, request: Request, _: str = Depends(admin)):
    same_origin(request)
    realms = sorted({r.strip() for r in body.realms if isinstance(r, str) and r.strip()})
    if body.enabled:
        known = {r["realm"] for r in pve.run(proxmox_realms)}
        if not realms or any(r not in known for r in realms):
            raise HTTPException(400, "Kies een of meer realms die in Proxmox bestaan")
    elif any(not PVE_REALM_RE.match(r) for r in realms):
        raise HTTPException(400, "Kies een of meer realms die in Proxmox bestaan")
    sso_store("proxmox", {"enabled": body.enabled, "realms": realms})
    return sso_view(request)


# ---------------------------------------------------------------- via Cloudflare: alleen bekijken
# Via Cloudflare Zero Trust is de tool trager en kan een verbinding halverwege wegvallen. Komt een verzoek via
# Cloudflare binnen (Cloudflare zet dan altijd Cf-Ray), dan vraagt de pagina of je alleen wilt kijken; de beheerder
# kan ook instellen dat het daar altijd alleen kijken is. Wie alleen kijkt kan niets veranderen: de bewakers weigeren
# het, net als bij een gebruiker zonder rollen. In het eigen netwerk (zonder Cloudflare) geldt het niet.
VIEW_COOKIE = "maintool_viewonly"
CF_MODES = ("ask", "readonly", "off")
VIEW_MSG = {"policy": "Via Cloudflare kun je de tool alleen bekijken; wijzigen doe je via het adres in je eigen netwerk",
            "chosen": "Je bekijkt de tool nu alleen; kies bovenaan Volledig gebruiken om iets te wijzigen"}


def via_cloudflare(request) -> bool:
    headers = getattr(request, "headers", None) or {}
    return bool(headers.get("cf-ray") or headers.get("cf-connecting-ip"))


def cf_mode() -> str:
    mode = (state.load().get("policy") or {}).get("cloudflare")
    return mode if mode in CF_MODES else "ask"


def view_only(request) -> str | None:
    """Waarom dit verzoek alleen mag kijken: "policy" (zo ingesteld) of "chosen" (zelf gekozen); None als het mag."""
    if request is None or not via_cloudflare(request):
        return None
    mode = cf_mode()
    if mode == "readonly":
        return "policy"
    if mode == "ask" and request.cookies.get(VIEW_COOKIE) == "1":
        return "chosen"
    return None


def refuse_view_only(request):
    why = view_only(request)
    if why:
        raise HTTPException(403, VIEW_MSG[why])


class ViewIn(BaseModel):
    on: bool


@app.post("/api/viewonly")
def view_choice(body: ViewIn, request: Request, response: Response, _: str = Depends(auth)):
    """De keuze in de pop-up (of bovenaan de pagina): via Cloudflare alleen bekijken of volledig gebruiken. Geldt tot
    de browser wordt gesloten; daarna vraagt de pagina het opnieuw."""
    same_origin(request)
    if not via_cloudflare(request):
        raise HTTPException(400, "Dit geldt alleen als je de tool via Cloudflare opent")
    if not body.on and cf_mode() == "readonly":
        raise HTTPException(403, VIEW_MSG["policy"])
    response.set_cookie(VIEW_COOKIE, "1" if body.on else "0", path="/", httponly=True, secure=True, samesite="lax")
    return {"view_only": body.on}


@app.get("/api/overview")
def overview(_: str = Depends(auth)):
    def f(api):
        nodes = api.cluster.resources.get(type="node")
        guests = api.cluster.resources.get(type="vm")
        storages = api.cluster.resources.get(type="storage")
        up = [n["node"] for n in nodes if n.get("status") == "online"]
        online = next((n for n in up if not node_trouble.skip(n)), None)
        # De container waarin deze tool draait heeft dezelfde hostnaam als de CT in Proxmox.
        me = next((g["vmid"] for g in guests if g.get("type") == "lxc" and g.get("name") == socket.gethostname()), None)
        snapshots = dict(zip((g["vmid"] for g in guests), POOL.map(lambda g: snapshot_count(api, g), guests)))
        return {
            "self_vmid": me,
            "snapshots": snapshots,
            "ceph_osds": on_node(online, lambda: ceph_osds(api, online), []) if online else [],
            "node_trouble": trouble_view(api, up),
            "tag_style": tag_colors(api),
            "connected_via": pve.host,
            "nodes": sorted(nodes, key=lambda n: n.get("node", "")),
            "guests": sorted(guests, key=lambda g: g.get("vmid", 0)),
            "storages": sorted(storages, key=lambda s: (s.get("node", ""), s.get("storage", ""))),
        }
    data = pve.run(f)
    data["issues"] = issues.get(wait=issues.at == 0)   # voor de kleur van de tabbladen; zie Issues
    return data


TAG_STYLE = {"at": -1e9, "map": {}}
HEX6_RE = re.compile(r"^[0-9A-Fa-f]{6}$")


def tag_colors(api) -> dict:
    """De kleuren die in Proxmox bij labels zijn ingesteld (Datacenter > Options > Tag Style > Color Overrides), als
    {label: [achtergrond, tekst of None]}; hooguit eens per 5 minuten gelezen. Zonder eigen kleur kleurt de pagina een
    label zoals Proxmox zelf dat doet."""
    if time.monotonic() - TAG_STYLE["at"] > 300:
        TAG_STYLE["at"] = time.monotonic()
        try:
            style = parse_options((api.cluster.options.get() or {}).get("tag-style") or "")
            out = {}
            for part in str(style.get("color-map") or "").split(";")[:200]:
                bits = part.split(":")
                if len(bits) >= 2 and TAG_RE.match(bits[0]) and HEX6_RE.match(bits[1]):
                    out[bits[0].lower()] = [bits[1].upper(), bits[2].upper() if len(bits) > 2 and HEX6_RE.match(bits[2]) else None]
            TAG_STYLE["map"] = out
        except (ResourceException, AttributeError, TypeError):
            pass
    return TAG_STYLE["map"]


def trouble_view(api, up) -> dict:
    """De online nodes die via de API niet antwoorden (zie NodeTrouble), met het adres waaronder het cluster ze kent."""
    trouble = {n: v for n, v in node_trouble.current().items() if n in up}
    if trouble:
        try:
            ips = node_ips(api)
        except ResourceException:
            ips = {}
        for n, v in trouble.items():
            v["ip"] = ips.get(n)
    return trouble


def node_live(api, node):
    """Actuele cijfers van één node en zijn guests, rechtstreeks van de node; None als die niet antwoordt.

    cluster/resources (zie overview) wordt door Proxmox maar eens per ~10 s bijgewerkt.
    """
    try:
        found = on_node(node, lambda: (api.nodes(node).status.get(), api.nodes(node).lxc.get() + api.nodes(node).qemu.get()))
    except ResourceException:
        return None
    if found is None:
        return None
    status, guests = found
    mem = status.get("memory") or {}
    return {
        "node": node,
        "stats": {"cpu": status.get("cpu"), "mem": mem.get("used"), "maxmem": mem.get("total"),
                  "uptime": status.get("uptime")},
        "guests": {str(g["vmid"]): {k: g.get(k) for k in ("status", "cpu", "mem", "maxmem", "uptime", "netin", "netout", "diskread", "diskwrite")}
                   for g in guests},
    }


@app.get("/api/live")
def live(_: str = Depends(auth)):
    def f(api):
        online = [n["node"] for n in api.nodes.get() if n.get("status") == "online"]
        rows = [r for r in POOL.map(lambda n: node_live(api, n), online) if r]
        return {
            "nodes": {r["node"]: r["stats"] for r in rows},
            "guests": {vmid: g for r in rows for vmid, g in r["guests"].items()},
        }
    data = pve.run(f)
    data["hosts"] = pve.hosts_status()
    return data


def parse_options(text) -> dict:
    """'name=eth0,bridge=vmbr0' -> {'name': 'eth0', 'bridge': 'vmbr0'}; een deel zonder '=' komt onder ''."""
    out = {}
    for part in str(text or "").split(","):
        key, eq, value = part.partition("=")
        out[key if eq else ""] = value if eq else key
    return out


NET_RE = re.compile(r"^net\d+$")
LXC_DISK_RE = re.compile(r"^(rootfs|mp\d+)$")
VM_DISK_RE = re.compile(r"^(scsi|virtio|sata|ide|efidisk|tpmstate)\d+$")
NIC_MODELS = ("virtio", "e1000", "e1000e", "rtl8139", "vmxnet3")


def guest_details(api, node: str, kind: str, vmid: int) -> dict:
    """Wat de uitklapregel van een guest toont. Leest alleen; wat niet op te vragen is blijft gewoon weg."""
    g = guest(api, node, kind, vmid)
    cfg, cur = g.config.get(), g.status.current.get()
    running = cur.get("status") == "running"

    nets, disks = [], []
    for key in sorted(cfg, key=lambda k: (len(k), k)):
        if NET_RE.match(key):
            o = parse_options(cfg[key])
            model = next((m for m in NIC_MODELS if m in o), "")
            nets.append({"key": key, "name": o.get("name") or key, "bridge": o.get("bridge"), "ip": o.get("ip"), "gw": o.get("gw"),
                         "ip6": o.get("ip6"), "mac": o.get("hwaddr") or o.get(model), "vlan": o.get("tag"),
                         "model": model, "firewall": o.get("firewall") == "1", "rate": o.get("rate")})
        elif (LXC_DISK_RE if kind == "lxc" else VM_DISK_RE).match(key):
            o = parse_options(cfg[key])
            volume = o.get("") or o.get("volume") or o.get("file") or ""
            if "media" in o and o["media"] == "cdrom":
                continue
            storage, _, name = volume.partition(":")
            disks.append({"key": key, "storage": storage if name else "", "volume": name or volume, "size": o.get("size"),
                          "mount": o.get("mp") or ("/" if key == "rootfs" else None)})

    ips = []
    if running:
        try:
            if kind == "lxc":
                for i in g.interfaces.get():
                    for addr in (i.get("inet"), i.get("inet6")):
                        if addr and i.get("name") != "lo" and not addr.lower().startswith("fe80"):
                            ips.append({"name": i.get("name"), "addr": addr})
            elif parse_options(cfg.get("agent")).get("", cfg.get("agent")) not in (None, "", "0"):
                for i in (g.agent("network-get-interfaces").get() or {}).get("result") or []:
                    for a in i.get("ip-addresses") or []:
                        addr = a.get("ip-address") or ""
                        if i.get("name") != "lo" and addr and not addr.startswith("127.") and not addr.lower().startswith("fe80"):
                            ips.append({"name": i.get("name"), "addr": f"{addr}/{a.get('prefix')}" if a.get("prefix") is not None else addr})
        except ResourceException:
            pass  # oudere Proxmox-versie, of de guest agent antwoordt niet

    last = None
    try:
        for s in backup_storages(api):
            for f in api.nodes(node).storage(s["storage"]).content.get(content="backup", vmid=vmid):
                if not last or (f.get("ctime") or 0) > last["ctime"]:
                    last = {"ctime": f.get("ctime") or 0, "storage": s["storage"], "size": f.get("size")}
    except ResourceException:
        pass

    ha = cur.get("ha") or {}
    text = lambda key, limit=120: (str(cfg[key])[:limit] if cfg.get(key) not in (None, "") else None)  # noqa: E731
    return {
        "status": cur.get("status"), "uptime": cur.get("uptime"), "ips": ips[:16], "nets": nets[:16], "disks": disks[:32],
        "cores": cfg.get("cores"), "sockets": cfg.get("sockets"), "cpulimit": cfg.get("cpulimit"), "cputype": text("cpu", 60),
        "memory": cfg.get("memory"), "swap": cfg.get("swap"), "balloon": cfg.get("balloon"),
        "disk": cur.get("disk"), "maxdisk": cur.get("maxdisk"),
        "hostname": text("hostname") or text("name"), "ostype": text("ostype", 40), "arch": text("arch", 20),
        "nameserver": text("nameserver"), "searchdomain": text("searchdomain"),
        "onboot": bool(cfg.get("onboot")), "startup": text("startup", 60), "protection": bool(cfg.get("protection")),
        "unprivileged": bool(cfg.get("unprivileged")) if kind == "lxc" else None, "features": text("features", 80),
        "bios": text("bios", 20), "machine": text("machine", 40), "boot": text("boot", 80),
        "agent": (parse_options(cfg.get("agent")).get("", "0") not in ("", "0")) if kind == "qemu" else None,
        "lock": text("lock", 40), "template": bool(cfg.get("template")),
        "tags": tag_list(cfg.get("tags"))[:20],
        "description": text("description", 600),
        "ha": {"managed": bool(ha.get("managed")), "state": ha.get("state"), "group": ha.get("group")},
        "last_backup": last,
    }


@app.get("/api/guest/{node}/{kind}/{vmid}/details")
def details(node: str, kind: str, vmid: int, _: str = Depends(auth)):
    check_target(node, kind, vmid)
    return pve.run(lambda api: guest_details(api, node, kind, vmid))


@app.delete("/api/guest/{node}/{kind}/{vmid}")
def destroy(node: str, kind: str, vmid: int, name: str, request: Request, _: str = Depends(manage_overview)):
    """Verwijdert een guest definitief, met zijn schijven en snapshots. Back-ups op de back-upopslag blijven staan.

    De pagina vraagt eerst om het overtypen van het ID. Hier wordt daarnaast gecontroleerd dat het om precies de
    bedoelde guest gaat (zelfde node, soort en naam als op het scherm), dat hij uit staat, niet beschermd of
    vergrendeld is en niet de tool zelf is."""
    same_origin(request)
    check_target(node, kind, vmid)

    def f(api):
        found = next((g for g in api.cluster.resources.get(type="vm") if g.get("vmid") == vmid), None)
        if not found or found.get("node") != node or found.get("type") != kind:
            raise HTTPException(404, "Deze guest bestaat niet (meer) op deze node")
        if (found.get("name") or "") != name:
            raise HTTPException(409, "De naam komt niet overeen met de guest; er is niets verwijderd")
        if kind == "lxc" and found.get("name") == socket.gethostname():
            raise HTTPException(409, "De tool kan zijn eigen container niet verwijderen")
        if found.get("template"):
            raise HTTPException(409, "Een sjabloon wordt hier niet verwijderd; doe dat in Proxmox zelf")
        if found.get("status") != "stopped":
            raise HTTPException(409, "Zet de guest eerst uit; een draaiende guest wordt niet verwijderd")
        cfg = guest(api, node, kind, vmid).config.get()
        if cfg.get("protection"):
            raise HTTPException(409, "Deze guest is in Proxmox beschermd tegen verwijderen (Protection staat aan)")
        if cfg.get("lock"):
            raise HTTPException(409, f"Deze guest is vergrendeld ({cfg['lock']}); er is niets verwijderd")
        # purge: ook uit HA, back-upschema's en replicatie halen, zodat er geen verwijzingen naar dit ID achterblijven.
        return guest(api, node, kind, vmid).delete(purge=1)

    return {"upid": pve.run(f), "node": node}


@app.post("/api/guest/{node}/{kind}/{vmid}/status/{action}")
def power(node: str, kind: str, vmid: int, action: str, _: str = Depends(manage_overview)):
    check_target(node, kind, vmid)
    if action not in ACTIONS:
        raise HTTPException(400, "Onbekende actie")
    if kind == "lxc" and action != "start" and pve.run(lambda api: ct_busy(api, node, vmid)):
        raise HTTPException(409, BUSY_MSG)
    upid = pve.run(lambda api: guest(api, node, kind, vmid).status(action).post())
    return {"upid": upid, "node": node}


class MigrateIn(BaseModel):
    target: str


@app.post("/api/guest/{node}/{kind}/{vmid}/migrate")
def migrate(node: str, kind: str, vmid: int, body: MigrateIn, _: str = Depends(manage_overview)):
    check_target(node, kind, vmid)
    if not NODE_RE.match(body.target) or body.target == node:
        raise HTTPException(400, "Ongeldige doel-node")

    def f(api):
        if kind == "lxc" and ct_busy(api, node, vmid):
            raise HTTPException(409, BUSY_MSG)
        params = {"target": body.target}
        if guest(api, node, kind, vmid).status.current.get().get("status") == "running":
            # Een VM verhuist live; een CT kan dat niet en wordt afgesloten, verplaatst en weer gestart.
            params["online" if kind == "qemu" else "restart"] = 1
        return guest(api, node, kind, vmid).migrate.post(**params)
    return {"upid": pve.run(f), "node": node}


# ---------------------------------------------------------------- HA (High Availability)
# Een guest in HA wordt door Proxmox bewaakt: valt zijn node uit, dan start HA hem op een andere node, en loopt hij
# vast, dan herstart HA hem. Hier zie je hoe HA ervoor staat, en zet je guests in HA, pas je hun instellingen aan of
# haal je ze eruit. Regels (Proxmox 9) en groepen (Proxmox 8) worden alleen getoond; die stel je in Proxmox zelf in.
HA_SID_RE = re.compile(r"^(vm|ct):([1-9][0-9]{2,8})$")
HA_STATES = ("started", "stopped", "disabled", "ignored")
HA_MAX = 10   # zo vaak mag HA hoogstens herstarten of verhuizen (max_restart, max_relocate)
HA_KIND = {"vm": "qemu", "ct": "lxc"}
HA_POLICIES = ("conditional", "freeze", "failover", "migrate")
HA_LOCAL, HA_LOCAL_TTL = {}, 300   # (node, soort, id) -> (tijd, schijven op lokale opslag); een configuratie verandert zelden


def ha_list(text) -> list:
    """'vm:100,ct:101' (of al een lijst) -> ['vm:100', 'ct:101']."""
    items = text if isinstance(text, list) else str(text or "").split(",")
    return [str(x).strip() for x in items if str(x).strip()][:64]


def ha_word(status) -> str:
    """'pve1 (active, watchdog active, Wed Oct 14 11:27:18 2026)' -> 'active'."""
    m = re.search(r"\(([^,()]+)", str(status or ""))
    return (m.group(1).strip() if m else str(status or ""))[:60]


def shared_storages(api) -> set:
    return {s.get("storage") for s in api.cluster.resources.get(type="storage") if s.get("shared")}


def local_disks(kind: str, cfg: dict, shared: set) -> list:
    """De schijven en cd-roms die niet op gedeelde opslag staan. Met zo'n schijf kan HA de guest wel herstarten op zijn
    eigen node, maar niet op een andere node starten als die van hem uitvalt."""
    out = []
    for key in sorted(cfg, key=lambda k: (len(k), k)):
        if not (LXC_DISK_RE.match(key) if kind == "lxc" else VM_DISK_RE.match(key)):
            continue
        o = parse_options(cfg[key])
        volume = str(o.get("") or o.get("volume") or o.get("file") or "")
        if volume in ("", "none"):
            continue
        if volume.startswith("/") or volume == "cdrom":   # een map, apparaat of cd-speler van de node zelf
            if o.get("shared") not in ("1", "yes", "on", "true"):   # een map met shared=1 is er op elke node
                out.append({"key": key, "storage": volume[:80]})
            continue
        storage = volume.partition(":")[0]
        if storage and storage not in shared:
            out.append({"key": key, "storage": storage})
    return out[:32]


def ha_local(api, node, kind, vmid, shared: set | None = None, fresh: bool = False):
    """local_disks van één guest; None als zijn configuratie niet te lezen is (bijvoorbeeld net verhuisd)."""
    if not (node and kind in KINDS and vmid):
        return None
    key, hit = (node, kind, int(vmid)), HA_LOCAL.get((node, kind, int(vmid)))
    if hit and not fresh and time.time() - hit[0] < HA_LOCAL_TTL:
        return hit[1]
    try:
        found = local_disks(kind, guest(api, node, kind, vmid).config.get(), shared_storages(api) if shared is None else shared)
    except ResourceException:
        return None
    HA_LOCAL[key] = (time.time(), found)
    return found


def own_vmid(guests) -> int | None:
    """De container waarin deze tool draait heeft dezelfde hostnaam als de CT in Proxmox."""
    return next((g["vmid"] for g in guests if g.get("type") == "lxc" and g.get("name") == socket.gethostname()), None)


@app.get("/api/ha")
def ha_info(_: str = Depends(auth)):
    """Hoe HA ervoor staat: de bewaking per node, de guests in HA en de guests die er nog bij kunnen."""
    def f(api):
        resources = api.cluster.ha.resources.get()
        try:
            current = api.cluster.ha.status.current.get()
        except ResourceException:
            current = []
        try:
            rules = api.cluster.ha.rules.get()
        except ResourceException:
            rules = None   # Proxmox 8: nog geen regels
        try:
            groups = api.cluster.ha.groups.get()
        except ResourceException:
            groups = None  # Proxmox 9: de groepen zijn regels geworden
        try:
            opts = (api.cluster.options.get() or {}).get("ha")
        except ResourceException:
            opts = None
        opts = opts if isinstance(opts, dict) else parse_options(opts)
        listed = [g for g in api.cluster.resources.get(type="vm") if isinstance(g.get("vmid"), int)]
        guests, shared = {g["vmid"]: g for g in listed}, shared_storages(api)
        service = {e.get("sid"): e for e in current if e.get("type") == "service"}
        quorum, master, fencing = (next((e for e in current if e.get("type") == kind), None) for kind in ("quorum", "master", "fencing"))
        rule_rows = [{"rule": str(r.get("rule") or "")[:80], "type": r.get("type"), "resources": ha_list(r.get("resources")),
                      "nodes": ha_list(r.get("nodes")), "strict": bool(r.get("strict")), "affinity": r.get("affinity"),
                      "disabled": bool(r.get("disable")), "comment": str(r["comment"])[:200] if r.get("comment") else None}
                     for r in rules or []]
        group_rows = [{"group": str(g.get("group") or "")[:80], "nodes": ha_list(g.get("nodes")), "restricted": bool(g.get("restricted")),
                       "nofailback": bool(g.get("nofailback"))} for g in groups or []]
        rows = []
        for r in resources:
            sid = str(r.get("sid") or "")
            m = HA_SID_RE.match(sid)
            vmid, kind = (int(m.group(2)), HA_KIND[m.group(1)]) if m else (None, None)
            g, s = guests.get(vmid) or {}, service.get(sid) or {}
            node = g.get("node") or s.get("node")
            pick = lambda name: r.get(name) if r.get(name) is not None else s.get(name, 1)  # noqa: E731
            rows.append({
                "sid": sid, "vmid": vmid, "type": kind, "name": g.get("name"), "node": node, "status": g.get("status"),
                "exists": bool(g), "state": r.get("state") or "started", "crm_state": s.get("crm_state") or s.get("state"),
                "max_restart": pick("max_restart"), "max_relocate": pick("max_relocate"),
                "comment": str(r["comment"])[:200] if r.get("comment") else None, "group": r.get("group"),
                "rules": [x["rule"] for x in rule_rows if sid in x["resources"]],
                "local": ha_local(api, node, kind, vmid, shared) if g else None, "digest": r.get("digest")})
        inside = {row["vmid"] for row in rows}
        free = [{"vmid": v, "type": g.get("type"), "name": g.get("name"), "node": g.get("node"), "status": g.get("status")}
                for v, g in sorted(guests.items()) if v not in inside and not g.get("template")]
        policy = opts.get("shutdown_policy")
        return {
            "quorum": {"ok": bool(quorum.get("quorate")), "node": quorum.get("node")} if quorum else None,
            "master": {"node": master.get("node"), "state": ha_word(master.get("status")), "time": master.get("timestamp")} if master else None,
            "fencing": str(fencing.get("armed-state") or ha_word(fencing.get("status")))[:40] if fencing else None,
            "nodes": sorted(({"node": e.get("node"), "state": ha_word(e.get("status")), "watchdog": "watchdog active" in str(e.get("status") or ""),
                              "time": e.get("timestamp")} for e in current if e.get("type") == "lrm"), key=lambda n: str(n["node"])),
            "resources": sorted(rows, key=lambda x: (x["vmid"] or 0, x["sid"])), "free": free,
            "rules": rule_rows if rules is not None else None, "groups": group_rows if groups is not None else None,
            "shutdown_policy": policy if policy in HA_POLICIES else "conditional", "self_vmid": own_vmid(listed),
            "states": list(HA_STATES), "max": HA_MAX,
        }
    return pve.run(f)


@app.get("/api/ha/check/{node}/{kind}/{vmid}")
def ha_check(node: str, kind: str, vmid: int, _: str = Depends(auth)):
    """Welke schijven van deze guest niet op gedeelde opslag staan (voor de waarschuwing bij het toevoegen)."""
    check_target(node, kind, vmid)
    return {"local": pve.run(lambda api: ha_local(api, node, kind, vmid, fresh=True))}


class HaIn(BaseModel):
    sid: str = Field(max_length=20)
    state: str = "started"
    max_restart: int = Field(1, strict=True)
    max_relocate: int = Field(1, strict=True)
    comment: str = Field("", max_length=200)


class HaChange(BaseModel):
    state: str | None = None
    max_restart: int | None = Field(None, strict=True)
    max_relocate: int | None = Field(None, strict=True)
    comment: str | None = Field(None, max_length=200)
    digest: str | None = Field(None, pattern="^[0-9a-f]{40,64}$")   # wat de pagina zag; Proxmox weigert als het intussen veranderde


def ha_values(wanted, max_restart, max_relocate, comment) -> dict:
    """Controleert wat er voor HA is opgegeven; alleen wat is opgegeven komt terug."""
    out = {}
    if wanted is not None:
        if wanted not in HA_STATES:
            raise HTTPException(400, "Onbekende HA-toestand")
        out["state"] = wanted
    for name, value in (("max_restart", max_restart), ("max_relocate", max_relocate)):
        if value is not None:
            if isinstance(value, bool) or not 0 <= value <= HA_MAX:
                raise HTTPException(400, "Herstarten en verhuizen: 0 tot 10 keer")
            out[name] = value
    if comment is not None:
        text = comment.strip()
        if any(ord(c) < 32 or ord(c) == 127 for c in text):
            raise HTTPException(400, "De opmerking mag geen regeleinden of stuurtekens bevatten")
        out["comment"] = text
    return out


def ha_guest(api, sid: str, missing_ok: bool = False):
    """De guest achter een HA-naam ('ct:109'); 404 als hij niet (meer) bestaat, of None met missing_ok."""
    m = HA_SID_RE.match(sid)
    if not m:
        raise HTTPException(400, "Ongeldige HA-naam; verwacht vm:ID of ct:ID")
    found = next((g for g in api.cluster.resources.get(type="vm") if g.get("vmid") == int(m.group(2))), None)
    if not found or found.get("type") != HA_KIND[m.group(1)]:
        if missing_ok:
            return None
        raise HTTPException(404, "Deze guest bestaat niet (meer)")
    return found


def ha_in(api, sid: str) -> bool:
    return any(r.get("sid") == sid for r in api.cluster.ha.resources.get())


def ha_not_self(found: dict, wanted):
    """Laat de tool zichzelf niet via HA uitzetten: daarna is de pagina weg en kan alleen Proxmox hem weer starten."""
    if wanted in ("stopped", "disabled") and found.get("type") == "lxc" and found.get("name") == socket.gethostname():
        raise HTTPException(409, "Dit is de container van de tool zelf; die zet de tool niet via HA uit")


@app.post("/api/ha")
def ha_add(body: HaIn, request: Request, user: str = Depends(manage_overview)):
    """Zet een guest in HA. Let op: met started start HA een guest die uit staat meteen, met stopped zet HA een
    draaiende guest uit. De pagina kiest daarom standaard de toestand waarin de guest nu is."""
    same_origin(request)
    values = ha_values(body.state, body.max_restart, body.max_relocate, body.comment)

    def f(api):
        found = ha_guest(api, body.sid)
        if found.get("template"):
            raise HTTPException(409, "Een sjabloon kan niet in HA")
        if ha_in(api, body.sid):
            raise HTTPException(409, "Deze guest staat al in HA")
        ha_not_self(found, values["state"])
        api.cluster.ha.resources.post(sid=body.sid, **{k: v for k, v in values.items() if k != "comment" or v})
        return found, ha_local(api, found.get("node"), found.get("type"), found["vmid"], fresh=True)
    found, local = pve.run(f)
    state.event("ha", "in HA gezet", node=found.get("node"), target=str(found["vmid"]), name=found.get("name") or "", user=user)
    return {"ok": True, "sid": body.sid, "local": local}


@app.put("/api/ha/{sid}")
def ha_change(sid: str, body: HaChange, request: Request, user: str = Depends(manage_overview)):
    """Past de HA-instellingen van een guest aan: de gewenste toestand, hoe vaak HA mag herstarten en verhuizen, en de
    opmerking (leeg = weg)."""
    same_origin(request)
    values = ha_values(body.state, body.max_restart, body.max_relocate, body.comment)
    if not values:
        raise HTTPException(400, "Er is niets om aan te passen")

    def f(api):
        found = ha_guest(api, sid)
        if not ha_in(api, sid):
            raise HTTPException(404, "Deze guest staat niet (meer) in HA")
        ha_not_self(found, values.get("state"))
        params = dict(values)
        if params.get("comment") == "":
            del params["comment"]
            params["delete"] = "comment"
        if body.digest:
            params["digest"] = body.digest
        api.cluster.ha.resources(sid).put(**params)
        return found
    found = pve.run(f)
    state.event("ha", "HA-instellingen aangepast", node=found.get("node"), target=str(found["vmid"]), name=found.get("name") or "", user=user)
    return {"ok": True, "sid": sid}


@app.delete("/api/ha/{sid}")
def ha_remove(sid: str, request: Request, user: str = Depends(manage_overview)):
    """Haalt een guest uit HA. De guest zelf blijft zoals hij is: aan blijft aan, uit blijft uit. Ook een HA-regel van
    een guest die niet meer bestaat is zo op te ruimen."""
    same_origin(request)

    def f(api):
        found = ha_guest(api, sid, missing_ok=True)
        if not ha_in(api, sid):
            raise HTTPException(404, "Deze guest staat niet (meer) in HA")
        api.cluster.ha.resources(sid).delete()
        return found or {}
    found = pve.run(f)
    state.event("ha", "uit HA gehaald", node=found.get("node"), target=sid.partition(":")[2], name=found.get("name") or "", user=user)
    return {"ok": True, "sid": sid}


# ---------------------------------------------------------------- Proxmox-gebruikers, -groepen en -rechten (tabblad Users)
# Dit gaat over de gebruikers van Proxmox zelf (Datacenter > Permissions), niet over die van deze tool (menu,
# Gebruikers). Alleen voor beheerders van de tool. Drie soorten gebruikers wijzigt de tool niet: root@pam, de
# gebruiker waarmee de tool zelf werkt (PVE_USER) en gebruikers met een naam die de tool niet kent. En een wijziging
# waarna niemand meer volledige beheerrechten heeft (Administrator op /), behalve de tool zelf, wordt geweigerd: dan
# kom je zelf niet meer in Proxmox. Wachtwoorden gaan alleen door naar Proxmox; de tool bewaart en logt ze niet.
PVE_GROUPID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
ACL_PATH_RE = re.compile(r"^/(|vms(/[1-9][0-9]{2,8})?|storage(/[A-Za-z][A-Za-z0-9._-]{0,63})?|nodes(/[A-Za-z0-9][A-Za-z0-9-]{0,62})?"
                         r"|pool/[A-Za-z0-9._-]{1,64}|sdn(/zones(/[A-Za-z0-9]{1,8}(/[A-Za-z0-9]{1,8})?)?)?|access(/groups(/[A-Za-z0-9._-]{1,64})?)?"
                         r"|mapping(/(pci|usb|dir)(/[A-Za-z0-9._-]{1,64})?)?)$")
ROLE_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
FULL_ADMIN = "Administrator"
EXPIRE_RANGE = (946684800, 4102444800)   # 2000 tot 2100, in seconden; 0 = verloopt nooit


def access_list(value) -> list:
    """'a,b' (of al een lijst) -> ['a', 'b']."""
    items = value if isinstance(value, list) else str(value or "").split(",")
    return [str(x).strip() for x in items if str(x).strip()]


def protected_user(userid: str) -> str | None:
    """Waarom de tool deze Proxmox-gebruiker niet wijzigt, of None."""
    if userid == "root@pam":
        return "root@pam wijzigt de tool niet; doe dat in Proxmox zelf"
    if userid == PVE_USER:
        return "Met deze gebruiker werkt de tool zelf; die wijzigt de tool niet"
    if not PVE_USERID_RE.match(userid or ""):
        return "Deze naam kent de tool niet; wijzig deze gebruiker in Proxmox zelf"
    return None


def refuse_protected(userid: str):
    why = protected_user(userid)
    if why:
        raise HTTPException(409, why)


def access_state(api) -> dict:
    """Gebruikers, groepen en rechten zoals Proxmox ze nu heeft."""
    users = {}
    for u in api.access.users.get(full=1):
        uid = str(u.get("userid") or "")
        if uid:
            users[uid] = {"enable": u.get("enable", 1) not in (0, "0", False), "expire": int(u.get("expire") or 0),
                          "groups": set(access_list(u.get("groups"))), "raw": u}
    groups = {}
    for g in api.access.groups.get():
        gid = str(g.get("groupid") or "")
        if gid:
            groups[gid] = {"comment": g.get("comment"), "members": {m for m in access_list(g.get("users")) if m in users}}
    for uid, u in users.items():   # het lidmaatschap staat bij beide; samen is het compleet
        for gid in u["groups"]:
            if gid in groups:
                groups[gid]["members"].add(uid)
    for gid, g in groups.items():
        for uid in g["members"]:
            users[uid]["groups"].add(gid)
    acl = [{"path": a.get("path"), "type": a.get("type"), "ugid": a.get("ugid"), "roleid": a.get("roleid"),
            "propagate": a.get("propagate", 1) not in (0, "0", False)} for a in api.access.acl.get()]
    return {"users": users, "groups": groups, "acl": acl}


def access_copy(st: dict) -> dict:
    return {"users": {k: {**v, "groups": set(v["groups"])} for k, v in st["users"].items()},
            "groups": {k: {**v, "members": set(v["members"])} for k, v in st["groups"].items()},
            "acl": [dict(a) for a in st["acl"]]}


def full_admins(st: dict) -> set:
    """Wie (behalve de tool zelf) nu alles mag in Proxmox: actief, niet verlopen, en Administrator op /. Net als in
    Proxmox wint wat een gebruiker zelf op / heeft van wat hij via een groep heeft, en NoAccess haalt alles weg."""
    now = time.time()
    out = set()
    for uid, u in st["users"].items():
        if uid == PVE_USER or not u["enable"] or (u["expire"] and u["expire"] <= now):
            continue
        if uid == "root@pam":
            out.add(uid)
            continue
        own = {a["roleid"] for a in st["acl"] if a["path"] == "/" and a["type"] == "user" and a["ugid"] == uid}
        roles = own or {a["roleid"] for a in st["acl"] if a["path"] == "/" and a["type"] == "group" and a["ugid"] in u["groups"]}
        if FULL_ADMIN in roles and "NoAccess" not in roles:
            out.add(uid)
    return out


def keep_an_admin(before: dict, after: dict):
    if full_admins(before) and not full_admins(after):
        raise HTTPException(409, "Dan heeft niemand meer volledige beheerrechten in Proxmox (Administrator op /), behalve de tool zelf; er is niets gewijzigd")


def access_text(value) -> str:
    text = (value or "").strip()
    if any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise HTTPException(400, "Namen, e-mail en opmerking mogen geen regeleinden of stuurtekens bevatten")
    return text


def access_email(value) -> str:
    text = access_text(value)
    if text and not EMAIL_RE.match(text):
        raise HTTPException(400, "Ongeldig e-mailadres")
    return text


def access_expire(value):
    if value is not None and value != 0 and not EXPIRE_RANGE[0] < value < EXPIRE_RANGE[1]:
        raise HTTPException(400, "Ongeldige datum voor verlopen")
    return value


def access_password(value: str) -> str:
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise HTTPException(400, "Het wachtwoord mag geen regeleinden of stuurtekens bevatten")
    if not min_password() <= len(value) <= 64:
        raise HTTPException(400, "Het wachtwoord moet {0} tot 64 tekens lang zijn".format(min_password()))
    return value


def realm_types(api) -> dict:
    return {d.get("realm"): d.get("type") for d in api.access.domains.get() if d.get("realm")}


@app.get("/api/access")
def access_info(_: str = Depends(admin)):
    """Gebruikers, groepen, realms, rollen en rechten van Proxmox, plus de keuzes voor waar een recht geldt."""
    def f(api):
        st = access_state(api)
        realms = api.access.domains.get()
        roles = api.access.roles.get()
        try:
            pools = [p.get("poolid") for p in api.pools.get() if p.get("poolid")]
        except ResourceException:
            pools = []
        guests = sorted(api.cluster.resources.get(type="vm"), key=lambda g: g.get("vmid", 0))
        storages = sorted({s.get("storage") for s in api.cluster.resources.get(type="storage") if s.get("storage")})
        admins = full_admins(st)
        own_acl = lambda kind, ugid: [a for a in st["acl"] if a["type"] == kind and a["ugid"] == ugid]  # noqa: E731
        text = lambda v, n=200: str(v)[:n] if v not in (None, "") else None  # noqa: E731
        users = []
        for uid, u in sorted(st["users"].items(), key=lambda kv: kv[0].lower()):
            r = u["raw"]
            try:
                linked = find_linked("proxmox", uid)
            except Exception:  # noqa: BLE001 - zonder SSO-gegevens is er gewoon geen koppeling
                linked = None
            users.append({"userid": uid, "realm": uid.rpartition("@")[2], "realm_type": r.get("realm-type"), "enable": u["enable"],
                          "expire": u["expire"] or None, "firstname": text(r.get("firstname"), 64), "lastname": text(r.get("lastname"), 64),
                          "email": text(r.get("email"), 254), "comment": text(r.get("comment")), "groups": sorted(u["groups"]),
                          "tokens": len(r.get("tokens") or []), "admin": uid in admins, "protected": protected_user(uid),
                          "tool": uid == PVE_USER, "linked": linked, "acl": own_acl("user", uid)})
        groups = [{"groupid": gid, "comment": text(g["comment"]), "members": sorted(g["members"]), "acl": own_acl("group", gid),
                   "has_tool": PVE_USER in g["members"]} for gid, g in sorted(st["groups"].items(), key=lambda kv: kv[0].lower())]
        return {
            "users": users, "groups": groups,
            "realms": [{"realm": d.get("realm"), "type": d.get("type"), "comment": text(d.get("comment"))} for d in realms],
            "roles": sorted(({"roleid": r.get("roleid"), "privs": sorted(access_list(r.get("privs"))), "builtin": bool(r.get("special"))} for r in roles),
                            key=lambda r: (not r["builtin"], r["roleid"])),
            "paths": {"guests": [{"vmid": g["vmid"], "name": g.get("name"), "type": g.get("type")} for g in guests],
                      "storages": storages, "nodes": sorted(n["node"] for n in api.nodes.get()), "pools": sorted(pools)},
            "admins": sorted(admins), "tool_user": PVE_USER, "min_password": min_password(), "tokens": token_rows(api, st),
        }
    return pve.run(f)


class PveUserIn(BaseModel):
    name: str = Field(max_length=64)
    realm: str = Field(max_length=32)
    password: str | None = Field(None, max_length=200)
    firstname: str = Field("", max_length=64)
    lastname: str = Field("", max_length=64)
    email: str = Field("", max_length=254)
    comment: str = Field("", max_length=200)
    expire: int = Field(0, strict=True)   # seconden; 0 = verloopt nooit (de pagina rekent de datum om in de eigen tijdzone)
    enable: bool = Field(True, strict=True)
    groups: list[str] = Field(default_factory=list, max_length=100)


class PveUserEdit(BaseModel):
    firstname: str | None = Field(None, max_length=64)
    lastname: str | None = Field(None, max_length=64)
    email: str | None = Field(None, max_length=254)
    comment: str | None = Field(None, max_length=200)
    expire: int | None = Field(None, strict=True)
    enable: bool | None = Field(None, strict=True)
    groups: list[str] | None = Field(None, max_length=100)


class PvePasswordIn(BaseModel):
    password: str = Field(max_length=200)


class PveGroupIn(BaseModel):
    groupid: str = Field(max_length=64)
    comment: str = Field("", max_length=200)
    members: list[str] = Field(default_factory=list, max_length=500)


class PveGroupEdit(BaseModel):
    comment: str | None = Field(None, max_length=200)
    members: list[str] | None = Field(None, max_length=500)


class AclIn(BaseModel):
    path: str = Field(max_length=200)
    role: str = Field(max_length=64)
    user: str | None = Field(None, max_length=100)
    group: str | None = Field(None, max_length=64)
    token: str | None = Field(None, max_length=170)   # gebruiker@realm!token
    propagate: bool = Field(True, strict=True)
    remove: bool = Field(False, strict=True)


def known_groups(st: dict, names) -> list:
    names = sorted(set(names))
    missing = [g for g in names if g not in st["groups"]]
    if missing:
        raise HTTPException(400, "Onbekende groep: {0}".format(", ".join(missing[:5])))
    return names


@app.post("/api/access/users")
def access_user_add(body: PveUserIn, request: Request, user: str = Depends(admin)):
    """Maakt een Proxmox-gebruiker. Alleen in realm pve krijgt hij hier een wachtwoord; bij pam moet het account op
    elke node al bestaan, bij een andere realm regelt die het inloggen."""
    same_origin(request)
    userid = f"{body.name.strip()}@{body.realm.strip()}"
    if not PVE_USERID_RE.match(userid):
        raise HTTPException(400, "Ongeldige gebruikersnaam: letters, cijfers, punt, streepje of liggend streepje, tot 64 tekens")
    refuse_protected(userid)
    params = {"userid": userid, "enable": 1 if body.enable else 0}
    for key in ("firstname", "lastname", "comment"):
        if access_text(getattr(body, key)):
            params[key] = access_text(getattr(body, key))
    if access_email(body.email):
        params["email"] = access_email(body.email)
    if access_expire(body.expire):
        params["expire"] = body.expire
    password = body.password or ""

    def f(api):
        kind = realm_types(api).get(body.realm.strip())
        if not kind:
            raise HTTPException(400, "Deze realm bestaat niet")
        if kind == "pve" and not password:
            raise HTTPException(400, "Kies een wachtwoord: een gebruiker in realm pve logt daarmee in")
        if kind != "pve" and password:
            raise HTTPException(400, "Een wachtwoord stel je hier alleen in bij realm pve; bij deze realm regelt die het inloggen")
        st = access_state(api)
        if userid in st["users"]:
            raise HTTPException(409, "Deze Proxmox-gebruiker bestaat al")
        groups = known_groups(st, body.groups)
        if groups:
            params["groups"] = ",".join(groups)
        if password:
            params["password"] = access_password(password)
        api.access.users.post(**params)
    pve.run(f)
    state.event("access", "Proxmox-gebruiker aangemaakt", target=userid, name="", user=user)
    return {"ok": True, "userid": userid}


@app.put("/api/access/users/{userid}")
def access_user_change(userid: str, body: PveUserEdit, request: Request, user: str = Depends(admin)):
    """Past naam, e-mail, opmerking, verlopen, aan/uit en de groepen van een Proxmox-gebruiker aan; alleen wat is
    opgegeven. Een lege tekst maakt dat veld leeg."""
    same_origin(request)
    refuse_protected(userid)
    params = {}
    for key in ("firstname", "lastname", "comment"):
        if getattr(body, key) is not None:
            params[key] = access_text(getattr(body, key))
    if body.email is not None:
        params["email"] = access_email(body.email)
    if body.expire is not None:
        params["expire"] = access_expire(body.expire)
    if body.enable is not None:
        params["enable"] = 1 if body.enable else 0

    def f(api):
        st = access_state(api)
        if userid not in st["users"]:
            raise HTTPException(404, "Deze Proxmox-gebruiker bestaat niet (meer)")
        after = access_copy(st)
        if body.groups is not None:
            groups = known_groups(st, body.groups)
            params["groups"] = ",".join(groups)
            after["users"][userid]["groups"] = set(groups)
        if not params:
            raise HTTPException(400, "Er is niets om aan te passen")
        if "enable" in params:
            after["users"][userid]["enable"] = bool(params["enable"])
        if "expire" in params:
            after["users"][userid]["expire"] = params["expire"]
        keep_an_admin(st, after)
        api.access.users(userid).put(**params)
    pve.run(f)
    state.event("access", "Proxmox-gebruiker aangepast", target=userid, name="", user=user)
    return {"ok": True, "userid": userid}


@app.delete("/api/access/users/{userid}")
def access_user_delete(userid: str, request: Request, user: str = Depends(admin)):
    """Verwijdert een Proxmox-gebruiker; Proxmox haalt daarbij ook zijn rechten, groepen en API-tokens weg."""
    same_origin(request)
    refuse_protected(userid)

    def f(api):
        st = access_state(api)
        if userid not in st["users"]:
            raise HTTPException(404, "Deze Proxmox-gebruiker bestaat niet (meer)")
        after = access_copy(st)
        del after["users"][userid]
        after["acl"] = [a for a in after["acl"] if not (a["type"] == "user" and a["ugid"] == userid)]
        keep_an_admin(st, after)
        api.access.users(userid).delete()
    pve.run(f)
    state.event("access", "Proxmox-gebruiker verwijderd", target=userid, name="", user=user)
    return {"ok": True, "userid": userid}


@app.put("/api/access/users/{userid}/password")
def access_user_password(userid: str, body: PvePasswordIn, request: Request, user: str = Depends(admin)):
    """Een nieuw wachtwoord voor een gebruiker in realm pve. Proxmox kan daarbij het wachtwoord vragen van wie het
    wijzigt; met de toegangssleutel van de tool kan dat niet, en dan zegt de tool waar het wel kan."""
    same_origin(request)
    refuse_protected(userid)
    password = access_password(body.password)

    def f(api):
        if realm_types(api).get(userid.rpartition("@")[2]) != "pve":
            raise HTTPException(400, "Een wachtwoord wijzig je hier alleen bij realm pve; bij deze realm regelt die het inloggen")
        if userid not in access_state(api)["users"]:
            raise HTTPException(404, "Deze Proxmox-gebruiker bestaat niet (meer)")
        try:
            api.access.password.put(userid=userid, password=password)
        except ResourceException as err:
            if "confirmation-password" in f"{err.content} {err.errors}":
                raise HTTPException(409, "Proxmox vraagt hierbij het eigen wachtwoord van wie het wijzigt, en dat heeft de tool niet. "
                                         "Wijzig het wachtwoord in Proxmox zelf (Datacenter, Permissions, Users, Password)")
            raise
    pve.run(f)
    state.event("access", "wachtwoord van Proxmox-gebruiker gewijzigd", target=userid, name="", user=user)
    return {"ok": True, "userid": userid}


def group_members(st: dict, names) -> set:
    names = set(names)
    missing = sorted(n for n in names if n not in st["users"])
    if missing:
        raise HTTPException(400, "Onbekende gebruiker: {0}".format(", ".join(missing[:5])))
    return names


def set_membership(api, st: dict, gid: str, add: set, remove: set):
    """Zet gebruikers in of uit een groep. Proxmox kent dat alleen per gebruiker: toevoegen kan erbij (append),
    eruit halen door de rest van zijn groepen opnieuw op te geven."""
    for uid in sorted(add | remove):
        refuse_protected(uid)
    for uid in sorted(add):
        api.access.users(uid).put(groups=gid, append=1)
    for uid in sorted(remove):
        api.access.users(uid).put(groups=",".join(sorted(st["users"][uid]["groups"] - {gid})))


@app.post("/api/access/groups")
def access_group_add(body: PveGroupIn, request: Request, user: str = Depends(admin)):
    same_origin(request)
    gid = body.groupid.strip()
    if not PVE_GROUPID_RE.match(gid):
        raise HTTPException(400, "Ongeldige groepsnaam: letters, cijfers, punt, streepje of liggend streepje, tot 64 tekens")
    comment = access_text(body.comment)

    def f(api):
        st = access_state(api)
        if gid in st["groups"]:
            raise HTTPException(409, "Deze groep bestaat al")
        members = group_members(st, body.members)
        for uid in sorted(members):
            refuse_protected(uid)
        api.access.groups.post(groupid=gid, **({"comment": comment} if comment else {}))
        set_membership(api, st, gid, members, set())
    pve.run(f)
    state.event("access", "Proxmox-groep aangemaakt", target=gid, name="", user=user)
    return {"ok": True, "groupid": gid}


@app.put("/api/access/groups/{groupid}")
def access_group_change(groupid: str, body: PveGroupEdit, request: Request, user: str = Depends(admin)):
    """Past de opmerking en de leden van een groep aan."""
    same_origin(request)
    if not PVE_GROUPID_RE.match(groupid):
        raise HTTPException(400, "Ongeldige groepsnaam: letters, cijfers, punt, streepje of liggend streepje, tot 64 tekens")
    comment = access_text(body.comment) if body.comment is not None else None

    def f(api):
        st = access_state(api)
        if groupid not in st["groups"]:
            raise HTTPException(404, "Deze groep bestaat niet (meer)")
        old = st["groups"][groupid]["members"]
        new = group_members(st, body.members) if body.members is not None else set(old)
        add, remove = new - old, old - new
        if comment is None and not add and not remove:
            raise HTTPException(400, "Er is niets om aan te passen")
        for uid in sorted(add | remove):
            refuse_protected(uid)
        after = access_copy(st)
        after["groups"][groupid]["members"] = set(new)
        for uid in add:
            after["users"][uid]["groups"].add(groupid)
        for uid in remove:
            after["users"][uid]["groups"].discard(groupid)
        keep_an_admin(st, after)
        if comment is not None:
            api.access.groups(groupid).put(comment=comment)
        set_membership(api, st, groupid, add, remove)
    pve.run(f)
    state.event("access", "Proxmox-groep aangepast", target=groupid, name="", user=user)
    return {"ok": True, "groupid": groupid}


@app.delete("/api/access/groups/{groupid}")
def access_group_delete(groupid: str, request: Request, user: str = Depends(admin)):
    """Verwijdert een groep, met zijn rechten. De gebruikers zelf blijven bestaan."""
    same_origin(request)
    if not PVE_GROUPID_RE.match(groupid):
        raise HTTPException(400, "Ongeldige groepsnaam: letters, cijfers, punt, streepje of liggend streepje, tot 64 tekens")

    def f(api):
        st = access_state(api)
        if groupid not in st["groups"]:
            raise HTTPException(404, "Deze groep bestaat niet (meer)")
        if PVE_USER in st["groups"][groupid]["members"]:
            raise HTTPException(409, "De gebruiker waarmee de tool werkt zit in deze groep; die groep verwijdert de tool niet")
        after = access_copy(st)
        del after["groups"][groupid]
        for u in after["users"].values():
            u["groups"].discard(groupid)
        after["acl"] = [a for a in after["acl"] if not (a["type"] == "group" and a["ugid"] == groupid)]
        keep_an_admin(st, after)
        api.access.groups(groupid).delete()
    pve.run(f)
    state.event("access", "Proxmox-groep verwijderd", target=groupid, name="", user=user)
    return {"ok": True, "groupid": groupid}


@app.put("/api/access/acl")
def access_acl(body: AclIn, request: Request, user: str = Depends(admin)):
    """Kent een gebruiker, groep of API-token een rol toe op een plek (pad), of trekt die in (remove)."""
    same_origin(request)
    if sum(x is not None for x in (body.user, body.group, body.token)) != 1:
        raise HTTPException(400, "Kies een gebruiker, een groep of een token")
    if not ACL_PATH_RE.match(body.path):
        raise HTTPException(400, "Ongeldige plek voor een recht")
    if not ROLE_RE.match(body.role):
        raise HTTPException(400, "Onbekende rol")
    kind, ugid = (("user", body.user) if body.user is not None else ("group", body.group) if body.group is not None
                  else ("token", body.token))
    if kind == "user":
        refuse_protected(ugid)
    elif kind == "token":
        token_target(ugid.partition("!")[0], ugid.partition("!")[2])
    elif not PVE_GROUPID_RE.match(ugid):
        raise HTTPException(400, "Ongeldige groepsnaam: letters, cijfers, punt, streepje of liggend streepje, tot 64 tekens")

    def f(api):
        st = access_state(api)
        if kind == "user" and ugid not in st["users"]:
            raise HTTPException(404, "Deze Proxmox-gebruiker bestaat niet (meer)")
        if kind == "group" and ugid not in st["groups"]:
            raise HTTPException(404, "Deze groep bestaat niet (meer)")
        if kind == "token" and not any(f"{uid}!{tk.get('tokenid')}" == ugid for uid, u in st["users"].items() for tk in u["raw"].get("tokens") or []):
            raise HTTPException(404, "Dit token bestaat niet (meer)")
        if kind == "group" and body.remove and PVE_USER in st["groups"][ugid]["members"]:
            raise HTTPException(409, "De gebruiker waarmee de tool werkt zit in deze groep; de rechten van die groep wijzigt de tool niet")
        if body.role not in {r.get("roleid") for r in api.access.roles.get()}:
            raise HTTPException(400, "Onbekende rol")
        entry = {"path": body.path, "type": kind, "ugid": ugid, "roleid": body.role}
        same = [a for a in st["acl"] if all(a[k] == v for k, v in entry.items())]
        after = access_copy(st)
        if body.remove:
            if not same:
                raise HTTPException(404, "Dit recht bestaat niet (meer)")
            after["acl"] = [a for a in after["acl"] if not all(a[k] == v for k, v in entry.items())]
        else:
            after["acl"].append({**entry, "propagate": body.propagate})
        keep_an_admin(st, after)
        params = {"path": body.path, "roles": body.role, {"user": "users", "group": "groups", "token": "tokens"}[kind]: ugid,
                  "propagate": 1 if body.propagate else 0}
        if body.remove:
            params["delete"] = 1
        api.access.acl.put(**params)
    pve.run(f)
    state.event("access", "recht ingetrokken" if body.remove else "recht toegekend", target=ugid, name=f"{body.role}, {body.path}", user=user)
    return {"ok": True}


# ---------------------------------------------------------------- instellingen van een node (de steeksleutel bij de node)
# Wat Proxmox per node laat instellen: een notitie, de tijdzone, DNS, Wake-on-LAN, hoe lang de node wacht voordat hij
# de guests start, en de pakketbronnen (aan/uit, een standaardbron erbij). De naam en het netwerk van een node horen
# hier niet: die wijzigt de tool niet (het netwerk staat op het tabblad Netwerken).
TZ_RE = re.compile(r"^(UTC|[A-Za-z]+(/[A-Za-z0-9_+\-]+){1,2})$")
MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
REPO_PATH_RE = re.compile(r"^/etc/apt/(sources\.list|sources\.list\.d/[A-Za-z0-9._-]{1,100})$")
STARTALL_MAX = 300   # seconden, zoals Proxmox toestaat


def node_repos(api, node: str) -> dict:
    """De pakketbronnen van een node: per bestand en regel, plus de standaardbronnen van Proxmox en wat Proxmox
    ervan vindt (bijvoorbeeld een verouderde release)."""
    r = api.nodes(node).apt.repositories.get() or {}
    rows = []
    for f in r.get("files") or []:
        for i, rr in enumerate(f.get("repositories") or []):
            rows.append({"path": f.get("path"), "index": i, "types": rr.get("Types") or [], "uris": rr.get("URIs") or [],
                         "suites": rr.get("Suites") or [], "components": rr.get("Components") or [], "enabled": bool(rr.get("Enabled")),
                         "comment": (str(rr.get("Comment") or "").strip()[:200] or None)})
    warnings = [{"path": i.get("path"), "index": i.get("index"), "message": str(i.get("message") or "")[:200]}
                for i in r.get("infos") or [] if i.get("kind") == "warning"]
    standard = [{"handle": s.get("handle"), "name": s.get("name"), "status": s.get("status"), "description": s.get("description")}
                for s in r.get("standard-repos") or [] if s.get("handle")]
    return {"repos": rows, "standard": standard, "warnings": warnings}


def wol_mac(value) -> str:
    o = parse_options(value)
    return str(o.get("mac") or o.get("") or "")


@app.get("/api/node/{node}/settings")
def node_settings(node: str, _: str = Depends(auth)):
    """De instellingen van een node zoals Proxmox ze nu heeft."""
    if not NODE_RE.match(node):
        raise HTTPException(400, "Ongeldige nodenaam")

    def f(api):
        cfg = api.nodes(node).config.get() or {}
        dns = api.nodes(node).dns.get() or {}
        tm = api.nodes(node).time.get() or {}
        try:
            repos = node_repos(api, node)
        except ResourceException:
            repos = None
        try:
            sub = (api.nodes(node).subscription.get() or {}).get("status")
        except ResourceException:
            sub = None
        delay = cfg.get("startall-onboot-delay")
        return {"node": node, "description": str(cfg.get("description") or ""), "wakeonlan": wol_mac(cfg.get("wakeonlan")),
                "startall_delay": int(delay) if str(delay or "").isdigit() else None, "timezone": tm.get("timezone"),
                "dns": {k: str(dns.get(k) or "") for k in ("search", "dns1", "dns2", "dns3")}, "repos": repos,
                "subscription": str(sub or "")[:40] or None}
    return pve.run(f)


class NodeDnsIn(BaseModel):
    search: str = Field(max_length=253)
    dns1: str = Field("", max_length=45)
    dns2: str = Field("", max_length=45)
    dns3: str = Field("", max_length=45)


class RepoChange(BaseModel):
    path: str = Field(max_length=200)
    index: int = Field(strict=True)
    enabled: bool = Field(strict=True)


class NodeSettingsIn(BaseModel):
    description: str | None = Field(None, max_length=8000)
    timezone: str | None = Field(None, max_length=64)
    startall_delay: int | None = Field(None, strict=True)   # leeg (None) = laat zoals het is; -1 = weghalen
    wakeonlan: str | None = Field(None, max_length=17)      # "" = weghalen
    dns: NodeDnsIn | None = None
    repos: list[RepoChange] | None = Field(None, max_length=50)
    add_repo: str | None = Field(None, max_length=64)


def dns_values(d: NodeDnsIn) -> dict:
    search = d.search.strip()
    if not DOMAIN_RE.match(search):
        raise HTTPException(400, "Ongeldig zoekdomein")
    out = {"search": search}
    for key in ("dns1", "dns2", "dns3"):
        value = getattr(d, key).strip()
        if value:
            try:
                ipaddress.ip_address(value)
            except ValueError:
                raise HTTPException(400, "Ongeldig adres van een DNS-server: {0}".format(value[:45]))
            out[key] = value
    if "dns1" not in out:
        raise HTTPException(400, "Vul minstens de eerste DNS-server in")
    return out


@app.put("/api/node/{node}/settings")
def node_settings_save(node: str, body: NodeSettingsIn, request: Request, user: str = Depends(manage_overview)):
    """Past de instellingen van een node aan; alleen wat is opgegeven."""
    same_origin(request)
    if not NODE_RE.match(node):
        raise HTTPException(400, "Ongeldige nodenaam")
    config, delete = {}, []
    if body.description is not None:
        if "\x00" in body.description:
            raise HTTPException(400, "De notitie bevat een ongeldig teken")
        if body.description.strip():
            config["description"] = body.description
        else:
            delete.append("description")
    if body.startall_delay is not None:
        if body.startall_delay == -1:
            delete.append("startall-onboot-delay")
        elif isinstance(body.startall_delay, bool) or not 0 <= body.startall_delay <= STARTALL_MAX:
            raise HTTPException(400, "Wachttijd voor het starten van de guests: 0 tot 300 seconden")
        else:
            config["startall-onboot-delay"] = body.startall_delay
    if body.wakeonlan is not None:
        mac = body.wakeonlan.strip()
        if not mac:
            delete.append("wakeonlan")
        elif not MAC_RE.match(mac):
            raise HTTPException(400, "Ongeldig MAC-adres voor Wake-on-LAN")
        else:
            config["wakeonlan"] = mac.lower()
    if body.timezone is not None and not TZ_RE.match(body.timezone):
        raise HTTPException(400, "Onbekende tijdzone")
    dns = dns_values(body.dns) if body.dns is not None else None
    for change in body.repos or []:
        if not REPO_PATH_RE.match(change.path) or not 0 <= change.index <= 200:
            raise HTTPException(400, "Onbekende pakketbron")
    if not (config or delete or body.timezone or dns or body.repos or body.add_repo):
        raise HTTPException(400, "Er is niets om aan te passen")

    def f(api):
        if node not in [n.get("node") for n in api.nodes.get() if n.get("status") == "online"]:
            raise HTTPException(409, "Deze node is niet online")
        changes = []
        if body.repos or body.add_repo:
            current = node_repos(api, node)
            known = {(r["path"], r["index"]): r for r in current["repos"]}
            if any((c.path, c.index) not in known for c in body.repos or []):
                raise HTTPException(409, "De pakketbronnen zijn intussen veranderd; open het venster opnieuw")
            if body.add_repo and not any(s["handle"] == body.add_repo and s["status"] is None for s in current["standard"]):
                raise HTTPException(400, "Deze standaardbron is onbekend of staat er al")
        if config or delete:
            params = dict(config)
            if delete:
                params["delete"] = ",".join(delete)
            api.nodes(node).config.put(**params)
            changes.append("config")
        if body.timezone:
            api.nodes(node).time.put(timezone=body.timezone)
            changes.append("timezone")
        if dns:
            api.nodes(node).dns.put(**dns)
            changes.append("dns")
        for c in body.repos or []:
            if known[(c.path, c.index)]["enabled"] != c.enabled:
                api.nodes(node).apt.repositories.post(path=c.path, index=c.index, enabled=1 if c.enabled else 0)
                changes.append("repo")
        if body.add_repo:
            api.nodes(node).apt.repositories.put(handle=body.add_repo)
            changes.append("repo")
        return changes
    changes = pve.run(f)
    if changes:
        state.event("nodecfg", "instellingen aangepast", node=node, target="node", name="", user=user)
    return {"ok": True, "changed": sorted(set(changes))}


# ---------------------------------------------------------------- logboek van de back-ups (tabblad Back-ups, Log)
# Elke back-upronde is een vzdump-taak op een node. De eerste regels van zijn log zeggen welke guests, naar welke
# opslag en hoe; daarmee zoekt de tool het schema erbij. Bij een ronde met fouten leest hij het hele log, voor
# welke guest het misging en waarom.
VZDUMP_START_RE = re.compile(r"starting new backup job: vzdump (.*)$")
VZDUMP_FAIL_RE = re.compile(r"ERROR: Backup of VM (\d+) failed - (.*)$")
VZDUMP_DONE_RE = re.compile(r"Finished Backup of VM (\d+) \(([0-9:]+)\)")
BACKUP_LOG_DAYS = (7, 30, 90)
BACKUP_LOG_MAX = 300   # zoveel rondes laat het overzicht hoogstens zien
JOB_UPIDS_MAX = 300    # zoveel rondes die via de tool met 'nu uitvoeren' zijn gestart onthoudt de tool (taak -> schema)


def remember_job_run(job: str, tasks: list):
    """Onthoudt bij welk schema de taken horen die de tool met 'nu uitvoeren' startte; anders zijn die niet te
    onderscheiden van een losse back-up van dezelfde guests."""
    def keep(d):
        runs = d.get("job_upids") if isinstance(d.get("job_upids"), dict) else {}
        runs.update({t["upid"]: job for t in tasks if isinstance(t.get("upid"), str)})
        d["job_upids"] = dict(list(runs.items())[-JOB_UPIDS_MAX:])
    try:
        state.change(keep)
    except OSError:
        pass


def vzdump_args(text: str) -> dict:
    """'101 104 --mode snapshot --storage nas --all 0' -> {"vmids": [101, 104], "mode": "snapshot", "storage": "nas", "all": False}."""
    try:
        words = shlex.split(text)
    except ValueError:
        words = text.split()
    out, vmids, i = {}, [], 0
    while i < len(words):
        w = words[i]
        if w.startswith("--"):
            if i + 1 < len(words) and not words[i + 1].startswith("--"):
                out[w[2:]], i = words[i + 1], i + 2
            else:
                out[w[2:]], i = "1", i + 1
            continue
        if w.isdigit():
            vmids.append(int(w))
        i += 1
    vmids += [int(v) for v in re.split(r"[,\s]+", out.get("vmid", "")) if v.isdigit()]
    return {"vmids": sorted(set(vmids)), "storage": out.get("storage"), "mode": out.get("mode"),
            "all": out.get("all") in ("1", "true"), "exclude": [int(v) for v in re.split(r"[,\s]+", out.get("exclude", "")) if v.isdigit()]}


def backup_job_for(args: dict, vmids: list, jobs: list):
    """Het schema waar deze ronde bij hoort, of None: zelfde opslag (en modus), en de guests passen erin. Bij twijfel
    het schema met de minste guests."""
    ids = lambda text: {int(v) for v in str(text or "").split(",") if v.strip().isdigit()}  # noqa: E731
    fits = []
    for j in jobs:
        if args.get("storage") and j.get("storage") != args["storage"]:
            continue
        if args.get("mode") and j.get("mode") and j.get("mode") != args["mode"]:
            continue
        if j.get("all"):
            if args.get("all") or (vmids and not set(vmids) & ids(j.get("exclude"))):
                fits.append((10 ** 6, j))
        elif vmids and set(vmids) <= ids(j.get("vmid")):
            fits.append((len(ids(j.get("vmid"))), j))
    return min(fits, key=lambda x: x[0])[1] if fits else None


@app.get("/api/backup/log")
def backup_log(days: int = 30, _: str = Depends(auth)):
    """De back-uprondes van de laatste 7, 30 of 90 dagen op alle nodes, met per schema de laatste keer."""
    days = days if days in BACKUP_LOG_DAYS else 30

    def f(api):
        listed = api.nodes.get()
        nodes = sorted(n["node"] for n in listed if n.get("status") == "online")
        since = int(time.time()) - days * 86400

        def tasks(node):
            try:
                return api.nodes(node).tasks.get(typefilter="vzdump", since=since, limit=500, source="all")
            except ResourceException:
                return []

        found = [dict(t, node=t.get("node") or n) for n, ts in zip(nodes, POOL.map(tasks, nodes)) for t in ts or []]
        found = sorted(found, key=lambda t: t.get("starttime") or 0, reverse=True)[:BACKUP_LOG_MAX]

        def log(task, limit):
            try:
                return [str(line.get("t") or "") for line in api.nodes(task["node"]).tasks(task["upid"]).log.get(start=0, limit=limit)]
            except ResourceException:
                return []

        heads = list(POOL.map(lambda t: log(t, 15), found))
        level = lambda t: ("running" if t.get("endtime") is None else "ok" if t.get("status") == "OK"  # noqa: E731
                           else "warning" if str(t.get("status") or "").startswith("WARNINGS") else "error")
        bad = [t for t in found if level(t) in ("warning", "error")]
        tails = dict(zip((t["upid"] for t in bad), POOL.map(lambda t: log(t, 20000), bad)))
        jobs = api.cluster.backup.get()
        by_id = {j.get("id"): j for j in jobs}
        started = state.load().get("job_upids") or {}
        names = {g["vmid"]: g.get("name") for g in api.cluster.resources.get(type="vm") if isinstance(g.get("vmid"), int)}
        runs = []
        for task, head in zip(found, heads):
            args = next((vzdump_args(m.group(1)) for m in (VZDUMP_START_RE.search(line) for line in head) if m), {})
            vmids = args.get("vmids") or ([int(task["id"])] if str(task.get("id") or "").isdigit() else [])
            lines = tails.get(task["upid"], [])
            failed = [{"vmid": int(m.group(1)), "name": names.get(int(m.group(1))), "reason": m.group(2)[:200]}
                      for m in (VZDUMP_FAIL_RE.search(line) for line in lines) if m]
            done = sorted({int(m.group(1)) for m in (VZDUMP_DONE_RE.search(line) for line in lines) if m})
            # een schema van Proxmox draait als root@pam; 'nu uitvoeren' via de tool staat in job_upids; de rest is los
            job = by_id.get(started.get(task["upid"])) or (backup_job_for(args, vmids, jobs) if task.get("user") == "root@pam" else None)
            runs.append({"upid": task["upid"], "node": task["node"], "start": task.get("starttime"), "end": task.get("endtime"),
                         "status": str(task.get("status") or "")[:200] or None, "level": level(task), "user": task.get("user"),
                         "vmids": vmids, "names": {str(v): names.get(v) for v in vmids}, "all": bool(args.get("all")),
                         "storage": args.get("storage"), "mode": args.get("mode"), "job": job.get("id") if job else None,
                         "job_name": (job.get("comment") or job.get("id")) if job else None, "failed": failed[:50], "done": done if lines else None})
        order = {"error": 0, "warning": 1, "running": 2, "ok": 3}
        summary = []
        for j in sorted(jobs, key=lambda j: j.get("comment") or j.get("id", "")):
            mine = [r for r in runs if r["job"] == j.get("id")]
            last = max((r["start"] or 0 for r in mine), default=None)
            batch = [r for r in mine if last and abs((r["start"] or 0) - last) < 3600]   # één ronde loopt op meer nodes tegelijk
            starts = sorted({(r["start"] or 0) // 3600 for r in mine})
            summary.append({"id": j.get("id"), "name": j.get("comment") or j.get("id"), "schedule": j.get("schedule"), "enabled": j.get("enabled", 1) != 0,
                            "next_run": j.get("next-run"), "storage": j.get("storage"), "last": last,
                            "last_level": min((r["level"] for r in batch), key=lambda x: order[x]) if batch else None,
                            "runs": len(starts), "bad_runs": len({(r["start"] or 0) // 3600 for r in mine if r["level"] in ("error", "warning")})})
        return {"days": days, "runs": runs, "jobs": summary, "offline": sorted(n["node"] for n in listed if n.get("status") != "online"),
                "more": len(found) >= BACKUP_LOG_MAX, "tool_user": PVE_USER}
    return pve.run(f)


# ---------------------------------------------------------------- bibliotheek: ISO's en containersjablonen (tabblad Opslag)
# De tool zoekt zelf op elke opslag waar ISO-bestanden of sjablonen mogen staan (op elke node: een lokale opslag is per
# node anders). Erbij: een ISO laten downloaden door Proxmox zelf (download-url), een sjabloon uit de lijst van
# Proxmox ophalen, en een ISO of sjabloon verwijderen (een ISO alleen als geen VM hem in de cd-speler heeft).
MEDIA = ("iso", "vztmpl")
VOLID_MEDIA_RE = re.compile(r"^([A-Za-z][A-Za-z0-9._-]{0,63}):(iso|vztmpl)/([A-Za-z0-9][A-Za-z0-9._+-]{0,250})$")
ISO_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,190}\.(iso|img)$")
CHECKSUMS = {"md5": 32, "sha1": 40, "sha224": 56, "sha256": 64, "sha384": 96, "sha512": 128}
FREE_IDS = 10   # zoveel vrije ID's biedt het formulier voor een nieuwe guest aan


def media_stores(api, nodes: list) -> dict:
    """Per opslag waar ISO's of sjablonen mogen staan: gedeeld of niet, op welke nodes, wat erop mag en hoeveel vrij."""
    stores = {}
    for node, listed in zip(nodes, POOL.map(lambda n: api.nodes(n).storage.get(), nodes)):
        for s in listed or []:
            kinds = sorted(set((s.get("content") or "").split(",")) & set(MEDIA))
            if not kinds or not s.get("active") or not s.get("enabled", 1):
                continue
            st = stores.setdefault(s["storage"], {"storage": s["storage"], "type": s.get("type"), "shared": bool(s.get("shared")),
                                                  "content": kinds, "nodes": [], "avail": {}})
            st["nodes"].append(node)
            st["avail"][node] = s.get("avail")
    return stores


def media_scan(api, nodes: list | None = None) -> dict:
    """Alle ISO's en sjablonen op het cluster. Een gedeelde opslag wordt één keer gelezen, een lokale op elke node."""
    nodes = nodes or online_nodes(api)
    stores = media_stores(api, nodes)
    jobs = [(name, n, kind) for name, st in sorted(stores.items()) for n in (st["nodes"][:1] if st["shared"] else st["nodes"]) for kind in st["content"]]

    def read(job):
        name, node, kind = job
        try:
            return job, api.nodes(node).storage(name).content.get(content=kind)
        except ResourceException:
            return job, None
    items, unreadable = [], []
    for (name, node, kind), found in POOL.map(read, jobs):
        if found is None:
            unreadable.append({"storage": name, "node": node})
            continue
        st = stores[name]
        for v in found:
            volid = str(v.get("volid") or "")
            items.append({"volid": volid, "file": volid.split("/", 1)[-1], "content": kind, "size": v.get("size"), "ctime": v.get("ctime"),
                          "storage": name, "shared": st["shared"], "node": node, "nodes": st["nodes"] if st["shared"] else [node]})
    items.sort(key=lambda i: (i["content"], i["file"].lower(), i["storage"], i["node"]))
    return {"items": items, "stores": [{**st, "avail": st["avail"]} for st in sorted(stores.values(), key=lambda s: (not s["shared"], s["storage"]))],
            "nodes": nodes, "unreadable": unreadable}


def iso_users(api) -> dict:
    """Welke VM's een ISO in de cd-speler hebben: volid -> [vmid]."""
    users = {}
    vms = [g for g in api.cluster.resources.get(type="vm") if g.get("type") == "qemu"]

    def config(g):
        try:
            return g["vmid"], guest(api, g["node"], "qemu", g["vmid"]).config.get()
        except ResourceException:
            return g["vmid"], {}
    for vmid, cfg in POOL.map(config, vms):
        for key, value in cfg.items():
            if VM_DISK_RE.match(key):
                o = parse_options(value)
                volume = str(o.get("") or o.get("file") or "")
                if o.get("media") == "cdrom" and ":iso/" in volume:
                    users.setdefault(volume, []).append(vmid)
    return users


@app.get("/api/library")
def library(_: str = Depends(auth)):
    """De bibliotheek: alle ISO's en sjablonen, waar ze te gebruiken zijn, welke VM een ISO gebruikt, waar er iets bij
    kan, en de sjablonen die Proxmox aanbiedt."""
    def f(api):
        scan = media_scan(api)
        users = iso_users(api)
        names = {g["vmid"]: g.get("name") for g in api.cluster.resources.get(type="vm") if isinstance(g.get("vmid"), int)}
        for i in scan["items"]:
            if i["content"] == "iso":
                i["used_by"] = [{"vmid": v, "name": names.get(v)} for v in users.get(i["volid"], [])]
        offered = []
        if scan["nodes"]:
            try:
                for a in api.nodes(scan["nodes"][0]).aplinfo.get():
                    if a.get("template") and a.get("section") in ("system", "turnkeylinux", "mail"):
                        offered.append({"template": a["template"], "section": a.get("section"), "headline": str(a.get("headline") or "")[:200],
                                        "os": a.get("os"), "version": a.get("version")})
            except ResourceException:
                pass
        return {**scan, "offered": sorted(offered, key=lambda a: (a["section"] != "system", a["template"]))}
    return pve.run(f)


class IsoDownloadIn(BaseModel):
    node: str = Field(max_length=63)
    storage: str = Field(max_length=64)
    url: str = Field(max_length=2000)
    filename: str = Field(max_length=200)
    checksum: str = Field("", max_length=200)
    algorithm: str = Field("", max_length=10)


def media_target(api, node: str, storage: str, kind: str) -> dict:
    """Controleert dat deze opslag op deze node actief is en dit soort bestanden mag hebben."""
    if not NODE_RE.match(node) or not STORAGE_RE.match(storage):
        raise HTTPException(400, "Ongeldige node of opslag")
    stores = media_stores(api, online_nodes(api))
    st = stores.get(storage)
    if not st or node not in st["nodes"] or kind not in st["content"]:
        raise HTTPException(400, "Op deze opslag mogen geen ISO-bestanden staan" if kind == "iso" else "Op deze opslag mogen geen sjablonen staan")
    return st


@app.post("/api/library/iso")
def library_iso(body: IsoDownloadIn, request: Request, user: str = Depends(manage_storage)):
    """Laat Proxmox een ISO downloaden van een webadres naar een opslag. Proxmox haalt hem zelf op: de tool en de
    browser doen niets met het bestand. Met een controlesom controleert Proxmox het bestand na het downloaden."""
    same_origin(request)
    url = body.url.strip()
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or any(c.isspace() for c in url):
        raise HTTPException(400, "Vul een webadres in dat begint met http:// of https://")
    if not ISO_NAME_RE.match(body.filename):
        raise HTTPException(400, "Bestandsnaam: letters, cijfers, punt, streepje, liggend streepje of plus, eindigend op .iso of .img")
    params = {"url": url, "filename": body.filename, "content": "iso"}
    if body.checksum or body.algorithm:
        want = CHECKSUMS.get(body.algorithm)
        if not want or not re.fullmatch(rf"[0-9a-fA-F]{{{want}}}", body.checksum.strip()):
            raise HTTPException(400, "De controlesom past niet bij het gekozen soort ({0})".format(body.algorithm or "?"))
        params.update({"checksum": body.checksum.strip().lower(), "checksum-algorithm": body.algorithm})

    def f(api):
        media_target(api, body.node, body.storage, "iso")
        present = {v.get("volid") for v in api.nodes(body.node).storage(body.storage).content.get(content="iso")}
        if f"{body.storage}:iso/{body.filename}" in present:
            raise HTTPException(409, "Er staat al een ISO met deze naam op deze opslag")
        return api.nodes(body.node).storage(body.storage)("download-url").post(**params)
    upid = pve.run(f)
    state.event("library", "ISO downloaden gestart", node=body.node, target=body.filename, name=body.storage, user=user)
    return {"upid": upid, "node": body.node, "volid": f"{body.storage}:iso/{body.filename}"}


class LibTemplateIn(BaseModel):
    node: str = Field(max_length=63)
    storage: str = Field(max_length=64)
    template: str = Field(max_length=200)


@app.post("/api/library/template")
def library_template(body: LibTemplateIn, request: Request, user: str = Depends(manage_storage)):
    """Haalt een containersjabloon uit de lijst van Proxmox op naar een opslag."""
    same_origin(request)

    def f(api):
        media_target(api, body.node, body.storage, "vztmpl")
        offered = {a.get("template") for a in api.nodes(body.node).aplinfo.get()}
        if body.template not in offered:
            raise HTTPException(400, "Dit sjabloon staat niet in de lijst van Proxmox")
        present = {v.get("volid") for v in api.nodes(body.node).storage(body.storage).content.get(content="vztmpl")}
        if f"{body.storage}:vztmpl/{body.template}" in present:
            raise HTTPException(409, "Dit sjabloon staat al op deze opslag")
        return api.nodes(body.node).aplinfo.post(storage=body.storage, template=body.template)
    upid = pve.run(f)
    state.event("library", "sjabloon ophalen gestart", node=body.node, target=body.template, name=body.storage, user=user)
    return {"upid": upid, "node": body.node, "volid": f"{body.storage}:vztmpl/{body.template}"}


@app.delete("/api/library")
def library_delete(node: str, volid: str, request: Request, user: str = Depends(manage_storage)):
    """Verwijdert een ISO of sjabloon van een opslag. Een ISO die een VM in de cd-speler heeft, blijft staan."""
    same_origin(request)
    m = VOLID_MEDIA_RE.match(volid)
    if not m or not NODE_RE.match(node):
        raise HTTPException(400, "Ongeldig bestand")
    storage, kind = m.group(1), m.group(2)

    def f(api):
        media_target(api, node, storage, kind)
        if volid not in {v.get("volid") for v in api.nodes(node).storage(storage).content.get(content=kind)}:
            raise HTTPException(404, "Dit bestand staat niet (meer) op deze opslag")
        if kind == "iso":
            users = iso_users(api).get(volid)
            if users:
                raise HTTPException(409, "Deze ISO zit nog in de cd-speler van VM {0}; haal hem daar eerst uit".format(", ".join(str(v) for v in users)))
        return api.nodes(node).storage(storage).content(volid).delete()
    upid = pve.run(f)
    state.event("library", "ISO verwijderd" if kind == "iso" else "sjabloon verwijderd", node=node, target=volid.split("/", 1)[1], name=storage, user=user)
    return {"upid": upid, "node": node}


# ---------------------------------------------------------------- bladeren door een opslag
BROWSE_KINDS = ("iso", "vztmpl", "backup", "images", "rootdir", "snippets", "import")


@app.get("/api/storage/{storage}/content")
def storage_content(storage: str, node: str = "", _: str = Depends(auth)):
    """Wat er op een opslag staat (zoals Proxmox het per soort bijhoudt), met de guest erbij. Alleen lezen."""
    if not STORAGE_RE.match(storage) or (node and not NODE_RE.match(node)):
        raise HTTPException(400, "Ongeldige node of opslag")

    def f(api):
        nodes = online_nodes(api)
        where, shared, content = [], False, []
        for n, listed in zip(nodes, POOL.map(lambda n: api.nodes(n).storage.get(), nodes)):
            s = next((x for x in listed or [] if x.get("storage") == storage), None)
            if s and s.get("active") and s.get("enabled", 1):
                where.append(n)
                shared = shared or bool(s.get("shared"))
                content = sorted(set((s.get("content") or "").split(",")) & set(BROWSE_KINDS))
        if not where:
            raise HTTPException(404, "Deze opslag is nu op geen enkele node beschikbaar")
        chosen = node if node in where else where[0]
        names = {g["vmid"]: g.get("name") for g in api.cluster.resources.get(type="vm") if isinstance(g.get("vmid"), int)}
        items = []
        for v in api.nodes(chosen).storage(storage).content.get():
            volid = str(v.get("volid") or "")
            vmid = int(v["vmid"]) if str(v.get("vmid") or "").isdigit() else None
            items.append({"volid": volid, "file": volid.split(":", 1)[-1].split("/", 1)[-1], "content": v.get("content"), "format": v.get("format"),
                          "size": v.get("size"), "used": v.get("used"), "ctime": v.get("ctime"), "vmid": vmid, "guest": names.get(vmid) if vmid else None,
                          "notes": str(v["notes"])[:200] if v.get("notes") else None, "protected": bool(v.get("protected"))})
        items.sort(key=lambda i: (BROWSE_KINDS.index(i["content"]) if i["content"] in BROWSE_KINDS else 99, i["file"].lower()))
        return {"storage": storage, "node": chosen, "nodes": where, "shared": shared, "content": content, "items": items}
    return pve.run(f)


def free_ids(api, start: int, count: int = FREE_IDS) -> list:
    """De eerste vrije ID's vanaf start (de guests van het hele cluster tellen mee)."""
    used = {g.get("vmid") for g in api.cluster.resources.get(type="vm")}
    out, vmid = [], max(100, start)
    while len(out) < count and vmid <= 999999999:
        if vmid not in used:
            out.append(vmid)
        vmid += 1
    return out


def node_cpu(api, node: str) -> dict:
    try:
        info = api.nodes(node).status.get().get("cpuinfo") or {}
    except ResourceException:
        return {}
    cores, sockets = info.get("cores"), info.get("sockets")
    return {"threads": info.get("cpus"), "cores": cores * sockets if isinstance(cores, int) and isinstance(sockets, int) else cores,
            "model": str(info.get("model") or "")[:80]}


# ---------------------------------------------------------------- loadbalancer: Cluster Resource Scheduling (tabblad HA)
# Proxmox VE 9.2 verdeelt HA-guests zelf over de nodes. De CRS (Cluster Resource Scheduler) kiest bij herstel en, als
# dat aan staat, bij het starten de beste node; de loadbalancer van de HA-manager verplaatst guests als de nodes te
# ongelijk belast zijn: alleen HA-guests, één tegelijk en volgens de HA-regels. De tool stelt dat in (Datacenter >
# Opties > crs) en houdt bij welke HA-guests meedoen (auto-rebalance per guest). Zelf verplaatst de tool niets.
# Een container kan niet live verhuizen en gaat daarbij even uit. Met het tijdvenster doen containers alleen binnen
# die uren mee: daarbuiten zet de tool hun auto-rebalance uit (balance_loop, elke minuut). Welke containers de
# gebruiker zelf heeft uitgezet staat dan in state.json ("balance": "pinned"); zonder tijdvenster geldt wat in
# Proxmox staat.
CRS_MODES = ("basic", "static", "dynamic")
CRS_METHODS = ("bruteforce", "topsis")
CRS_DEFAULT = {"ha": "basic", "ha-rebalance-on-start": False, "ha-auto-rebalance": False, "ha-auto-rebalance-threshold": 30,
               "ha-auto-rebalance-margin": 10, "ha-auto-rebalance-hold-duration": 3, "ha-auto-rebalance-method": "bruteforce"}
CRS_AUTO_KEYS = ("ha-auto-rebalance-threshold", "ha-auto-rebalance-margin", "ha-auto-rebalance-hold-duration", "ha-auto-rebalance-method")
CRS_KEY_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
CRS_VALUE_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
BAL_HOLD_MAX = 60        # wachtrondes; een ronde van de HA-manager duurt ongeveer 10 seconden
BAL_DAYS = 7             # zo ver terug staan de verplaatsingen in het overzicht
BAL_MOVES_MAX = 30
BAL_CACHE = {"t": 0.0, "moves": []}
bal_lock = threading.Lock()


def crs_flag(value) -> bool:
    return str(value).strip().lower() in ("1", "yes", "on", "true")


def crs_number(value, low, high, default):
    try:
        n = float(value)
    except (TypeError, ValueError):
        return default
    if n != n or not low <= n <= high:   # n != n: geen getal (nan)
        return default
    return int(n) if n == int(n) else round(n, 2)


def crs_read(raw) -> tuple:
    """De CRS-instelling van het cluster ('ha=static,ha-rebalance-on-start=1', of al uitgepakt) als waarden, met de
    standaard van Proxmox waar niets staat, plus de sleutels die de tool niet kent: die blijven bij opslaan staan."""
    found = dict(raw) if isinstance(raw, dict) else parse_options(raw or "")
    found.pop("", None)
    v = dict(CRS_DEFAULT)
    if found.get("ha") in CRS_MODES:
        v["ha"] = found["ha"]
    for key in ("ha-rebalance-on-start", "ha-auto-rebalance"):
        if key in found:
            v[key] = crs_flag(found[key])
    for key, low, high in (("ha-auto-rebalance-threshold", 0, 100), ("ha-auto-rebalance-margin", 0, 100),
                           ("ha-auto-rebalance-hold-duration", 0, 10 ** 6)):
        if key in found:
            v[key] = crs_number(found[key], low, high, CRS_DEFAULT[key])
    if found.get("ha-auto-rebalance-method") in CRS_METHODS:
        v["ha-auto-rebalance-method"] = found["ha-auto-rebalance-method"]
    other = {k: str(x) for k, x in found.items()
             if k not in CRS_DEFAULT and CRS_KEY_RE.match(str(k)) and CRS_VALUE_RE.match(str(x))}
    return v, other


def crs_text(v: dict, other: dict | None = None) -> str | None:
    """Terug naar de tekst voor Proxmox; None als alles op de standaard staat (dan gaat de instelling weg)."""
    parts = [f"ha={v['ha']}"]
    if v["ha-rebalance-on-start"]:
        parts.append("ha-rebalance-on-start=1")
    if v["ha-auto-rebalance"]:   # de fijnafstelling mag alleen als de loadbalancer aan staat
        parts.append("ha-auto-rebalance=1")
        parts += [f"{k}={v[k]}" for k in CRS_AUTO_KEYS]
    parts += [f"{k}={x}" for k, x in sorted((other or {}).items())]
    return None if parts == ["ha=basic"] else ",".join(parts)


def pve_version(api) -> tuple:
    """(9, 2, 21) voor Proxmox VE 9.2.21; (0,) als het niet te lezen is."""
    try:
        text = str(api.version.get().get("version") or "")
    except ResourceException:
        return (0,)
    return tuple(int(x) for x in re.findall(r"\d+", text)[:3]) or (0,)


def balance_config() -> dict:
    cfg = {"window": False, "from": "02:00", "to": "05:00", "pinned": []}
    saved = state.load().get("balance")
    if not isinstance(saved, dict):
        return cfg
    cfg["window"] = saved.get("window") is True
    for key in ("from", "to"):
        if isinstance(saved.get(key), str) and TIME_RE.match(saved[key]):
            cfg[key] = saved[key]
    if isinstance(saved.get("pinned"), list):
        cfg["pinned"] = sorted({s for s in saved["pinned"] if isinstance(s, str) and HA_SID_RE.match(s) and s.startswith("ct:")})
    return cfg


def bal_minutes(hhmm: str) -> int:
    return int(hhmm[:2]) * 60 + int(hhmm[3:])


def bal_window_open(cfg: dict, now=None) -> bool:
    """Of het tijdvenster voor containers nu open is; een venster als 22:00-05:00 loopt over middernacht."""
    now = now or dt.datetime.now(REPORT_TZ)
    m, a, b = now.hour * 60 + now.minute, bal_minutes(cfg["from"]), bal_minutes(cfg["to"])
    return a <= m < b if a < b else (m >= a or m < b)


def bal_flag(resource: dict) -> bool:
    """auto-rebalance van een HA-guest; zonder waarde geldt de standaard van Proxmox: aan."""
    value = resource.get("auto-rebalance")
    return True if value is None else crs_flag(value)


def bal_wanted(sid: str, cfg: dict, now=None):
    """Wat auto-rebalance van deze HA-guest volgens het tijdvenster moet zijn; None als de tool hem niet regelt."""
    if not (cfg["window"] and sid.startswith("ct:")):
        return None
    return bal_window_open(cfg, now) and sid not in cfg["pinned"]


def bal_set(api, sid: str, on: bool):
    api.cluster.ha.resources(sid).put(**{"auto-rebalance": 1 if on else 0})


def balance_sync(api, cfg: dict | None = None, now=None) -> tuple:
    """Zet auto-rebalance van de HA-containers goed volgens het tijdvenster. Geeft (veranderd, mislukt)."""
    cfg = cfg or balance_config()
    changed, failed = [], []
    if not cfg["window"]:
        return changed, failed
    for r in api.cluster.ha.resources.get():
        sid = str(r.get("sid") or "")
        if not HA_SID_RE.match(sid):
            continue
        want = bal_wanted(sid, cfg, now)
        if want is None or bal_flag(r) == want:
            continue
        try:
            bal_set(api, sid, want)
            changed.append((sid, want))
        except ResourceException as err:
            failed.append((sid, str(err.status_message or err)[:120]))
    return changed, failed


def bal_note(changed: list, failed: list, why: str = ""):
    """Schrijft de uitkomst van het bijstellen in het logboek en onthoudt een mislukking voor de aandachtspunten."""
    texts = {(True, True): "tijdvenster open: containers doen mee aan het verdelen",
             (False, True): "buiten het tijdvenster: containers doen niet mee aan het verdelen",
             (True, False): "containers doen weer mee aan het verdelen", (False, False): "containers doen niet mee aan het verdelen"}
    for want in (True, False):
        sids = [s for s, w in changed if w is want]
        if sids:
            state.event("balance", texts[(want, why == "tijdvenster")], target=", ".join(s.partition(":")[2] for s in sids)[:200], by="automatisch")
    try:
        if failed:
            state.change(lambda d: d.update(balance_error={"t": int(time.time()), "who": [s for s, _ in failed][:12],
                                                            "text": "; ".join(f"{s}: {e}" for s, e in failed)[:300]}))
        elif "balance_error" in state.load():
            state.change(lambda d: d.pop("balance_error", None))
    except OSError:
        pass


def balance_loop():
    while True:
        time.sleep(60)
        try:
            cfg = balance_config()
            if not cfg["window"]:
                continue
            with bal_lock:
                changed, failed = pve.run(lambda api: balance_sync(api, cfg))
            if changed or failed or "balance_error" in state.load():
                bal_note(changed, failed, "tijdvenster")
        except Exception:  # noqa: BLE001 - Proxmox even niet te bereiken: over een minuut opnieuw; de lus mag nooit stoppen
            pass


def balance_moves(api, ha_sids: set) -> list:
    """De verplaatsingen van de afgelopen week (nieuwste eerst): van welke node naar welke, en wie ze startte.
    Een migratie als root@pam van een HA-guest zonder verzoek via de API ervoor (hamigrate) heeft de HA-manager zelf
    uitgevoerd: door de loadbalancer, bij het starten, door een regel, of op opdracht op de node (ha-manager)."""
    since = int(time.time()) - BAL_DAYS * 86400
    tasks = []
    for n in api.nodes.get():
        if n.get("status") != "online":
            continue
        for typ in ("vzmigrate", "qmigrate", "hamigrate"):
            try:
                tasks += [dict(x, node=x.get("node") or n["node"]) for x in
                          api.nodes(n["node"]).tasks.get(typefilter=typ, since=since, limit=200, source="all")]
            except ResourceException:
                pass
    asked = [x for x in tasks if x.get("type") == "hamigrate"]
    rows = []
    moves = sorted((x for x in tasks if x.get("type") in ("vzmigrate", "qmigrate") and x.get("upid")), key=lambda x: -(x.get("starttime") or 0))
    for x in moves[:BAL_MOVES_MAX]:
        vid, start = str(x.get("id") or ""), x.get("starttime") or 0
        kind = "qemu" if x["type"] == "qmigrate" else "lxc"
        request = next((r for r in asked if str(r.get("id")) == vid and 0 <= start - (r.get("starttime") or 0) <= 600), None)
        target = None
        try:
            for line in api.nodes(x["node"]).tasks(x["upid"]).log.get(limit=8):
                found = re.search(r"to node '([^']+)'", str(line.get("t") or ""))
                if found:
                    target = found.group(1)
                    break
        except ResourceException:
            pass
        sid = f"{'vm' if kind == 'qemu' else 'ct'}:{vid}"
        user = str((request or x).get("user") or "")
        by_ha = not request and user == "root@pam" and sid in ha_sids
        status = str(x.get("status") or "")
        rows.append({"vmid": int(vid) if vid.isdigit() else None, "type": kind, "from": x["node"], "to": target, "start": start,
                     "end": x.get("endtime"), "ok": task_ok(status) if x.get("endtime") else None, "status": status[:120],
                     "by": "ha" if by_ha else "user", "user": None if by_ha else user[:64], "upid": x["upid"],
                     "tool": not by_ha and user.split("!")[0] == PVE_USER})
    return rows


def balance_view(api) -> dict:
    cfg = balance_config()
    try:
        raw = (api.cluster.options.get() or {}).get("crs")
    except ResourceException:
        raw = None
    values, other = crs_read(raw)
    version = pve_version(api)
    try:
        imbalance = ((api.cluster.ha.status.manager_status.get() or {}).get("manager_status") or {}).get("imbalance")
    except ResourceException:
        imbalance = None
    resources = api.cluster.ha.resources.get()
    listed = [g for g in api.cluster.resources.get(type="vm") if isinstance(g.get("vmid"), int)]
    guests, shared = {g["vmid"]: g for g in listed}, shared_storages(api)
    try:
        rules = api.cluster.ha.rules.get()
    except ResourceException:
        rules = []
    in_rule = {}
    for rule in rules or []:
        for sid in ha_list(rule.get("resources")):
            in_rule.setdefault(sid, []).append(str(rule.get("rule") or "")[:80])
    rows, ha_sids = [], set()
    for r in resources:
        sid = str(r.get("sid") or "")
        m = HA_SID_RE.match(sid)
        if not m:
            continue
        ha_sids.add(sid)
        vmid, kind = int(m.group(2)), HA_KIND[m.group(1)]
        g = guests.get(vmid) or {}
        want = bal_wanted(sid, cfg)
        rows.append({"sid": sid, "vmid": vmid, "type": kind, "name": g.get("name"), "node": g.get("node"), "status": g.get("status"),
                     "exists": bool(g), "state": r.get("state") or "started", "flag": bal_flag(r),
                     # doet mee: zonder tijdvenster wat in Proxmox staat; met venster wat de gebruiker koos
                     "takes_part": (sid not in cfg["pinned"]) if want is not None else bal_flag(r), "window": want is not None,
                     "local": ha_local(api, g.get("node"), kind, vmid, shared) if g else None, "rules": in_rule.get(sid, [])})
    ha_vmids = {row["vmid"] for row in rows}
    free = [{"vmid": v, "type": g.get("type"), "name": g.get("name"), "node": g.get("node"), "status": g.get("status")}
            for v, g in sorted(guests.items()) if v not in ha_vmids and not g.get("template")]
    nodes = []
    for n in sorted(api.nodes.get(), key=lambda x: str(x.get("node"))):
        here = [g for g in listed if g.get("node") == n.get("node") and g.get("status") == "running" and not g.get("template")]
        nodes.append({"node": n.get("node"), "online": n.get("status") == "online", "cpu": n.get("cpu"), "maxcpu": n.get("maxcpu"),
                      "mem": n.get("mem"), "maxmem": n.get("maxmem"), "running": len(here),
                      "ha": sum(1 for g in here if g["vmid"] in ha_vmids)})
    if time.time() - BAL_CACHE["t"] > 60:
        BAL_CACHE.update(t=time.time(), moves=balance_moves(api, ha_sids))
    saved = state.load()
    error = saved.get("balance_error") if isinstance(saved.get("balance_error"), dict) else None
    return {"crs": values, "other": other, "imbalance": imbalance if isinstance(imbalance, (int, float)) else None,
            "version": ".".join(str(x) for x in version), "supported": version >= (9, 2),
            "window": {"on": cfg["window"], "from": cfg["from"], "to": cfg["to"], "open": bal_window_open(cfg)},
            "guests": sorted(rows, key=lambda x: x["vmid"]), "free": free, "nodes": nodes, "moves": BAL_CACHE["moves"],
            "error": error, "self_vmid": own_vmid(listed), "modes": list(CRS_MODES), "methods": list(CRS_METHODS), "hold_max": BAL_HOLD_MAX}


@app.get("/api/balance")
def balance_get(_: str = Depends(auth)):
    """De loadbalancer: de instelling van Proxmox, de nodes, welke HA-guests meedoen en de verplaatsingen."""
    return pve.run(balance_view)


class BalanceIn(BaseModel):
    mode: str = Field("basic", max_length=10)
    rebalance_on_start: bool = False
    auto: bool = False
    threshold: int = Field(30, strict=True)
    margin: int = Field(10, strict=True)
    hold: int = Field(3, strict=True)
    method: str = Field("bruteforce", max_length=12)
    window: bool = False
    window_from: str = Field("02:00", max_length=5)
    window_to: str = Field("05:00", max_length=5)


@app.put("/api/balance")
def balance_put(body: BalanceIn, request: Request, user: str = Depends(manage_overview)):
    """Slaat de CRS-instelling op in Proxmox en het tijdvenster voor containers in de tool, en zet daarna het meedoen
    van de containers goed. Wat Proxmox zelf weigert (bijvoorbeeld een oudere versie) komt terug als foutmelding."""
    same_origin(request)
    if body.mode not in CRS_MODES:
        raise HTTPException(400, "Onbekende manier van plaatsen")
    if body.method not in CRS_METHODS:
        raise HTTPException(400, "Onbekende rekenmethode")
    if body.auto and body.mode == "basic":
        raise HTTPException(400, "De loadbalancer werkt alleen als Proxmox naar het gebruik kijkt: kies Dynamisch of Statisch")
    if not (0 <= body.threshold <= 100 and 0 <= body.margin <= 100):
        raise HTTPException(400, "De drempel en de verbetering zijn een percentage van 0 tot en met 100")
    if not 0 <= body.hold <= BAL_HOLD_MAX:
        raise HTTPException(400, "Wachtrondes: 0 tot en met 60")
    if not (TIME_RE.match(body.window_from) and TIME_RE.match(body.window_to)):
        raise HTTPException(400, "Ongeldige tijd; gebruik uu:mm, bijvoorbeeld 05:00")
    if body.window and body.window_from == body.window_to:
        raise HTTPException(400, "Het tijdvenster moet een begin en een ander einde hebben")
    before = balance_config()

    def f(api):
        if body.auto and pve_version(api) < (9, 2):
            raise HTTPException(409, "De loadbalancer van Proxmox bestaat pas vanaf Proxmox VE 9.2; werk de nodes eerst bij")
        try:
            raw = (api.cluster.options.get() or {}).get("crs")
        except ResourceException:
            raw = None
        old, other = crs_read(raw)
        new = dict(old, **{"ha": body.mode, "ha-rebalance-on-start": body.rebalance_on_start, "ha-auto-rebalance": body.auto})
        if body.auto:
            new.update({"ha-auto-rebalance-threshold": body.threshold, "ha-auto-rebalance-margin": body.margin,
                        "ha-auto-rebalance-hold-duration": body.hold, "ha-auto-rebalance-method": body.method})
        text = crs_text(new, other)
        if text != crs_text(old, other):
            try:
                api.cluster.options.put(**({"crs": text} if text else {"delete": "crs"}))
            except ResourceException as err:
                raise HTTPException(400, f"Proxmox weigerde de instelling: {err.status_message} {err.content or ''}".strip()[:300])
        pinned = set(before["pinned"])
        if body.window and not before["window"]:   # nu gaat de tool het meedoen van containers regelen: neem over wat er staat
            pinned = {str(r.get("sid")) for r in api.cluster.ha.resources.get()
                      if str(r.get("sid") or "").startswith("ct:") and HA_SID_RE.match(str(r.get("sid"))) and not bal_flag(r)}
        cfg = {"window": body.window, "from": body.window_from, "to": body.window_to, "pinned": sorted(pinned)}
        state.change(lambda d: d.update(balance=cfg))
        changed, failed = balance_sync(api, cfg)
        if before["window"] and not body.window:   # venster uit: de containers doen weer mee zoals de gebruiker koos
            for r in api.cluster.ha.resources.get():
                sid = str(r.get("sid") or "")
                if sid.startswith("ct:") and HA_SID_RE.match(sid) and bal_flag(r) != (sid not in pinned):
                    try:
                        bal_set(api, sid, sid not in pinned)
                        changed.append((sid, sid not in pinned))
                    except ResourceException as err:
                        failed.append((sid, str(err.status_message or err)[:120]))
        return old["ha-auto-rebalance"], changed, failed

    with bal_lock:
        was_on, changed, failed = pve.run(f)
    words = ("loadbalancer aangezet" if body.auto and not was_on else "loadbalancer uitgezet" if was_on and not body.auto
             else "instellingen van de loadbalancer aangepast")
    state.event("balance", words, target="", name=f"{body.mode}" + (f", {body.window_from}-{body.window_to}" if body.window else ""), user=user)
    bal_note(changed, failed)
    BAL_CACHE["t"] = 0
    return pve.run(balance_view)


class BalanceGuestIn(BaseModel):
    auto: bool


@app.put("/api/balance/guest/{sid}")
def balance_guest(sid: str, body: BalanceGuestIn, request: Request, user: str = Depends(manage_overview)):
    """Of een HA-guest meedoet aan het automatisch verdelen. Een container met tijdvenster doet buiten het venster
    toch niet mee; de keuze geldt dan voor de uren binnen het venster."""
    same_origin(request)

    def f(api):
        found = ha_guest(api, sid)
        if not ha_in(api, sid):
            raise HTTPException(404, "Deze guest staat niet in HA; alleen guests in HA doen mee aan het verdelen")
        cfg = balance_config()
        pinned = set(cfg["pinned"])
        if sid.startswith("ct:"):
            (pinned.discard if body.auto else pinned.add)(sid)
            cfg["pinned"] = sorted(pinned)
            state.change(lambda d: d.update(balance={**cfg}))
        want = bal_wanted(sid, cfg)
        bal_set(api, sid, body.auto if want is None else want)
        return found

    with bal_lock:
        found = pve.run(f)
    state.event("balance", "doet mee aan het verdelen" if body.auto else "doet niet mee aan het verdelen", node=found.get("node"),
                target=str(found["vmid"]), name=found.get("name") or "", user=user)
    return pve.run(balance_view)


# ---------------------------------------------------------------- HA instellen (steeksleutel op het tabblad HA)
# Wat HA nodig heeft (gereedheid), de regels (Proxmox 9: voorkeur voor nodes en samen/apart), wat HA doet bij het
# uitzetten van een node (shutdown_policy), en HA tijdelijk uitschakelen voor clusteronderhoud (disarm/arm, 9.2).
HA_RULE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{1,62}$")
HA_RULE_TYPES = ("node-affinity", "resource-affinity")
HA_ARM_MODES = ("freeze", "ignore")
HA_PRIO_MAX = 1000


def ha_rule_row(r: dict) -> dict:
    nodes = []
    for part in ha_list(r.get("nodes")):
        name, _, prio = part.partition(":")
        nodes.append({"node": name, "prio": int(prio) if prio.isdigit() else 0})
    kind = r.get("type")
    return {"rule": str(r.get("rule") or "")[:80], "type": kind, "resources": ha_list(r.get("resources")), "nodes": nodes,
            "strict": crs_flag(r.get("strict", 0)), "affinity": r.get("affinity") or ("positive" if kind == "node-affinity" else None),
            "disabled": crs_flag(r.get("disable", 0)), "comment": str(r.get("comment") or "")[:200], "digest": r.get("digest")}


def guest_storages(api) -> list:
    """Gedeelde opslag waar schijven van VM's of containers op kunnen (wat HA nodig heeft om guests te verhuizen)."""
    names = set()
    for s in api.cluster.resources.get(type="storage"):
        content = set(str(s.get("content") or "").split(","))
        if s.get("shared") and content & {"images", "rootdir"}:
            names.add(s.get("storage"))
    return sorted(n for n in names if n)


def ha_setup_view(api) -> dict:
    status = api.cluster.status.get()
    members = [e for e in status if e.get("type") == "node"]
    online = [e for e in members if e.get("online")]
    quorate = any(e.get("type") == "cluster" and e.get("quorate") for e in status) or (len(members) <= 1 and bool(online))
    try:
        current = api.cluster.ha.status.current.get()
    except ResourceException:
        current = []
    fencing = next((e for e in current if e.get("type") == "fencing"), None)
    master = next((e for e in current if e.get("type") == "master"), None)
    lrms = sorted(({"node": e.get("node"), "state": ha_word(e.get("status")), "watchdog": "watchdog active" in str(e.get("status") or "")}
                   for e in current if e.get("type") == "lrm"), key=lambda x: str(x["node"]))
    try:
        rules, rules_ok = api.cluster.ha.rules.get(), True
    except ResourceException:
        rules, rules_ok = [], False
    try:
        opts = api.cluster.options.get() or {}
    except ResourceException:
        opts = {}
    ha_opt = opts.get("ha")
    ha_opt = ha_opt if isinstance(ha_opt, dict) else parse_options(ha_opt)
    policy = ha_opt.get("shutdown_policy") if ha_opt.get("shutdown_policy") in HA_POLICIES else "conditional"
    listed = [g for g in api.cluster.resources.get(type="vm") if isinstance(g.get("vmid"), int) and not g.get("template")]
    guests = {g["vmid"]: g for g in listed}
    shared, rows = shared_storages(api), []
    for r in api.cluster.ha.resources.get():
        sid = str(r.get("sid") or "")
        m = HA_SID_RE.match(sid)
        if not m:
            continue
        g = guests.get(int(m.group(2))) or {}
        rows.append({"sid": sid, "vmid": int(m.group(2)), "type": HA_KIND[m.group(1)], "name": g.get("name"), "node": g.get("node"),
                     "local": ha_local(api, g.get("node"), HA_KIND[m.group(1)], int(m.group(2)), shared) if g else None})
    store = guest_storages(api)
    armed = str((fencing or {}).get("armed-state") or "") or None
    local = [r["sid"] for r in rows if r["local"]]
    checks = [
        {"code": "nodes", "level": "ok" if len(members) >= 3 else "warn" if len(members) == 2 else "bad", "count": len(members), "online": len(online)},
        {"code": "quorum", "level": "ok" if quorate else "bad"},
        {"code": "shared", "level": "ok" if store else "bad", "names": store},
        {"code": "manager", "level": "ok" if master and ha_word(master.get("status")) == "active" else "warn",
         "node": (master or {}).get("node"), "state": ha_word((master or {}).get("status")) if master else None},
        {"code": "watchdog", "level": "ok" if lrms and all(x["state"] in ("active", "idle") for x in lrms) else "warn", "nodes": lrms},
        {"code": "fencing", "level": "ok" if armed in (None, "armed") else "warn", "state": armed},
        {"code": "guests", "level": "ok" if rows else "warn", "count": len(rows), "not_ha": sum(1 for v in guests if v not in {r["vmid"] for r in rows})},
        {"code": "local", "level": "warn" if local else "ok", "who": local[:20]},
    ]
    return {"checks": checks, "policy": policy, "policies": list(HA_POLICIES), "fencing": armed, "modes": list(HA_ARM_MODES),
            "rules": [ha_rule_row(r) for r in rules], "rules_supported": rules_ok, "resources": rows,
            "nodes": sorted(e.get("name") for e in members if e.get("name")), "supported_arm": pve_version(api) >= (9, 2),
            "self_vmid": own_vmid(listed), "prio_max": HA_PRIO_MAX}


@app.get("/api/ha-setup")
def ha_setup_get(_: str = Depends(auth)):
    """Voor het venster HA instellen: gereedheid, regels en instellingen."""
    return pve.run(ha_setup_view)


class HaSetupIn(BaseModel):
    shutdown_policy: str = Field(max_length=12)


@app.put("/api/ha-setup")
def ha_setup_put(body: HaSetupIn, request: Request, user: str = Depends(manage_overview)):
    """Wat HA doet als een node wordt uitgezet of herstart (Datacenter > Opties > HA-instellingen)."""
    same_origin(request)
    if body.shutdown_policy not in HA_POLICIES:
        raise HTTPException(400, "Onbekende keuze voor het uitzetten van een node")
    pve.run(lambda api: api.cluster.options.put(ha=f"shutdown_policy={body.shutdown_policy}"))
    state.event("ha", "HA-instelling aangepast", target="", name=body.shutdown_policy, user=user)
    return pve.run(ha_setup_view)


class HaArmIn(BaseModel):
    mode: str = Field("freeze", max_length=8)


@app.post("/api/ha-setup/disarm")
def ha_disarm(body: HaArmIn, request: Request, user: str = Depends(manage_overview)):
    """HA tijdelijk uitschakelen voor clusteronderhoud: geen fencing, geen herstel. Weer aan met /api/ha-setup/arm."""
    same_origin(request)
    if body.mode not in HA_ARM_MODES:
        raise HTTPException(400, "Onbekende keuze voor de guests tijdens het onderhoud")

    def f(api):
        if pve_version(api) < (9, 2):
            raise HTTPException(409, "HA tijdelijk uitschakelen kan pas vanaf Proxmox VE 9.2")
        fencing = next((e for e in api.cluster.ha.status.current.get() if e.get("type") == "fencing"), {})
        if str(fencing.get("armed-state") or "") in ("disarming", "disarmed"):
            raise HTTPException(409, "HA staat al uit voor onderhoud")
        api.cluster.ha.status("disarm-ha").post(**{"resource-mode": body.mode})
    pve.run(f)
    state.event("ha", "HA uitgeschakeld voor onderhoud", target="", name=body.mode, user=user)
    return pve.run(ha_setup_view)


@app.post("/api/ha-setup/arm")
def ha_arm(request: Request, user: str = Depends(manage_overview)):
    same_origin(request)

    def f(api):
        fencing = next((e for e in api.cluster.ha.status.current.get() if e.get("type") == "fencing"), {})
        if str(fencing.get("armed-state") or "armed") == "armed":
            raise HTTPException(409, "HA staat al aan")
        api.cluster.ha.status("arm-ha").post()
    pve.run(f)
    state.event("ha", "HA weer ingeschakeld", target="", user=user)
    return pve.run(ha_setup_view)


class HaRuleNode(BaseModel):
    node: str = Field(max_length=63)
    prio: int = Field(0, strict=True)


class HaRuleIn(BaseModel):
    rule: str = Field(max_length=64)
    type: str = Field(max_length=20)
    resources: list[str] = Field(max_length=64)
    nodes: list[HaRuleNode] = Field(default_factory=list, max_length=64)
    strict: bool = False
    affinity: str = Field("positive", max_length=10)
    disabled: bool = False
    comment: str = Field("", max_length=200)
    digest: str | None = Field(None, pattern="^[0-9a-f]{40,64}$")


def ha_rule_params(api, body: HaRuleIn) -> dict:
    """Controleert een regel en maakt er de parameters voor Proxmox van (zonder de naam)."""
    if body.type not in HA_RULE_TYPES:
        raise HTTPException(400, "Onbekende soort regel")
    if body.affinity not in ("positive", "negative"):
        raise HTTPException(400, "Onbekende keuze bij samen of apart")
    comment = body.comment.strip()
    if any(ord(c) < 32 or ord(c) == 127 for c in comment):
        raise HTTPException(400, "De opmerking mag geen regeleinden of stuurtekens bevatten")
    have = {str(r.get("sid")) for r in api.cluster.ha.resources.get()}
    sids = list(dict.fromkeys(s.strip() for s in body.resources))
    missing = [s for s in sids if not HA_SID_RE.match(s) or s not in have]
    if missing:
        raise HTTPException(400, "Deze guests staan niet in HA: {0}".format(", ".join(missing[:8])[:200]))
    nodes = [n["node"] for n in api.nodes.get()]
    params = {"type": body.type, "resources": ",".join(sids), "disable": 1 if body.disabled else 0}
    if body.type == "node-affinity":
        if not sids:
            raise HTTPException(400, "Kies minstens één guest")
        picked = {}
        for n in body.nodes:
            if n.node not in nodes:
                raise HTTPException(400, "Onbekende node: {0}".format(n.node[:63]))
            if not 0 <= n.prio <= HA_PRIO_MAX:
                raise HTTPException(400, "Prioriteit: 0 tot en met 1000")
            picked[n.node] = n.prio
        if not picked:
            raise HTTPException(400, "Kies minstens één node")
        if body.affinity == "negative" and len(picked) >= len(nodes):
            raise HTTPException(400, "Met 'niet op deze nodes' moet er minstens één node overblijven")
        params.update(nodes=",".join(f"{n}:{p}" if p else n for n, p in picked.items()), strict=1 if body.strict else 0, affinity=body.affinity)
    else:
        if len(sids) < 2:
            raise HTTPException(400, "Kies minstens twee guests")
        if body.affinity == "negative" and len(sids) > len(nodes):
            raise HTTPException(400, "Niet samen op één node kan hier niet: {0} guests en maar {1} nodes".format(len(sids), len(nodes)))
        params["affinity"] = body.affinity
    if comment:
        params["comment"] = comment
    return params


def ha_rules_on(api):
    try:
        return api.cluster.ha.rules.get()
    except ResourceException:
        raise HTTPException(409, "Deze Proxmox-versie kent geen HA-regels (vanaf Proxmox VE 9); gebruik daar de HA-groepen")


@app.post("/api/ha-rules")
def ha_rule_add(body: HaRuleIn, request: Request, user: str = Depends(manage_overview)):
    same_origin(request)
    if not HA_RULE_RE.match(body.rule):
        raise HTTPException(400, "Naam van de regel: begint met een letter, 2 tot 63 tekens: letters, cijfers, - en _")

    def f(api):
        if any(str(r.get("rule")) == body.rule for r in ha_rules_on(api)):
            raise HTTPException(409, "Er is al een regel met deze naam")
        api.cluster.ha.rules.post(rule=body.rule, **ha_rule_params(api, body))
    pve.run(f)
    state.event("ha", "HA-regel toegevoegd", target=body.rule, name=body.type, user=user)
    return pve.run(ha_setup_view)


@app.put("/api/ha-rules/{rule}")
def ha_rule_change(rule: str, body: HaRuleIn, request: Request, user: str = Depends(manage_overview)):
    same_origin(request)
    if not HA_RULE_RE.match(rule) or body.rule != rule:
        raise HTTPException(400, "Ongeldige naam van de regel")

    def f(api):
        old = next((r for r in ha_rules_on(api) if str(r.get("rule")) == rule), None)
        if not old:
            raise HTTPException(404, "Deze regel bestaat niet (meer)")
        if old.get("type") != body.type:
            raise HTTPException(400, "De soort van een regel kun je niet wijzigen; maak een nieuwe regel")
        params = ha_rule_params(api, body)
        if "comment" not in params and old.get("comment"):
            params["delete"] = "comment"
        if body.digest:
            params["digest"] = body.digest
        api.cluster.ha.rules(rule).put(**params)
    pve.run(f)
    state.event("ha", "HA-regel aangepast", target=rule, name=body.type, user=user)
    return pve.run(ha_setup_view)


@app.delete("/api/ha-rules/{rule}")
def ha_rule_delete(rule: str, request: Request, user: str = Depends(manage_overview)):
    same_origin(request)
    if not HA_RULE_RE.match(rule):
        raise HTTPException(400, "Ongeldige naam van de regel")

    def f(api):
        if not any(str(r.get("rule")) == rule for r in ha_rules_on(api)):
            raise HTTPException(404, "Deze regel bestaat niet (meer)")
        api.cluster.ha.rules(rule).delete()
    pve.run(f)
    state.event("ha", "HA-regel verwijderd", target=rule, user=user)
    return pve.run(ha_setup_view)


# ---------------------------------------------------------------- Ceph instellen (steeksleutel op het tabblad Opslag)
# Bekijken en beheren van monitors, managers, OSD's, pools en vlaggen, en Ceph inrichten op een cluster waar de
# pakketten al staan (installeren doe je per node met pveceph install). Alles wat data in gevaar kan brengen vraagt
# Ceph eerst of het veilig is (cmd-safety) of houdt de tool zelf tegen: geen OSD stoppen of verwijderen die Ceph nog
# nodig heeft, geen laatste monitor of manager weg, geen pool weg waar nog schijven op staan.
CEPH_FLAGS = ("noout", "noin", "norebalance", "norecover", "nobackfill", "noscrub", "nodeep-scrub")   # pause, noup, nodown niet
CEPH_POOL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$")
CEPH_APPS = ("rbd", "cephfs", "rgw")
CEPH_AUTOSCALE = ("on", "warn", "off")
CEPH_CLASSES = ("", "ssd", "hdd", "nvme")
CEPH_DEV_RE = re.compile(r"^/dev/[A-Za-z0-9][A-Za-z0-9/_.-]{0,60}$")


def ceph_state(api, node: str) -> tuple:
    """('ok', status) als Ceph op deze node draait, anders ('absent'|'unconfigured'|'error', melding)."""
    try:
        return "ok", api.nodes(node).ceph.status.get()
    except ResourceException as err:
        text = f"{err.status_message} {err.content or ''}".strip()
        low = text.lower()
        if "not installed" in low:
            return "absent", text[:200]
        if "not initialized" in low or "no such file" in low or "rados_connect" in low or "not configured" in low:
            return "unconfigured", text[:200]
        return "error", text[:200]


def ceph_osd_tree(api, node: str) -> list:
    try:
        tree = api.nodes(node).ceph.osd.get()
    except ResourceException:
        return []
    out, todo = [], [tree.get("root") or {}]
    while todo:
        n = todo.pop()
        todo.extend(n.get("children", []))
        if n.get("type") == "osd" and str(n.get("id")).isdigit():   # Proxmox geeft het nummer als tekst ("0")
            out.append({"id": int(n["id"]), "name": n.get("name"), "host": n.get("host"), "up": n.get("status") == "up", "in": bool(n.get("in")),
                        "class": n.get("device_class"), "used": n.get("bytes_used"), "total": n.get("total_space")})
    return sorted(out, key=lambda o: o["id"])


def ceph_free_disks(api, node: str) -> list:
    try:
        disks = api.nodes(node).disks.list.get()
    except ResourceException:
        return []
    return [{"dev": d.get("devpath"), "size": d.get("size"), "type": d.get("type"), "model": str(d.get("model") or "")[:80]}
            for d in sorted(disks, key=lambda d: str(d.get("devpath"))) if not d.get("used") and CEPH_DEV_RE.match(str(d.get("devpath") or ""))]


def ceph_setup_view(api) -> dict:
    nodes = sorted(api.nodes.get(), key=lambda n: str(n.get("node")))
    per, first, status = [], None, None
    for n in nodes:
        name, up = n.get("node"), n.get("status") == "online"
        kind, data = ceph_state(api, name) if up else ("offline", None)
        if kind == "ok" and first is None:
            first, status = name, data
        per.append({"node": name, "online": up, "ceph": kind, "message": data if isinstance(data, str) else None,
                    "free": ceph_free_disks(api, name) if up else []})
    out = {"configured": first is not None, "nodes": per, "flags_allowed": list(CEPH_FLAGS), "apps": list(CEPH_APPS),
           "autoscale": list(CEPH_AUTOSCALE), "classes": [c for c in CEPH_CLASSES if c]}
    if first is None:
        return out
    health = status.get("health") or {}
    mons = [{"name": m.get("name"), "host": m.get("host"), "state": m.get("state"), "quorum": bool(m.get("quorum")), "addr": m.get("addr"),
             "version": m.get("ceph_version_short")} for m in api.nodes(first).ceph.mon.get()]
    mgrs = [{"name": m.get("name"), "host": m.get("host"), "state": m.get("state"), "version": m.get("ceph_version_short")}
            for m in api.nodes(first).ceph.mgr.get()]
    rbd = {}
    try:
        for s in api.storage.get():
            if s.get("type") in ("rbd", "cephfs"):
                rbd.setdefault(s.get("pool") or ("rbd" if s.get("type") == "rbd" else s.get("fs-name") or ""), []).append(s.get("storage"))
    except ResourceException:
        pass
    pools = []
    for p in api.nodes(first).ceph.pool.get():
        name = str(p.get("pool_name") or "")
        pools.append({"name": name, "size": p.get("size"), "min_size": p.get("min_size"), "pg_num": p.get("pg_num"),
                      "autoscale": p.get("pg_autoscale_mode"), "application": sorted((p.get("application_metadata") or {}).keys()),
                      "used": p.get("bytes_used"), "percent": p.get("percent_used"), "system": name.startswith("."),
                      "storages": sorted(rbd.get(name, [])), "type": p.get("type")})
    try:
        flags = {f.get("name"): bool(f.get("value")) for f in api.cluster.ceph.flags.get()}
    except ResourceException:
        flags = {}
    try:
        net = (api.nodes(first).ceph.cfg.value.get(**{"config-keys": "global:public_network;global:cluster_network"}) or {}).get("global") or {}
    except ResourceException:
        net = {}
    try:
        versions = {k: (v.get("version") or {}).get("str") for k, v in ((api.cluster.ceph.metadata.get(scope="versions") or {}).get("node") or {}).items()}
    except ResourceException:
        versions = {}
    out.update({
        "node": first, "health": health.get("status"),
        "checks": [{"code": code, "severity": c.get("severity"), "text": str((c.get("summary") or {}).get("message") or "")[:300]}
                   for code, c in sorted((health.get("checks") or {}).items())][:20],
        "mons": sorted(mons, key=lambda m: str(m["name"])), "mgrs": sorted(mgrs, key=lambda m: str(m["name"])),
        "osds": ceph_osd_tree(api, first), "pools": sorted(pools, key=lambda p: (p["system"], p["name"])), "flags": flags,
        "networks": {"public": net.get("public-network") or net.get("public_network"), "cluster": net.get("cluster-network") or net.get("cluster_network")},
        "versions": versions})
    return out


@app.get("/api/ceph/setup")
def ceph_setup_get(_: str = Depends(auth)):
    return pve.run(ceph_setup_view)


def ceph_first(api) -> str:
    for n in online_nodes(api):
        if ceph_state(api, n)[0] == "ok":
            return n
    raise HTTPException(409, "Ceph draait nog op geen enkele node")


def ceph_node_ok(api, node: str):
    if not NODE_RE.match(node) or node not in online_nodes(api):
        raise HTTPException(400, "Deze node is niet online")


def ceph_safety(api, node: str, service: str, ident: str, action: str) -> dict:
    try:
        r = api.nodes(node).ceph("cmd-safety").get(service=service, id=ident, action=action) or {}
    except ResourceException as err:
        return {"safe": False, "status": f"Ceph kon het niet controleren: {err.status_message}"[:300]}
    return {"safe": bool(r.get("safe")), "status": str(r.get("status") or "")[:300]}


@app.get("/api/ceph/safety")
def ceph_safety_get(service: str, ident: str, action: str, _: str = Depends(auth)):
    """Vraagt Ceph of een OSD of monitor nu veilig kan stoppen of weg kan."""
    if service not in ("osd", "mon") or action not in ("stop", "destroy") or not re.match(r"^[A-Za-z0-9-]{1,63}$", ident):
        raise HTTPException(400, "Ongeldige vraag")
    return pve.run(lambda api: ceph_safety(api, ceph_first(api), service, ident, action))


class CephFlagIn(BaseModel):
    flag: str = Field(max_length=16)
    value: bool


@app.put("/api/ceph/flags")
def ceph_flag(body: CephFlagIn, request: Request, user: str = Depends(manage_storage)):
    same_origin(request)
    if body.flag not in CEPH_FLAGS:
        raise HTTPException(400, "Deze vlag zet de tool niet")

    def f(api):
        ceph_first(api)
        api.cluster.ceph.flags(body.flag).put(value=1 if body.value else 0)
    pve.run(f)
    state.event("ceph", "vlag aangezet" if body.value else "vlag uitgezet", target=body.flag, user=user)
    return pve.run(ceph_setup_view)


class CephNodeIn(BaseModel):
    node: str = Field(max_length=63)


@app.post("/api/ceph/osd/{osdid}/{action}")
def ceph_osd_action(osdid: int, action: str, body: CephNodeIn, request: Request, user: str = Depends(manage_storage)):
    """Een OSD in of uit gebruik nemen, starten of stoppen."""
    same_origin(request)
    if action not in ("in", "out", "start", "stop") or not 0 <= osdid <= 100000:
        raise HTTPException(400, "Onbekende handeling")

    def f(api):
        ceph_node_ok(api, body.node)
        first = ceph_first(api)
        osds = ceph_osd_tree(api, first)
        osd = next((o for o in osds if o["id"] == osdid), None)
        if not osd or osd["host"] != body.node:
            raise HTTPException(404, "Deze OSD staat niet op deze node")
        if action == "out":
            if not osd["in"]:
                raise HTTPException(409, "Deze OSD is al uit gebruik")
            hosts = {o["host"] for o in osds if o["in"] and o["id"] != osdid}
            need = max([p.get("min_size") or 1 for p in api.nodes(first).ceph.pool.get()] or [1])
            if len(hosts) < need:
                raise HTTPException(409, "Dan blijven er te weinig nodes met OSD's in gebruik over ({0}); de pools hebben er minstens {1} nodig".format(len(hosts), need))
            return api.nodes(body.node).ceph.osd(osdid).out.post()
        if action == "in":
            if osd["in"]:
                raise HTTPException(409, "Deze OSD is al in gebruik")
            return api.nodes(body.node).ceph.osd(osdid)("in").post()
        if action == "stop":
            if not osd["up"]:
                raise HTTPException(409, "Deze OSD draait niet")
            safe = ceph_safety(api, first, "osd", str(osdid), "stop")
            if not safe["safe"]:
                raise HTTPException(409, "Ceph raadt stoppen nu af: {0}".format(safe["status"]))
            return api.nodes(body.node).ceph.stop.post(service=f"osd.{osdid}")
        if osd["up"]:
            raise HTTPException(409, "Deze OSD draait al")
        return api.nodes(body.node).ceph.start.post(service=f"osd.{osdid}")
    upid = pve.run(f)
    words = {"in": "OSD in gebruik genomen", "out": "OSD uit gebruik genomen", "start": "OSD gestart", "stop": "OSD gestopt"}[action]
    state.event("ceph", words, node=body.node, target=f"osd.{osdid}", user=user)
    return {"upid": upid if isinstance(upid, str) else None, "node": body.node}


class CephOsdIn(BaseModel):
    node: str = Field(max_length=63)
    dev: str = Field(max_length=70)
    device_class: str = Field("", max_length=8)
    encrypted: bool = False


@app.post("/api/ceph/osd")
def ceph_osd_create(body: CephOsdIn, request: Request, user: str = Depends(manage_storage)):
    """Maakt van een lege schijf een OSD. Alles wat op de schijf staat gaat verloren; de tool neemt alleen schijven die
    Proxmox als ongebruikt ziet."""
    same_origin(request)
    if body.device_class not in CEPH_CLASSES:
        raise HTTPException(400, "Onbekende soort schijf")

    def f(api):
        ceph_node_ok(api, body.node)
        if ceph_state(api, body.node)[0] != "ok":
            raise HTTPException(409, "Ceph draait niet op deze node; voeg daar eerst Ceph toe")
        if body.dev not in {d["dev"] for d in ceph_free_disks(api, body.node)}:
            raise HTTPException(409, "Deze schijf is niet vrij (in gebruik of niet gevonden)")
        params = {"dev": body.dev, "encrypted": 1 if body.encrypted else 0}
        if body.device_class:
            params["crush-device-class"] = body.device_class
        return api.nodes(body.node).ceph.osd.post(**params)
    upid = pve.run(f)
    state.event("ceph", "OSD aangemaakt", node=body.node, target=body.dev, user=user)
    return {"upid": upid, "node": body.node}


@app.delete("/api/ceph/osd/{osdid}")
def ceph_osd_destroy(osdid: int, node: str, request: Request, user: str = Depends(manage_storage)):
    """Haalt een OSD weg en wist de schijf. Alleen als hij gestopt en uit gebruik is, en Ceph zegt dat het veilig is."""
    same_origin(request)

    def f(api):
        ceph_node_ok(api, node)
        first = ceph_first(api)
        osd = next((o for o in ceph_osd_tree(api, first) if o["id"] == osdid), None)
        if not osd or osd["host"] != node:
            raise HTTPException(404, "Deze OSD staat niet op deze node")
        if osd["up"] or osd["in"]:
            raise HTTPException(409, "Neem de OSD eerst uit gebruik en stop hem; wacht tot Ceph klaar is met verplaatsen")
        safe = ceph_safety(api, first, "osd", str(osdid), "destroy")
        if not safe["safe"]:
            raise HTTPException(409, "Ceph raadt verwijderen nu af: {0}".format(safe["status"]))
        return api.nodes(node).ceph.osd(osdid).delete(cleanup=1)
    upid = pve.run(f)
    state.event("ceph", "OSD verwijderd", node=node, target=f"osd.{osdid}", user=user)
    return {"upid": upid, "node": node}


@app.post("/api/ceph/mon")
def ceph_mon_create(body: CephNodeIn, request: Request, user: str = Depends(manage_storage)):
    same_origin(request)

    def f(api):
        ceph_node_ok(api, body.node)
        if ceph_state(api, body.node)[0] not in ("ok", "unconfigured"):
            raise HTTPException(409, "Op deze node staat Ceph niet; installeer het daar eerst")
        try:
            mons = api.nodes(ceph_first(api)).ceph.mon.get()
        except HTTPException:
            mons = []   # Ceph draait nog nergens: net ingericht, dit wordt de eerste monitor
        if any(m.get("host") == body.node or m.get("name") == body.node for m in mons):
            raise HTTPException(409, "Op deze node draait al een monitor")
        return api.nodes(body.node).ceph.mon(body.node).post()
    upid = pve.run(f)
    state.event("ceph", "monitor toegevoegd", node=body.node, target=body.node, user=user)
    return {"upid": upid, "node": body.node}


@app.delete("/api/ceph/mon/{monid}")
def ceph_mon_destroy(monid: str, node: str, request: Request, user: str = Depends(manage_storage)):
    same_origin(request)
    if not NODE_RE.match(monid):
        raise HTTPException(400, "Ongeldige monitor")

    def f(api):
        ceph_node_ok(api, node)
        first = ceph_first(api)
        mons = api.nodes(first).ceph.mon.get()
        mon = next((m for m in mons if m.get("name") == monid), None)
        if not mon or mon.get("host") != node:
            raise HTTPException(404, "Deze monitor staat niet op deze node")
        if len(mons) <= 1:
            raise HTTPException(409, "Dit is de laatste monitor; zonder monitor werkt Ceph niet")
        safe = ceph_safety(api, first, "mon", monid, "stop")
        if not safe["safe"]:
            raise HTTPException(409, "Ceph raadt dit nu af: {0}".format(safe["status"]))
        return api.nodes(node).ceph.mon(monid).delete()
    upid = pve.run(f)
    state.event("ceph", "monitor verwijderd", node=node, target=monid, user=user)
    return {"upid": upid, "node": node}


@app.post("/api/ceph/mgr")
def ceph_mgr_create(body: CephNodeIn, request: Request, user: str = Depends(manage_storage)):
    same_origin(request)

    def f(api):
        ceph_node_ok(api, body.node)
        if ceph_state(api, body.node)[0] != "ok":
            raise HTTPException(409, "Ceph draait niet op deze node; voeg daar eerst een monitor toe")
        if any(m.get("host") == body.node or m.get("name") == body.node for m in api.nodes(ceph_first(api)).ceph.mgr.get()):
            raise HTTPException(409, "Op deze node draait al een manager")
        return api.nodes(body.node).ceph.mgr(body.node).post()
    upid = pve.run(f)
    state.event("ceph", "manager toegevoegd", node=body.node, target=body.node, user=user)
    return {"upid": upid, "node": body.node}


@app.delete("/api/ceph/mgr/{mgrid}")
def ceph_mgr_destroy(mgrid: str, node: str, request: Request, user: str = Depends(manage_storage)):
    same_origin(request)
    if not NODE_RE.match(mgrid):
        raise HTTPException(400, "Ongeldige manager")

    def f(api):
        ceph_node_ok(api, node)
        mgrs = api.nodes(ceph_first(api)).ceph.mgr.get()
        mgr = next((m for m in mgrs if m.get("name") == mgrid), None)
        if not mgr or mgr.get("host") != node:
            raise HTTPException(404, "Deze manager staat niet op deze node")
        if len(mgrs) <= 1:
            raise HTTPException(409, "Dit is de laatste manager; zonder manager werkt Ceph niet goed")
        return api.nodes(node).ceph.mgr(mgrid).delete()
    upid = pve.run(f)
    state.event("ceph", "manager verwijderd", node=node, target=mgrid, user=user)
    return {"upid": upid, "node": node}


class CephPoolIn(BaseModel):
    name: str = Field(max_length=64)
    size: int = Field(3, strict=True)
    min_size: int = Field(2, strict=True)
    autoscale: str = Field("on", max_length=4)
    application: str = Field("rbd", max_length=8)
    add_storage: bool = True


def ceph_pool_check(api, first: str, size: int, min_size: int, autoscale: str):
    if not 2 <= size <= 7:
        raise HTTPException(400, "Aantal kopieën: 2 tot en met 7")
    if not 1 <= min_size <= size:
        raise HTTPException(400, "Minimum: 1 tot en met het aantal kopieën")
    if autoscale not in CEPH_AUTOSCALE:
        raise HTTPException(400, "Onbekende keuze voor het automatisch schalen")
    hosts = {o["host"] for o in ceph_osd_tree(api, first) if o["in"]}
    if size > len(hosts):
        raise HTTPException(400, "{0} kopieën kan niet: er zijn maar {1} nodes met OSD's".format(size, len(hosts)))


@app.post("/api/ceph/pool")
def ceph_pool_create(body: CephPoolIn, request: Request, user: str = Depends(manage_storage)):
    same_origin(request)
    if not CEPH_POOL_RE.match(body.name):
        raise HTTPException(400, "Naam van de pool: letters, cijfers, - en _, hooguit 63 tekens")
    if body.application not in CEPH_APPS:
        raise HTTPException(400, "Onbekende toepassing")

    def f(api):
        first = ceph_first(api)
        if any(p.get("pool_name") == body.name for p in api.nodes(first).ceph.pool.get()):
            raise HTTPException(409, "Er is al een pool met deze naam")
        if body.add_storage and any(s.get("storage") == body.name for s in api.storage.get()):
            raise HTTPException(409, "Er is al een opslag met deze naam in Proxmox")
        ceph_pool_check(api, first, body.size, body.min_size, body.autoscale)
        return api.nodes(first).ceph.pool.post(name=body.name, size=body.size, min_size=body.min_size, pg_autoscale_mode=body.autoscale,
                                               application=body.application, add_storages=1 if body.add_storage and body.application == "rbd" else 0), first
    upid, first = pve.run(f)
    state.event("ceph", "pool aangemaakt", node=first, target=body.name, user=user)
    return {"upid": upid, "node": first}


class CephPoolChange(BaseModel):
    size: int = Field(strict=True)
    min_size: int = Field(strict=True)
    autoscale: str = Field(max_length=4)


@app.put("/api/ceph/pool/{name}")
def ceph_pool_change(name: str, body: CephPoolChange, request: Request, user: str = Depends(manage_storage)):
    same_origin(request)
    if not CEPH_POOL_RE.match(name):
        raise HTTPException(400, "Een pool van Ceph zelf (met een punt ervoor) of met een ongeldige naam past de tool niet aan")

    def f(api):
        first = ceph_first(api)
        if not any(p.get("pool_name") == name for p in api.nodes(first).ceph.pool.get()):
            raise HTTPException(404, "Deze pool bestaat niet (meer)")
        ceph_pool_check(api, first, body.size, body.min_size, body.autoscale)
        return api.nodes(first).ceph.pool(name).put(size=body.size, min_size=body.min_size, pg_autoscale_mode=body.autoscale), first
    upid, first = pve.run(f)
    state.event("ceph", "pool aangepast", node=first, target=name, user=user)
    return {"upid": upid if isinstance(upid, str) else None, "node": first}


@app.delete("/api/ceph/pool/{name}")
def ceph_pool_delete(name: str, request: Request, user: str = Depends(manage_storage)):
    """Haalt een pool weg, met de opslag die Proxmox ervoor heeft. Alleen als er geen schijven meer op staan."""
    same_origin(request)
    if not CEPH_POOL_RE.match(name):
        raise HTTPException(400, "Een pool van Ceph zelf (met een punt ervoor) of met een ongeldige naam verwijdert de tool niet")

    def f(api):
        first = ceph_first(api)
        if not any(p.get("pool_name") == name for p in api.nodes(first).ceph.pool.get()):
            raise HTTPException(404, "Deze pool bestaat niet (meer)")
        for s in api.storage.get():
            if s.get("type") == "rbd" and (s.get("pool") or "rbd") == name:
                items = api.nodes(first).storage(s["storage"]).content.get()
                if items:
                    raise HTTPException(409, "Op opslag {0} staan nog {1} schijven; deze pool verwijdert de tool niet".format(s["storage"], len(items)))
        return api.nodes(first).ceph.pool(name).delete(remove_storages=1), first
    upid, first = pve.run(f)
    state.event("ceph", "pool verwijderd", node=first, target=name, user=user)
    return {"upid": upid, "node": first}


class CephInitIn(BaseModel):
    node: str = Field(max_length=63)
    network: str = Field(max_length=50)
    cluster_network: str = Field("", max_length=50)


def cidr_ok(text: str) -> bool:
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return False
    return "/" in text and net.prefixlen < net.max_prefixlen


@app.post("/api/ceph/init")
def ceph_init(body: CephInitIn, request: Request, user: str = Depends(manage_storage)):
    """Richt Ceph in op een cluster waar het nog niet draait (de pakketten moeten er al staan: pveceph install)."""
    same_origin(request)
    if not cidr_ok(body.network) or (body.cluster_network and not cidr_ok(body.cluster_network)):
        raise HTTPException(400, "Vul een netwerk in met de netwerkgrootte, bijvoorbeeld 10.10.10.0/24")

    def f(api):
        ceph_node_ok(api, body.node)
        states = {n: ceph_state(api, n)[0] for n in online_nodes(api)}
        if "ok" in states.values():
            raise HTTPException(409, "Ceph is al ingericht")
        if states.get(body.node) == "absent":
            raise HTTPException(409, "Op deze node staan de Ceph-pakketten nog niet; draai daar eerst pveceph install")
        params = {"network": body.network}
        if body.cluster_network:
            params["cluster-network"] = body.cluster_network
        api.nodes(body.node).ceph.init.post(**params)
    pve.run(f)
    state.event("ceph", "Ceph ingericht", node=body.node, target=body.network, user=user)
    return pve.run(ceph_setup_view)


# ---------------------------------------------------------------- beveiligingssleutels (WebAuthn: YubiKey, passkey)
# Een sleutel hoort bij één gebruiker en bij de naam waaronder de tool geopend is (rp-id): een sleutel die via het
# Cloudflare-adres is toegevoegd, werkt alleen op dat adres. Browsers staan WebAuthn niet toe op een IP-adres en ook
# niet bij een certificaatfout. In webauthn.json staat per gebruiker een willekeurige handle, de sleutels (alleen de
# openbare sleutel, de teller, een naam) en of de sleutel na het wachtwoord verplicht is. De tool controleert alleen
# handtekeningen (ES256 en RS256, zelf uitgerekend: er komt geen pakket bij) en maakt er nooit zelf een.
WEBAUTHN_FILE = STATE_DIR / "webauthn.json"
WEBAUTHN_MAX_KEYS = 10
WEBAUTHN_TIMEOUT = 120   # seconden om de sleutel aan te raken
WA_TRANSPORTS = ("usb", "nfc", "ble", "internal", "hybrid", "smart-card")
KEY_NAME_RE = re.compile(r"^[^\x00-\x1f\x7f<>\"&]{1,40}$")
CRED_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,1400}$")
HANDLE_RE = re.compile(r"^[A-Za-z0-9_-]{16,90}$")
B64_RE = re.compile(r"^[A-Za-z0-9_-]{2,800}$")
RP_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")
WA_BAD = "Het antwoord van de beveiligingssleutel klopt niet"
WA_UNKNOWN = "De beveiligingssleutel is niet herkend"
WA_EXPIRED = "Het aanmelden met de sleutel duurde te lang of is in een ander venster begonnen; probeer het opnieuw"
WA_IP = "Beveiligingssleutels werken alleen als je de tool via een naam opent (bijvoorbeeld je Cloudflare-adres), niet via een IP-adres"
_webauthn = {"stamp": None, "data": {}}
webauthn_lock = threading.Lock()
_wa_used = {}   # uitdagingen die al gebruikt zijn -> tot wanneer ze bewaard blijven
_wa_used_lock = threading.Lock()


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


# --- P-256 (secp256r1): alleen controleren. Gewone coördinaten; None is het punt op oneindig.
P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
P256_G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
          0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)


def p256_on_curve(pt) -> bool:
    x, y = pt
    return 0 <= x < P256_P and 0 <= y < P256_P and (y * y - (x * x * x - 3 * x + P256_B)) % P256_P == 0


def p256_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    (x1, y1), (x2, y2) = a, b
    if x1 == x2:
        if (y1 + y2) % P256_P == 0:
            return None
        m = (3 * x1 * x1 - 3) * pow(2 * y1, -1, P256_P) % P256_P
    else:
        m = (y2 - y1) * pow(x2 - x1, -1, P256_P) % P256_P
    x3 = (m * m - x1 - x2) % P256_P
    return x3, (m * (x1 - x3) - y1) % P256_P


def p256_mul(k: int, pt):
    out = None
    while k:
        if k & 1:
            out = p256_add(out, pt)
        pt = p256_add(pt, pt)
        k >>= 1
    return out


def p256_verify(x: int, y: int, message: bytes, r: int, s: int) -> bool:
    """ECDSA met SHA-256 op P-256 (ES256)."""
    if not p256_on_curve((x, y)) or not (1 <= r < P256_N and 1 <= s < P256_N):
        return False
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, P256_N)
    pt = p256_add(p256_mul(e * w % P256_N, P256_G), p256_mul(r * w % P256_N, (x, y)))
    return pt is not None and pt[0] % P256_N == r


def der_rs(sig: bytes):
    """(r, s) uit een DER-handtekening (een SEQUENCE van twee INTEGERs); None als die niet precies zo is opgebouwd."""
    def length(i):
        n = sig[i]
        if n < 0x80:
            return n, i + 1
        if n == 0x81 and sig[i + 1] >= 0x80:
            return sig[i + 1], i + 2
        raise ValueError("lengte")
    try:
        if not sig or sig[0] != 0x30:
            return None
        total, i = length(1)
        if i + total != len(sig):
            return None
        out = []
        for _ in range(2):
            if sig[i] != 0x02:
                return None
            n, i = length(i + 1)
            if not 1 <= n <= 33 or i + n > len(sig):
                return None
            out.append(int.from_bytes(sig[i:i + n], "big"))
            i += n
        return (out[0], out[1]) if i == len(sig) else None
    except (ValueError, IndexError):
        return None


# --- CBOR: alleen wat WebAuthn gebruikt (getallen, bytes, tekst, lijsten, maps, true/false/null).
class CBORError(ValueError):
    pass


def cbor_item(buf: bytes, i: int = 0, depth: int = 0):
    """Leest één CBOR-waarde vanaf positie i; geeft (waarde, volgende positie)."""
    if depth > 8 or i >= len(buf):
        raise CBORError("cbor")
    head = buf[i]
    major, info = head >> 5, head & 31
    i += 1
    if info < 24:
        arg = info
    elif info in (24, 25, 26, 27):
        size = 1 << (info - 24)
        if i + size > len(buf):
            raise CBORError("cbor")
        arg = int.from_bytes(buf[i:i + size], "big")
        i += size
    else:
        raise CBORError("cbor")   # onbepaalde lengtes en kommagetallen komen in WebAuthn niet voor
    if major == 0:
        return arg, i
    if major == 1:
        return -1 - arg, i
    if major in (2, 3):
        if i + arg > len(buf):
            raise CBORError("cbor")
        raw = buf[i:i + arg]
        return (raw if major == 2 else raw.decode("utf-8")), i + arg
    if major in (4, 5):
        if arg > 64:
            raise CBORError("cbor")
        if major == 4:
            out = []
            for _ in range(arg):
                value, i = cbor_item(buf, i, depth + 1)
                out.append(value)
            return out, i
        found = {}
        for _ in range(arg):
            key, i = cbor_item(buf, i, depth + 1)
            if isinstance(key, (list, dict)) or key in found:
                raise CBORError("cbor")
            found[key], i = cbor_item(buf, i, depth + 1)
        return found, i
    if major == 7 and info in (20, 21, 22):
        return {20: False, 21: True, 22: None}[info], i
    raise CBORError("cbor")


def cose_key(m) -> dict | None:
    """De openbare sleutel uit een COSE-sleutel: ES256 (P-256) of RS256 (RSA vanaf 2048 bit); anders None."""
    if not isinstance(m, dict):
        return None
    if m.get(1) == 2 and m.get(3) == -7 and m.get(-1) == 1:
        x, y = m.get(-2), m.get(-3)
        if (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == len(y) == 32
                and p256_on_curve((int.from_bytes(x, "big"), int.from_bytes(y, "big")))):
            return {"kty": "EC", "alg": -7, "x": b64u(x), "y": b64u(y)}
    if m.get(1) == 3 and m.get(3) == -257:
        n, e = m.get(-1), m.get(-2)
        if isinstance(n, bytes) and isinstance(e, bytes) and int.from_bytes(n, "big").bit_length() >= 2048 and 1 <= len(e) <= 8:
            return {"kty": "RSA", "alg": -257, "n": b64u(n), "e": b64u(e)}
    return None


def wa_verify(key: dict, signed: bytes, signature: bytes) -> bool:
    """Klopt deze handtekening bij deze opgeslagen sleutel?"""
    try:
        if key.get("kty") == "EC":
            rs = der_rs(signature)
            return bool(rs) and p256_verify(int.from_bytes(b64url(key["x"]), "big"), int.from_bytes(b64url(key["y"]), "big"), signed, *rs)
        if key.get("kty") == "RSA":
            return rs256_ok({"n": key["n"], "e": key["e"]}, signed, signature)
    except (KeyError, TypeError, ValueError):
        pass
    return False


def auth_data(ad: bytes, attested: bool) -> dict:
    """Ontleedt de authenticatorData: hash van de rp-id, vlaggen, teller en (bij toevoegen) de nieuwe sleutel."""
    if len(ad) < 37:
        raise CBORError("authdata")
    out = {"rp": ad[:32], "flags": ad[32], "count": int.from_bytes(ad[33:37], "big")}
    if attested:
        if not out["flags"] & 0x40 or len(ad) < 55:
            raise CBORError("authdata")
        n = int.from_bytes(ad[53:55], "big")
        if not 16 <= n <= 1023 or len(ad) < 55 + n:
            raise CBORError("authdata")
        out["cred"] = ad[55:55 + n]
        out["key"], end = cbor_item(ad, 55 + n)
        if end != len(ad) and not out["flags"] & 0x80:   # alleen extensies mogen er nog achter staan
            raise CBORError("authdata")
    return out


# --- de opgeslagen sleutels
def wa_clean_key(k) -> dict | None:
    if not isinstance(k, dict) or not CRED_ID_RE.match(str(k.get("id") or "")) or not RP_RE.match(str(k.get("rp") or "")):
        return None
    if k.get("kty") == "EC" and all(B64_RE.match(str(k.get(f) or "")) for f in ("x", "y")):
        key = {"kty": "EC", "alg": -7, "x": k["x"], "y": k["y"]}
    elif k.get("kty") == "RSA" and all(B64_RE.match(str(k.get(f) or "")) for f in ("n", "e")):
        key = {"kty": "RSA", "alg": -257, "n": k["n"], "e": k["e"]}
    else:
        return None
    whole = lambda v: isinstance(v, int) and not isinstance(v, bool) and v >= 0  # noqa: E731
    name = str(k.get("name") or "")
    return {"id": k["id"], **key, "count": k["count"] if whole(k.get("count")) else 0,
            "name": name if KEY_NAME_RE.match(name) else "?", "created": k["created"] if whole(k.get("created")) else 0,
            "used": k["used"] if whole(k.get("used")) else None, "rp": k["rp"],
            "transports": [x for x in k.get("transports") or [] if x in WA_TRANSPORTS] if isinstance(k.get("transports"), list) else []}


def wa_state() -> dict:
    """gebruiker -> {"handle", "required", "keys"}; wordt opnieuw gelezen zodra het bestand verandert."""
    try:
        info = WEBAUTHN_FILE.stat()
        stamp = (info.st_mtime_ns, info.st_size)
    except OSError:
        stamp = None
    if stamp != _webauthn["stamp"]:
        data = {}
        if stamp:
            try:
                for name, u in (json.loads(WEBAUTHN_FILE.read_text(encoding="utf-8")).get("users") or {}).items():
                    if not isinstance(u, dict) or not (name == APP_USER or USER_RE.match(str(name))):
                        continue
                    keys = [k for k in (wa_clean_key(x) for x in (u.get("keys") or [])[:WEBAUTHN_MAX_KEYS]) if k]
                    handle = str(u.get("handle") or "")
                    data[name] = {"handle": handle if HANDLE_RE.match(handle) else None, "required": u.get("required") is True and bool(keys), "keys": keys}
            except (OSError, ValueError, TypeError, AttributeError):
                pass
        _webauthn.update(stamp=stamp, data=data)
    return _webauthn["data"]


def save_wa(data: dict):
    tmp = WEBAUTHN_FILE.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json.dumps({"users": data}))
    os.replace(tmp, WEBAUTHN_FILE)


def wa_user(name: str) -> dict:
    found = wa_state().get(name) if isinstance(name, str) else None
    return {"handle": found["handle"], "required": found["required"], "keys": [dict(k) for k in found["keys"]]} if found else {"handle": None, "required": False, "keys": []}


def wa_required(name: str) -> bool:
    return wa_user(name)["required"]


def wa_find(cred_id: str):
    """(gebruiker, sleutel) bij dit sleutel-ID; (None, None) als niemand hem heeft."""
    for name, u in wa_state().items():
        for k in u["keys"]:
            if hmac.compare_digest(k["id"], cred_id):
                return name, dict(k)
    return None, None


def wa_forget(name: str):
    """Haalt alle sleutels van een gebruiker weg (bij verwijderen van de gebruiker, of door een beheerder)."""
    with webauthn_lock:
        data = dict(wa_state())
        if data.pop(name, None) is not None:
            save_wa(data)


def has_password(user: str) -> bool:
    return user == APP_USER or bool((users_state().get(user) or {}).get("pw", True))


def wa_view(user: str, rp) -> dict:
    u = wa_user(user)
    return {"keys": [{"id": k["id"], "name": k["name"], "created": k["created"], "used": k["used"], "rp": k["rp"], "here": k["rp"] == rp}
                     for k in u["keys"]],
            "required": u["required"], "password": has_password(user), "rp": rp, "max": WEBAUTHN_MAX_KEYS}


# --- uitdagingen: ondertekend meegegeven aan de pagina, elk maar één keer bruikbaar
def wa_token(data: dict) -> str:
    payload = b64u(json.dumps(data).encode())
    return f"{payload}.{sign('webauthn:' + payload)}"


def wa_read(token, purposes: tuple) -> dict:
    payload, _, signature = str(token or "").partition(".")
    if not signature or len(payload) > 4000 or not hmac.compare_digest(signature, sign("webauthn:" + payload)):
        raise HTTPException(400, WA_EXPIRED)
    try:
        st = json.loads(b64url(payload))
    except ValueError:
        raise HTTPException(400, WA_EXPIRED)
    if not isinstance(st, dict) or st.get("p") not in purposes or not isinstance(st.get("e"), int) or st["e"] < time.time():
        raise HTTPException(400, WA_EXPIRED)
    with _wa_used_lock:
        now = time.time()
        for c in [c for c, until in _wa_used.items() if until < now]:
            del _wa_used[c]
        if st.get("c") in _wa_used:
            raise HTTPException(400, WA_EXPIRED)
        _wa_used[st["c"]] = st["e"]
    return st


def wa_origin(request) -> tuple:
    """Het adres van de pagina (origin) en de naam waarvoor een sleutel geldt (rp-id). Alleen via een naam."""
    same_origin(request)
    origin = request.headers.get("origin")
    parts = urllib.parse.urlsplit(origin)
    host = (parts.hostname or "").lower()
    if not host or is_ip(host) or not RP_RE.match(host) or (parts.scheme != "https" and host != "localhost"):
        raise HTTPException(409, WA_IP)
    return origin, host


def wa_challenge() -> str:
    return b64u(secrets.token_bytes(32))


def wa_client(raw: str, kind: str, st: dict) -> bytes:
    """Controleert de clientData van de browser: soort, uitdaging en het adres van de pagina."""
    try:
        data = b64url(raw)
        c = json.loads(data)
    except (ValueError, TypeError):
        raise HTTPException(400, WA_BAD)
    if (not isinstance(c, dict) or c.get("type") != kind or not hmac.compare_digest(str(c.get("challenge") or ""), st["c"])
            or c.get("origin") != st["o"] or c.get("crossOrigin") is True):
        raise HTTPException(400, WA_BAD)
    return data


def wa_reauth(request, user: str, password: str):
    """Wie met een wachtwoord inlogt, bevestigt een wijziging aan zijn sleutels daarmee (zoals bij wachtwoord wijzigen)."""
    if not has_password(user):
        return
    source = source_of(request)
    if login_guard.blocked(source):
        raise HTTPException(429, "Te veel mislukte pogingen. Probeer het over tien minuten opnieuw.")
    if not check_login(user, password or ""):
        login_guard.failed(source)
        raise HTTPException(403, "Het wachtwoord klopt niet; er is niets gewijzigd")


def wa_request_options(rp: str, keys: list, verification: str) -> dict:
    return {"challenge": wa_challenge(), "rpId": rp, "timeout": WEBAUTHN_TIMEOUT * 1000, "userVerification": verification,
            "allowCredentials": [{"type": "public-key", "id": k["id"], **({"transports": k["transports"]} if k.get("transports") else {})} for k in keys]}


def wa_second_step(request, name: str, remember: bool) -> dict:
    """Na een goed wachtwoord: als deze gebruiker de sleutel verplicht heeft, eerst die nog (geen sessie tot dan)."""
    keys = wa_user(name)["keys"]
    places = ", ".join(sorted({k["rp"] for k in keys}))
    try:
        origin, rp = wa_origin(request)
    except HTTPException:
        raise HTTPException(409, "Voor deze gebruiker is na het wachtwoord ook de beveiligingssleutel nodig. Die werkt hier niet; open de tool via {0}".format(places))
    here = [k for k in keys if k["rp"] == rp]
    if not here:
        raise HTTPException(409, "Voor deze gebruiker is na het wachtwoord ook de beveiligingssleutel nodig. Die werkt hier niet; open de tool via {0}".format(places))
    options = wa_request_options(rp, here, "discouraged")
    return {"ok": False, "next": "webauthn", "publicKey": options,
            "state": wa_token({"p": "2fa", "u": name, "c": options["challenge"], "o": origin, "r": rp, "k": 1 if remember else 0,
                               "e": int(time.time()) + WEBAUTHN_TIMEOUT})}


class WaPasswordIn(BaseModel):
    password: str = Field("", max_length=300)


class WaRegisterIn(BaseModel):
    state: str = Field(max_length=4000)
    name: str = Field("", max_length=60)
    id: str = Field(max_length=1400)
    clientDataJSON: str = Field(max_length=6000)
    attestationObject: str = Field(max_length=20000)
    transports: list[str] = Field(default_factory=list, max_length=8)


class WaChangeIn(BaseModel):
    password: str = Field("", max_length=300)
    required: bool | None = None
    remove: str | None = Field(None, max_length=1400)


class WaStartIn(BaseModel):
    username: str = Field("", max_length=100)


class WaLoginIn(BaseModel):
    state: str = Field(max_length=4000)
    id: str = Field(max_length=1400)
    clientDataJSON: str = Field(max_length=6000)
    authenticatorData: str = Field(max_length=6000)
    signature: str = Field(max_length=1200)
    userHandle: str | None = Field(None, max_length=200)
    remember: bool = False


def request_rp(request) -> str | None:
    """De naam waaronder de pagina nu open is (voor een GET zonder Origin); None bij een IP-adres."""
    host = (urllib.parse.urlsplit("//" + (request.headers.get("host") or "")).hostname or "").lower()
    return host if host and not is_ip(host) and RP_RE.match(host) else None


@app.get("/api/webauthn")
def wa_get(request: Request, user: str = Depends(auth)):
    """De eigen beveiligingssleutels."""
    return wa_view(user, request_rp(request))


@app.post("/api/webauthn/register/start")
def wa_register_start(body: WaPasswordIn, request: Request, user: str = Depends(auth)):
    origin, rp = wa_origin(request)
    wa_reauth(request, user, body.password)
    with webauthn_lock:
        data = dict(wa_state())
        me = dict(data.get(user) or {"handle": None, "required": False, "keys": []})
        if len(me["keys"]) >= WEBAUTHN_MAX_KEYS:
            raise HTTPException(409, "Er kunnen niet meer dan 10 sleutels per gebruiker zijn")
        if not me.get("handle"):
            me["handle"] = b64u(secrets.token_bytes(16))
            data[user] = me
            try:
                save_wa(data)
            except OSError:
                raise HTTPException(500, "De sleutels konden niet bewaard worden")
    challenge = wa_challenge()
    return {"publicKey": {
        "rp": {"id": rp, "name": "Proxmox Maintool"}, "user": {"id": me["handle"], "name": user, "displayName": user},
        "challenge": challenge, "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}],
        "timeout": WEBAUTHN_TIMEOUT * 1000, "attestation": "none",
        "authenticatorSelection": {"residentKey": "preferred", "requireResidentKey": False, "userVerification": "preferred"},
        "excludeCredentials": [{"type": "public-key", "id": k["id"]} for k in me["keys"] if k["rp"] == rp]},
        "state": wa_token({"p": "reg", "u": user, "c": challenge, "o": origin, "r": rp, "e": int(time.time()) + WEBAUTHN_TIMEOUT})}


@app.post("/api/webauthn/register/finish")
def wa_register_finish(body: WaRegisterIn, request: Request, user: str = Depends(auth)):
    same_origin(request)
    st = wa_read(body.state, ("reg",))
    if st.get("u") != user or request.headers.get("origin") != st.get("o"):
        raise HTTPException(400, WA_BAD)
    wa_client(body.clientDataJSON, "webauthn.create", st)
    try:
        att, _ = cbor_item(b64url(body.attestationObject))
        if not isinstance(att, dict) or not isinstance(att.get("authData"), bytes):
            raise CBORError("attestation")
        ad = auth_data(att["authData"], True)
    except (ValueError, TypeError):
        raise HTTPException(400, WA_BAD)
    if not hmac.compare_digest(ad["rp"], hashlib.sha256(st["r"].encode()).digest()) or not ad["flags"] & 0x01 or b64u(ad["cred"]) != body.id:
        raise HTTPException(400, WA_BAD)
    key = cose_key(ad["key"])
    if not key:
        raise HTTPException(400, "Deze sleutel gebruikt een soort handtekening die de tool niet kent (alleen ES256 en RS256)")
    name = " ".join(body.name.split())
    if name and not KEY_NAME_RE.match(name):
        raise HTTPException(400, "Een naam voor de sleutel: hooguit 40 tekens, zonder < > \" &")
    with webauthn_lock:
        data = dict(wa_state())
        if any(k["id"] == body.id for u in data.values() for k in u["keys"]):
            raise HTTPException(409, "Deze sleutel is al toegevoegd")
        me = dict(data.get(user) or {"handle": b64u(secrets.token_bytes(16)), "required": False, "keys": []})
        if len(me["keys"]) >= WEBAUTHN_MAX_KEYS:
            raise HTTPException(409, "Er kunnen niet meer dan 10 sleutels per gebruiker zijn")
        entry = {"id": body.id, **key, "count": ad["count"], "name": name or str(len(me["keys"]) + 1), "created": int(time.time()),
                 "used": None, "rp": st["r"], "transports": [x for x in body.transports if x in WA_TRANSPORTS]}
        me["keys"] = me["keys"] + [entry]
        data[user] = me
        try:
            save_wa(data)
        except OSError:
            raise HTTPException(500, "De sleutels konden niet bewaard worden")
    state.event("webauthn", "beveiligingssleutel toegevoegd", target="", name=entry["name"], user=user)
    return wa_view(user, st["r"])


@app.put("/api/webauthn")
def wa_change(body: WaChangeIn, request: Request, user: str = Depends(auth)):
    """Een eigen sleutel verwijderen, of de sleutel na het wachtwoord verplicht maken (of niet meer)."""
    same_origin(request)
    if body.required is None and body.remove is None:
        raise HTTPException(400, "Er is niets om te wijzigen")
    wa_reauth(request, user, body.password)
    with webauthn_lock:
        data = dict(wa_state())
        me = dict(data.get(user) or {"handle": None, "required": False, "keys": []})
        removed = None
        if body.remove is not None:
            removed = next((k for k in me["keys"] if k["id"] == body.remove), None)
            if not removed:
                raise HTTPException(404, "Deze sleutel bestaat niet (meer)")
            me["keys"] = [k for k in me["keys"] if k["id"] != body.remove]
            me["required"] = me["required"] and bool(me["keys"])
        if body.required is not None:
            if body.required and not me["keys"]:
                raise HTTPException(400, "Voeg eerst een beveiligingssleutel toe")
            if body.required and not has_password(user):
                raise HTTPException(400, "Dit account logt niet met een wachtwoord in; de sleutel na het wachtwoord is dan niet nodig")
            me["required"] = body.required
        data[user] = me
        try:
            save_wa(data)
        except OSError:
            raise HTTPException(500, "De sleutels konden niet bewaard worden")
    if removed:
        state.event("webauthn", "beveiligingssleutel verwijderd", target="", name=removed["name"], user=user)
    if body.required is not None:
        state.event("webauthn", "sleutel na het wachtwoord verplicht" if body.required else "sleutel na het wachtwoord niet meer verplicht",
                    target="", name="", user=user)
    return wa_view(user, request_rp(request))


@app.delete("/api/users/{name}/webauthn")
def wa_reset(name: str, request: Request, actor: str = Depends(admin)):
    """Een beheerder haalt alle sleutels van een gebruiker weg, bijvoorbeeld als die zijn sleutel kwijt is."""
    same_origin(request)
    if not account(name):
        raise HTTPException(404, "Deze gebruiker bestaat niet")
    if not wa_user(name)["keys"]:
        raise HTTPException(404, "Deze gebruiker heeft geen beveiligingssleutels")
    try:
        wa_forget(name)
    except OSError:
        raise HTTPException(500, "De sleutels konden niet bewaard worden")
    state.event("webauthn", "beveiligingssleutels van een gebruiker weggehaald", target="", name=name, user=actor)
    return user_list()


@app.post("/api/webauthn/login/start")
def wa_login_start(body: WaStartIn, request: Request):
    """Inloggen met alleen een beveiligingssleutel (met pincode of vingerafdruk op de sleutel). Met een naam erbij
    biedt de browser alleen de sleutels van die gebruiker aan; zonder naam kiest de sleutel zelf het account."""
    if login_guard.blocked(source_of(request)):
        raise HTTPException(429, "Te veel mislukte pogingen. Probeer het over tien minuten opnieuw.")
    origin, rp = wa_origin(request)
    name = body.username.strip()
    if name and not secrets.compare_digest(name.encode(), APP_USER.encode()):
        name = name.lower()
    keys = [k for k in wa_user(name)["keys"] if k["rp"] == rp] if name else []
    options = wa_request_options(rp, keys, "required")
    return {"publicKey": options, "state": wa_token({"p": "login", "c": options["challenge"], "o": origin, "r": rp,
                                                     "e": int(time.time()) + WEBAUTHN_TIMEOUT})}


@app.post("/api/webauthn/login/finish")
def wa_login_finish(body: WaLoginIn, request: Request, response: Response):
    """Controleert het antwoord van de sleutel, zowel bij inloggen met alleen de sleutel als na het wachtwoord."""
    source = source_of(request)
    if login_guard.blocked(source):
        raise HTTPException(429, "Te veel mislukte pogingen. Probeer het over tien minuten opnieuw.")
    st = wa_read(body.state, ("login", "2fa"))

    def fail(reason=WA_UNKNOWN):
        login_guard.failed(source)
        raise HTTPException(401, reason)
    if request.headers.get("origin") != st.get("o"):
        fail()
    owner, key = wa_find(body.id)
    if not key or key["rp"] != st.get("r") or (st["p"] == "2fa" and owner != st.get("u")):
        fail()
    if body.userHandle and body.userHandle != wa_user(owner)["handle"]:
        fail()
    client = wa_client(body.clientDataJSON, "webauthn.get", st)
    try:
        raw = b64url(body.authenticatorData)
        ad = auth_data(raw, False)
        signature = b64url(body.signature)
    except ValueError:
        fail()
    if not hmac.compare_digest(ad["rp"], hashlib.sha256(st["r"].encode()).digest()) or not ad["flags"] & 0x01:
        fail()
    if st["p"] == "login" and not ad["flags"] & 0x04:
        fail("Voor inloggen met alleen de sleutel moet de sleutel je pincode of vingerafdruk vragen")
    if not wa_verify(key, raw + hashlib.sha256(client).digest(), signature):
        fail()
    if (ad["count"] or key["count"]) and ad["count"] <= key["count"]:
        fail("Deze beveiligingssleutel meldt een teller die niet klopt (mogelijk een kopie); er is niet ingelogd")
    if not account(owner):
        fail()
    with webauthn_lock:   # teller en laatste gebruik bijwerken
        data = dict(wa_state())
        me = dict(data.get(owner) or {})
        me["keys"] = [{**k, "count": ad["count"], "used": int(time.time())} if k["id"] == key["id"] else k for k in me.get("keys", [])]
        data[owner] = me
        try:
            save_wa(data)
        except OSError:
            pass
    login_guard.succeeded(source)
    start_session(response, owner, bool(st.get("k")) if st["p"] == "2fa" else body.remember)
    return {"ok": True}


# ---------------------------------------------------------------- console van een node
# Proxmox geeft een shell op een node niet aan de toegangssleutel van de tool, wel aan een account met het recht
# Sys.Console op de node: root@pam meteen, elk ander account (pam of pve) na nog een keer inloggen op de node zelf. Een
# beheerder logt in het consolevenster daarom met zo'n account in; de tool vraagt Proxmox daarmee een ticket en houdt
# dat alleen in het geheugen, voor deze browsersessie en hooguit een uur. Het wachtwoord wordt nergens bewaard of gelogd.
NODECON_TTL = 3600
PAM_USER_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")    # een Linux-gebruiker op de nodes
PVE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")       # een gebruiker van Proxmox zelf (realm pve)
CONSOLE_REALMS = ("pam", "pve")
TFA_CODE_RE = re.compile(r"^[A-Za-z0-9-]{4,64}$")
_nodecon = {}   # sha256(sessiecookie) -> {"owner", "user", "ticket", "csrf", "exp"} of, halverwege, {"owner", "user", "challenge", "exp"}
nodecon_lock = threading.Lock()


def nodecon_key(request) -> str:
    return hashlib.sha256((request.cookies.get(SESSION_COOKIE) or "").encode()).hexdigest()


def nodecon_entry(key: str, owner: str) -> dict | None:
    with nodecon_lock:
        now = time.time()
        for k in [k for k, v in _nodecon.items() if v["exp"] < now]:
            del _nodecon[k]
        found = _nodecon.get(key)
        return dict(found) if found and found["owner"] == owner else None


def nodecon_view(entry) -> dict:
    ready = bool(entry and entry.get("ticket"))
    return {"ready": ready, "user": entry["user"] if ready else None, "until": entry["exp"] if ready else None,
            "need_code": bool(entry and entry.get("challenge"))}


class NodeConIn(BaseModel):
    username: str = Field("root", max_length=70)
    password: str = Field("", max_length=300)
    code: str = Field("", max_length=64)
    realm: str = Field("pam", pattern="^(pam|pve)$")   # pam: een account van de node zelf; pve: een account van Proxmox


def nodecon_why(userid: str) -> str:
    """Waarom Proxmox het inloggen weigerde, voor zover de tool dat met zijn eigen sleutel kan zien: het account staat
    uit, is verlopen of bestaat niet. Proxmox zegt dat zelf alleen in het logboek van de node; anders de gewone melding."""
    plain = "Gebruikersnaam, wachtwoord of code klopt niet"
    try:
        u = pve.run(lambda api: api.access.users(userid).get())
    except HTTPException as err:
        if "no such user" not in str(err.detail):
            return plain
        if userid.endswith("@pve"):
            return "{0} bestaat niet in Proxmox; maak het account aan op het tabblad Gebruikers, in realm pve".format(userid)
        return "{0} bestaat niet in Proxmox; een pam-account moet daar bestaan (tabblad Gebruikers) en als Linux-account op de nodes".format(userid)
    if not isinstance(u, dict):
        return plain
    if u.get("enable") in (0, "0", False):
        return "{0} staat in Proxmox uit (Datacenter, Permissions, Users). Zet het account daar aan, of log in met een ander account dat een console mag openen".format(userid)
    expire = int(u.get("expire") or 0)
    if expire and expire < time.time():
        return "{0} is in Proxmox verlopen. Verleng het account (tabblad Gebruikers), of log in met een ander account".format(userid)
    return plain


@app.get("/api/nodeconsole")
def nodecon_get(request: Request, user: str = Depends(admin)):
    return nodecon_view(nodecon_entry(nodecon_key(request), user))


@app.post("/api/nodeconsole/login")
def nodecon_login(body: NodeConIn, request: Request, user: str = Depends(admin)):
    """Inloggen bij Proxmox voor de console van de nodes, met een account in realm pam of pve; met
    tweestapsverificatie in twee keer."""
    same_origin(request)
    source, key = source_of(request), nodecon_key(request)
    if login_guard.blocked(source):
        raise HTTPException(429, "Te veel mislukte pogingen. Probeer het over tien minuten opnieuw.")
    pending = nodecon_entry(key, user)
    if body.code:
        if not pending or not pending.get("challenge"):
            raise HTTPException(400, "Log eerst opnieuw in met gebruikersnaam en wachtwoord")
        code = body.code.strip().replace(" ", "")
        if not TFA_CODE_RE.match(code):
            raise HTTPException(400, "Ongeldige code")
        kind = "totp" if code.isdigit() and len(code) <= 8 else "recovery"
        data = pve_ticket(pending["user"], f"{kind}:{code}", **{"tfa-challenge": pending["challenge"]})
        userid = pending["user"]
    else:
        name, realm = body.username.strip(), body.realm
        for suffix in CONSOLE_REALMS:   # wie zelf @pam of @pve achter de naam typt, bedoelt die realm
            if name.lower().endswith("@" + suffix):
                name, realm = name[:-len(suffix) - 1], suffix
        if realm == "pve":
            if not PVE_NAME_RE.match(name) or not body.password:
                raise HTTPException(400, "Vul een gebruiker van Proxmox in (realm pve) en zijn wachtwoord")
        elif not PAM_USER_RE.match(name) or not body.password:
            raise HTTPException(400, "Vul een gebruiker van de node in (bijvoorbeeld root) en zijn wachtwoord")
        userid = f"{name}@{realm}"
        data = pve_ticket(userid, body.password)
    if data is None:
        login_guard.failed(source)
        with nodecon_lock:
            _nodecon.pop(key, None)
        raise HTTPException(403, nodecon_why(userid))   # geen 401: dat leest de pagina als "sessie verlopen" en stuurt naar de inlogpagina
    if not isinstance(data.get("ticket"), str) or not str(data.get("username") or "").endswith("@" + userid.rpartition("@")[2]):
        raise HTTPException(502, "Proxmox gaf geen bruikbaar antwoord bij het controleren van het account")
    if data.get("NeedTFA"):
        with nodecon_lock:
            _nodecon[key] = {"owner": user, "user": userid, "challenge": data["ticket"], "exp": time.time() + 300}
        return nodecon_view(nodecon_entry(key, user))
    if not isinstance(data.get("CSRFPreventionToken"), str):
        raise HTTPException(502, "Proxmox gaf geen bruikbaar antwoord bij het controleren van het account")
    login_guard.succeeded(source)
    with nodecon_lock:
        _nodecon[key] = {"owner": user, "user": str(data["username"]), "ticket": data["ticket"], "csrf": data["CSRFPreventionToken"],
                         "exp": time.time() + NODECON_TTL}
    state.event("console", "ingelogd voor de console van de nodes", target="", name=str(data["username"]), user=user)
    return nodecon_view(nodecon_entry(key, user))


@app.delete("/api/nodeconsole")
def nodecon_forget(request: Request, user: str = Depends(auth)):
    with nodecon_lock:
        _nodecon.pop(nodecon_key(request), None)
    return nodecon_view(None)


def node_termproxy(entry: dict, node: str) -> dict:
    """Vraagt met het ticket van de beheerder een shell op de node aan (termproxy); geeft port, ticket en user."""
    session = requests.Session()
    session.verify = VERIFY
    if CA_FILE:
        session.mount("https://", ClusterCAAdapter(CA_FILE))
    host = pve.host or (pve.hosts[0] if pve.hosts else "")
    address = f"[{host}]" if ":" in host else host
    r = session.post(f"https://{address}:8006/api2/json/nodes/{node}/termproxy", cookies={"PVEAuthCookie": entry["ticket"]},
                     headers={"CSRFPreventionToken": entry["csrf"]}, timeout=15, allow_redirects=False)
    if r.status_code == 401:
        raise HTTPException(401, "Het inloggen bij Proxmox is verlopen; log opnieuw in voor de console")
    if r.status_code == 403:
        raise HTTPException(403, "Dit account mag geen console op deze node openen")
    data = (r.json() or {}).get("data") if r.headers.get("content-type", "").startswith("application/json") else None
    if r.status_code != 200 or not isinstance(data, dict) or not data.get("ticket") or not data.get("port"):
        raise HTTPException(502, "Proxmox gaf geen console voor deze node")
    return {"host": host, **data}


@app.websocket("/api/nodeconsole/{node}")
async def node_console(ws: WebSocket, node: str):
    """Terminal naar de shell van een node, met het account (pam of pve) waarmee de beheerder in het consolevenster inlogde.
    Verder net als de console van een container (zie console)."""
    same_site = urllib.parse.urlsplit(ws.headers.get("origin", "")).netloc == ws.headers.get("host")
    user = read_token(ws.cookies.get(SESSION_COOKIE))
    who = account(user)
    if not same_site or not who:
        await ws.close(code=4401)
        return
    if not who.get("admin") or view_only(ws):
        await ws.close(code=4403)
        return
    if not NODE_RE.match(node):
        await ws.close(code=4400)
        return
    entry = nodecon_entry(hashlib.sha256((ws.cookies.get(SESSION_COOKIE) or "").encode()).hexdigest(), user)
    await ws.accept()
    try:
        if not entry or not entry.get("ticket"):
            raise HTTPException(401, "Log eerst in voor de console")
        term = await asyncio.to_thread(node_termproxy, entry, node)
        host = f"[{term['host']}]" if ":" in term["host"] else term["host"]
        url = f"wss://{host}:8006/api2/json/nodes/{node}/vncwebsocket?port={term['port']}&vncticket={urllib.parse.quote(term['ticket'], safe='')}"
        tls = cluster_ssl_context(CA_FILE) if CA_FILE else None
        state.event("console", "console geopend", node=node, target="node", name=entry["user"], user=user)
        async with websockets.connect(url, ssl=tls, additional_headers={"Cookie": f"PVEAuthCookie={entry['ticket']}"},
                                      subprotocols=["binary"], open_timeout=10, max_size=None) as upstream:
            await upstream.send(f"{term.get('user') or entry['user']}:{term['ticket']}\n")
            if await asyncio.wait_for(upstream.recv(), 10) not in (b"OK", "OK"):
                raise RuntimeError("Proxmox weigert de console")

            async def to_browser():
                async for message in upstream:
                    await ws.send_bytes(message if isinstance(message, bytes) else message.encode())

            async def to_proxmox():
                while True:
                    message = await ws.receive()
                    if message["type"] == "websocket.disconnect":
                        return
                    if message.get("bytes") is not None:
                        await upstream.send(b"0:%d:" % len(message["bytes"]) + message["bytes"])
                    elif message.get("text"):
                        try:
                            cols, rows = json.loads(message["text"])["resize"]
                            await upstream.send(f"1:{int(cols)}:{int(rows)}:")
                        except (ValueError, KeyError, TypeError):
                            pass

            async def keepalive():
                while True:
                    await asyncio.sleep(30)
                    await upstream.send("2")

            tasks = [asyncio.create_task(job()) for job in (to_browser, to_proxmox, keepalive)]
            _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
    except Exception as err:  # noqa: BLE001 - wat er ook misgaat, de browser krijgt een regel uitleg
        reason = translate(err.detail, lang_of(ws)) if isinstance(err, HTTPException) else err.__class__.__name__
        try:
            await ws.send_bytes(f"\r\n[console: {reason}]\r\n".encode())
        except Exception:  # noqa: BLE001
            pass
    finally:
        try:
            await ws.close()
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------- API-tokens van Proxmox (tabblad Gebruikers)
# Tokens voor scripts en andere programma's. Met "eigen rechten" (privilege separation) mag een token alleen wat het
# zelf op een plek krijgt, en nooit meer dan zijn gebruiker; zonder mag het precies wat de gebruiker mag. Het geheim
# toont Proxmox maar één keer, bij het aanmaken; de tool bewaart het nergens. Tokens van root@pam en van de gebruiker
# waarmee de tool zelf werkt, wijzigt de tool niet.
TOKEN_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{1,63}$")


class PveTokenIn(BaseModel):
    userid: str = Field(max_length=100)
    tokenid: str = Field(max_length=64)
    comment: str = Field("", max_length=200)
    expire: int = Field(0, strict=True)
    privsep: bool = Field(True, strict=True)


class PveTokenEdit(BaseModel):
    comment: str | None = Field(None, max_length=200)
    expire: int | None = Field(None, strict=True)
    privsep: bool | None = Field(None, strict=True)


def token_rows(api, st: dict) -> list:
    """Alle tokens van alle gebruikers, met hun eigen rechten."""
    out = []
    for uid, u in sorted(st["users"].items(), key=lambda kv: kv[0].lower()):
        for tk in u["raw"].get("tokens") or []:
            tid = str(tk.get("tokenid") or "")
            if not tid:
                continue
            full = f"{uid}!{tid}"
            out.append({"tokenid": full, "userid": uid, "name": tid, "comment": str(tk.get("comment") or "")[:200] or None,
                        "expire": int(tk.get("expire") or 0) or None, "privsep": tk.get("privsep") not in (0, "0", False),
                        "tool": uid == PVE_USER and tid == TOKEN_NAME, "protected": protected_user(uid),
                        "acl": [a for a in st["acl"] if a["type"] == "token" and a["ugid"] == full]})
    return out


def token_target(userid: str, tokenid: str):
    if not TOKEN_ID_RE.match(tokenid or ""):
        raise HTTPException(400, "Ongeldige naam voor een token: begint met een letter, dan letters, cijfers, punt, streepje of liggend streepje (2 tot 64 tekens)")
    refuse_protected(userid)


@app.post("/api/access/tokens")
def access_token_add(body: PveTokenIn, request: Request, user: str = Depends(admin)):
    """Maakt een API-token. Het antwoord bevat het geheim: dat is het enige moment waarop het te zien is."""
    same_origin(request)
    userid, tokenid = body.userid.strip(), body.tokenid.strip()
    token_target(userid, tokenid)
    params = {"privsep": 1 if body.privsep else 0}
    if access_text(body.comment):
        params["comment"] = access_text(body.comment)
    if access_expire(body.expire):
        params["expire"] = body.expire

    def f(api):
        st = access_state(api)
        if userid not in st["users"]:
            raise HTTPException(404, "Deze Proxmox-gebruiker bestaat niet (meer)")
        if any(str(tk.get("tokenid")) == tokenid for tk in st["users"][userid]["raw"].get("tokens") or []):
            raise HTTPException(409, "Deze gebruiker heeft al een token met die naam")
        return api.access.users(userid).token(tokenid).post(**params)
    made = pve.run(f)
    secret = made.get("value") if isinstance(made, dict) else None
    if not isinstance(secret, str) or not secret:
        raise HTTPException(502, "Proxmox gaf geen geheim terug voor het nieuwe token")
    full = str(made.get("full-tokenid") or f"{userid}!{tokenid}")
    state.event("access", "API-token aangemaakt", target=full, name="", user=user)
    return {"ok": True, "tokenid": full, "secret": secret, "privsep": body.privsep}


@app.put("/api/access/tokens/{userid}/{tokenid}")
def access_token_change(userid: str, tokenid: str, body: PveTokenEdit, request: Request, user: str = Depends(admin)):
    same_origin(request)
    token_target(userid, tokenid)
    params = {}
    if body.comment is not None:
        params["comment"] = access_text(body.comment)
    if body.expire is not None:
        params["expire"] = access_expire(body.expire)
    if body.privsep is not None:
        params["privsep"] = 1 if body.privsep else 0
    if not params:
        raise HTTPException(400, "Er is niets om aan te passen")

    def f(api):
        st = access_state(api)
        if userid not in st["users"] or not any(str(tk.get("tokenid")) == tokenid for tk in st["users"][userid]["raw"].get("tokens") or []):
            raise HTTPException(404, "Dit token bestaat niet (meer)")
        api.access.users(userid).token(tokenid).put(**params)
    pve.run(f)
    state.event("access", "API-token aangepast", target=f"{userid}!{tokenid}", name="", user=user)
    return {"ok": True}


@app.delete("/api/access/tokens/{userid}/{tokenid}")
def access_token_delete(userid: str, tokenid: str, request: Request, user: str = Depends(admin)):
    """Verwijdert een token; wat het nog deed, werkt daarna meteen niet meer. Proxmox haalt ook zijn rechten weg."""
    same_origin(request)
    token_target(userid, tokenid)

    def f(api):
        st = access_state(api)
        if userid not in st["users"] or not any(str(tk.get("tokenid")) == tokenid for tk in st["users"][userid]["raw"].get("tokens") or []):
            raise HTTPException(404, "Dit token bestaat niet (meer)")
        api.access.users(userid).token(tokenid).delete()
    pve.run(f)
    state.event("access", "API-token verwijderd", target=f"{userid}!{tokenid}", name="", user=user)
    return {"ok": True}


# ---------------------------------------------------------------- tabellen aanpassen (bewaard per gebruiker)
# Per tabel welke kolommen uit staan (hide: "i3" = de vierde kolom, of de naam van een kolom) en welke extra kolommen
# erbij staan (add), met het aantal kolommen (sig) waarvoor dat gold: verandert een tabel in een nieuwe versie, dan
# geldt de keuze niet meer. Per tabblad de volgorde van de blokken (order).
TABLE_KEY_RE = re.compile(r"^[a-z][a-z0-9-]{0,30}(\.[a-z0-9-]{1,30})?$")
TABLE_COL_RE = re.compile(r"^(i\d{1,2}|[a-z][a-z0-9-]{0,20})$")


def clean_tables(d) -> dict:
    bad = HTTPException(400, "Ongeldige indeling van de tabellen")
    if not isinstance(d, dict) or set(d) - {"cols", "order"}:
        raise bad
    cols, order = d.get("cols", {}), d.get("order", {})
    if not isinstance(cols, dict) or not isinstance(order, dict) or len(cols) > 60 or len(order) > 20:
        raise bad
    out_cols, out_order = {}, {}
    for key, c in cols.items():
        if not TABLE_KEY_RE.match(str(key)) or not isinstance(c, dict) or set(c) - {"sig", "hide", "add"}:
            raise bad
        sig, hide, add = c.get("sig"), c.get("hide", []), c.get("add", [])
        if not isinstance(sig, int) or isinstance(sig, bool) or not 1 <= sig <= 60:
            raise bad
        if (not isinstance(hide, list) or not isinstance(add, list) or len(hide) > 60 or len(add) > 20
                or any(not isinstance(x, str) or not TABLE_COL_RE.match(x) for x in hide + add)):
            raise bad
        out_cols[key] = {"sig": sig, "hide": sorted(set(hide)), "add": sorted(set(add))}
    for view, keys in order.items():
        if (not re.fullmatch(r"[a-z]{2,12}", str(view)) or not isinstance(keys, list) or len(keys) > 20
                or any(not isinstance(k, str) or not TABLE_KEY_RE.match(k) for k in keys) or len(set(keys)) != len(keys)):
            raise bad
        out_order[view] = keys
    return {"cols": out_cols, "order": out_order}


class SnapIn(BaseModel):
    name: str
    description: str = Field("", max_length=500)
    vmstate: bool = False  # RAM meenemen (alleen qemu)


@app.get("/api/guest/{node}/{kind}/{vmid}/snapshots")
def list_snaps(node: str, kind: str, vmid: int, _: str = Depends(auth)):
    check_target(node, kind, vmid)
    snaps = pve.run(lambda api: guest(api, node, kind, vmid).snapshot.get())
    snaps = [s for s in snaps if s.get("name") != "current"]
    return sorted(snaps, key=lambda s: s.get("snaptime", 0), reverse=True)


@app.post("/api/guest/{node}/{kind}/{vmid}/snapshots")
def create_snap(node: str, kind: str, vmid: int, body: SnapIn, _: str = Depends(manage_overview)):
    check_target(node, kind, vmid)
    check_snap(body.name)
    params = {"snapname": body.name, "description": body.description}
    if kind == "qemu" and body.vmstate:
        params["vmstate"] = 1
    upid = pve.run(lambda api: guest(api, node, kind, vmid).snapshot.post(**params))
    return {"upid": upid, "node": node}


@app.delete("/api/guest/{node}/{kind}/{vmid}/snapshots/{name}")
def delete_snap(node: str, kind: str, vmid: int, name: str, _: str = Depends(manage_overview)):
    check_target(node, kind, vmid)
    check_snap(name)
    upid = pve.run(lambda api: guest(api, node, kind, vmid).snapshot(name).delete())
    return {"upid": upid, "node": node}


@app.post("/api/guest/{node}/{kind}/{vmid}/snapshots/{name}/rollback")
def rollback_snap(node: str, kind: str, vmid: int, name: str, _: str = Depends(manage_overview)):
    check_target(node, kind, vmid)
    check_snap(name)
    if kind == "lxc" and pve.run(lambda api: ct_busy(api, node, vmid)):
        raise HTTPException(409, BUSY_MSG)
    upid = pve.run(lambda api: guest(api, node, kind, vmid).snapshot(name).rollback.post())
    return {"upid": upid, "node": node}


# ---------------------------------------------------------------- console
XTERM = {"xterm.js": "application/javascript", "xterm.css": "text/css", "addon-fit.js": "application/javascript"}


@app.get("/static/xterm/{name}")
def xterm_file(name: str, _: str = Depends(manage_overview)):
    """De terminalbibliotheek (xterm.js, overgenomen uit het pakket pve-xtermjs van de eigen nodes)."""
    if name not in XTERM:
        raise HTTPException(404, "Onbekend bestand")
    data = (Path(__file__).parent / "static" / "xterm" / name).read_bytes()
    return Response(data, media_type=XTERM[name], headers={"Cache-Control": "private, max-age=86400"})


@app.websocket("/api/console/{node}/{vmid}")
async def console(ws: WebSocket, node: str, vmid: int):
    """Terminal naar de console van een container.

    De browser praat met dit adres; de tool vraagt bij Proxmox een console aan (termproxy) en geeft de
    toetsaanslagen en de uitvoer door. Je komt uit bij de inlogprompt van de container.
    Browser -> tool: binaire berichten zijn invoer, tekstberichten zijn {"resize": [kolommen, regels]}.
    """
    # Zelfde sessiecookie als de rest van de tool, en alleen vanaf de eigen pagina (geen andere website).
    same_site = urllib.parse.urlsplit(ws.headers.get("origin", "")).netloc == ws.headers.get("host")
    who = account(read_token(ws.cookies.get(SESSION_COOKIE)))
    if not same_site or not who:
        await ws.close(code=4401)
        return
    if "overview" not in who["can"] or view_only(ws):
        await ws.close(code=4403)
        return
    if not NODE_RE.match(node) or not (100 <= vmid <= 999999999):
        await ws.close(code=4400)
        return
    await ws.accept()
    try:
        ticket = await asyncio.to_thread(lambda: pve.run(lambda api: api.nodes(node).lxc(vmid).termproxy.post()))
        url = (f"wss://{pve.host}:8006/api2/json/nodes/{node}/lxc/{vmid}/vncwebsocket"
               f"?port={ticket['port']}&vncticket={urllib.parse.quote(ticket['ticket'], safe='')}")
        token = f"PVEAPIToken={PVE_USER}!{TOKEN_NAME}={TOKEN_VALUE}"
        tls = cluster_ssl_context(CA_FILE) if CA_FILE else None
        async with websockets.connect(url, ssl=tls, additional_headers={"Authorization": token},
                                      subprotocols=["binary"], open_timeout=10, max_size=None) as upstream:
            await upstream.send(f"{ticket['user']}:{ticket['ticket']}\n")
            if await asyncio.wait_for(upstream.recv(), 10) not in (b"OK", "OK"):
                raise RuntimeError("Proxmox weigert de console")

            async def to_browser():
                async for message in upstream:
                    await ws.send_bytes(message if isinstance(message, bytes) else message.encode())

            async def to_proxmox():
                while True:
                    message = await ws.receive()
                    if message["type"] == "websocket.disconnect":
                        return
                    if message.get("bytes") is not None:  # termproxy wil "0:<lengte>:<invoer>"
                        await upstream.send(b"0:%d:" % len(message["bytes"]) + message["bytes"])
                    elif message.get("text"):
                        try:
                            cols, rows = json.loads(message["text"])["resize"]
                            await upstream.send(f"1:{int(cols)}:{int(rows)}:")
                        except (ValueError, KeyError, TypeError):
                            pass

            async def keepalive():
                while True:
                    await asyncio.sleep(30)
                    await upstream.send("2")

            tasks = [asyncio.create_task(job()) for job in (to_browser, to_proxmox, keepalive)]
            _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
    except Exception as err:  # noqa: BLE001 - wat er ook misgaat, de browser krijgt een regel uitleg
        reason = err.detail if isinstance(err, HTTPException) else err.__class__.__name__
        try:
            await ws.send_bytes(f"\r\n[console niet beschikbaar: {reason}]\r\n".encode())
        except Exception:  # noqa: BLE001
            pass
    finally:
        try:
            await ws.close()
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------- versies en updates
def ssh_ready() -> bool:
    return os.path.isfile(SSH_KEY) and os.path.isfile(SSH_KNOWN_HOSTS)


def node_ips(api) -> dict:
    return {e["name"]: e["ip"] for e in api.cluster.status.get() if e.get("type") == "node" and e.get("ip")}


def agent(ip: str, *words: str, timeout: int = 30) -> str:
    """Laat de maintool-agent op een node één commando uit zijn vaste lijst uitvoeren."""
    if not ssh_ready():
        raise HTTPException(503, "SSH naar de nodes is nog niet ingesteld; draai op een node: bash maintool-setup.sh --update")
    cmd = ["ssh", "-F", "none", "-i", SSH_KEY, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
           "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={SSH_KNOWN_HOSTS}",
           "-o", "ConnectTimeout=5", f"root@{ip}", " ".join(words)]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "Node reageert niet op tijd via SSH")
    if p.returncode != 0:
        raise HTTPException(502, "Agent: " + (p.stderr.strip().splitlines() or ["onbekende fout"])[-1])
    return p.stdout


KERNEL_PKG_RE = re.compile(r"^(?:proxmox|pve)-kernel-(\d+\.\d+\.\d+-\d+-pve)(?:-signed)?$")


def newer_kernel(versions, running):
    """De nieuwste geïnstalleerde kernel als die nieuwer is dan de draaiende (herstart nodig), anders None."""
    def key(release):
        return [int(x) for x in re.findall(r"\d+", release)]
    installed = [m.group(1) for v in versions
                 if v.get("CurrentState") == "Installed" and (m := KERNEL_PKG_RE.match(v.get("Package", "")))]
    newest = max(installed, key=key, default=None)
    return newest if newest and running and key(newest) > key(running) else None


def agent_version(ip: str) -> int:
    parts = agent(ip, "ping").split()  # "maintool-agent <versie> <hostnaam>"
    return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0


class Updates:
    """Versies en klaarstaande updates van nodes en guests.

    Verzamelen kost seconden (apt op elke node, pct exec in elke CT) en gebeurt daarom op de
    achtergrond; de webpagina leest alleen het laatste resultaat.
    """

    def __init__(self):
        self.info = {"nodes": {}, "guests": {}, "checked": None, "error": None, "ssh": None}
        self.busy = False
        self.lock = threading.Lock()

    def start(self, lists: bool) -> bool:
        with self.lock:
            if self.busy:
                return False
            self.busy = True
        threading.Thread(target=self._collect, args=(lists,), daemon=True).start()
        return True

    def loop(self):
        while True:
            self.start(lists=False)
            time.sleep(600)

    def _collect(self, lists):
        ssh = ssh_ready()  # onthouden waarmee deze ronde is verzameld, zie updates_info
        try:
            self.info = {**pve.run(lambda api: self._gather(api, lists)), "checked": int(time.time()), "error": None, "ssh": ssh}
        except HTTPException as e:
            self.info = {**self.info, "error": e.detail, "ssh": ssh}
        except Exception as e:  # noqa: BLE001
            self.info = {**self.info, "error": e.__class__.__name__, "ssh": ssh}
        finally:
            self.busy = False

    def _gather(self, api, lists):
        nodes = [n["node"] for n in api.nodes.get() if n.get("status") == "online"]
        ips = node_ips(api)
        if lists:
            # 'apt-get update' op elke node; een mislukte taak (bv. een repo zonder abonnement) is geen
            # reden om te stoppen, de overige pakketlijsten zijn dan wel bijgewerkt.
            tasks = {n: api.nodes(n).apt.update.post() for n in nodes}
            deadline = time.monotonic() + 180
            while tasks and time.monotonic() < deadline:
                time.sleep(2)
                tasks = {n: u for n, u in tasks.items() if api.nodes(n).tasks(u).status.get().get("status") != "stopped"}
        guests = {}
        for found in POOL.map(lambda n: self._cts(ips.get(n), lists), nodes):
            guests.update(found)
        for g in api.cluster.resources.get(type="vm"):
            if g.get("type") == "qemu" and g.get("status") == "running" and g.get("node") in nodes:
                guests[str(g["vmid"])] = {"os": self._vm_os(api, g["node"], g["vmid"]), "updates": None}
        found = dict(zip(nodes, POOL.map(lambda n: self._node(api, n), nodes)))
        if ssh_ready():   # een node die er later bij is gekomen heeft het hulpscript nog niet; de pagina meldt dat
            for node, version in zip(nodes, POOL.map(lambda n: self._agent(ips.get(n)), nodes)):
                if found[node] is not None:
                    found[node]["agent"] = version
        return {"nodes": found, "guests": guests}

    @staticmethod
    def _agent(ip) -> int:
        try:
            return agent_version(ip) if ip else 0
        except HTTPException:
            return 0

    @staticmethod
    def _node(api, node):
        try:
            status = api.nodes(node).status.get()
            pending = api.nodes(node).apt.update.get()
            versions = api.nodes(node).apt.versions.get()
        except ResourceException:
            return None
        kernel = (status.get("current-kernel") or {}).get("release")
        return {"version": (status.get("pveversion") or "").partition("/")[2].partition("/")[0],
                "kernel": kernel, "updates": len(pending), "reboot": newer_kernel(versions, kernel)}

    @staticmethod
    def _cts(ip, lists):
        """Regels 'ct <vmid> <updates|-> <os>' van de agent; leeg als SSH (nog) niet werkt."""
        if not ip or not ssh_ready():
            return {}
        try:
            out = agent(ip, "refresh" if lists else "info", "cts", timeout=900 if lists else 180)
        except HTTPException:
            return {}
        found = {}
        for line in out.splitlines():
            parts = line.split(None, 3)
            if len(parts) == 4 and parts[0] == "ct":
                found[parts[1]] = {"os": parts[3], "updates": int(parts[2]) if parts[2].isdigit() else None}
        return found

    @staticmethod
    def _vm_os(api, node, vmid):
        try:
            return api.nodes(node).qemu(vmid).agent("get-osinfo").get()["result"].get("pretty-name")
        except (ResourceException, KeyError, TypeError):
            return None  # geen QEMU guest agent in de VM


updates = Updates()
threading.Thread(target=updates.loop, daemon=True).start()


class UpgradeIn(BaseModel):
    """Hoe de gebruiker zich indekt vóór een update of release-upgrade (zie "eerst een back-up")."""
    backup: str = Field("none", max_length=10)       # vzdump, snapshot of none
    storage: str | None = Field(None, max_length=64)  # bij vzdump: de back-upopslag
    mode: str = Field("snapshot", max_length=10)     # bij vzdump: snapshot, suspend of stop


def upgrade_words(node: str, target: str) -> list:
    """Vertaalt het doel uit de URL ('node' of een CT-nummer) naar de woorden voor de agent."""
    if not NODE_RE.match(node):
        raise HTTPException(400, "Ongeldige nodenaam")
    if target == "node":
        return ["node"]
    if not target.isdigit():
        raise HTTPException(400, "Doel moet 'node' of een CT-nummer zijn")
    check_target(node, "lxc", int(target))
    return ["ct", str(int(target))]


def node_ip(node: str) -> str:
    ip = pve.run(node_ips).get(node)
    if not ip:
        raise HTTPException(404, "Onbekende node")
    return ip


def parse_status(out: str) -> dict:
    first, _, log = out.partition("\n")
    fields = dict(f.split("=", 1) for f in first.split() if "=" in f)
    return {"state": fields.get("state", "none"), "exit": fields.get("exit"), "log": log}


@app.get("/api/updates")
def updates_info(request: Request, _: str = Depends(auth)):
    if updates.info["ssh"] != ssh_ready():
        # SSH is ingesteld (of weggevallen) na de laatste ronde: niet wachten op de volgende, de CT's ontbreken nu.
        updates.start(lists=False)
    return {**updates.info, "error": translate(updates.info.get("error"), lang_of(request)),
            "busy": updates.busy, "ssh": ssh_ready()}


@app.post("/api/updates/check")
def updates_check(lists: bool = True, _: str = Depends(manage_overview)):
    """Verzamelt opnieuw; met lists=true worden eerst overal de pakketlijsten ververst."""
    return {"started": updates.start(lists)}


@app.post("/api/upgrade/{node}/{target}")
def upgrade_start(node: str, target: str, body: UpgradeIn | None = None, _: str = Depends(manage_overview)):
    """Installeert de updates van een node of container. Bij een container kan eerst een back-up of snapshot worden
    gemaakt (body.backup); de update start dan op de achtergrond, pas als die gelukt is."""
    words = upgrade_words(node, target)
    body = body or UpgradeIn()
    check_backup_choice(body, target == "node")
    ips = pve.run(node_ips)
    if node not in ips:
        raise HTTPException(404, "Onbekende node")
    if target == "node":
        # Eén node tegelijk: het cluster (en Ceph) moet de andere twee kunnen blijven vertrouwen.
        for other, ip in ips.items():
            if other != node and parse_status(agent(ip, "status", "node"))["state"] == "active":
                raise HTTPException(409, f"Er loopt al een update op {other}; werk één node tegelijk bij")
    if body.backup != "none":
        if parse_status(agent(ips[node], "status", *words))["state"] == "active":
            return {"state": "running"}
        return start_prepared(node, int(target), ips[node], "update", body)
    with prep_lock:
        PREP.pop((node, target), None)
    started = agent(ips[node], "upgrade", *words).strip()
    if started == "started":
        remember("update", node, target, "" if target == "node" else pve.run(lambda api: guest_label(api, target)))
    return {"state": started}


@app.get("/api/upgrade/{node}/{target}")
def upgrade_status(node: str, target: str, request: Request, _: str = Depends(auth)):
    words = upgrade_words(node, target)
    p = prep_status(node, target) if target != "node" else None
    if p and p["state"] in ("backup", "snapshot"):
        text = "Back-up vooraf wordt gemaakt…" if p["state"] == "backup" else "Snapshot vooraf wordt gemaakt…"
        return {"state": "preparing", "exit": None, "log": translate(text, lang_of(request))}
    if p and p["state"] == "failed":
        return {"state": "failed", "exit": "backup", "log": translate(p["error"], lang_of(request))}
    return parse_status(agent(node_ip(node), "status", *words))


@app.post("/api/release/{node}/{vmid}")
def release_start(node: str, vmid: int, body: UpgradeIn | None = None, _: str = Depends(manage_overview)):
    """Brengt een Debian-CT één release omhoog. Maakt altijd eerst een snapshot om naar terug te kunnen; met
    body.backup = vzdump eerst ook een volledige back-up (op de achtergrond, de upgrade start pas als die gelukt is)."""
    check_target(node, "lxc", vmid)
    body = body or UpgradeIn()
    check_backup_choice(body, False)
    ip = node_ip(node)
    if agent_version(ip) < 3:
        # Zonder deze controle zou er een snapshot achterblijven voor een upgrade die niet kan starten.
        raise HTTPException(409, "De agent op de nodes is te oud voor release-upgrades; draai op een node: bash maintool-setup.sh --update")
    if parse_status(agent(ip, "status", "ct", str(vmid)))["state"] == "active":
        return {"state": "running", "snapshot": None}
    if body.backup == "vzdump":
        return {**start_prepared(node, vmid, ip, "release", body), "snapshot": None}
    with prep_lock:
        PREP.pop((node, str(vmid)), None)
    return release_now(node, vmid, ip)


def release_now(node: str, vmid: int, ip: str) -> dict:
    """De snapshot en daarna de release-upgrade zelf."""
    snap = time.strftime("voor_release_%Y%m%d_%H%M")

    def f(api):
        upid = guest(api, node, "lxc", vmid).snapshot.post(
            snapname=snap, description="automatisch, voor de release-upgrade via maintool")
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            task = api.nodes(node).tasks(upid).status.get()
            if task.get("status") == "stopped":
                if task.get("exitstatus") != "OK":
                    raise HTTPException(409, f"Snapshot mislukt ({task.get('exitstatus')}); de upgrade is niet gestart")
                return
            time.sleep(1)
        raise HTTPException(504, "Snapshot duurt te lang; de upgrade is niet gestart")
    pve.run(f)
    started = agent(ip, "release", "ct", str(vmid)).strip()
    if started == "started":
        remember("release", node, str(vmid), pve.run(lambda api: guest_label(api, vmid)))
    return {"state": started, "snapshot": snap}


# ---------------------------------------------------------------- eerst een back-up, dan bijwerken
# Bij updates en release-upgrades van een container kiest de gebruiker eerst hoe hij zich indekt: een volledige
# back-up (vzdump) naar een opslag, alleen een snapshot, of niets extra omdat er al een recente back-up is. De tool
# doet dat zelf op de achtergrond en start de update pas als de back-up gelukt is; mislukt die, dan gebeurt er niets.
# Dat loopt door, ook als de pagina wordt gesloten.
BACKUP_FIRST = ("vzdump", "snapshot", "none")
PREP = {}                     # (node, doel) -> {"state": "backup" | "snapshot" | "failed", "error", "t"}
prep_lock = threading.Lock()


def wait_task(api, node: str, upid: str, limit: float) -> str:
    """Wacht tot een taak van Proxmox klaar is; geeft de afloop ("OK", "WARNINGS: 1", een fout, of "duurt te lang")."""
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        st = api.nodes(node).tasks(upid).status.get()
        if st.get("status") == "stopped":
            return str(st.get("exitstatus") or "?")
        time.sleep(3)
    return "duurt te lang"


def task_ok(status: str) -> bool:
    return status == "OK" or status.startswith("WARNINGS")


def take_backup(node: str, vmid: int, how: str, storage: str | None = None, mode: str = "snapshot", snapname: str = "") -> str | None:
    """Maakt de gekozen back-up van een container; None als het gelukt is, anders de reden."""
    def f(api):
        if how == "vzdump":
            upid = api.nodes(node).vzdump.post(vmid=str(vmid), storage=storage, mode=mode, compress="zstd", **{"notes-template": NOTES})
            status = wait_task(api, node, upid, 6 * 3600)
        else:
            upid = guest(api, node, "lxc", vmid).snapshot.post(snapname=snapname, description="automatisch, voor een update via maintool")
            status = wait_task(api, node, upid, 900)
        return None if task_ok(status) else status
    try:
        return pve.run(f)
    except HTTPException as err:
        return str(err.detail)


def check_backup_choice(body: UpgradeIn, node_target: bool):
    if body.backup not in BACKUP_FIRST:
        raise HTTPException(400, "Onbekende keuze voor de back-up vooraf")
    if node_target and body.backup != "none":
        raise HTTPException(400, "Van een node zelf maakt Proxmox geen back-up; maak back-ups van de guests op die node")
    if body.backup == "vzdump":
        if body.mode not in MODES:
            raise HTTPException(400, "Kies minstens één guest en een geldige modus")
        pve.run(lambda api: check_storage(api, body.storage or ""))


def prepare_then(node: str, vmid: int, ip: str, verb: str, body: UpgradeIn):
    """Achtergrond: eerst de back-up, dan de update of release-upgrade. Een mislukte back-up stopt alles."""
    key, label = (node, str(vmid)), ""
    try:
        label = pve.run(lambda api: guest_label(api, vmid))
    except HTTPException:
        pass
    why = take_backup(node, vmid, body.backup, body.storage, body.mode, time.strftime("voor_update_%Y%m%d_%H%M"))
    if why:
        with prep_lock:
            PREP[key] = {"state": "failed", "t": time.time(),
                         "error": f"De back-up vooraf is mislukt ({why}); de {'release-upgrade' if verb == 'release' else 'update'} is niet gestart"}
        state.event(verb if verb == "release" else "update", f"niet gestart: back-up vooraf mislukt ({why})"[:200], node=node, target=str(vmid), name=label)
        return
    try:
        if verb == "release":
            release_now(node, vmid, ip)
        else:
            if agent(ip, "upgrade", "ct", str(vmid)).strip() == "started":
                remember("update", node, str(vmid), label)
        with prep_lock:
            PREP.pop(key, None)
    except HTTPException as err:
        with prep_lock:
            PREP[key] = {"state": "failed", "t": time.time(), "error": str(err.detail)}


def prep_status(node: str, target: str) -> dict | None:
    with prep_lock:
        p = PREP.get((node, target))
        if p and p["state"] == "failed" and time.time() - p["t"] > 3600:
            PREP.pop((node, target), None)
            return None
        return dict(p) if p else None


def start_prepared(node: str, vmid: int, ip: str, verb: str, body: UpgradeIn) -> dict:
    with prep_lock:
        if (PREP.get((node, str(vmid))) or {}).get("state") in ("backup", "snapshot"):
            return {"state": "preparing"}
        PREP[(node, str(vmid))] = {"state": "backup" if body.backup == "vzdump" else "snapshot", "t": time.time(), "error": None}
    threading.Thread(target=prepare_then, args=(node, vmid, ip, verb, body), daemon=True).start()
    return {"state": "preparing"}


@app.get("/api/backupfirst/{node}/{vmid}")
def backup_first_info(node: str, vmid: int, _: str = Depends(auth)):
    """Voor het venster vóór een update: de back-upopslag om uit te kiezen en de laatste back-up van deze guest."""
    check_target(node, "lxc", vmid)

    def f(api):
        stores, last = backup_storages(api), None
        for s in stores:
            try:
                for item in api.nodes(online_node(api)).storage(s["storage"]).content.get(content="backup", vmid=vmid):
                    if not last or (item.get("ctime") or 0) > last["ctime"]:
                        last = {"ctime": item.get("ctime") or 0, "storage": s["storage"], "size": item.get("size")}
            except ResourceException:
                pass
        return {"storages": stores, "last": last}
    return pve.run(f)


# ---------------------------------------------------------------- automatisch bijwerken volgens schema
# Op het geplande moment installeert de tool de updates in de gekozen containers en, als dat aan staat, op de nodes:
# één node tegelijk en alleen als het cluster gezond is (alle nodes online, Ceph klaar met herstellen). Naar keuze
# eerst een snapshot (de vorige automatische snapshot van die container wordt daarna opgeruimd) of een volledige
# back-up. Nodes worden nooit vanzelf herstart; een nodige herstart verschijnt bij de aandachtspunten. Elke uitkomst
# komt in het logboek (tabblad Events en het overzicht per mail).
AUTO_FREQ = ("daily", "weekly", "biweekly", "monthly")
AUTO_CTS = ("all", "list", "none")
AUTO_SNAP = "auto_update_"
AUTO = {"busy": False, "step": "", "results": [], "started": None, "finished": None}
auto_lock = threading.Lock()


AUTO_MAX = 20                                   # zoveel schema's naast elkaar
AUTO_ID_RE = re.compile(r"^s[0-9a-f]{1,8}$")
AUTO_NAME_RE = re.compile(r"^[^\x00-\x1f\x7f<>]{0,40}$")


def auto_clean(saved, sid: str = "s1") -> dict:
    """Eén schema, nagekeken en aangevuld met de standaard: wat ontbreekt of niet klopt wordt de standaard."""
    cfg = {"id": sid, "name": "", "enabled": False, "frequency": "weekly", "day": 6, "monthday": 1, "time": "03:00", "parity": 0,
           "cts": "all", "ct_list": [], "nodes": False, "backup": "snapshot", "storage": None, "mode": "snapshot", "config_at": 0}
    if not isinstance(saved, dict):
        return cfg
    whole = lambda v, low, high: isinstance(v, int) and not isinstance(v, bool) and low <= v <= high  # noqa: E731
    cfg["enabled"] = saved.get("enabled") is True
    if isinstance(saved.get("name"), str) and AUTO_NAME_RE.match(saved["name"].strip()):
        cfg["name"] = saved["name"].strip()
    if saved.get("frequency") in AUTO_FREQ:
        cfg["frequency"] = saved["frequency"]
    for key, low, high in (("day", 0, 6), ("monthday", 1, 28), ("parity", 0, 1), ("config_at", 0, 2**40)):
        if whole(saved.get(key), low, high):
            cfg[key] = saved[key]
    if isinstance(saved.get("time"), str) and TIME_RE.match(saved["time"]):
        cfg["time"] = saved["time"]
    if saved.get("cts") in AUTO_CTS:
        cfg["cts"] = saved["cts"]
    if isinstance(saved.get("ct_list"), list):
        cfg["ct_list"] = sorted({v for v in saved["ct_list"] if whole(v, 100, 999999999)})
    cfg["nodes"] = saved.get("nodes") is True
    if saved.get("backup") in BACKUP_FIRST:
        cfg["backup"] = saved["backup"]
    if isinstance(saved.get("storage"), str):
        cfg["storage"] = saved["storage"]
    if saved.get("mode") in MODES:
        cfg["mode"] = saved["mode"]
    return cfg


def auto_state(saved=None) -> tuple:
    """(de schema's, wanneer elk voor het laatst volgens schema draaide, de laatste ronde van elk). Tot 1.4 was er één
    schema (autoupdate, autoupdate_ran, autoupdate_last); dat is hier vanzelf het eerste, met id s1."""
    saved = state.load() if saved is None else saved
    raw = saved.get("autoupdate_schedules")
    if isinstance(raw, list):
        out, seen = [], set()
        for x in raw[:AUTO_MAX]:
            sid = x.get("id") if isinstance(x, dict) else None
            if isinstance(sid, str) and AUTO_ID_RE.match(sid) and sid not in seen:
                seen.add(sid)
                out.append(auto_clean(x, sid))
        ran = saved.get("autoupdate_ran_by") if isinstance(saved.get("autoupdate_ran_by"), dict) else {}
        last = saved.get("autoupdate_last_by") if isinstance(saved.get("autoupdate_last_by"), dict) else {}
        return out, ran, last
    if isinstance(saved.get("autoupdate"), dict):
        one = auto_clean({**saved["autoupdate"], "config_at": saved.get("autoupdate_config_at", 0)}, "s1")
        last = {"s1": saved["autoupdate_last"]} if isinstance(saved.get("autoupdate_last"), dict) else {}
        return [one], {"s1": saved.get("autoupdate_ran", 0)}, last
    return [], {}, {}


def auto_migrate(d: dict):
    """Zet de bewaarde gegevens om naar de vorm met meer schema's (binnen state.change)."""
    if not isinstance(d.get("autoupdate_schedules"), list):
        schedules, ran, last = auto_state(d)
        d["autoupdate_schedules"] = schedules
        d["autoupdate_ran_by"] = {k: v for k, v in ran.items() if isinstance(v, (int, float)) and not isinstance(v, bool)}
        d["autoupdate_last_by"] = last


def auto_store(d: dict, schedules: list):
    """Bewaart de schema's (binnen state.change). Het eerste staat ook nog op de oude plek: gaat iemand terug naar een
    versie van voor 1.4, dan werkt die met dat schema verder."""
    d["autoupdate_schedules"] = schedules
    first = schedules[0] if schedules else auto_clean(None)
    d["autoupdate"] = {k: v for k, v in first.items() if k not in ("id", "name", "config_at")}
    d["autoupdate_config_at"] = first["config_at"]
    keep = {c["id"] for c in schedules}
    for key in ("autoupdate_ran_by", "autoupdate_last_by"):
        if isinstance(d.get(key), dict):
            d[key] = {k: v for k, v in d[key].items() if k in keep}


def autoupdate_config() -> dict:
    """Het eerste schema (tot 1.4 het enige), of de standaard als er nog geen is."""
    schedules = auto_state()[0]
    return schedules[0] if schedules else auto_clean(None)


def autoupdate_due(saved: dict, cfg: dict, now=None):
    """Het geplande moment dat nu moet draaien, of None. Stond de tool toen uit, dan alsnog tot drie uur later (niet
    midden op de dag een update die voor de nacht bedoeld was)."""
    if not cfg["enabled"]:
        return None
    now = now or dt.datetime.now(REPORT_TZ)
    moment = report_moment(now, cfg)
    sid, old = cfg.get("id"), not isinstance(saved.get("autoupdate_schedules"), list)
    ran_by = auto_state(saved)[1]
    ran = ran_by.get(sid) if sid in ran_by else saved.get("autoupdate_ran", 0) if sid in (None, "s1") else 0
    changed = max(cfg.get("config_at") or 0, saved.get("autoupdate_config_at", 0) if old and sid in (None, "s1") else 0)
    ran = ran if isinstance(ran, (int, float)) and not isinstance(ran, bool) else 0
    if moment is None or ran >= moment.timestamp() or changed >= moment.timestamp():
        return None
    return moment if now - moment <= dt.timedelta(hours=3) else None


def cluster_blockers(api) -> list:
    """Redenen om nu geen node bij te werken: een node offline, geen meerderheid, of Ceph nog niet klaar."""
    blockers = [f"{n['node']} is niet online" for n in api.nodes.get() if n.get("status") != "online"]
    try:
        if any(e.get("type") == "cluster" and not e.get("quorate") for e in api.cluster.status.get()):
            blockers.append("het cluster heeft geen meerderheid (quorum)")
    except ResourceException:
        pass
    online = [n["node"] for n in api.nodes.get() if n.get("status") == "online"]
    try:
        ceph = api.nodes(online[0]).ceph.status.get() if online else None
    except ResourceException:
        ceph = None
    if ceph:
        osdmap = ceph.get("osdmap") or {}
        osdmap = osdmap.get("osdmap", osdmap)
        if osdmap.get("num_up_osds") != osdmap.get("num_osds"):
            blockers.append("niet alle Ceph-schijven (OSD's) zijn actief")
        if any(p.get("state_name") != "active+clean" for p in (ceph.get("pgmap") or {}).get("pgs_by_state", [])):
            blockers.append("Ceph is nog aan het herstellen")
    return blockers


def agent_wait(ip: str, words: list, limit: float) -> str:
    """Wacht tot een update via de agent klaar is; geeft "0" bij succes, anders de exitcode of een reden."""
    deadline = time.monotonic() + limit
    time.sleep(5)
    while time.monotonic() < deadline:
        try:
            st = parse_status(agent(ip, "status", *words, timeout=30))
        except HTTPException:
            time.sleep(20)
            continue
        if st["state"] != "active":
            return st["exit"] or st["state"]
        time.sleep(10)
    return "duurt te lang"


def prune_auto_snapshots(node: str, vmid: int, keep: str):
    """Haalt de oudere automatische snapshots (auto_update_...) van een container weg; die van nu blijft staan.
    Andere snapshots worden nooit aangeraakt."""
    def f(api):
        g = guest(api, node, "lxc", vmid)
        for s in g.snapshot.get():
            name = str(s.get("name") or "")
            if name.startswith(AUTO_SNAP) and name != keep and re.fullmatch(r"auto_update_\d{8}_\d{4}", name):
                wait_task(api, node, g.snapshot(name).delete(), 300)
    try:
        pve.run(f)
    except HTTPException:
        pass


def run_autoupdate(cfg: dict, why: str = "schema") -> bool:
    """Eén ronde automatisch bijwerken. False als er al een ronde loopt."""
    with auto_lock:
        if AUTO["busy"]:
            return False
        AUTO.update(busy=True, step="pakketlijsten verversen", results=[], started=int(time.time()), finished=None, why=why, id=cfg.get("id"))
    results = AUTO["results"]

    def note(target, code, ok, node=None, vmid=None, name="", n=None, detail=None):
        """Eén uitkomst: een vaste code (de pagina maakt er tekst van in haar taal); ok None = niets gedaan."""
        results.append({"target": target, "code": code, "ok": ok, "n": n, "detail": detail})
        if ok is not None and node:   # in het logboek, zoals een update die met de hand is gestart
            text = "gelukt" if ok else (f"niet gestart: back-up vooraf mislukt ({detail})" if code == "backupfail"
                                        else f"mislukt (code {detail})" if code == "failed" else "niet gestart")
            state.event("update", text[:200], node=node, target=str(vmid) if vmid is not None else "node", name=name, by="automatisch")
    try:
        if not ssh_ready():
            note("alles", "nossh", None)
            return True
        updates.start(lists=True)
        waited = 0
        while updates.busy and waited < 1200:
            time.sleep(5)
            waited += 5
        info = updates.info
        ips = pve.run(node_ips)
        online = {n["node"] for n in pve.run(lambda api: api.nodes.get()) if n.get("status") == "online"}
        cts = sorted((g for g in pve.run(lambda api: api.cluster.resources.get(type="vm"))
                      if g.get("type") == "lxc" and not g.get("template")), key=lambda g: g["vmid"])
        chosen = [g for g in cts if cfg["cts"] == "all" or (cfg["cts"] == "list" and g["vmid"] in cfg["ct_list"])]
        for g in chosen:
            vmid, node, name = g["vmid"], g.get("node"), g.get("name") or ""
            target = f"CT {vmid} {name}".strip()
            AUTO["step"] = target
            n = (info.get("guests", {}).get(str(vmid)) or {}).get("updates")
            if g.get("status") != "running" or node not in online:
                note(target, "off", None)
                continue
            if n is None:
                note(target, "noapt", None)
                continue
            if n == 0:
                note(target, "uptodate", None)
                continue
            if pve.run(lambda api: guest(api, node, "lxc", vmid).config.get()).get("lock"):
                note(target, "locked", None)
                continue
            if parse_status(agent(ips[node], "status", "ct", str(vmid)))["state"] == "active":
                note(target, "busy", None)
                continue
            snapname = time.strftime(AUTO_SNAP + "%Y%m%d_%H%M")
            if cfg["backup"] != "none":
                AUTO["step"] = f"{target}: back-up"
                failed = take_backup(node, vmid, cfg["backup"], cfg["storage"], cfg["mode"], snapname)
                if failed:
                    note(target, "backupfail", False, node, vmid, name, detail=str(failed)[:160])
                    continue
            AUTO["step"] = f"{target}: {n} update{'s' if n != 1 else ''}"
            if agent(ips[node], "upgrade", "ct", str(vmid)).strip() != "started":
                note(target, "notstarted", False, node, vmid, name)
                continue
            code = agent_wait(ips[node], ["ct", str(vmid)], 3600)
            ok = code == "0"
            note(target, "done" if ok else "failed", ok, node, vmid, name, n=n, detail=None if ok else code)
            if ok and cfg["backup"] == "snapshot":
                prune_auto_snapshots(node, vmid, snapname)
        if cfg["nodes"]:
            for node in sorted(online):
                target = f"node {node}"
                n = (info.get("nodes", {}).get(node) or {}).get("updates")
                if not n:
                    note(target, "uptodate" if n == 0 else "unreadable", None)
                    continue
                blockers = pve.run(cluster_blockers)
                if blockers:
                    note(target, "blocked", None, detail="; ".join(blockers)[:300])
                    break
                if any(parse_status(agent(ip, "status", "node"))["state"] == "active" for ip in ips.values()):
                    note(target, "nodebusy", None)
                    break
                AUTO["step"] = f"{target}: {n} updates"
                if agent(ips[node], "upgrade", "node").strip() != "started":
                    note(target, "notstarted", False, node)
                    break
                code = agent_wait(ips[node], ["node"], 5400)
                ok = code == "0"
                note(target, "nodedone" if ok else "failed", ok, node, n=n, detail=None if ok else code)
                if not ok:
                    break   # bij een fout niet aan de volgende node beginnen
                for _ in range(120):   # eerst Ceph en het cluster weer helemaal in orde, dan pas de volgende
                    if not pve.run(cluster_blockers):
                        break
                    time.sleep(15)
        return True
    except Exception as err:  # noqa: BLE001 - de ronde mag de tool niet laten struikelen
        results.append({"target": "alles", "code": "aborted", "ok": False, "n": None, "detail": str(getattr(err, "detail", None) or err.__class__.__name__)[:200]})
        return True
    finally:
        AUTO.update(busy=False, step="", finished=int(time.time()))
        last = {"started": AUTO["started"], "finished": AUTO["finished"], "why": why, "results": results[:100],
                "id": cfg.get("id"), "name": cfg.get("name") or ""}

        def keep(d):
            d["autoupdate_last"] = last   # de laatste ronde van alle schema's samen (zoals voor 1.4)
            if cfg.get("id"):
                by = d.get("autoupdate_last_by") if isinstance(d.get("autoupdate_last_by"), dict) else {}
                d["autoupdate_last_by"] = {**by, cfg["id"]: last}
        try:
            state.change(keep)
        except OSError:
            pass
        issues.at = 0   # de aandachtspunten opnieuw uitrekenen


def autoupdate_loop():
    """Eens per minuut: is er een schema aan de beurt, dan draait dat. Staan er meer tegelijk, dan na elkaar: één ronde
    tegelijk, en een schema dat moest wachten draait alsnog zolang dat binnen drie uur na zijn moment is."""
    while True:
        time.sleep(60)
        try:
            saved = state.load()
            if AUTO["busy"]:
                continue
            due = [(m, c) for c in auto_state(saved)[0] for m in [autoupdate_due(saved, c)] if m is not None]
            if not due:
                continue
            cfg = min(due, key=lambda x: x[0])[1]

            def mark(d):
                auto_migrate(d)
                d["autoupdate_ran_by"] = {**d["autoupdate_ran_by"], cfg["id"]: int(time.time())}
            state.change(mark)
            run_autoupdate(cfg)
        except Exception:  # noqa: BLE001 - de planner mag nooit stoppen
            pass


class AutoIn(BaseModel):
    enabled: bool
    name: str = Field("", max_length=40)
    frequency: str = Field("weekly", max_length=10)
    day: int = Field(6, strict=True)
    monthday: int = Field(1, strict=True)
    time: str = Field("03:00", max_length=5)
    cts: str = Field("all", max_length=5)
    ct_list: list[int] = Field(default_factory=list, max_length=500)
    nodes: bool = False
    backup: str = Field("snapshot", max_length=10)
    storage: str | None = Field(None, max_length=64)
    mode: str = Field("snapshot", max_length=10)


def auto_checked(body: AutoIn, sid: str) -> dict:
    """De instellingen van één schema uit wat de pagina stuurt; 400 bij iets dat niet klopt."""
    if not AUTO_NAME_RE.match(body.name.strip()):
        raise HTTPException(400, "Ongeldige naam: hooguit 40 tekens, zonder < of >")
    if body.frequency not in AUTO_FREQ:
        raise HTTPException(400, "Ongeldige keuze bij Hoe vaak")
    if not 0 <= body.day <= 6:
        raise HTTPException(400, "Ongeldige dag")
    if not 1 <= body.monthday <= 28:
        raise HTTPException(400, "Kies een dag van de maand van 1 tot en met 28")
    if not TIME_RE.match(body.time):
        raise HTTPException(400, "Ongeldige tijd; gebruik uu:mm, bijvoorbeeld 05:00")
    if body.cts not in AUTO_CTS:
        raise HTTPException(400, "Ongeldige keuze van de containers")
    if any(not 100 <= v <= 999999999 for v in body.ct_list):
        raise HTTPException(400, "Ongeldig VMID")
    if body.cts == "list" and not body.ct_list:
        raise HTTPException(400, "Kies minstens één container, of kies Alle containers")
    if body.enabled and body.cts == "none" and not body.nodes:
        raise HTTPException(400, "Kies wat er bijgewerkt moet worden: containers, nodes of allebei")
    if body.backup not in BACKUP_FIRST:
        raise HTTPException(400, "Onbekende keuze voor de back-up vooraf")
    if body.backup == "vzdump":
        if body.mode not in MODES:
            raise HTTPException(400, "Kies minstens één guest en een geldige modus")
        pve.run(lambda api: check_storage(api, body.storage or ""))
    cfg = {"id": sid, "name": body.name.strip(), "enabled": body.enabled, "frequency": body.frequency, "day": body.day,
           "monthday": body.monthday, "time": body.time, "cts": body.cts, "ct_list": sorted(set(body.ct_list)), "nodes": body.nodes,
           "backup": body.backup, "storage": body.storage if body.backup == "vzdump" else None, "mode": body.mode, "parity": 0,
           "config_at": int(time.time())}
    if body.frequency == "biweekly":   # om de week: de eerstvolgende keer is de eerstvolgende week met die dag
        weekly = {**cfg, "frequency": "weekly"}
        cfg["parity"] = week_number(report_step(report_moment(cfg=weekly), weekly)) % 2
    return cfg


def auto_change(fn):
    """Past de lijst met schema's aan met fn(lijst) en bewaart hem. fn vraagt niets aan Proxmox: dat gebeurt vooraf
    (auto_checked), want de toestand blijft zolang op slot."""
    def change(d):
        auto_migrate(d)
        schedules = [auto_clean(x, x["id"]) for x in d["autoupdate_schedules"]]
        auto_store(d, fn(schedules))
    try:
        state.change(change)
    except OSError:
        raise HTTPException(500, "De instelling kon niet bewaard worden")


def autoupdate_view() -> dict:
    saved = state.load()
    schedules, _ran, last_by = auto_state(saved)

    def one(cfg):
        moment = report_moment(cfg=cfg) if cfg["enabled"] else None
        upcoming = report_step(moment, cfg) if moment else None
        last = last_by.get(cfg["id"])
        return {**cfg, "next": int(upcoming.timestamp()) if upcoming else None, "last": last if isinstance(last, dict) else None}
    views = [one(c) for c in schedules]
    last = saved.get("autoupdate_last") if isinstance(saved.get("autoupdate_last"), dict) else None
    return {"config": views[0] if views else auto_clean(None), "next": views[0]["next"] if views else None, "schedules": views,
            "max": AUTO_MAX, "busy": AUTO["busy"], "step": AUTO["step"], "running_id": AUTO.get("id") if AUTO["busy"] else None,
            "running": list(AUTO["results"]) if AUTO["busy"] else None, "last": last}


@app.get("/api/autoupdate")
def autoupdate_get(_: str = Depends(auth)):
    return autoupdate_view()


@app.put("/api/autoupdate")
def autoupdate_put(body: AutoIn, request: Request, _: str = Depends(manage_overview)):
    """Het eerste schema instellen (zoals voor 1.4, toen er één was); bestaat er nog geen, dan wordt het aangemaakt."""
    same_origin(request)
    now = auto_state()[0]
    cfg = auto_checked(body, now[0]["id"] if now else "s1")
    auto_change(lambda schedules: [cfg] + [c for c in schedules[1:] if c["id"] != cfg["id"]])
    return autoupdate_view()


@app.post("/api/autoupdate/schedules")
def autoupdate_add(body: AutoIn, request: Request, _: str = Depends(manage_overview)):
    """Een nieuw schema, met eigen containers, een eigen moment en een eigen back-up vooraf."""
    same_origin(request)
    taken = {c["id"] for c in auto_state()[0]}
    cfg = auto_checked(body, next(s for s in ("s" + secrets.token_hex(3) for _ in range(50)) if s not in taken))

    def change(schedules):
        if len(schedules) >= AUTO_MAX:
            raise HTTPException(409, f"Er kunnen hooguit {AUTO_MAX} schema's zijn")
        if any(c["id"] == cfg["id"] for c in schedules):
            raise HTTPException(409, "Probeer het nog een keer")
        return schedules + [cfg]
    auto_change(change)
    return {**autoupdate_view(), "id": cfg["id"]}


def auto_find(schedules: list, sid: str) -> int:
    if not AUTO_ID_RE.match(sid):
        raise HTTPException(400, "Ongeldig schema")
    for i, c in enumerate(schedules):
        if c["id"] == sid:
            return i
    raise HTTPException(404, "Dit schema bestaat niet (meer)")


@app.put("/api/autoupdate/schedules/{sid}")
def autoupdate_edit(sid: str, body: AutoIn, request: Request, _: str = Depends(manage_overview)):
    same_origin(request)
    auto_find(auto_state()[0], sid)   # eerst: bestaat het nog (404), dan pas de rest nakijken
    cfg = auto_checked(body, sid)

    def change(schedules):
        i = auto_find(schedules, sid)
        return schedules[:i] + [cfg] + schedules[i + 1:]
    auto_change(change)
    return autoupdate_view()


@app.delete("/api/autoupdate/schedules/{sid}")
def autoupdate_remove(sid: str, request: Request, _: str = Depends(manage_overview)):
    same_origin(request)
    if AUTO["busy"] and AUTO.get("id") == sid:
        raise HTTPException(409, "Dit schema draait nu; verwijder het als de ronde klaar is")

    def change(schedules):
        i = auto_find(schedules, sid)
        return schedules[:i] + schedules[i + 1:]
    auto_change(change)
    return autoupdate_view()


def auto_start(cfg: dict):
    if cfg["cts"] == "none" and not cfg["nodes"]:
        raise HTTPException(400, "Kies wat er bijgewerkt moet worden: containers, nodes of allebei")
    if AUTO["busy"]:
        raise HTTPException(409, "Er loopt al een ronde automatisch bijwerken")
    threading.Thread(target=run_autoupdate, args=(cfg, "met de hand"), daemon=True).start()
    return {"started": True}


@app.post("/api/autoupdate/run")
def autoupdate_run(request: Request, _: str = Depends(manage_overview)):
    """Nu een ronde draaien met het eerste schema zoals het is opgeslagen (ook als het uit staat)."""
    same_origin(request)
    return auto_start(autoupdate_config())


@app.post("/api/autoupdate/schedules/{sid}/run")
def autoupdate_run_one(sid: str, request: Request, _: str = Depends(manage_overview)):
    """Nu een ronde draaien met dit schema zoals het is opgeslagen (ook als het uit staat)."""
    same_origin(request)
    schedules = auto_state()[0]
    return auto_start(schedules[auto_find(schedules, sid)])


# ---------------------------------------------------------------- node herstarten
def reboot_check(api, node):
    """Redenen om een node nu niet te herstarten, en de guests die er nog op draaien."""
    nodes = api.nodes.get()
    if not any(n["node"] == node and n.get("status") == "online" for n in nodes):
        raise HTTPException(409, "Deze node is niet online")
    blockers = []
    offline = [n["node"] for n in nodes if n["node"] != node and n.get("status") != "online"]
    if offline:
        blockers.append(f"{', '.join(offline)} is niet online; met nog een node uit verliest het cluster zijn meerderheid")
    try:
        ceph = api.nodes(node).ceph.status.get()
    except ResourceException:
        ceph = None  # cluster zonder Ceph
    if ceph:
        # Een OSD die al weg is of data die nog hersteld wordt: nog een node uit kan de opslag stilleggen.
        osdmap = ceph.get("osdmap") or {}
        osdmap = osdmap.get("osdmap", osdmap)
        if osdmap.get("num_up_osds") != osdmap.get("num_osds"):
            blockers.append("niet alle Ceph-schijven (OSD's) zijn actief")
        busy = [p for p in (ceph.get("pgmap") or {}).get("pgs_by_state", []) if p.get("state_name") != "active+clean"]
        if busy:
            blockers.append("Ceph is nog aan het herstellen (" + ", ".join(f"{p['count']}x {p['state_name']}" for p in busy) + ")")
    if ssh_ready():
        ip = node_ips(api).get(node)
        if ip and parse_status(agent(ip, "status", "node"))["state"] == "active":
            blockers.append("er loopt nog een update op deze node")
    guests = []
    for g in api.cluster.resources.get(type="vm"):
        if g.get("node") == node and g.get("status") == "running":
            auto = g.get("hastate") == "started" or bool(guest(api, node, g["type"], g["vmid"]).config.get().get("onboot"))
            guests.append({"vmid": g["vmid"], "name": g.get("name"), "auto": auto})
            if g["type"] == "lxc" and ct_busy(api, node, g["vmid"]):
                blockers.append(f"er loopt nog een update in CT {g['vmid']} ({g.get('name')})")
    return {"blockers": blockers, "guests": sorted(guests, key=lambda g: g["vmid"])}


@app.get("/api/node/{node}/reboot")
def reboot_info(node: str, request: Request, _: str = Depends(auth)):
    if not NODE_RE.match(node):
        raise HTTPException(400, "Ongeldige nodenaam")
    info = pve.run(lambda api: reboot_check(api, node))
    return {**info, "blockers": [translate(b, lang_of(request)) for b in info["blockers"]]}


@app.post("/api/node/{node}/reboot")
def reboot_node(node: str, request: Request, _: str = Depends(manage_overview)):
    if not NODE_RE.match(node):
        raise HTTPException(400, "Ongeldige nodenaam")

    def f(api):
        blockers = reboot_check(api, node)["blockers"]
        if blockers:
            raise HTTPException(409, "Herstart geweigerd: " + "; ".join(translate(b, lang_of(request)) for b in blockers))
        api.nodes(node).status.post(command="reboot")
        try:
            state.event("reboot", "gestart", node=node, target="node")
        except OSError:
            pass
        return {"started": True}
    return pve.run(f)


@app.get("/api/task/{node}/{upid}")
def task_status(node: str, upid: str, _: str = Depends(auth)):
    if not NODE_RE.match(node) or not upid.startswith("UPID:"):
        raise HTTPException(400, "Ongeldige taak")
    return pve.run(lambda api: api.nodes(node).tasks(upid).status.get())


@app.get("/api/task/{node}/{upid}/log")
def task_log(node: str, upid: str, _: str = Depends(auth)):
    """Staat en (het einde van) het log van een Proxmox-taak, voor taken die lang lopen zoals een back-up."""
    if not NODE_RE.match(node) or not upid.startswith("UPID:"):
        raise HTTPException(400, "Ongeldige taak")

    def f(api):
        status = api.nodes(node).tasks(upid).status.get()
        lines = [line.get("t", "") for line in api.nodes(node).tasks(upid).log.get(limit=5000)]
        return {"status": status.get("status"), "exitstatus": status.get("exitstatus"), "log": "\n".join(lines[-400:])}
    return pve.run(f)


# ---------------------------------------------------------------- back-ups
# De tool beheert de back-upschema's van Proxmox zelf (/cluster/backup) en start vzdump op de nodes. Proxmox voert
# de schema's dus uit, ook als deze tool uit staat, en schrijft gewone vzdump-archieven (CT: tar.zst, VM: vma.zst)
# die elke Proxmox-installatie kan terugzetten, zonder deze tool.
JOB_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,49}$")
SCHEDULE_RE = re.compile(r"^[A-Za-z0-9 ,.*:/-]{1,100}$")
VOLID_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*):backup/vzdump-(lxc|qemu)-(\d+)-[0-9_-]+\.[A-Za-z0-9.]+$")
MODES = {"snapshot", "suspend", "stop"}
KEEP = ("last", "daily", "weekly", "monthly")
NOTES = "{{guestname}}"


def prune_text(value) -> str:
    """Proxmox geeft de bewaarregels van een schema als object terug; de pagina en vzdump willen 'keep-last=3,...'."""
    if isinstance(value, dict):
        return ",".join(f"{k}={v}" for k, v in value.items())
    return value or ""


def online_node(api) -> str:
    """Een node die online is, bij voorkeur een die ook via de API antwoordt (zie NodeTrouble)."""
    up = [n["node"] for n in api.nodes.get() if n.get("status") == "online"]
    node = next((n for n in up if not node_trouble.skip(n)), None) or next(iter(up), None)
    if not node:
        raise HTTPException(503, "Geen enkele node is online")
    return node


def single_node(api) -> bool:
    return len(api.nodes.get()) == 1


def backup_storages(api) -> list:
    """Opslag waar back-ups naartoe mogen. In een cluster alleen gedeelde opslag: daar kan elke node bij, ook na
    een migratie. Met maar één node valt er niets te delen en telt elke back-upopslag."""
    alone = single_node(api)
    usage = {s["storage"]: s for s in api.cluster.resources.get(type="storage") if s.get("status") == "available"}
    return [{"storage": s["storage"], "type": s.get("type"),
             "disk": usage.get(s["storage"], {}).get("disk"), "maxdisk": usage.get(s["storage"], {}).get("maxdisk")}
            for s in api.storage.get()
            if "backup" in (s.get("content") or "").split(",") and (s.get("shared") or alone) and not s.get("disable")]


def check_storage(api, storage: str):
    if storage not in {s["storage"] for s in backup_storages(api)}:
        raise HTTPException(400, "Deze opslag is niet beschikbaar voor back-ups")


def check_job(job: str):
    if not JOB_RE.match(job):
        raise HTTPException(400, "Ongeldig schema")


class JobIn(BaseModel):
    comment: str = Field("", max_length=120)
    all: bool = False               # alle guests, ook die er later bij komen
    vmids: list[int] = []
    schedule: str                   # Proxmox-notatie, bv. "mon,wed,fri 02:30" of "02:30" (elke dag)
    storage: str
    mode: str = "snapshot"
    enabled: bool = True
    keep_last: int = Field(0, ge=0, le=999)
    keep_daily: int = Field(0, ge=0, le=999)
    keep_weekly: int = Field(0, ge=0, le=999)
    keep_monthly: int = Field(0, ge=0, le=999)


def job_params(api, body: JobIn) -> dict:
    """Controleert een schema uit de webpagina en vertaalt het naar de opties van Proxmox."""
    if body.mode not in MODES:
        raise HTTPException(400, "Onbekende modus")
    if not SCHEDULE_RE.match(body.schedule):
        raise HTTPException(400, "Ongeldig tijdschema")
    check_storage(api, body.storage)
    params = {"schedule": body.schedule.strip(), "storage": body.storage, "mode": body.mode,
              "enabled": int(body.enabled), "compress": "zstd", "notes-template": NOTES}
    if body.all:
        params["all"] = 1
    else:
        known = {g["vmid"] for g in api.cluster.resources.get(type="vm")}
        if not body.vmids or not set(body.vmids) <= known:
            raise HTTPException(400, "Kies minstens één bestaande guest")
        params["vmid"] = ",".join(str(v) for v in sorted(set(body.vmids)))
    keep = ",".join(f"keep-{k}={getattr(body, 'keep_' + k)}" for k in KEEP if getattr(body, "keep_" + k))
    params["prune-backups"] = keep or "keep-all=1"
    if body.comment.strip():
        params["comment"] = body.comment.strip()
    return params


def start_backups(api, vmids, storage: str, mode: str, prune: str = "") -> list:
    """Start per node één vzdump-taak voor de guests die daar op dit moment staan."""
    where = {g["vmid"]: g["node"] for g in api.cluster.resources.get(type="vm")}
    online = {n["node"] for n in api.nodes.get() if n.get("status") == "online"}
    tasks = []
    for node in sorted({where[v] for v in vmids if where.get(v) in online}):
        ids = ",".join(str(v) for v in sorted(v for v in set(vmids) if where.get(v) == node))
        params = {"vmid": ids, "storage": storage, "mode": mode, "compress": "zstd", "notes-template": NOTES}
        if prune:
            params["prune-backups"] = prune
        tasks.append({"node": node, "vmids": ids, "upid": api.nodes(node).vzdump.post(**params)})
    if not tasks:
        raise HTTPException(409, "Geen van deze guests staat op een node die online is")
    return tasks


@app.get("/api/backup/overview")
def backup_overview(_: str = Depends(auth)):
    def f(api):
        jobs = sorted(api.cluster.backup.get(), key=lambda j: j.get("comment") or j.get("id", ""))
        for j in jobs:
            j["prune-backups"] = prune_text(j.get("prune-backups"))
        return {"jobs": jobs, "storages": backup_storages(api), "nextid": int(api.cluster.nextid.get())}
    return pve.run(f)


@app.post("/api/backup/jobs")
def backup_job_create(body: JobIn, _: str = Depends(manage_backups)):
    def f(api):
        api.cluster.backup.post(**job_params(api, body))
        return {"ok": True}
    return pve.run(f)


@app.put("/api/backup/jobs/{job}")
def backup_job_update(job: str, body: JobIn, _: str = Depends(manage_backups)):
    check_job(job)

    def f(api):
        params = job_params(api, body)
        # Wat het schema had maar nu niet meer hoort te hebben, moet expliciet weg (bv. 'all' bij een lijst guests).
        current = api.cluster.backup(job).get()
        gone = [k for k in ("all", "vmid", "comment") if k in current and k not in params]
        if "exclude" in current and not body.all:
            gone.append("exclude")  # uitzonderingen horen alleen bij "alle guests"; daar blijven ze staan
        if gone:
            params["delete"] = ",".join(gone)
        api.cluster.backup(job).put(**params)
        return {"ok": True}
    return pve.run(f)


@app.post("/api/backup/jobs/{job}/enabled")
def backup_job_enable(job: str, on: bool, _: str = Depends(manage_backups)):
    check_job(job)
    pve.run(lambda api: api.cluster.backup(job).put(enabled=int(on)))
    return {"ok": True}


@app.delete("/api/backup/jobs/{job}")
def backup_job_delete(job: str, _: str = Depends(manage_backups)):
    check_job(job)
    pve.run(lambda api: api.cluster.backup(job).delete())
    return {"ok": True}


@app.post("/api/backup/jobs/{job}/run")
def backup_job_run(job: str, _: str = Depends(manage_backups)):
    """Voert een schema nu één keer uit, met zijn eigen opslag, modus en bewaarregels."""
    check_job(job)

    def f(api):
        j = api.cluster.backup(job).get()
        if j.get("all"):
            skip = {int(v) for v in str(j.get("exclude") or "").split(",") if v.strip().isdigit()}
            vmids = [g["vmid"] for g in api.cluster.resources.get(type="vm") if g["vmid"] not in skip and not g.get("template")]
        else:
            vmids = [int(v) for v in str(j.get("vmid") or "").split(",") if v.strip().isdigit()]
        check_storage(api, j.get("storage", ""))
        return start_backups(api, vmids, j["storage"], j.get("mode", "snapshot"), prune_text(j.get("prune-backups")))
    tasks = pve.run(f)
    remember_job_run(job, tasks)   # voor het logboek van de back-ups (zie backup_log)
    return {"tasks": tasks}


class BackupNowIn(BaseModel):
    vmids: list[int]
    storage: str
    mode: str = "snapshot"


@app.post("/api/backup/run")
def backup_now(body: BackupNowIn, _: str = Depends(manage_backups)):
    """Losse back-up, buiten een schema om. Ruimt geen oudere back-ups op."""
    if body.mode not in MODES or not body.vmids:
        raise HTTPException(400, "Kies minstens één guest en een geldige modus")

    def f(api):
        check_storage(api, body.storage)
        return start_backups(api, body.vmids, body.storage, body.mode)
    return {"tasks": pve.run(f)}


@app.get("/api/backup/files")
def backup_files(storage: str, _: str = Depends(auth)):
    def f(api):
        check_storage(api, storage)
        files = api.nodes(online_node(api)).storage(storage).content.get(content="backup")
        keys = ("volid", "vmid", "subtype", "ctime", "size", "notes", "protected")
        return sorted(({k: x.get(k) for k in keys} for x in files), key=lambda x: -(x.get("ctime") or 0))
    return pve.run(f)


def check_volid(api, storage: str, volid: str):
    """Geeft het soort guest ('lxc' of 'qemu') van een back-upbestand, na controle dat het bij deze opslag hoort."""
    m = VOLID_RE.match(volid)
    if not m or m.group(1) != storage:
        raise HTTPException(400, "Ongeldig back-upbestand")
    check_storage(api, storage)
    return m.group(2)


def backup_origin(api, volid: str, kind: str):
    """De opslag waarop de (eerste) schijf van de guest stond, volgens de configuratie die in het archief zit."""
    text = api.nodes(online_node(api)).vzdump.extractconfig.get(volume=volid) or ""
    pattern = r"^rootfs: ([^:,\s]+):" if kind == "lxc" else r"^(?:scsi|virtio|sata|ide)\d+: ([^:,\s]+):(?!.*media=cdrom)"
    m = re.search(pattern, text, re.M)
    return m.group(1) if m else None


def disk_storages(api, kind: str) -> list:
    """Opslag waarop de schijf van een CT (rootdir) of VM (images) mag staan."""
    want = "rootdir" if kind == "lxc" else "images"
    return sorted(s["storage"] for s in api.storage.get()
                  if want in (s.get("content") or "").split(",") and not s.get("disable"))


@app.get("/api/backup/restoreinfo")
def backup_restoreinfo(storage: str, volid: str, _: str = Depends(auth)):
    def f(api):
        kind = check_volid(api, storage, volid)
        return {"original": backup_origin(api, volid, kind), "storages": disk_storages(api, kind)}
    return pve.run(f)


@app.delete("/api/backup/files")
def backup_file_delete(storage: str, volid: str, _: str = Depends(manage_backups)):
    def f(api):
        check_volid(api, storage, volid)
        node = online_node(api)
        return {"upid": api.nodes(node).storage(storage).content(volid).delete(), "node": node}
    return pve.run(f)


class RestoreIn(BaseModel):
    storage: str
    volid: str
    vmid: int                   # het ID dat de teruggezette guest krijgt
    node: str                   # alleen voor een nieuw ID; een bestaande guest wordt op zijn eigen node overschreven
    overwrite: bool = False
    disk_storage: str = ""      # opslag voor de schijf; leeg = waar hij stond toen de back-up werd gemaakt


@app.post("/api/backup/restore")
def backup_restore(body: RestoreIn, _: str = Depends(manage_backups)):
    if not NODE_RE.match(body.node) or not (100 <= body.vmid <= 999999999):
        raise HTTPException(400, "Ongeldige node of ongeldig ID")

    def f(api):
        kind = check_volid(api, body.storage, body.volid)
        guests = api.cluster.resources.get(type="vm")
        # Alleen een kopie náást het origineel krijgt een eigen MAC-adres; een verwijderde guest komt terug zoals hij was.
        origin_alive = any(g["vmid"] == int(VOLID_RE.match(body.volid).group(3)) for g in guests)
        node, extra = body.node, ({"unique": 1} if origin_alive else {})
        existing = next((g for g in guests if g["vmid"] == body.vmid), None)
        if existing:
            if not body.overwrite:
                raise HTTPException(409, f"ID {body.vmid} is al in gebruik")
            if existing["type"] != kind:
                raise HTTPException(409, f"ID {body.vmid} is een ander soort guest dan deze back-up")
            if existing.get("status") != "stopped":
                raise HTTPException(409, "Zet de guest eerst uit; een draaiende guest kan niet worden overschreven")
            node, extra = existing["node"], {"force": 1}
        elif body.overwrite:
            raise HTTPException(409, f"Er is geen guest met ID {body.vmid} om te overschrijven")
        # Proxmox zet een CT zonder opgave op 'local' terug, en dat mag daar meestal niet staan.
        target = body.disk_storage or backup_origin(api, body.volid, kind)
        if target not in disk_storages(api, kind):
            raise HTTPException(400, "Op deze opslag mag de schijf van de guest niet staan" if body.disk_storage
                                else "Kies een opslag voor de schijf van de guest; de oorspronkelijke is er niet meer")
        if kind == "lxc" or body.disk_storage:
            extra["storage"] = target
        if kind == "lxc":
            upid = api.nodes(node).lxc.post(vmid=body.vmid, ostemplate=body.volid, restore=1, **extra)
        else:
            upid = api.nodes(node).qemu.post(vmid=body.vmid, archive=body.volid, **extra)
        return {"upid": upid, "node": node}
    return pve.run(f)


# ---------------------------------------------------------------- weekoverzicht per mail
# Eén mail per week (standaard zondag 05:00) over de afgelopen 7 dagen: nodes, guests, back-ups en updates.
# De cijfers komen uit de takenlijst van Proxmox en uit een eigen logboekje van wat via deze tool is gestart
# (updates draaien via de agent en staan niet in de takenlijst van Proxmox).
MAIL_HOST = os.environ.get("MAIL_SMTP_HOST", "smtp.gmail.com")
MAIL_PORT = int(os.environ.get("MAIL_SMTP_PORT", "587"))
MAIL_USER = os.environ.get("MAIL_USER", "")
MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "").replace(" ", "")  # Gmail toont een app-wachtwoord met spaties
MAIL_TO = os.environ.get("MAIL_TO", "") or MAIL_USER
MAIL_FROM = os.environ.get("MAIL_FROM", "") or MAIL_USER
REPORT_DAY = os.environ.get("REPORT_DAY", "sun").lower()[:3]
REPORT_TIME = os.environ.get("REPORT_TIME", "05:00")
REPORT_TZ = ZoneInfo(os.environ.get("REPORT_TZ", "Europe/Amsterdam"))
# Guests waarvan bewust geen back-up wordt gemaakt; het overzicht meldt die niet als aandachtspunt.
NO_BACKUP = {int(v) for v in os.environ.get("REPORT_NO_BACKUP", "").replace(" ", "").split(",") if v.isdigit()}
WEEKDAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
DAGEN = ["maandag", "dinsdag", "woensdag", "donderdag", "vrijdag", "zaterdag", "zondag"]
MAANDEN = ["jan", "feb", "mrt", "apr", "mei", "jun", "jul", "aug", "sep", "okt", "nov", "dec"]
TASK_NAMES = {
    "vzdump": "back-up", "vzstart": "starten", "vzstop": "stoppen", "vzshutdown": "afsluiten", "vzreboot": "herstarten",
    "vzmigrate": "migreren", "hamigrate": "migreren (HA)", "vzsnapshot": "snapshot maken", "vzrollback": "snapshot terugzetten",
    "vzdelsnapshot": "snapshot verwijderen", "vzrestore": "terugzetten", "vzcreate": "aanmaken", "vzdestroy": "verwijderen",
    "qmstart": "starten", "qmstop": "stoppen", "qmshutdown": "afsluiten", "qmreboot": "herstarten", "qmigrate": "migreren",
    "qmsnapshot": "snapshot maken", "qmrollback": "snapshot terugzetten", "qmdelsnapshot": "snapshot verwijderen",
    "qmrestore": "terugzetten", "qmcreate": "aanmaken", "qmdestroy": "verwijderen", "aptupdate": "updates zoeken",
    "startall": "alles starten", "stopall": "alles stoppen", "imgdel": "bestand verwijderen",
}
STARTS = {"vzstart", "qmstart", "vzreboot", "qmreboot"}
STOPS = {"vzstop", "qmstop", "vzshutdown", "qmshutdown"}
MOVES = {"vzmigrate", "qmigrate"}
NOISE = {"vncproxy", "vncshell", "spiceproxy", "termproxy"}  # afgebroken consolesessies zijn geen storing


class State:
    """Het geheugen van de tool op schijf: het logboekje, welke updates nog lopen en wanneer er gemaild is."""

    def __init__(self):
        self.lock = threading.Lock()
        self.file = STATE_DIR / "state.json"
        self.log = STATE_DIR / "events.jsonl"

    def load(self) -> dict:
        try:
            return json.loads(self.file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def change(self, fn):
        """Leest de toestand, laat fn hem aanpassen en schrijft hem terug, als één geheel."""
        with self.lock:
            data = self.load()
            fn(data)
            tmp = self.file.with_suffix(".tmp")
            tmp.write_text(json.dumps(data), encoding="utf-8")
            tmp.replace(self.file)

    def event(self, kind: str, result: str, **fields):
        with self.lock, self.log.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"t": int(time.time()), "kind": kind, "result": result, **fields}) + "\n")

    def events(self, since: float) -> list:
        try:
            rows = [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines() if line.strip()]
        except (OSError, ValueError):
            return []
        return [r for r in rows if r.get("t", 0) >= since]


state = State()


def remember(kind: str, node: str, target: str, name: str = ""):
    """Onthoudt dat er via de tool een update of release-upgrade is gestart, zodat de bewaker de afloop kan noteren."""
    try:
        job = {"t": int(time.time()), "kind": kind, "node": node, "target": target, "name": name}
        state.change(lambda d: d.setdefault("pending", []).append(job))
    except OSError:
        pass  # zonder schrijfbare map werkt alles behalve het logboekje


def guest_label(api, vmid) -> str:
    return next((g.get("name") or "" for g in api.cluster.resources.get(type="vm") if str(g["vmid"]) == str(vmid)), "")


def watch_jobs():
    """Volgt wat via de tool is gestart tot het klaar is, ook als de webpagina dicht is, en noteert de afloop."""
    while True:
        time.sleep(30)
        try:
            pending = state.load().get("pending", [])
            if not pending or not ssh_ready():
                continue
            ips = pve.run(node_ips)
            done = []
            for job in pending:
                words = ["node"] if job["target"] == "node" else ["ct", str(job["target"])]
                try:
                    status = parse_status(agent(ips[job["node"]], "status", *words, timeout=15))
                except (HTTPException, KeyError):
                    if time.time() - job["t"] < 6 * 3600:
                        continue  # node even weg, of de guest is verplaatst; later nog eens proberen
                    status = {"state": "lost", "exit": None}
                if status["state"] == "active":
                    continue
                result = "gelukt" if status["exit"] == "0" else "afloop onbekend" if status["state"] == "lost" \
                    else f"mislukt (code {status['exit'] or '?'})"
                state.event(job["kind"], result, node=job["node"], target=job["target"], name=job.get("name", ""), started=job["t"])
                done.append(job)
            if done:
                state.change(lambda d: d.update(pending=[j for j in d.get("pending", []) if j not in done]))
        except Exception:  # noqa: BLE001 - de bewaker mag nooit stoppen
            pass


# De mailinstellingen komen uit maintool.env, tenzij ze in de pagina zijn ingesteld: dan staan ze in mail.json en gaan
# die voor. Het wachtwoord moet daar leesbaar in staan (de tool logt ermee in bij de mailserver); het bestand is
# alleen voor de tool leesbaar en het wachtwoord gaat nooit terug naar de pagina.
MAIL_FILE = STATE_DIR / "mail.json"
MAIL_SECURITY = ("starttls", "ssl", "none")   # STARTTLS (meestal poort 587), direct versleuteld (465), of onversleuteld
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9]([A-Za-z0-9.\-]{0,188}[A-Za-z0-9])?\.[A-Za-z]{2,24}$")
MAILHOST_RE = re.compile(r"^(?=.{4,253}$)[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$")
MAILNAME_RE = re.compile(r"^[^\x00-\x1f\x7f\"<>\\\\]{0,60}$")
MAILLOGIN_RE = re.compile(r"^[^\x00-\x20\x7f]{1,255}$")
APP_PASSWORD_RE = re.compile(r"^[A-Za-z]{4}( [A-Za-z]{4}){3}$")   # zo toont Google een app-wachtwoord: vier groepjes
_mail = {"stamp": None, "data": None}


def mail_shape(d) -> dict | None:
    """Maakt van wat in mail.json staat de vorm van nu; None als het niet klopt. De vorm van 1.5 (één adres waarmee
    je inlogt en verstuurt, poort bepaalt de beveiliging) wordt meegenomen."""
    if not isinstance(d, dict):
        return None
    if "sender" not in d and "user" in d:   # vorm van versie 1.5
        d = {**d, "sender": d.get("user"), "login": d.get("user"), "auth": True, "name": "", "verify": True,
             "security": "ssl" if d.get("port") == 465 else "starttls"}
    host, port = str(d.get("host") or ""), d.get("port")
    if not (MAILHOST_RE.match(host) or is_ip(host)) or not (isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535):
        return None
    if d.get("security") not in MAIL_SECURITY or not EMAIL_RE.match(str(d.get("sender"))) or not isinstance(d.get("to"), str) or not d["to"]:
        return None
    use_login = bool(d.get("auth"))
    if use_login and not (isinstance(d.get("login"), str) and d["login"] and isinstance(d.get("password"), str) and d["password"]):
        return None
    return {"host": host, "port": port, "security": d["security"], "auth": use_login, "login": d.get("login") if use_login else "",
            "password": d.get("password") if use_login else "", "sender": d["sender"], "name": str(d.get("name") or "")[:60],
            "to": d["to"], "verify": d.get("verify") is not False}


def mail_saved():
    """Wat in de pagina is ingesteld; None als dat er niet (geldig) is."""
    try:
        info = MAIL_FILE.stat()
        stamp = (info.st_mtime_ns, info.st_size)
    except OSError:
        stamp = None
    if stamp != _mail["stamp"]:
        data = None
        if stamp:
            try:
                data = mail_shape(json.loads(MAIL_FILE.read_text(encoding="utf-8")))
            except (OSError, ValueError, TypeError):
                pass
        _mail.update(stamp=stamp, data=data)
    return _mail["data"]


def mail_config() -> dict:
    """De mailinstellingen die nu gelden, met waar ze vandaan komen ("tool" of "env")."""
    saved = mail_saved()
    if saved:
        return {**saved, "source": "tool"}
    return {"host": MAIL_HOST, "port": MAIL_PORT, "security": "ssl" if MAIL_PORT == 465 else "starttls", "auth": True,
            "login": MAIL_USER, "password": MAIL_PASSWORD, "sender": MAIL_FROM, "name": "", "to": MAIL_TO, "verify": True,
            "source": "env"}


def mail_ready() -> bool:
    c = mail_config()
    return bool(c["host"] and c["sender"] and c["to"] and (not c["auth"] or (c["login"] and c["password"])))


def mail_from(c: dict) -> str:
    return formataddr((c["name"], c["sender"])) if c.get("name") else c["sender"]


def mail_deliver(c: dict, message=None, saving: bool = False):
    """Verbindt met de mailserver, logt in als dat is ingesteld en verstuurt het bericht, als dat er is; zonder
    bericht is het alleen een controle van de instellingen. Een wachtwoord gaat nooit over een onversleutelde
    verbinding (zie mail_plan)."""
    context = ssl.create_default_context()
    if not c.get("verify", True):   # eigen server in het eigen netwerk met een zelfgemaakt certificaat
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        if c["security"] == "ssl":
            smtp = smtplib.SMTP_SSL(c["host"], c["port"], timeout=30, context=context)
        else:
            smtp = smtplib.SMTP(c["host"], c["port"], timeout=30)
        with smtp:
            if c["security"] == "starttls":
                smtp.starttls(context=context)
            if c["auth"]:
                smtp.login(c["login"], c["password"])
            elif message is None:
                smtp.noop()   # zonder inlog is dit de controle: de server geeft antwoord
            if message is not None:
                smtp.send_message(message)
    except smtplib.SMTPAuthenticationError:
        raise HTTPException(502, "De mailserver weigert de inlog; controleer de inlognaam en het wachtwoord (bij Gmail een app-wachtwoord, niet je gewone)")
    except ssl.SSLCertVerificationError:
        if saving:
            raise HTTPException(502, "Het certificaat van de mailserver klopt niet; er is niets bewaard")
        raise HTTPException(502, "Versturen mislukt: SSLCertVerificationError")
    except smtplib.SMTPNotSupportedError as err:
        if saving:
            raise HTTPException(502, f"De mailserver ondersteunt deze manier van verbinden of inloggen niet ({err.__class__.__name__}); er is niets bewaard")
        raise HTTPException(502, f"Versturen mislukt: {err.__class__.__name__}")
    except (smtplib.SMTPException, OSError) as err:
        if saving:
            raise HTTPException(502, f"De mailserver is niet bereikbaar of weigert de verbinding ({err.__class__.__name__}); er is niets bewaard")
        raise HTTPException(502, f"Versturen mislukt: {err.__class__.__name__}")


def os_outdated(name: str) -> bool:
    """Releases die geen updates meer krijgen (stand oktober 2026); zelfde regel als outdated() in de pagina."""
    m = re.search(r"Debian GNU/Linux (\d+)", name or "")
    if m:
        return int(m.group(1)) <= 11
    m = re.search(r"Ubuntu (\d+)\.", name or "")
    return bool(m) and "LTS" not in name and int(m.group(1)) < 26


def nl_date(ts: float, with_time: bool = True) -> str:
    d = dt.datetime.fromtimestamp(ts, REPORT_TZ)
    return f"{d.day} {MAANDEN[d.month - 1]}" + (f" {d:%H:%M}" if with_time else "")


def schedule_nl(schedule: str) -> str:
    """'mon,wed 02:30' -> 'ma, wo om 02:30'; andere Proxmox-notaties blijven zoals ze zijn."""
    m = re.fullmatch(r"(?:((?:mon|tue|wed|thu|fri|sat|sun)(?:,(?:mon|tue|wed|thu|fri|sat|sun))*) +)?(\d{1,2}):(\d{2})", (schedule or "").strip())
    if not m:
        return schedule or ""
    days = "elke dag" if not m.group(1) else ", ".join(DAGEN[WEEKDAYS.index(d)][:2] for d in m.group(1).split(","))
    return f"{days} om {int(m.group(2)):02d}:{m.group(3)}"


def keep_nl(prune: str) -> str:
    names = {"last": "laatste", "daily": "per dag", "weekly": "per week", "monthly": "per maand", "yearly": "per jaar"}
    parts = [f"{n} {names[k]}" for k, n in re.findall(r"keep-(\w+)=(\d+)", prune or "") if k in names]
    return ", ".join(parts) or "alles"


def report_data(api, since: float) -> dict:
    """Alles wat het overzicht nodig heeft, opgehaald bij Proxmox en uit het eigen logboekje."""
    nodes = sorted(api.nodes.get(), key=lambda n: n["node"])
    online = [n["node"] for n in nodes if n.get("status") == "online"]
    guests = sorted((g for g in api.cluster.resources.get(type="vm") if not g.get("template")), key=lambda g: g["vmid"])
    tasks = []
    for n in online:
        tasks += [dict(t, node=n) for t in api.nodes(n).tasks.get(since=int(since), limit=5000)]
    files = []
    if online:
        for s in backup_storages(api):
            files += api.nodes(online[0]).storage(s["storage"]).content.get(content="backup")
    try:
        ceph = api.nodes(online[0]).ceph.status.get() if online else None
    except ResourceException:
        ceph = None
    jobs = api.cluster.backup.get()
    for j in jobs:
        j["prune-backups"] = prune_text(j.get("prune-backups"))
    stores, alone = {}, single_node(api)
    for s in api.cluster.resources.get(type="storage"):
        if (s.get("shared") or alone) and s.get("maxdisk"):
            stores[s["storage"]] = s
    return {"nodes": nodes, "guests": guests, "tasks": tasks, "files": files, "ceph": ceph, "jobs": jobs,
            "stores": sorted(stores.values(), key=lambda s: s["storage"]), "updates": updates.info,
            "events": state.events(since), "snapshots": {g["vmid"]: snapshot_count(api, g) for g in guests}}


def build_report(d: dict, since: float, until: float, cfg: dict | None = None):
    """Maakt van de gegevens het onderwerp, de HTML-mail en een versie in platte tekst."""
    return compose_report(d, since, until, cfg)[:3]


def compose_report(d: dict, since: float, until: float, cfg: dict | None = None):
    """Als build_report, plus het aantal aandachtspunten. Alleen de gekozen onderdelen komen erin; de aandachtspunten
    van een onderdeel dat uit staat tellen ook niet mee."""
    cfg = cfg or report_config()
    freq = cfg["frequency"] if cfg["frequency"] != "off" else "weekly"
    parts, inside = set(cfg["parts"]), REPORT_IN[freq]
    Inside, days_long = inside[:1].upper() + inside[1:], (until - since) / 86400
    e = html.escape
    ok_task = lambda t: t.get("status") == "OK" or str(t.get("status", "")).startswith("WARNINGS")  # noqa: E731
    week = lambda ts: since <= (ts or 0) <= until  # noqa: E731
    up_nodes, up_guests = d["updates"].get("nodes") or {}, d["updates"].get("guests") or {}
    issues, sections, text = [], [], []

    def table(head, rows):
        th = "".join(f'<th style="text-align:left;padding:6px 10px;border-bottom:2px solid #d0d5dd;font-size:12px;color:#667085">{e(h)}</th>' for h in head)
        body = "".join("<tr>" + "".join(f'<td style="padding:6px 10px;border-bottom:1px solid #eaecf0;font-size:13px;vertical-align:top">{c}</td>' for c in r) + "</tr>" for r in rows)
        return f'<table style="border-collapse:collapse;width:100%;margin:6px 0 4px">{("<tr>" + th + "</tr>") if head else ""}{body}</table>'

    def issue(where, text_):
        issues.extend([(where, text_)])

    def section(where, title, body, plain):
        if where not in parts:
            return
        sections.append(f'<h2 style="font-size:16px;margin:26px 0 6px;color:#101828">{e(title)}</h2>{body}')
        text.extend(["", title.upper(), *plain])

    def mark(text_, color):
        return f'<span style="color:{color};font-weight:600">{e(text_)}</span>'

    good, warn, bad = (lambda s: mark(s, "#067647")), (lambda s: mark(s, "#b54708")), (lambda s: mark(s, "#b42318"))

    # --- nodes
    rows, plain = [], []
    for n in d["nodes"]:
        u = up_nodes.get(n["node"]) or {}
        on = n.get("status") == "online"
        if not on:
            issue("nodes", f"Node {n['node']} is niet online")
        if u.get("reboot"):
            issue("nodes", f"Node {n['node']} moet herstarten voor kernel {u['reboot']}")
        days = round(n.get("uptime", 0) / 86400, 1)
        kernel = e(u.get("kernel") or "–") + (f' → {warn(u["reboot"])} na herstart' if u.get("reboot") else "")
        pending = u.get("updates")
        rows.append([f"<b>{e(n['node'])}</b>", good("online") if on else bad("offline"), e(u.get("version") or "–"), kernel,
                     f"{days} dagen" + (f" ({inside} herstart)" if on and days < days_long else ""),
                     "–" if pending is None else good("bijgewerkt") if pending == 0 else warn(f"{pending} klaar")])
        plain.append(f"- {n['node']}: {'online' if on else 'OFFLINE'}, PVE {u.get('version') or '?'}, kernel {u.get('kernel') or '?'}"
                     f"{', herstart nodig' if u.get('reboot') else ''}, {pending if pending is not None else '?'} updates klaar")
    section("nodes", "Nodes", table(["Node", "Status", "Proxmox", "Kernel", "Aan sinds", "Updates"], rows), plain)

    # --- back-ups per guest
    last, count = {}, {}
    for f in d["files"]:
        v = f.get("vmid")
        if week(f.get("ctime")):
            count[v] = count.get(v, 0) + 1
        if not last.get(v) or f.get("ctime", 0) > last[v].get("ctime", 0):
            last[v] = f
    failed_dumps = [t for t in d["tasks"] if t.get("type") == "vzdump" and t.get("endtime") and not ok_task(t)]
    for t in failed_dumps:
        issue("backups", f"Back-up mislukt op {t['node']} op {nl_date(t['starttime'])}: {str(t.get('status'))[:90]}")

    # --- guests
    acts = {}
    for t in d["tasks"]:
        if str(t.get("id", "")).isdigit():
            a = acts.setdefault(int(t["id"]), {"start": 0, "stop": 0, "move": 0})
            a["start"] += t.get("type") in STARTS
            a["stop"] += t.get("type") in STOPS
            a["move"] += t.get("type") in MOVES
    rows, plain, no_backup, never_backup = [], [], [], []
    for g in d["guests"]:
        v, u = g["vmid"], up_guests.get(str(g["vmid"])) or {}
        osname = (u.get("os") or "").replace(" GNU/Linux", "")
        old = os_outdated(u.get("os") or "")
        if old:
            issue("guests", f"{v} {g.get('name')} draait {osname}; die release krijgt geen updates meer")
        pending = u.get("updates")
        a = acts.get(v, {"start": 0, "stop": 0, "move": 0})
        happened = ", ".join(x for x in (f"{a['start']}× gestart" if a["start"] else "", f"{a['stop']}× gestopt" if a["stop"] else "",
                                          f"{a['move']}× gemigreerd" if a["move"] else "") if x) or "geen bijzonderheden"
        lb = last.get(v)
        skip = v in NO_BACKUP and not count.get(v)
        if not count.get(v) and not skip:
            (no_backup if lb else never_backup).append(f"{v} {g.get('name')}")
        backup = ('<span style="color:#667085">niet nodig</span>' if skip else good(f"{count[v]}×") if count.get(v) else bad("geen")) + \
            (f'<br><span style="color:#667085;font-size:12px">laatste {e(nl_date(lb["ctime"]))}, {lb.get("size", 0) / 2**20:.0f} MB</span>' if lb else "")
        running = g.get("status") == "running"
        rows.append([f"<b>{v}</b> {e(g.get('name') or '')}", "VM" if g["type"] == "qemu" else "CT", e(g.get("node", "")),
                     good("aan") if running else warn("uit"), (warn(osname) if old else e(osname)) or "–",
                     "–" if pending is None else good("bijgewerkt") if pending == 0 and not old else warn("verouderd") if old and pending == 0 else warn(f"{pending} klaar"),
                     backup, e(happened)])
        plain.append(f"- {v} {g.get('name')}: {'aan' if running else 'uit'} op {g.get('node')}, {osname or 'OS onbekend'}, "
                     f"{pending if pending is not None else '?'} updates klaar, back-ups {inside}: {'niet nodig' if skip else count.get(v, 0)}, {happened}")
    if never_backup:
        issue("backups", f"Van {len(never_backup)} guest{'s' if len(never_backup) != 1 else ''} staat er geen enkele back-up op de opslag: " + ", ".join(never_backup))
    if no_backup:
        issue("backups", f"{len(no_backup)} guest{'s' if len(no_backup) != 1 else ''} zonder back-up van {inside}: " + ", ".join(no_backup))
    section("guests", "VM's en CT's", table(["Guest", "Type", "Node", "Status", "OS", "Updates", f"Back-ups ({inside})", Inside], rows), plain)

    # --- back-ups: schema's en opslag
    dumps = [t for t in d["tasks"] if t.get("type") == "vzdump" and t.get("endtime")]
    total = sum(count.values())
    summary = f"Er staan {total} back-up{'s' if total != 1 else ''} van {inside} op de opslag; er {'is' if len(dumps) == 1 else 'zijn'} " \
        f"{len(dumps)} run{'s' if len(dumps) != 1 else ''} gedraaid, " + \
        (bad(f"waarvan {len(failed_dumps)} mislukt") if failed_dumps else good("geen mislukt"))
    names = {g["vmid"]: g.get("name") for g in d["guests"]}
    rows, plain = [], [f"- {total} back-ups van {inside} op de opslag, {len(dumps)} runs gedraaid, {len(failed_dumps)} mislukt"]
    for j in d["jobs"]:
        who = "alle guests" if j.get("all") else ", ".join(f"{v} {names.get(int(v), '')}".strip() for v in str(j.get("vmid") or "").split(",") if v)
        nxt = nl_date(j["next-run"]) if j.get("next-run") and j.get("enabled", 1) else "–"
        rows.append([e(j.get("comment") or j.get("id", "")), good("aan") if j.get("enabled", 1) else warn("uit"), e(who), e(schedule_nl(j.get("schedule", ""))),
                     e(j.get("storage", "")), e(keep_nl(j.get("prune-backups"))), e(nxt)])
        plain.append(f"- schema {j.get('comment') or j.get('id')}: {'aan' if j.get('enabled', 1) else 'uit'}, {who}, {schedule_nl(j.get('schedule', ''))}, volgende {nxt}")
    if not [j for j in d["jobs"] if j.get("enabled", 1)]:
        issue("backups", "Er is geen actief back-upschema")
    body = f'<p style="font-size:13px;margin:4px 0">{summary}</p>' + (table(["Schema", "Status", "Guests", "Wanneer", "Opslag", "Bewaren", "Volgende run"], rows)
                                                                    if rows else f'<p style="font-size:13px">{bad("Er zijn geen back-upschema’s.")}</p>')
    section("backups", "Back-ups", body, plain)

    # --- updates via de tool
    kinds = {"update": "update", "release": "upgrade naar nieuwe release", "reboot": "herstart node"}
    rows, plain = [], []
    for ev in sorted((x for x in d["events"] if x.get("kind") in kinds), key=lambda x: x["t"]):
        what = f"node {ev.get('node')}" if ev.get("target") == "node" else f"CT {ev.get('target')} {ev.get('name', '')}".strip()
        okay = ev.get("result") in ("gelukt", "gestart")
        if not okay:
            issue("updates", f"{kinds.get(ev['kind'], ev['kind']).capitalize()} van {what} op {nl_date(ev['t'])}: {ev.get('result')}")
        rows.append([e(nl_date(ev["t"])), e(kinds.get(ev["kind"], ev["kind"])), e(what), good(ev["result"]) if okay else bad(ev.get("result", "?"))])
        plain.append(f"- {nl_date(ev['t'])}: {kinds.get(ev['kind'], ev['kind'])} van {what}: {ev.get('result')}")
    open_n = sum((u or {}).get("updates") or 0 for u in up_nodes.values())
    open_g = sum((u or {}).get("updates") or 0 for u in up_guests.values())
    note = f'<p style="font-size:13px;margin:4px 0">Nu klaarstaand: {open_n} pakketten op de nodes en {open_g} in de guests.</p>'
    plain.append(f"- nu klaarstaand: {open_n} op de nodes, {open_g} in de guests")
    section("updates", "Updates", note + (table(["Wanneer", "Wat", "Waar", "Afloop"], rows) if rows
                               else f'<p style="font-size:13px;color:#667085">{Inside} zijn er via de tool geen updates geïnstalleerd.</p>'), plain)

    # --- opslag en Ceph
    rows, plain = [], []
    for s in d["stores"]:
        pct = round(s.get("disk", 0) / s["maxdisk"] * 100)
        if pct >= 85:
            issue("storage", f"Opslag {s['storage']} is voor {pct}% vol")
        rows.append([f"<b>{e(s['storage'])}</b>", f"{s.get('disk', 0) / 2**30:.0f} van {s['maxdisk'] / 2**30:.0f} GB", (bad if pct >= 85 else e)(f"{pct}%")])
        plain.append(f"- {s['storage']}: {pct}% vol")
    if d["ceph"]:
        health = (d["ceph"].get("health") or {})
        checks = ", ".join((health.get("checks") or {}).keys())
        if health.get("status") != "HEALTH_OK":
            issue("storage", f"Ceph meldt {health.get('status')}" + (f" ({checks})" if checks else ""))
        tone = good if health.get("status") == "HEALTH_OK" else bad if health.get("status") == "HEALTH_ERR" else warn
        rows.append(["<b>Ceph-gezondheid</b>", tone(str(health.get("status"))), e(checks)])
        plain.append(f"- Ceph: {health.get('status')} {checks}")
    section("storage", "Opslag", table(["Opslag", "Gebruik", ""], rows), plain)

    # --- mislukte taken
    fails = [t for t in d["tasks"] if t.get("endtime") and not ok_task(t) and t.get("type") not in NOISE and t.get("type") != "vzdump"]
    if fails:
        groups = {}  # dezelfde fout op dezelfde plek telt als één regel
        for t in sorted(fails, key=lambda t: t["starttime"]):
            key = (t["node"], t.get("type"), str(t.get("id") or ""), str(t.get("status"))[:140])
            groups[key] = (groups.get(key, (0, 0))[0] + 1, t["starttime"])
        top = sorted(groups.items(), key=lambda kv: -kv[1][1])[:15]
        rows = [[e(nl_date(last_t)), f"{n}×", e(node), e(TASK_NAMES.get(typ, typ or "")), e(gid), e(msg)] for (node, typ, gid, msg), (n, last_t) in top]
        section("failed", f"Mislukte taken in Proxmox ({len(fails)})", table(["Laatste keer", "Aantal", "Node", "Taak", "Guest", "Melding"], rows),
                [f"- {n}x {node} {TASK_NAMES.get(typ, typ)} {gid}: {msg[:100]} (laatst {nl_date(last_t)})" for (node, typ, gid, msg), (n, last_t) in top])

    period = f"{nl_date(since, False)} t/m {nl_date(until, False)} {dt.datetime.fromtimestamp(until, REPORT_TZ).year}"
    issues = [x for where, x in issues if where in parts]
    verdict = "alles in orde" if not issues else f"{len(issues)} aandachtspunt{'en' if len(issues) != 1 else ''}"
    box = (f'<div style="background:#ecfdf3;border:1px solid #abefc6;border-radius:8px;padding:10px 14px;font-size:14px;color:#067647">'
           f'<b>Geen aandachtspunten.</b> Alles is {inside} goed gegaan.</div>') if not issues else \
        ('<div style="background:#fffaeb;border:1px solid #fedf89;border-radius:8px;padding:10px 14px;font-size:13px;color:#93370d">'
         f'<b>{e(verdict.capitalize())}</b><ul style="margin:6px 0 0;padding-left:18px">' + "".join(f"<li>{e(i)}</li>" for i in issues) + "</ul></div>")
    page = ('<div style="font-family:-apple-system,Segoe UI,Arial,sans-serif;color:#101828;max-width:860px;margin:0 auto;padding:8px">'
            f'<h1 style="font-size:20px;margin:0 0 2px">{REPORT_TITLE[freq]} Proxmox</h1>'
            f'<p style="color:#667085;font-size:13px;margin:0 0 14px">{e(period)}</p>{box if "issues" in parts else ""}{"".join(sections)}'
            '<p style="color:#98a2b3;font-size:11px;margin-top:26px">Verstuurd door de Proxmox Maintool. '
            'De cijfers over starten, stoppen, migreren en back-ups komen uit de takenlijst van Proxmox; updates alleen voor zover ze via de tool zijn gestart.</p></div>')
    plain_all = [f"{REPORT_TITLE[freq]} Proxmox, {period}", *(["", "Geen aandachtspunten." if not issues else "AANDACHTSPUNTEN",
                                                                   *[f"- {i}" for i in issues]] if "issues" in parts else []), *text]
    return f"Proxmox {REPORT_TITLE[freq].lower()} {period}: {verdict}", page, "\n".join(plain_all), len(issues)


def make_report(cfg: dict | None = None):
    """Onderwerp, HTML, platte tekst en het aantal aandachtspunten, over één periode tot nu."""
    cfg = cfg or report_config()
    since, until = report_period(cfg)
    return compose_report(pve.run(lambda api: report_data(api, since)), since, until, cfg)


def send_report(scheduled: bool = False):
    """Verstuurt het overzicht. Op het geplande moment (scheduled) en met "alleen als er iets is" wordt een overzicht
    zonder aandachtspunten overgeslagen; met de hand versturen gaat altijd."""
    if not mail_ready():
        raise HTTPException(409, "Mail is nog niet ingesteld; doe dat op het tabblad Events bij Overzicht per mail")
    c, cfg = mail_config(), report_config()
    subject, page, plain, count = make_report(cfg)
    if scheduled and cfg["only_issues"] and not count:
        state.change(lambda d: d.update(report_sent=int(time.time()), report_error=None, report_skipped=True))
        return None
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, mail_from(c), c["to"]
    msg.set_content(plain)
    msg.add_alternative(page, subtype="html")
    mail_deliver(c, msg)
    state.change(lambda d: d.update(report_sent=int(time.time()), report_error=None, report_skipped=False))
    return subject


def report_when(cfg: dict) -> str:
    """De planning in een zin, voor wie de status zonder de pagina leest."""
    f = cfg["frequency"]
    return ("niet automatisch" if f == "off" else f"elke dag om {cfg['time']}" if f == "daily"
            else f"elke maand op de {cfg['monthday']}e om {cfg['time']}" if f == "monthly"
            else f"{'elke' if f == 'weekly' else 'om de week op'} {DAGEN[cfg['day']]} om {cfg['time']}")


def report_loop():
    """Verstuurt het overzicht op het geplande moment. Stond de tool toen uit, dan alsnog, tot een dag later (bij elke
    dag: een halve dag). Een moment van vóór de laatste wijziging van de planning wordt niet alsnog verstuurd."""
    while True:
        time.sleep(60)
        try:
            saved = state.load()
            if not mail_ready() or report_due(saved, report_config()) is None:
                continue
            if time.time() - saved.get("report_tried", 0) < 1800:
                continue  # na een mislukte poging een half uur wachten
            state.change(lambda d: d.update(report_tried=int(time.time())))
            updates.start(lists=True)  # eerst overal de pakketlijsten verversen, zodat de aantallen kloppen
            waited = 0
            while updates.busy and waited < 600:
                time.sleep(5)
                waited += 5
            send_report(scheduled=True)
        except HTTPException as err:
            state.change(lambda d: d.update(report_error=str(err.detail)))
        except Exception as err:  # noqa: BLE001 - de planner mag nooit stoppen
            state.change(lambda d: d.update(report_error=err.__class__.__name__))


@app.on_event("startup")
def start_background():
    # Alleen in de echte service; scripts die main.py inladen om iets te controleren mailen en bewaken niet.
    threading.Thread(target=watch_jobs, daemon=True).start()
    threading.Thread(target=report_loop, daemon=True).start()
    threading.Thread(target=autoupdate_loop, daemon=True).start()
    threading.Thread(target=balance_loop, daemon=True).start()
    threading.Thread(target=github_loop, daemon=True).start()


@app.get("/api/report/status")
def report_status(request: Request, _: str = Depends(auth)):
    saved, cfg, c = state.load(), report_config(), mail_config()
    upcoming = report_next(cfg)
    return {"ready": mail_ready(), "to": c["to"], "from": c["sender"],
            # voor het instelvenster; het wachtwoord zelf gaat nooit naar de pagina, alleen of er een is
            "name": c["name"], "host": c["host"], "port": c["port"], "security": c["security"], "auth": c["auth"], "login": c["login"],
            "verify": c["verify"], "password_set": bool(c["password"]), "source": c["source"],
            "when": report_when(cfg),   # de pagina maakt hier zelf een zin van, in haar taal
            "frequency": cfg["frequency"], "day": cfg["day"], "monthday": cfg["monthday"], "time": cfg["time"],
            "parts": cfg["parts"], "only_issues": cfg["only_issues"], "next": int(upcoming.timestamp()) if upcoming else None,
            "sent": saved.get("report_sent"), "skipped": saved.get("report_skipped") is True,
            "error": translate(saved.get("report_error"), lang_of(request))}


@app.get("/api/report/preview")
def report_preview(_: str = Depends(auth)):
    subject, page, _plain, _count = make_report()
    return {"subject": subject, "html": page}


@app.post("/api/report/send")
def report_send(_: str = Depends(manage_events)):
    try:
        return {"subject": send_report()}
    except HTTPException as err:
        try:
            state.change(lambda d: d.update(report_error=str(err.detail)))
        except OSError:
            pass
        raise


# ---------------------------------------------------------------- het overzicht per mail: wanneer, hoe vaak en wat
# Zonder eigen instelling: elke week op de dag en tijd uit maintool.env, met alle onderdelen. In de pagina (tabblad
# Events) kies je hoe vaak, wanneer, welke onderdelen erin staan en of het alleen komt als er iets aan de hand is.
REPORT_FREQ = ("off", "daily", "weekly", "biweekly", "monthly")
REPORT_PARTS = ("issues", "nodes", "guests", "backups", "updates", "storage", "failed")
TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
REPORT_TITLE = {"daily": "Dagoverzicht", "weekly": "Weekoverzicht", "biweekly": "Tweewekelijks overzicht", "monthly": "Maandoverzicht"}
REPORT_IN = {"daily": "de afgelopen dag", "weekly": "deze week", "biweekly": "de afgelopen twee weken", "monthly": "de afgelopen maand"}


def report_config() -> dict:
    cfg = {"frequency": "weekly", "day": WEEKDAYS.index(REPORT_DAY) if REPORT_DAY in WEEKDAYS else 6, "monthday": 1,
           "time": REPORT_TIME if TIME_RE.match(REPORT_TIME) else "05:00", "parts": list(REPORT_PARTS), "only_issues": False, "parity": 0}
    saved = state.load().get("report")
    if not isinstance(saved, dict):
        return cfg
    ok_int = lambda v, low, high: isinstance(v, int) and not isinstance(v, bool) and low <= v <= high  # noqa: E731
    if saved.get("frequency") in REPORT_FREQ:
        cfg["frequency"] = saved["frequency"]
    if ok_int(saved.get("day"), 0, 6):
        cfg["day"] = saved["day"]
    if ok_int(saved.get("monthday"), 1, 28):
        cfg["monthday"] = saved["monthday"]
    if isinstance(saved.get("time"), str) and TIME_RE.match(saved["time"]):
        cfg["time"] = saved["time"]
    if isinstance(saved.get("parts"), list):
        cfg["parts"] = [p for p in REPORT_PARTS if p in saved["parts"]]
    cfg["only_issues"] = saved.get("only_issues") is True
    if saved.get("parity") in (0, 1):
        cfg["parity"] = saved["parity"]
    return cfg


def week_number(moment) -> int:
    """Doorlopende weektelling (maandag tot en met zondag), ook over de jaargrens; voor 'om de week'."""
    return (moment.date().toordinal() - 1) // 7


def month_shift(moment, months: int):
    """Hetzelfde moment een aantal maanden eerder of later (dag 1 tot en met 28 bestaat in elke maand)."""
    index = moment.year * 12 + moment.month - 1 + months
    return moment.replace(year=index // 12, month=index % 12 + 1)


def report_moment(now=None, cfg=None):
    """Het laatste geplande verzendmoment tot nu, in de tijdzone van het overzicht; None als er niet automatisch wordt
    verstuurd."""
    cfg = cfg or report_config()
    now = now or dt.datetime.now(REPORT_TZ)
    if cfg["frequency"] == "off":
        return None
    hour, minute = (int(x) for x in cfg["time"].split(":"))
    if cfg["frequency"] == "daily":
        moment = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        return moment - dt.timedelta(days=1) if moment > now else moment
    if cfg["frequency"] == "monthly":
        moment = now.replace(day=cfg["monthday"], hour=hour, minute=minute, second=0, microsecond=0)
        return month_shift(moment, -1) if moment > now else moment
    moment = (now - dt.timedelta(days=(now.weekday() - cfg["day"]) % 7)).replace(hour=hour, minute=minute, second=0, microsecond=0)
    if moment > now:
        moment -= dt.timedelta(days=7)
    if cfg["frequency"] == "biweekly" and week_number(moment) % 2 != cfg["parity"]:
        moment -= dt.timedelta(days=7)
    return moment


def report_step(moment, cfg, steps: int = 1):
    """Een of meer perioden later (of eerder, met een negatief aantal)."""
    if cfg["frequency"] == "monthly":
        return month_shift(moment, steps)
    return moment + dt.timedelta(days=steps * {"daily": 1, "biweekly": 14}.get(cfg["frequency"], 7))


def report_due(saved: dict, cfg: dict, now=None):
    """Het geplande moment dat nu verstuurd moet worden, of None. Niet als het al verstuurd (of overgeslagen) is, niet
    als de planning daarna nog is gewijzigd, en niet meer als het te lang geleden is: een dag, bij elke dag een halve."""
    now = now or dt.datetime.now(REPORT_TZ)
    moment = report_moment(now, cfg)
    if moment is None:
        return None
    if saved.get("report_sent", 0) >= moment.timestamp() or saved.get("report_config_at", 0) >= moment.timestamp():
        return None
    if now - moment > dt.timedelta(hours=12 if cfg["frequency"] == "daily" else 24):
        return None
    return moment


def report_next(cfg=None):
    cfg = cfg or report_config()
    moment = report_moment(cfg=cfg)
    return None if moment is None else report_step(moment, cfg)


def report_period(cfg=None, until=None) -> tuple:
    """Van wanneer tot wanneer het overzicht gaat: één periode terug vanaf nu (bij 'niet automatisch': een week)."""
    cfg = cfg or report_config()
    until_dt = dt.datetime.fromtimestamp(until or time.time(), REPORT_TZ)
    shape = cfg if cfg["frequency"] != "off" else {**cfg, "frequency": "weekly"}
    return report_step(until_dt, shape, -1).timestamp(), until_dt.timestamp()


class ReportIn(BaseModel):
    frequency: str = Field(max_length=10)
    day: int = Field(6, strict=True)
    monthday: int = Field(1, strict=True)
    time: str = Field("05:00", max_length=5)
    parts: list[str] = Field(default_factory=list, max_length=10)
    only_issues: bool = False


@app.put("/api/report/config")
def report_config_save(body: ReportIn, request: Request, _: str = Depends(manage_events)):
    """Bewaart hoe vaak, wanneer en wat er gemaild wordt. Een moment dat al voorbij is wordt daarna niet alsnog
    verstuurd; het eerstvolgende geplande moment telt."""
    same_origin(request)
    if body.frequency not in REPORT_FREQ:
        raise HTTPException(400, "Ongeldige keuze bij Hoe vaak")
    if not 0 <= body.day <= 6:
        raise HTTPException(400, "Ongeldige dag")
    if not 1 <= body.monthday <= 28:
        raise HTTPException(400, "Kies een dag van de maand van 1 tot en met 28")
    if not TIME_RE.match(body.time):
        raise HTTPException(400, "Ongeldige tijd; gebruik uu:mm, bijvoorbeeld 05:00")
    if any(p not in REPORT_PARTS for p in body.parts):
        raise HTTPException(400, "Onbekend onderdeel voor de mail")
    parts = [p for p in REPORT_PARTS if p in body.parts]
    if not parts:
        raise HTTPException(400, "Kies minstens één onderdeel voor de mail")
    cfg = {"frequency": body.frequency, "day": body.day, "monthday": body.monthday, "time": body.time, "parts": parts,
           "only_issues": body.only_issues, "parity": 0}
    if body.frequency == "biweekly":   # om de week: de eerstvolgende keer is de eerstvolgende week met die dag
        upcoming = report_step(report_moment(cfg={**cfg, "frequency": "weekly"}), {**cfg, "frequency": "weekly"})
        cfg["parity"] = week_number(upcoming) % 2
    try:
        state.change(lambda d: d.update(report=cfg, report_config_at=int(time.time())))
    except OSError:
        raise HTTPException(500, "De instelling kon niet bewaard worden")
    return report_status(request, "")


class MailIn(BaseModel):
    to: str = Field(max_length=400)
    sender: str = Field(max_length=255)
    name: str | None = Field(None, max_length=80)
    host: str = Field(max_length=253)
    port: int
    security: str = Field("starttls", max_length=10)
    auth: bool = True
    login: str | None = Field(None, max_length=255)
    password: str | None = Field(None, max_length=250)
    verify: bool = True


def mail_plan(body: MailIn, current: dict) -> dict:
    """Kijkt nieuwe mailinstellingen na en geeft terug wat er bewaard moet worden. current = mail_config().

    Zonder nieuw wachtwoord blijft het huidige gelden, maar alleen als de mailserver en de inlognaam dezelfde
    blijven: zo kan niemand het bewaarde wachtwoord naar een andere server laten sturen, en een app-wachtwoord van
    Google hoort hoe dan ook bij één account."""
    to = [a.strip() for a in re.split(r"[,;\s]+", body.to) if a.strip()]
    if not 1 <= len(to) <= 5:
        raise HTTPException(400, "Vul bij 'Versturen naar' één tot vijf adressen in")
    for address in to:
        if not EMAIL_RE.match(address):
            raise HTTPException(400, f"Ongeldig adres bij 'Versturen naar': {address[:80]}")
    sender, host, name = body.sender.strip(), body.host.strip().lower(), (body.name or "").strip()
    if not EMAIL_RE.match(sender):
        raise HTTPException(400, "Ongeldig afzenderadres")
    if not MAILNAME_RE.match(name):
        raise HTTPException(400, "Ongeldige naam van de afzender: hooguit 60 tekens, zonder aanhalingstekens en haakjes")
    if not (MAILHOST_RE.match(host) or is_ip(host)):
        raise HTTPException(400, "Ongeldige mailserver; gebruik een naam zoals smtp.gmail.com of een IP-adres")
    if not 1 <= body.port <= 65535:
        raise HTTPException(400, "Ongeldige poort; kies een getal tussen 1 en 65535")
    if body.security not in MAIL_SECURITY:
        raise HTTPException(400, "Ongeldige beveiliging van de verbinding")
    new = {"host": host, "port": body.port, "security": body.security, "auth": bool(body.auth), "login": "", "password": "",
           "sender": sender, "name": name, "to": ", ".join(to), "verify": bool(body.verify)}
    if not body.auth:
        return new
    if body.security == "none":
        raise HTTPException(400, "Zonder versleuteling stuurt de tool geen wachtwoord mee; kies STARTTLS of SSL/TLS, of zet inloggen uit")
    login = (body.login or "").strip() or sender
    if not MAILLOGIN_RE.match(login):
        raise HTTPException(400, "Ongeldige inlognaam")
    password = (body.password or "").strip()
    if password:
        if APP_PASSWORD_RE.match(password):
            password = password.replace(" ", "")
        if len(password) > 200 or any(ord(ch) < 32 or ord(ch) == 127 for ch in password):
            raise HTTPException(400, "Ongeldig wachtwoord: geen stuurtekens, hooguit 200 tekens")
    elif not (current.get("auth") and current.get("password")):
        raise HTTPException(400, "Vul het wachtwoord in (bij Gmail een app-wachtwoord)")
    elif login.lower() != str(current.get("login") or "").lower() or host != str(current.get("host") or "").lower():
        raise HTTPException(400, "Bij een andere mailserver of inlognaam hoort het wachtwoord opnieuw; vul het in")
    else:
        password = current["password"]
    return {**new, "login": login, "password": password}


@app.put("/api/report/mail")
def report_mail_save(body: MailIn, request: Request, _: str = Depends(manage_events)):
    """Bewaart de mailinstellingen voor het weekoverzicht, nadat de tool er één keer mee heeft verbonden (en ingelogd,
    als dat is ingesteld) bij de mailserver. Er wordt dan niets verstuurd. Lukt dat niet, dan wordt er niets bewaard."""
    same_origin(request)
    new = mail_plan(body, mail_config())
    mail_deliver(new, saving=True)
    try:
        tmp = MAIL_FILE.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(new))
        os.replace(tmp, MAIL_FILE)
        state.change(lambda d: d.update(report_error=None))
    except OSError:
        raise HTTPException(500, "De mailinstellingen konden niet bewaard worden")
    return report_status(request, "")


@app.delete("/api/report/mail")
def report_mail_reset(request: Request, _: str = Depends(manage_events)):
    """Wist wat in de pagina is ingesteld; daarna gelden weer de mailregels uit maintool.env, als die er zijn."""
    same_origin(request)
    try:
        MAIL_FILE.unlink(missing_ok=True)
    except OSError:
        raise HTTPException(500, "De mailinstellingen konden niet bewaard worden")
    return report_status(request, "")


@app.post("/api/report/mail/test")
def report_mail_test(request: Request, user: str = Depends(manage_events)):
    """Stuurt een kort testbericht met de instellingen die nu gelden, zodat te zien is dat mail echt aankomt."""
    same_origin(request)
    if not mail_ready():
        raise HTTPException(409, "Mail is nog niet ingesteld; doe dat op het tabblad Events bij Overzicht per mail")
    c = mail_config()
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = "Proxmox Maintool: testbericht", mail_from(c), c["to"]
    msg.set_content("Dit is een testbericht van de Proxmox Maintool. Komt het aan, dan zijn de mailinstellingen in orde.\n\n"
                    "This is a test message from the Proxmox Maintool. If it arrives, the mail settings are fine.\n")
    mail_deliver(c, msg)
    return {"to": c["to"]}


# ---------------------------------------------------------------- instellingen van de pagina

COLOR = r"^#[0-9a-fA-F]{6}$"


class SettingsIn(BaseModel):
    """Alleen wat meegestuurd wordt, verandert. Een kleur is #rrggbb; null is het oorspronkelijke thema van de tool."""
    background: str | None = Field(None, pattern=COLOR)  # de achtergrond die nu getoond wordt
    default: str | None = Field(None, pattern=COLOR)     # waar de knop "Standaard" naar teruggaat
    language: str | None = Field(None, pattern="^(nl|en|de)$")   # taal van de pagina; null = volgt de browser
    dashboard: dict | None = None   # indeling en verversingstijden van het dashboard SXY; null = de standaard
    tables: dict | None = None      # kolommen en volgorde van de tabellen (zie clean_tables); null = de standaard
    update_dismissed: str | None = Field(None, pattern=r"^\d{1,4}(\.\d{1,4}){1,2}$")   # Herinner mij niet: voor deze versie


# De indeling van het dashboard: tegels op een raster van 24 kolommen (x, y, breedte w, hoogte h in hokjes), welke
# tegels uit staan, hoe vaak de cijfers (live) en de grafieken (history) ververst worden en of alles op één scherm
# moet passen (fit).
DASH_ID_RE = re.compile(r"^(gauge:(cpu|mem):[A-Za-z0-9][A-Za-z0-9\-]{0,62}|guest:\d{1,9}|chart:(cpu|mem|net)|nums|issues|top|storage|clock)$")
DASH_COLS, DASH_MAX = 24, 200
DASH_LIVE, DASH_HISTORY = (2, 5, 10, 15, 30, 60), (30, 60, 120, 300, 600)


def clean_dashboard(d) -> dict:
    bad = HTTPException(400, "Ongeldige indeling van het dashboard")
    if not isinstance(d, dict):
        raise bad
    whole = lambda v, low, high: isinstance(v, int) and not isinstance(v, bool) and low <= v <= high  # noqa: E731
    layout, seen = [], set()
    if not isinstance(d.get("layout", []), list) or len(d.get("layout", [])) > DASH_MAX:
        raise bad
    for w in d.get("layout", []):
        if not isinstance(w, dict) or not isinstance(w.get("id"), str) or not DASH_ID_RE.match(w["id"]) or w["id"] in seen:
            raise bad
        x, y, width, height = (w.get(k) for k in ("x", "y", "w", "h"))
        if not (whole(x, 0, DASH_COLS - 1) and whole(width, 1, DASH_COLS) and x + width <= DASH_COLS and whole(y, 0, 999) and whole(height, 1, 60)):
            raise bad
        seen.add(w["id"])
        layout.append({"id": w["id"], "x": x, "y": y, "w": width, "h": height})
    hidden = d.get("hidden", [])
    if not isinstance(hidden, list) or len(hidden) > DASH_MAX or any(not isinstance(i, str) or not DASH_ID_RE.match(i) for i in hidden):
        raise bad
    live, history = d.get("live", 2), d.get("history", 60)
    if live not in DASH_LIVE or isinstance(live, bool) or history not in DASH_HISTORY or isinstance(history, bool):
        raise bad
    return {"layout": layout, "hidden": sorted(set(hidden) - seen), "live": live, "history": history, "fit": d.get("fit") is True}


def saved_settings(data: dict, user: str) -> dict:
    """Wat er voor deze gebruiker bewaard is. Het hoofdaccount erft wat er stond van vóór er meer gebruikers waren."""
    own = (data.get("user_settings") or {}).get(user)
    if own is None and user == APP_USER:
        own = data.get("settings")
    return dict(own or {})


def page_settings(user: str) -> dict:
    saved = saved_settings(state.load(), user)
    return {"background": saved.get("background"), "default": saved.get("default"), "language": saved.get("language"),
            "dashboard": saved.get("dashboard") if isinstance(saved.get("dashboard"), dict) else None,
            "tables": saved.get("tables") if isinstance(saved.get("tables"), dict) else None,
            "update_dismissed": saved.get("update_dismissed")}


@app.get("/api/settings")
def settings_get(user: str = Depends(auth)):
    return page_settings(user)


@app.put("/api/settings")
def settings_put(body: SettingsIn, user: str = Depends(auth)):
    """Bewaart achtergrond, standaard, taal en/of de indeling van het dashboard van deze gebruiker; ze gelden voor hem
    op elk apparaat."""
    asked = body.model_dump(exclude_unset=True)
    change = {k: v.lower() if v else None for k, v in asked.items() if k not in ("dashboard", "tables")}
    if "dashboard" in asked:
        change["dashboard"] = clean_dashboard(asked["dashboard"]) if asked["dashboard"] is not None else None
    if "tables" in asked:
        change["tables"] = clean_tables(asked["tables"]) if asked["tables"] is not None else None

    def apply(d: dict):
        d.setdefault("user_settings", {})[user] = {**saved_settings(d, user), **change}
    try:
        state.change(apply)
    except OSError:
        raise HTTPException(500, "De instelling kon niet bewaard worden")
    return page_settings(user)


# ---------------------------------------------------------------- helper-scripts (zoekveld in de kop)

SCRIPTS_API = "https://db.community-scripts.org/api/collections"   # openbare gegevens achter community-scripts.org
SCRIPTS_SITE = "https://community-scripts.org/scripts/"
SCRIPTS_FIELDS = "name,slug,description,categories,port,is_deleted,is_disabled,is_dev,expand.type.type"
SCRIPTS_MAX_AGE = 24 * 3600
SCRIPTS_RETRY = 600
SCRIPT_SLUG = re.compile(r"^[a-z0-9][a-z0-9._-]{0,80}$")
SCRIPT_TYPES = {"lxc", "vm", "pve", "addon"}


def plain(value, limit: int) -> str:
    """Platte tekst uit een veld van buiten: opmaak eruit, witruimte samengevoegd, ingekort."""
    text = html.unescape(re.sub(r"<[^>]{0,300}>", " ", str(value or "")))
    return " ".join(text.split())[:limit]


def compact_scripts(items: list, cats: dict) -> list:
    """Houdt per script alleen over wat het zoekveld toont. De gegevens komen van buiten: alles wordt
    ingekort en nagekeken, en de pagina zet er zelf nooit iets van om in opmaak of opdrachten."""
    out = []
    for i in items:
        slug = str(i.get("slug") or "")
        if i.get("is_deleted") or i.get("is_disabled") or not SCRIPT_SLUG.match(slug):
            continue
        kind = ((i.get("expand") or {}).get("type") or {}).get("type")
        port = i.get("port")
        out.append({
            "name": plain(i.get("name"), 80) or slug, "slug": slug,
            "type": kind if kind in SCRIPT_TYPES else "",
            "desc": plain(i.get("description"), 320),
            "cats": [cats[c] for c in (i.get("categories") or []) if isinstance(c, str) and c in cats][:4],
            "port": port if isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536 else None,
            "dev": bool(i.get("is_dev")),
        })
    return sorted(out, key=lambda s: s["name"].lower())


class Scripts:
    """De catalogus van Proxmox VE Helper-Scripts, hooguit eens per dag opgehaald en op schijf bewaard, zodat
    een herstart of een storing aan hun kant het zoeken niet breekt."""

    def __init__(self):
        self.lock = threading.Lock()
        self.file = STATE_DIR / "scripts.json"
        self.data = None
        self.tried = 0.0

    def fetch(self) -> dict:
        def records(collection: str, **params) -> dict:
            r = requests.get(f"{SCRIPTS_API}/{collection}/records", params=params, timeout=20,
                             headers={"User-Agent": "proxmox-maintool"})
            r.raise_for_status()
            return r.json()

        cats = {c["id"]: plain(c.get("name"), 40)
                for c in records("script_categories", perPage=200, fields="id,name")["items"]}
        items, page = [], 1
        while True:
            got = records("script_scripts", perPage=500, page=page, expand="type", sort="name", fields=SCRIPTS_FIELDS)
            items += got["items"]
            if page >= min(int(got.get("totalPages") or 1), 10):
                break
            page += 1
        scripts = compact_scripts(items, cats)
        if not scripts:
            raise ValueError("lege catalogus ontvangen")
        return {"updated": int(time.time()), "scripts": scripts}

    def get(self) -> dict:
        with self.lock:
            if self.data is None:
                try:
                    self.data = json.loads(self.file.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    pass
            old = not self.data or time.time() - self.data.get("updated", 0) > SCRIPTS_MAX_AGE
            error = None
            if old and time.time() - self.tried > SCRIPTS_RETRY:
                self.tried = time.time()
                try:
                    self.data = self.fetch()
                    try:
                        tmp = self.file.with_suffix(".tmp")
                        tmp.write_text(json.dumps(self.data), encoding="utf-8")
                        tmp.replace(self.file)
                    except OSError:
                        pass  # zonder schrijfbare map blijft de catalogus alleen in het geheugen
                    old = False
                except (requests.RequestException, ValueError, KeyError, TypeError) as err:
                    error = str(err)[:200]
            if not self.data:
                raise HTTPException(502, "De catalogus van community-scripts.org is nu niet bereikbaar"
                                         + (f": {error}" if error else ""))
            return {**self.data, "count": len(self.data["scripts"]), "site": SCRIPTS_SITE, "stale": old}


scripts_catalog = Scripts()


@app.get("/api/scripts")
def scripts_list(_: str = Depends(auth)):
    return scripts_catalog.get()



# ---------------------------------------------------------------- de tool bijwerken met één bestand
# De pagina levert het setup-bestand van een nieuwere versie aan. Deze dienst kan zijn eigen programmabestanden niet
# vervangen (en hoort dat ook niet te kunnen); hij bewaart het bestand, laat het controleren en zet na bevestiging met
# het wachtwoord een startsein neer. Een apart programma van root (updater/maintool-updater, gestart door systemd)
# controleert alles opnieuw, installeert, herstart deze dienst en zet de oude versie terug als de nieuwe niet antwoordt.
UPDATER = Path("/usr/local/sbin/maintool-updater")
UPDATE_DIR = STATE_DIR / "update"
UPDATE_FILE = UPDATE_DIR / "upload.bin"
UPDATE_TRIGGER = UPDATE_DIR / "apply"
UPDATE_RESULT = Path("/var/lib/maintool-update/result.json")
UPDATE_MAX = 20 * 2**20


def update_check() -> dict:
    """Laat het bijwerkprogramma het klaargezette bestand controleren (alleen lezen); geeft zijn oordeel terug."""
    try:
        p = subprocess.run(["/usr/bin/python3", str(UPDATER), "check", str(UPDATE_FILE)], capture_output=True, text=True, timeout=120)
        verdict = json.loads(p.stdout)
        if not isinstance(verdict, dict) or "ok" not in verdict:
            raise ValueError
        return verdict
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise HTTPException(500, "De controle van het bestand is mislukt")


def update_guard(request: Request):
    same_origin(request)
    if not UPDATER.is_file():
        raise HTTPException(409, "Bijwerken via de pagina is op deze installatie niet ingeschakeld; draai op een node: "
                                 "bash maintool-setup.sh --update")
    if UPDATE_TRIGGER.exists():
        raise HTTPException(409, "Er wordt al een update geïnstalleerd")


def selfupdate_view(user: str) -> dict:
    try:
        result = json.loads(UPDATE_RESULT.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        result = None
    return {"version": VERSION, "available": UPDATER.is_file(), "busy": UPDATE_TRIGGER.exists(),
            "result": result if isinstance(result, dict) else None, "github": github_view(user)}


@app.get("/api/selfupdate/status")
def selfupdate_status(user: str = Depends(auth)):
    return selfupdate_view(user)


@app.post("/api/selfupdate/upload")
async def selfupdate_upload(request: Request, _: str = Depends(admin)):
    """Neemt het bestand aan (de inhoud van het verzoek is het bestand zelf) en geeft het oordeel van de controle."""
    update_guard(request)
    if int(request.headers.get("content-length") or 0) > UPDATE_MAX:
        raise HTTPException(413, "Het bestand is te groot")
    part = UPDATE_DIR / "upload.part"
    try:
        UPDATE_DIR.mkdir(mode=0o700, exist_ok=True)
        size = 0
        with open(part, "wb") as f:
            async for chunk in request.stream():
                size += len(chunk)
                if size > UPDATE_MAX:
                    raise HTTPException(413, "Het bestand is te groot")
                f.write(chunk)
        os.replace(part, UPDATE_FILE)
    except OSError:
        raise HTTPException(500, "Het bestand kon niet worden opgeslagen")
    finally:
        part.unlink(missing_ok=True)
    return await judge_update()


async def judge_update() -> dict:
    """Het oordeel over het klaargezette bestand: eerst het setup-bestand uit een ZIP of tar.gz halen, dan de controle
    van het bijwerkprogramma. Voor een aangeleverd bestand en voor een versie die de tool zelf van GitHub haalt."""
    member, refused = await asyncio.to_thread(from_archive, UPDATE_FILE)
    if refused:
        UPDATE_FILE.unlink(missing_ok=True)
        return {"ok": False, "code": refused}
    verdict = await asyncio.to_thread(update_check)
    if member:
        verdict["from_archive"] = member
    if not verdict["ok"]:
        if verdict.get("code") == "not_a_package" and not member:
            verdict["code"] = wrong_file(UPDATE_FILE) or "not_a_package"
        UPDATE_FILE.unlink(missing_ok=True)   # een afgekeurd bestand blijft niet liggen
    return verdict


# De ZIP die GitHub van een versie maakt (en de tar.gz) mag in één keer worden aangeleverd: vanaf 1.4.1 staat het
# gebouwde setup-bestand daarin bovenin (map/maintool-setup.sh, naast de uitleg). Alleen dat ene bestand wordt eruit
# gelezen, nooit iets uitgepakt op schijf, en hooguit UPDATE_MAX groot; daarna volgt dezelfde controle als voor een los
# setup-bestand.
ARCHIVE_SETUP_RE = re.compile(r"^(?:[^/]+/)?maintool-setup\.sh$")


def from_archive(path: Path) -> tuple:
    """(naam in het archief, None) als het setup-bestand uit een ZIP of tar.gz nu op path staat; (None, code) als het
    archief niet bruikbaar is; (None, None) als het geen archief is."""
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError:
        return None, None
    try:
        if head.startswith(b"PK\x03\x04"):
            with zipfile.ZipFile(path) as z:
                items = [i for i in z.infolist() if not i.is_dir()]
                found = [i for i in items if ARCHIVE_SETUP_RE.match(i.filename)]
                if len(found) != 1:
                    return None, "archive_old" if any(i.filename.endswith("setup/maintool-setup.sh") for i in items) else "archive_empty"
                if found[0].file_size > UPDATE_MAX:
                    return None, "too_big"
                name = found[0].filename
                with z.open(found[0]) as src:
                    data = src.read(UPDATE_MAX + 1)
        elif head.startswith(b"\x1f\x8b"):
            with tarfile.open(path, "r:gz") as tar:
                items = [m for m in tar.getmembers() if m.isfile()][:20000]
                found = [m for m in items if ARCHIVE_SETUP_RE.match(m.name)]
                if len(found) != 1:
                    return None, "archive_old" if any(m.name.endswith("setup/maintool-setup.sh") for m in items) else "archive_empty"
                if found[0].size > UPDATE_MAX:
                    return None, "too_big"
                name = found[0].name
                data = tar.extractfile(found[0]).read(UPDATE_MAX + 1)
        else:
            return None, None
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, RuntimeError, NotImplementedError, ValueError):
        return None, "damaged"
    if len(data) > UPDATE_MAX:
        return None, "too_big"
    part = path.with_suffix(".part")
    try:
        part.write_bytes(data)
        os.replace(part, path)
    except OSError:
        part.unlink(missing_ok=True)
        return None, "damaged"
    return name[:200], None


def wrong_file(path: Path) -> str | None:
    """Het sjabloon uit setup/ van de broncode (nog zonder de tool erin) in plaats van het setup-bestand: dan zegt de
    pagina welk bestand het wel is."""
    try:
        with open(path, "rb") as f:
            head = f.read(65536)
    except OSError:
        return None
    return "source" if head.startswith(b"#!") and b'VERSION="@VERSION@"' in head else None


@app.delete("/api/selfupdate/upload")
def selfupdate_discard(request: Request, _: str = Depends(admin)):
    update_guard(request)
    UPDATE_FILE.unlink(missing_ok=True)
    return {"ok": True}


class UpdateIn(BaseModel):
    password: str = Field(max_length=300)
    sha256: str = Field(pattern="^[0-9a-f]{64}$")   # de vingerafdruk die de pagina na de controle heeft getoond


@app.post("/api/selfupdate/apply")
def selfupdate_apply(body: UpdateIn, request: Request, user: str = Depends(admin)):
    """Geeft het startsein voor de installatie. Vraagt het wachtwoord opnieuw: een open staande, ingelogde pagina
    is hier niet genoeg."""
    update_guard(request)
    source = request.client.host if request.client else "?"
    if login_guard.blocked(source):
        raise HTTPException(429, "Te veel mislukte pogingen. Probeer het over tien minuten opnieuw.")
    if not check_login(user, body.password):
        login_guard.failed(source)
        raise HTTPException(403, "Het wachtwoord klopt niet; er is niets geïnstalleerd")
    if not UPDATE_FILE.is_file():
        raise HTTPException(409, "Er staat geen gecontroleerd bestand klaar; kies het bestand opnieuw")
    verdict = update_check()
    if not verdict["ok"]:
        UPDATE_FILE.unlink(missing_ok=True)
        raise HTTPException(409, "Het bestand is afgekeurd; er is niets geïnstalleerd")
    if verdict.get("sha256") != body.sha256:
        raise HTTPException(409, "Het bestand is veranderd sinds de controle; kies het opnieuw")
    try:
        tmp = UPDATE_DIR / "apply.tmp"
        tmp.write_text(json.dumps({"sha256": body.sha256, "time": int(time.time())}), encoding="utf-8")
        os.replace(tmp, UPDATE_TRIGGER)   # systemd (maintool-update.path) ziet dit en start het bijwerkprogramma
    except OSError:
        raise HTTPException(500, "Het bestand kon niet worden opgeslagen")
    return {"started": True, "version": verdict["version"], "previous": VERSION, "time": int(time.time())}


# ---------------------------------------------------------------- nieuwe versies op GitHub
# De tool kijkt kort na het starten en daarna elke zes uur op GitHub of daar een nieuwere versie staat: een tag vX.Y of
# vX.Y.Z van de repository. Is die er, dan kleurt de pagina het menu oranje en meldt ze het aan beheerders. Met één knop
# haalt de tool de ZIP van die versie zelf op; die gaat door precies dezelfde controle als een bestand dat je zelf
# aanlevert, en installeren vraagt daarna nog steeds het wachtwoord. Naar GitHub gaat alleen de vraag welke versies er
# zijn, niets over het cluster. UPDATE_REPO leeg in maintool.env zet het kijken uit.
UPDATE_REPO = os.environ.get("UPDATE_REPO", "EduardWichers/Proxmox-MainTool").strip()
REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$")
if UPDATE_REPO and not REPO_RE.match(UPDATE_REPO):
    UPDATE_REPO = ""   # onzin in maintool.env: dan niet kijken, in plaats van een vreemd adres op te vragen
GITHUB_API = "https://api.github.com"
GITHUB_SITE = "https://github.com"
GITHUB_ZIP_HOSTS = ("github.com", "codeload.github.com")   # de ZIP van een tag komt via codeload
GITHUB_EVERY = 6 * 3600   # zo vaak kijken
GITHUB_RETRY = 3600       # na een mislukte poging eerder opnieuw
GITHUB_GAP = 30           # vaker dan dit op Opnieuw kijken drukken geeft het vorige antwoord (GitHub telt de vragen)
VERSION_TAG_RE = re.compile(r"^v?(\d{1,4}(?:\.\d{1,4}){1,2})$")
NOTES_MAX = 4000
github_lock = threading.Lock()


def version_key(text):
    """'1.4.1' of 'v1.5' -> (1, 4, 1) of (1, 5, 0); None als het geen versienummer is."""
    m = VERSION_TAG_RE.match(str(text or "").strip())
    if not m:
        return None
    parts = [int(x) for x in m.group(1).split(".")]
    return tuple(parts + [0] * (3 - len(parts)))


def github_get(path: str, etag: str | None = None):
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
               "User-Agent": f"proxmox-maintool/{VERSION}"}
    if etag:
        headers["If-None-Match"] = etag   # niets veranderd: GitHub antwoordt 304 en telt de vraag niet mee
    return requests.get(f"{GITHUB_API}/repos/{UPDATE_REPO}{path}", headers=headers, timeout=15)


def release_notes(message) -> str:
    """Wat er nieuw is, uit het commitbericht van de versie: zonder de titelregel en zonder regels als
    Co-Authored-By, en de afgebroken regels van een opsomming weer aan elkaar. Platte tekst; de pagina zet er nooit
    opmaak van om."""
    out = []
    for line in re.sub(r"[^\S\n]", " ", str(message or "")).split("\n")[1:]:
        if re.match(r"^[A-Za-z-]+: .*<[^<>]*>\s*$", line):
            continue
        if line.startswith("  ") and out and out[-1].strip():
            out[-1] = out[-1].rstrip() + " " + line.strip()
        else:
            out.append(line.rstrip())
    return "\n".join(out).strip()[:NOTES_MAX]


def github_saved() -> dict:
    """Wat de tool het laatst over GitHub weet (in state.json); leeg als dat over een andere repository ging."""
    g = state.load().get("github")
    return g if isinstance(g, dict) and g.get("repo") == UPDATE_REPO else {}


class GithubError(Exception):
    """Geen bruikbaar antwoord van GitHub; de tekst is een code die de pagina vertaalt."""


def github_check(manual: bool = False) -> dict:
    """Vraagt GitHub welke versies er zijn en bewaart de nieuwste in state.json. Lukt dat niet, dan blijft de laatst
    bekende versie staan en komt alleen de fout erbij."""
    with github_lock:
        saved, now = github_saved(), int(time.time())
        if manual and now - (saved.get("tried") or 0) < GITHUB_GAP:
            return saved
        info = {**saved, "repo": UPDATE_REPO, "tried": now}
        try:
            try:
                r = github_get("/tags?per_page=100", saved.get("etag"))
            except requests.RequestException:
                raise GithubError("unreachable")
            if r.status_code == 404:
                raise GithubError("not_found")      # verkeerde naam, of de repository is (nog) niet openbaar
            if r.status_code in (403, 429):
                raise GithubError("rate_limited")
            if r.status_code == 200:
                try:
                    tags = [t for t in r.json() if isinstance(t, dict) and version_key(t.get("name"))]
                except (ValueError, TypeError):
                    raise GithubError("bad_answer")
                best = max(tags, key=lambda t: version_key(t["name"]), default=None)
                if best is None:
                    info.update(tag=None, version=None, sha=None, notes=None)
                else:
                    sha = str((best.get("commit") or {}).get("sha") or "")
                    if not re.fullmatch(r"[0-9a-f]{40}", sha):
                        raise GithubError("bad_answer")
                    if best["name"] != saved.get("tag") or sha != saved.get("sha"):
                        notes = None
                        try:
                            c = github_get(f"/commits/{sha}")
                            if c.status_code == 200:
                                notes = release_notes(((c.json() or {}).get("commit") or {}).get("message")) or None
                        except (requests.RequestException, ValueError, TypeError, AttributeError):
                            pass   # zonder toelichting kan het ook
                        info.update(tag=best["name"], version=VERSION_TAG_RE.match(best["name"]).group(1), sha=sha, notes=notes)
                info["etag"] = r.headers.get("ETag")   # pas nu: een antwoord dat niet te gebruiken was, wordt opnieuw gelezen
            elif r.status_code != 304:
                raise GithubError("bad_answer")
            info.update(checked=now, error=None)
        except GithubError as err:
            info["error"] = str(err)
        try:
            state.change(lambda d: d.update(github=info))
        except OSError:
            pass
        return info


def github_view(user: str) -> dict:
    """Voor de pagina: de nieuwste versie op GitHub, of die nieuwer is dan wat hier draait, en voor welke versie deze
    gebruiker heeft gekozen om er niet meer aan herinnerd te worden."""
    g, mine = github_saved(), version_key(VERSION)
    latest = g.get("version")
    newer = bool(UPDATE_REPO and mine and version_key(latest) and version_key(latest) > mine)
    return {"enabled": bool(UPDATE_REPO), "repo": UPDATE_REPO or None, "latest": latest, "tag": g.get("tag"),
            "newer": newer, "notes": g.get("notes") if newer else None, "checked": g.get("checked"),
            "tried": g.get("tried"), "error": g.get("error"),
            "dismissed": saved_settings(state.load(), user).get("update_dismissed")}


def github_loop():
    """Kort na het starten kijken, daarna elke zes uur; na een mislukte poging elk uur."""
    time.sleep(60)
    while UPDATE_REPO:
        try:
            g = github_saved()
            if time.time() - (g.get("tried") or 0) >= (GITHUB_RETRY if g.get("error") else GITHUB_EVERY):
                github_check()
        except Exception:  # noqa: BLE001 - het kijken mag de tool nooit hinderen
            pass
        time.sleep(600)


def github_download(tag: str) -> str | None:
    """Haalt de ZIP van een versie op GitHub naar het klaarzetbestand, hooguit UPDATE_MAX groot. None als dat lukte,
    anders een code voor de pagina."""
    part = UPDATE_DIR / "upload.part"
    try:
        UPDATE_DIR.mkdir(mode=0o700, exist_ok=True)
        with requests.get(f"{GITHUB_SITE}/{UPDATE_REPO}/archive/refs/tags/{tag}.zip", stream=True, timeout=(10, 60),
                          headers={"User-Agent": f"proxmox-maintool/{VERSION}"}) as r:
            if r.status_code == 404:
                return "github_not_found"
            if r.status_code != 200 or urllib.parse.urlsplit(r.url).hostname not in GITHUB_ZIP_HOSTS:
                return "github_unreachable"
            if int(r.headers.get("content-length") or 0) > UPDATE_MAX:
                return "too_big"
            size = 0
            with open(part, "wb") as f:
                for chunk in r.iter_content(65536):
                    size += len(chunk)
                    if size > UPDATE_MAX:
                        return "too_big"
                    f.write(chunk)
        os.replace(part, UPDATE_FILE)
        return None
    except requests.RequestException:
        return "github_unreachable"
    except OSError:
        raise HTTPException(500, "Het bestand kon niet worden opgeslagen")
    finally:
        part.unlink(missing_ok=True)


@app.post("/api/selfupdate/check")
def selfupdate_check(request: Request, user: str = Depends(admin)):
    """Nu meteen opnieuw kijken op GitHub (de knop Opnieuw kijken bij Tool bijwerken)."""
    same_origin(request)
    if not UPDATE_REPO:
        raise HTTPException(409, "Zoeken naar nieuwe versies staat uit (UPDATE_REPO in maintool.env)")
    github_check(manual=True)
    return selfupdate_view(user)


class GithubIn(BaseModel):
    version: str = Field(pattern=r"^\d{1,4}(\.\d{1,4}){1,2}$")   # de versie die de pagina heeft getoond


@app.post("/api/selfupdate/github")
async def selfupdate_github(body: GithubIn, request: Request, _: str = Depends(admin)):
    """Haalt de nieuwste versie zelf van GitHub en geeft het oordeel van de controle, net als bij een aangeleverd
    bestand. Installeren gaat daarna langs dezelfde weg: /api/selfupdate/apply, met het wachtwoord."""
    update_guard(request)
    if not UPDATE_REPO:
        raise HTTPException(409, "Zoeken naar nieuwe versies staat uit (UPDATE_REPO in maintool.env)")
    g = github_saved()
    if not g.get("tag") or version_key(g.get("version")) != version_key(body.version):
        raise HTTPException(409, "Deze versie staat niet (meer) op GitHub; kijk opnieuw")
    refused = await asyncio.to_thread(github_download, g["tag"])
    if refused:
        return {"ok": False, "code": refused}
    verdict = await judge_update()
    if verdict.get("ok") and version_key(verdict.get("version")) != version_key(body.version):
        # het setup-bestand in de ZIP is niet opnieuw gebouwd voor deze versie: niet stilletjes iets anders installeren
        UPDATE_FILE.unlink(missing_ok=True)
        return {"ok": False, "code": "github_mismatch", "version": verdict.get("version"), "wanted": body.version}
    verdict["from_github"] = g["tag"]
    return verdict


# ---------------------------------------------------------------- aanmaken: container, VM, opslag
# De plusknop in de pagina. Elk verzoek wordt hier opnieuw nagekeken tegen wat de gekozen node werkelijk heeft
# (opslag, sjablonen, ISO's, netwerkbruggen); er gaat niets ongecontroleerd door naar Proxmox.
NAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
STORAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{1,31}$")
SERVER_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
SSH_KEY_RE = re.compile(r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/]{40,}={0,3}( [^\r\n]{0,200})?$")
CONTENT_KINDS = ("backup", "images", "rootdir", "iso", "vztmpl", "snippets")


def node_options(api, node: str) -> dict:
    """Wat er op een node gekozen kan worden bij het aanmaken van een container of VM."""
    stores = api.nodes(node).storage.get()

    def having(kind: str) -> list:
        return [{"storage": s["storage"], "type": s.get("type"), "avail": s.get("avail"), "shared": bool(s.get("shared"))}
                for s in sorted(stores, key=lambda s: s["storage"])
                if s.get("active") and s.get("enabled", 1) and kind in (s.get("content") or "").split(",")]

    def volumes(kind: str) -> list:
        found = []
        for s in having(kind):
            try:
                found += [v["volid"] for v in api.nodes(node).storage(s["storage"]).content.get(content=kind)]
            except ResourceException:
                pass  # opslag even niet bereikbaar: de rest blijft bruikbaar
        return sorted(set(found))

    newest = {}
    for a in api.nodes(node).aplinfo.get():
        name = a.get("template") or ""
        if a.get("section") == "system" and "_amd64." in name and a.get("package"):
            key = [int(x) for x in re.findall(r"\d+", str(a.get("version") or "0"))]
            if a["package"] not in newest or key > newest[a["package"]][0]:
                newest[a["package"]] = (key, name)
    templates = volumes("vztmpl")
    present = {v.split("/", 1)[-1] for v in templates}
    return {
        "node": node, "rootdir": having("rootdir"), "images": having("images"), "vztmpl": having("vztmpl"),
        "templates": templates, "isos": volumes("iso"),
        "available": sorted(name for _, name in newest.values() if name not in present),
        "bridges": sorted(b["iface"] for b in api.nodes(node).network.get(type="any_bridge") if b.get("active")),
    }


def online_nodes(api) -> list:
    return sorted(n["node"] for n in api.nodes.get() if n.get("status") == "online")


def create_checks(api, node: str, vmid: int, name: str) -> dict:
    """De controles die voor een container en een VM gelijk zijn; geeft de keuzes van de node terug."""
    if not NODE_RE.match(node) or node not in online_nodes(api):
        raise HTTPException(400, "Deze node is niet online of bestaat niet")
    if not (100 <= vmid <= 999999999):
        raise HTTPException(400, "Ongeldig VMID")
    if any(g.get("vmid") == vmid for g in api.cluster.resources.get(type="vm")):
        raise HTTPException(409, f"ID {vmid} is al in gebruik")
    if not NAME_RE.match(name):
        raise HTTPException(400, "Deze naam is ongeldig: gebruik letters, cijfers en streepjes")
    if name.lower() == socket.gethostname().lower():
        # De tool herkent zijn eigen container aan de naam; een tweede met die naam zou hij voor zichzelf aanzien.
        raise HTTPException(409, "Deze naam is al de naam van de container van de tool zelf; kies een andere")
    return node_options(api, node)


def net_options(options: dict, bridge: str, vlan) -> str:
    if bridge not in options["bridges"]:
        raise HTTPException(400, "Deze netwerkbrug bestaat niet op deze node")
    return f"bridge={bridge}" + (f",tag={vlan}" if vlan else "")


@app.get("/api/create/options")
def create_options(node: str = "", _: str = Depends(manage_create)):
    def f(api):
        nodes = online_nodes(api)
        if not nodes:
            raise HTTPException(503, "Geen enkele node is online")
        chosen = node if node in nodes else nodes[0]
        nextid = int(api.cluster.nextid.get())
        guests = api.cluster.resources.get(type="vm")
        media = media_scan(api, nodes)
        def elsewhere(kind):   # wat alleen op andere nodes staat; hetzelfde bestand op meer nodes is één regel
            here = {i["file"] for i in media["items"] if i["content"] == kind and chosen in i["nodes"]}
            found = {}
            for i in media["items"]:
                if i["content"] == kind and chosen not in i["nodes"] and i["file"] not in here:
                    x = found.setdefault(i["file"], {"volid": i["volid"], "file": i["file"], "nodes": []})
                    x["nodes"] = sorted(set(x["nodes"]) | set(i["nodes"]))
            return [found[k] for k in sorted(found, key=str.lower)]
        return {**node_options(api, chosen), "nodes": nodes, "nextid": nextid, "free_ids": free_ids(api, nextid),
                "used_ids": {str(g["vmid"]): g.get("name") or "" for g in guests if isinstance(g.get("vmid"), int)},
                "cpu": node_cpu(api, chosen), "isos_elsewhere": elsewhere("iso"), "templates_elsewhere": elsewhere("vztmpl"),
                "media_info": {i["volid"]: {"size": i["size"], "shared": i["shared"]} for i in media["items"] if chosen in i["nodes"]}}
    return pve.run(f)


class TemplateIn(BaseModel):
    node: str
    storage: str
    template: str = Field(max_length=200)


@app.post("/api/create/template")
def create_template(body: TemplateIn, request: Request, _: str = Depends(manage_overview)):
    """Haalt een containersjabloon uit de lijst van Proxmox op naar een opslag van de node."""
    same_origin(request)

    def f(api):
        if not NODE_RE.match(body.node) or body.node not in online_nodes(api):
            raise HTTPException(400, "Deze node is niet online of bestaat niet")
        options = node_options(api, body.node)
        if body.storage not in {s["storage"] for s in options["vztmpl"]}:
            raise HTTPException(400, "Op deze opslag mogen geen sjablonen staan")
        if body.template not in options["available"]:
            raise HTTPException(400, "Dit sjabloon staat niet in de lijst van Proxmox")
        return api.nodes(body.node).aplinfo.post(storage=body.storage, template=body.template)
    return {"upid": pve.run(f), "node": body.node, "volid": f"{body.storage}:vztmpl/{body.template}"}


class CtIn(BaseModel):
    node: str
    vmid: int
    hostname: str = Field(max_length=63)
    template: str = Field(max_length=300)
    password: str = Field("", max_length=200)
    ssh_key: str = Field("", max_length=2000)
    cores: int = Field(1, ge=1, le=128)
    memory: int = Field(512, ge=64, le=1048576)   # MB
    swap: int = Field(512, ge=0, le=1048576)      # MB
    disk: int = Field(8, ge=1, le=10000)          # GB
    storage: str
    bridge: str
    ip: str = Field("dhcp", max_length=50)        # "dhcp" of adres/prefix
    gateway: str = Field("", max_length=50)
    vlan: int | None = Field(None, ge=1, le=4094)
    unprivileged: bool = True
    nesting: bool = True
    start: bool = True
    onboot: bool = False


def ct_params(body: CtIn, options: dict) -> dict:
    """De opdracht voor Proxmox om deze container aan te maken, na controle van elke keuze."""
    if body.template not in options["templates"]:
        raise HTTPException(400, "Dit sjabloon staat niet op een opslag van deze node")
    if body.storage not in {s["storage"] for s in options["rootdir"]}:
        raise HTTPException(400, "Op deze opslag mag deze schijf niet staan")
    key = " ".join(body.ssh_key.split())
    if key and not SSH_KEY_RE.match(key):
        raise HTTPException(400, "Dit is geen geldige openbare SSH-sleutel")
    if len(body.password) < 8 and not key:
        raise HTTPException(400, "Geef een root-wachtwoord van minstens 8 tekens of een SSH-sleutel op")
    net = "name=eth0," + net_options(options, body.bridge, body.vlan)
    if body.ip.strip().lower() == "dhcp":
        net += ",ip=dhcp"
    else:
        try:
            address = ipaddress.ip_interface(body.ip.strip())
            if address.version != 4 or "/" not in body.ip or not (8 <= address.network.prefixlen <= 30):
                raise ValueError
            if address.ip in (address.network.network_address, address.network.broadcast_address):
                raise ValueError
        except ValueError:
            raise HTTPException(400, "Ongeldig IP-adres; gebruik de vorm 192.168.1.50/24")
        net += f",ip={address.with_prefixlen}"
        if body.gateway.strip():
            try:
                gateway = ipaddress.ip_address(body.gateway.strip())
                if gateway.version != 4 or gateway not in address.network or gateway == address.ip:
                    raise ValueError
            except ValueError:
                raise HTTPException(400, "De gateway is geen geldig adres in hetzelfde netwerk")
            net += f",gw={gateway}"
    params = {"vmid": body.vmid, "ostemplate": body.template, "hostname": body.hostname, "cores": body.cores,
              "memory": body.memory, "swap": body.swap, "rootfs": f"{body.storage}:{body.disk}", "net0": net,
              "unprivileged": int(body.unprivileged), "onboot": int(body.onboot), "start": int(body.start)}
    if body.unprivileged and body.nesting:
        params["features"] = "nesting=1"   # bij een bevoorrechte container mag alleen root@pam dit zetten
    if body.password:
        params["password"] = body.password
    if key:
        params["ssh-public-keys"] = key
    return params


@app.post("/api/create/ct")
def create_ct(body: CtIn, request: Request, _: str = Depends(manage_overview)):
    same_origin(request)

    def f(api):
        params = ct_params(body, create_checks(api, body.node, body.vmid, body.hostname))
        return api.nodes(body.node).lxc.post(**params)
    return {"upid": pve.run(f), "node": body.node}


class VmIn(BaseModel):
    node: str
    vmid: int
    name: str = Field(max_length=63)
    os: str = Field("linux", pattern="^(linux|windows|other)$")
    iso: str = Field("", max_length=300)          # volume op een ISO-opslag; leeg = lege cd-speler
    cores: int = Field(2, ge=1, le=128)
    memory: int = Field(2048, ge=64, le=4194304)  # MB
    disk: int = Field(32, ge=1, le=100000)        # GB
    storage: str
    bridge: str
    vlan: int | None = Field(None, ge=1, le=4094)
    uefi: bool = False
    agent: bool = True
    start: bool = False
    onboot: bool = False


def vm_params(body: VmIn, options: dict) -> dict:
    """De opdracht voor Proxmox om deze VM aan te maken. Windows krijgt wat Windows 11 eist (UEFI en een TPM) en
    een schijf en netwerkkaart die de installatie zonder extra stuurprogramma's herkent."""
    if body.storage not in {s["storage"] for s in options["images"]}:
        raise HTTPException(400, "Op deze opslag mag deze schijf niet staan")
    if body.iso and body.iso not in options["isos"]:
        raise HTTPException(400, "Dit ISO-bestand staat niet op een opslag van deze node")
    windows = body.os == "windows"
    params = {"vmid": body.vmid, "name": body.name, "cores": body.cores, "sockets": 1, "memory": body.memory,
              "cpu": "x86-64-v2-AES", "ostype": {"linux": "l26", "windows": "win11", "other": "other"}[body.os],
              "scsihw": "virtio-scsi-single", "net0": ("e1000," if windows else "virtio,") + net_options(options, body.bridge, body.vlan),
              "ide2": f"{body.iso},media=cdrom" if body.iso else "none,media=cdrom",
              "agent": int(body.agent), "onboot": int(body.onboot), "start": int(body.start)}
    disk = "sata0" if windows else "scsi0"
    params[disk] = f"{body.storage}:{body.disk}" + ("" if windows else ",iothread=1,discard=on")
    params["boot"] = f"order={disk};ide2;net0"
    if body.uefi or windows:
        params.update(bios="ovmf", machine="q35", efidisk0=f"{body.storage}:1,efitype=4m,pre-enrolled-keys=1")
    if windows:
        params["tpmstate0"] = f"{body.storage}:1,version=v2.0"
    return params


@app.post("/api/create/vm")
def create_vm(body: VmIn, request: Request, _: str = Depends(manage_overview)):
    same_origin(request)

    def f(api):
        params = vm_params(body, create_checks(api, body.node, body.vmid, body.name))
        return api.nodes(body.node).qemu.post(**params)
    return {"upid": pve.run(f), "node": body.node}


class StorageIn(BaseModel):
    kind: str = Field(pattern="^(nfs|cifs)$")
    name: str = Field(max_length=32)
    server: str = Field(max_length=253)
    path: str = Field(max_length=200)             # NFS: de export (/volume1/backup); SMB: de naam van de gedeelde map
    username: str = Field("", max_length=100)
    password: str = Field("", max_length=200)
    content: list[str] = Field(max_length=6)


def storage_params(body: StorageIn) -> dict:
    if not STORAGE_RE.match(body.name):
        raise HTTPException(400, "Ongeldige naam voor de opslag: begin met een letter; letters, cijfers, punt, streepje")
    if not SERVER_RE.match(body.server):
        raise HTTPException(400, "Ongeldig adres van de server")
    nfs = body.kind == "nfs"
    if not re.fullmatch(r"/[A-Za-z0-9._/ -]{0,199}" if nfs else r"[A-Za-z0-9._$ -]{1,80}", body.path) or ".." in body.path:
        raise HTTPException(400, "Ongeldige gedeelde map")
    content = [c for c in CONTENT_KINDS if c in body.content]
    if not content or set(body.content) - set(CONTENT_KINDS):
        raise HTTPException(400, "Kies minstens één soort inhoud")
    params = {"storage": body.name, "type": body.kind, "server": body.server, "content": ",".join(content),
              ("export" if nfs else "share"): body.path}
    if not nfs and body.username:
        params.update(username=body.username, password=body.password)
    return params


@app.post("/api/create/storage")
def create_storage(body: StorageIn, request: Request, _: str = Depends(manage_storage)):
    """Koppelt een NFS- of SMB-share als opslag voor het hele cluster."""
    same_origin(request)
    params = storage_params(body)

    def f(api):
        if any(s.get("storage") == body.name for s in api.storage.get()):
            raise HTTPException(409, f"Er bestaat al een opslag met de naam {body.name}")
        api.storage.post(**params)
        return {"ok": True, "storage": body.name}
    return pve.run(f)


class ScanIn(BaseModel):
    kind: str = Field(pattern="^(nfs|cifs)$")
    server: str = Field(max_length=253)
    username: str = Field("", max_length=100)
    password: str = Field("", max_length=200)


@app.post("/api/create/scan")
def create_scan(body: ScanIn, request: Request, _: str = Depends(manage_storage)):
    """Vraagt een node welke mappen een server deelt. Een POST, zodat een wachtwoord niet in een adres belandt."""
    same_origin(request)
    if not SERVER_RE.match(body.server):
        raise HTTPException(400, "Ongeldig adres van de server")

    def f(api):
        scan = api.nodes(online_node(api)).scan
        if body.kind == "nfs":
            return sorted(str(x.get("path")) for x in scan.nfs.get(server=body.server) if x.get("path"))
        extra = {"username": body.username, "password": body.password} if body.username else {}
        return sorted(str(x.get("share")) for x in scan.cifs.get(server=body.server, **extra) if x.get("share"))
    return {"shares": pve.run(f)}


# ---------------------------------------------------------------- tabblad Opslag en het ballonnetje per node
def storage_target(cfg: dict) -> str:
    kind = cfg.get("type")
    if kind == "nfs":
        return f"{cfg.get('server')}:{cfg.get('export')}"
    if kind == "cifs":
        return f"//{cfg.get('server')}/{cfg.get('share')}"
    if kind == "pbs":
        return f"{cfg.get('server')}:{cfg.get('datastore')}"
    if kind in ("lvm", "lvmthin"):
        return "/".join(x for x in (cfg.get("vgname"), cfg.get("thinpool")) if x)
    return str(cfg.get("path") or cfg.get("pool") or "")


def storage_overview(api, nodes: list) -> list:
    """Elke opslag van het cluster: waar hij staat, wat erop mag, hoe vol hij is en wat erop staat."""
    resources = api.cluster.resources.get(type="storage")
    out, counting = [], []
    for cfg in sorted(api.storage.get(), key=lambda s: s["storage"]):
        name = cfg["storage"]
        mine = sorted((r for r in resources if r.get("storage") == name), key=lambda r: r.get("node") or "")
        shared = bool(cfg.get("shared")) or any(r.get("shared") for r in mine)
        usable = [r for r in mine if r.get("status") == "available" and r.get("node") in nodes]
        usage = [{"node": r.get("node"), "disk": r.get("disk"), "maxdisk": r.get("maxdisk")} for r in usable]
        out.append({
            "storage": name, "type": cfg.get("type"), "shared": shared, "enabled": not cfg.get("disable"),
            "content": [c for c in str(cfg.get("content") or "").split(",") if c], "target": storage_target(cfg)[:200],
            "restricted": str(cfg.get("nodes") or "")[:200] or None,
            "usage": usage[:1] if shared else usage,   # gedeelde opslag is overal dezelfde: één keer tonen
            "unavailable": sorted(r.get("node") for r in mine if r.get("status") != "available" and r.get("node")),
            "prune": prune_text(cfg.get("prune-backups")) if cfg.get("prune-backups") else None,
            "counts": {}, "sizes": {}})
        counting += [(len(out) - 1, r["node"], name) for r in (usable[:1] if shared else usable)]

    def contents(job):
        index, node, name = job
        try:
            return index, on_node(node, lambda: api.nodes(node).storage(name).content.get())
        except ResourceException:
            return index, None

    for index, volumes in POOL.map(contents, counting):
        for v in volumes or []:
            kind = str(v.get("content") or "?")
            out[index]["counts"][kind] = out[index]["counts"].get(kind, 0) + 1
            out[index]["sizes"][kind] = out[index]["sizes"].get(kind, 0) + int(v.get("size") or 0)
    return out


def ceph_overview(api, node: str) -> dict | None:
    """Gezondheid, vulling, pools en OSD's van Ceph; None als het cluster geen Ceph heeft."""
    try:
        status = api.nodes(node).ceph.status.get()
    except ResourceException:
        return None
    health, pg = status.get("health") or {}, status.get("pgmap") or {}
    osd = status.get("osdmap") or {}
    osd = osd.get("osdmap") or osd   # oudere versies nestelen dit een niveau dieper
    try:
        listed = api.nodes(node).ceph.pool.get()
    except ResourceException:
        try:
            listed = api.nodes(node).ceph.pools.get()   # Proxmox 7 en ouder
        except ResourceException:
            listed = []
    pools = [{"name": p.get("pool_name"), "size": p.get("size"), "min_size": p.get("min_size"), "pgs": p.get("pg_num"),
              "used": p.get("bytes_used"), "percent": p.get("percent_used")} for p in listed]
    return {
        "health": health.get("status"),
        "checks": [{"code": code, "severity": c.get("severity"), "text": str((c.get("summary") or {}).get("message") or "")[:300]}
                   for code, c in sorted((health.get("checks") or {}).items())][:20],
        "used": pg.get("bytes_used"), "total": pg.get("bytes_total"), "pgs": pg.get("num_pgs"),
        "states": [{"name": s.get("state_name"), "count": s.get("count")} for s in pg.get("pgs_by_state") or []][:12],
        "osds": osd.get("num_osds"), "osds_up": osd.get("num_up_osds"), "osds_in": osd.get("num_in_osds"),
        "pools": sorted(pools, key=lambda p: str(p["name"])), "osd_list": ceph_osds(api, node)}


def node_disks(api, node: str):
    """De fysieke schijven van een node, met wat Proxmox over hun gezondheid weet; None als de node niet antwoordt."""
    try:
        return [{"dev": d.get("devpath"), "model": str(d.get("model") or "")[:80], "size": d.get("size"), "type": d.get("type"),
                 "health": d.get("health"), "wearout": d.get("wearout"), "used": d.get("used"),
                 "osds": [int(x) for x in (d.get("osdid-list") or [d.get("osdid")]) if str(x).isdigit()]}
                for d in sorted(api.nodes(node).disks.list.get(), key=lambda d: str(d.get("devpath")))]
    except ResourceException:
        return None


@app.get("/api/storage")
def storage_info(_: str = Depends(auth)):
    def f(api):
        nodes = [n for n in online_nodes(api) if not node_trouble.skip(n)]   # een node die niet antwoordt houdt alles op
        return {"storages": storage_overview(api, nodes), "ceph": on_node(nodes[0], lambda: ceph_overview(api, nodes[0])) if nodes else None,
                "disks": dict(zip(nodes, POOL.map(lambda n: on_node(n, lambda: node_disks(api, n)), nodes)))}
    return pve.run(f)


@app.get("/api/node/{node}/info")
def node_info(node: str, _: str = Depends(auth)):
    """Beknopte gegevens van één node, voor het ballonnetje bij zijn naam."""
    if not NODE_RE.match(node):
        raise HTTPException(400, "Ongeldige nodenaam")

    def f(api):
        listed = next((n for n in api.nodes.get() if n.get("node") == node), None)
        if listed is None:
            raise HTTPException(404, "Onbekende node")
        if listed.get("status") != "online":
            return {"node": node, "online": False, "ip": node_ips(api).get(node)}
        s = api.nodes(node).status.get()
        cpu, mem, swap, root = s.get("cpuinfo") or {}, s.get("memory") or {}, s.get("swap") or {}, s.get("rootfs") or {}
        guests = [g for g in api.cluster.resources.get(type="vm") if g.get("node") == node and not g.get("template")]
        return {"node": node, "online": True, "ip": node_ips(api).get(node),
                "pve": (s.get("pveversion") or "").partition("/")[2].partition("/")[0],
                "kernel": (s.get("current-kernel") or {}).get("release") or s.get("kversion"),
                "cpu": str(cpu.get("model") or "")[:80], "sockets": cpu.get("sockets"), "cores": cpu.get("cores"), "threads": cpu.get("cpus"),
                "load": [str(x) for x in s.get("loadavg") or []][:3], "mem": mem.get("used"), "maxmem": mem.get("total"),
                "swap": swap.get("used"), "maxswap": swap.get("total"), "root": root.get("used"), "maxroot": root.get("total"),
                "uptime": s.get("uptime"), "guests": len(guests), "running": sum(1 for g in guests if g.get("status") == "running"),
                "boot": (s.get("boot-info") or {}).get("mode")}
    return pve.run(f)


# ---------------------------------------------------------------- topologie (tabblad)
# Hoe het cluster in elkaar zit: de router, de gedeelde opslag, de nodes met hun bridges en de guests aan die bridges.
# De opbouw (configuratie van elke guest) verandert zelden en wordt hooguit eens per minuut gelezen; de stroom per node
# komt uit de RRD-cijfers van Proxmox (gemiddelde per minuut) en van Ceph. De stroom per guest rekent de pagina zelf uit
# met de tellers uit /api/live.
TOPO = {"at": -1e9, "data": None}
topo_lock = threading.Lock()
SHARED_KINDS = ("rbd", "cephfs", "nfs", "cifs", "pbs", "iscsi", "glusterfs", "zfs")


def topo_guest(api, g: dict) -> dict:
    """Netwerkkaarten (bridge, VLAN) en de opslag van de schijven van één guest, uit zijn configuratie."""
    try:
        cfg = on_node(g["node"], lambda: guest(api, g["node"], g["type"], g["vmid"]).config.get(), {}) or {}
    except ResourceException:
        cfg = {}
    nets, stores = [], []
    for key in sorted((k for k in cfg if NET_RE.match(k)), key=lambda k: (len(k), k)):
        o = parse_options(cfg[key])
        nets.append({"key": key, "bridge": o.get("bridge"), "tag": int(o["tag"]) if str(o.get("tag") or "").isdigit() else None})
    disk_re = LXC_DISK_RE if g["type"] == "lxc" else VM_DISK_RE
    for key in cfg:
        if disk_re.match(key):
            o = parse_options(cfg[key])
            volume = o.get("") or o.get("volume") or o.get("file") or ""
            if o.get("media") != "cdrom" and ":" in volume and not volume.startswith("/") and "cloudinit" not in volume:
                stores.append(volume.split(":", 1)[0])
    return {"nets": nets[:8], "stores": sorted(set(stores))[:8]}


def topo_structure(api) -> dict:
    nodes = sorted(api.nodes.get(), key=lambda n: n["node"])
    up = [n["node"] for n in nodes if n.get("status") == "online" and not node_trouble.skip(n["node"])]
    guests = sorted((g for g in api.cluster.resources.get(type="vm") if not g.get("template")), key=lambda g: g["vmid"])
    details = dict(zip((g["vmid"] for g in guests), POOL.map(lambda g: topo_guest(api, g) if g.get("node") in up else {"nets": [], "stores": []}, guests)))

    def bridges(node):
        rows = on_node(node, lambda: api.nodes(node).network.get(), []) or []
        return sorted(({"iface": i.get("iface"), "cidr": i.get("cidr"), "gateway": i.get("gateway"), "vlan_aware": bool(i.get("bridge_vlan_aware")),
                        "ports": " ".join(str(i[k]) for k in ("bridge_ports", "ovs_ports") if i.get(k)) or None}
                       for i in rows if i.get("type") in ("bridge", "OVSBridge")), key=lambda b: str(b["iface"]))[:12]
    nets = dict(zip(up, POOL.map(bridges, up)))
    gateway = next((b["gateway"] for n in up for b in nets.get(n) or [] if b.get("gateway")), None)
    stores = [{"storage": s["storage"], "type": s.get("type"), "target": storage_target(s)[:120], "content": str(s.get("content") or "")}
              for s in sorted(api.storage.get(), key=lambda s: s["storage"])
              if not s.get("disable") and (s.get("shared") or s.get("type") in ("rbd", "cephfs", "pbs"))][:12]
    ips = node_ips(api)
    return {"gateway": gateway, "storages": stores,
            "nodes": [{"node": n["node"], "status": n.get("status"), "ip": ips.get(n["node"]), "bridges": nets.get(n["node"]) or [],
                       "maxcpu": n.get("maxcpu")} for n in nodes],
            "guests": [{"vmid": g["vmid"], "name": g.get("name"), "type": g.get("type"), "node": g.get("node"), "status": g.get("status"),
                        **details.get(g["vmid"], {"nets": [], "stores": []})} for g in guests][:400]}


def node_rate(api, node: str):
    """Het netwerkverkeer van een node in bytes per seconde (in, uit), het gemiddelde van de laatste minuut uit de RRD."""
    rows = on_node(node, lambda: api.nodes(node).rrddata.get(timeframe="hour", cf="AVERAGE"), []) or []
    last = next((r for r in reversed(rows) if isinstance(r, dict) and isinstance(r.get("netin"), (int, float))), None)
    return {"in": round(last["netin"]), "out": round(last.get("netout") or 0), "time": last.get("time")} if last else None


@app.get("/api/topology")
def topology(_: str = Depends(auth)):
    def f(api):
        with topo_lock:
            if TOPO["data"] is None or time.monotonic() - TOPO["at"] > 60:
                TOPO["data"], TOPO["at"] = topo_structure(api), time.monotonic()
            data = TOPO["data"]
        up = [n["node"] for n in data["nodes"] if n["status"] == "online" and not node_trouble.skip(n["node"])]
        ceph = None
        if up and any(s["type"] in ("rbd", "cephfs") for s in data["storages"]):
            try:
                st = on_node(up[0], lambda: api.nodes(up[0]).ceph.status.get(), None)
            except ResourceException:
                st = None
            if st:
                pg = st.get("pgmap") or {}
                ceph = {"health": (st.get("health") or {}).get("status"), "read": pg.get("read_bytes_sec") or 0, "write": pg.get("write_bytes_sec") or 0,
                        "recovery": pg.get("recovering_bytes_per_sec") or 0}
        return {**data, "rates": dict(zip(up, POOL.map(lambda n: node_rate(api, n), up))), "ceph": ceph,
                "trouble": sorted(node_trouble.current()), "time": int(time.time())}
    return pve.run(f)


# ---------------------------------------------------------------- logboek van één node (knop op de nodekaart)
# Alles wat over precies die ene node te lezen is: zijn systeemlogboek (journal), zijn taken, de toestand van zijn
# diensten, wat het cluster over hem meldt en wat de tool zelf op hem deed. Alleen lezen.
NODE_JOURNAL = {"15m": 900, "1h": 3600, "6h": 21600, "24h": 86400}   # periode -> seconden; "last": de laatste regels
NODE_JOURNAL_MAX = 5000      # zoveel regels hooguit, de nieuwste
CURSOR_RE = re.compile(r"^s=[0-9a-f]+;i=[0-9a-f]+;")   # de journal begint en eindigt met een cursor: geen logregel


def node_known(api, node: str) -> dict:
    """De node zoals het cluster hem kent; 404 als hij er niet is, 409 als hij niet online is."""
    if not NODE_RE.match(node):
        raise HTTPException(400, "Ongeldige nodenaam")
    listed = next((n for n in api.nodes.get() if n.get("node") == node), None)
    if listed is None:
        raise HTTPException(404, "Onbekende node")
    if listed.get("status") != "online":
        raise HTTPException(409, "Deze node is niet online; zijn logboek is nu niet te lezen")
    return listed


def node_silent(node: str):
    """503 voor een node die via de API niet antwoordt (zie NodeTrouble), met wat je eraan doet."""
    raise HTTPException(503, "{0} antwoordt niet via de Proxmox-API; meestal staat in /etc/hosts op die node nog een oud adres".format(node))


@app.get("/api/node/{node}/journal")
def node_journal(node: str, period: str = "1h", _: str = Depends(auth)):
    """Het systeemlogboek van één node over de gekozen periode, de nieuwste regels onderaan; hooguit NODE_JOURNAL_MAX.
    Een dag is op een gewone node zo'n 15.000 regels; Proxmox geeft ze in een fractie van een seconde. Een periode en
    een aantal tegelijk kan Proxmox niet: "last" vraagt alleen de laatste regels, ongeacht hoe oud."""
    if period not in NODE_JOURNAL and period != "last":
        raise HTTPException(400, "Ongeldige periode")

    def f(api):
        node_known(api, node)
        since = None if period == "last" else int(time.time()) - NODE_JOURNAL[period]
        ask = {"lastentries": NODE_JOURNAL_MAX} if since is None else {"since": since}
        lines = on_node(node, lambda: api.nodes(node).journal.get(**ask))
        if lines is None:
            node_silent(node)
        lines = [str(x)[:2000] for x in lines if isinstance(x, str) and not CURSOR_RE.match(x)]
        return {"node": node, "period": period, "since": since, "total": len(lines),
                "truncated": len(lines) > NODE_JOURNAL_MAX, "lines": lines[-NODE_JOURNAL_MAX:]}
    return pve.run(f)


@app.get("/api/node/{node}/logbook")
def node_logbook(node: str, _: str = Depends(auth)):
    """De rest van het logboek van één node: zijn diensten, zijn laatste taken (alles en de mislukte apart), wat het
    cluster over hem meldt en wat de tool de afgelopen 30 dagen op hem deed."""
    def f(api):
        listed = node_known(api, node)
        found = on_node(node, lambda: (api.nodes(node).services.get(), api.nodes(node).tasks.get(limit=300, source="all"),
                                       api.nodes(node).tasks.get(limit=100, errors=1, source="all")))
        if found is None:
            node_silent(node)
        services, tasks, failed = found
        try:
            clog = [e for e in api.cluster.log.get(max=2000) if e.get("node") == node]
        except ResourceException:
            clog = []

        def task(x):
            status, done = x.get("status"), x.get("endtime") is not None
            return {"upid": x.get("upid"), "type": x.get("type"), "id": str(x.get("id") or ""), "user": x.get("user"),
                    "start": x.get("starttime"), "end": x.get("endtime"),
                    "level": "running" if not done else "info" if status == "OK" else "warning" if str(status).startswith("WARNINGS") else "error",
                    "status": None if status in (None, "OK") else str(status)[:300]}
        seen = {x.get("upid") for x in tasks}
        tasks = sorted([task(x) for x in tasks] + [task(x) for x in failed if x.get("upid") not in seen],
                       key=lambda x: x["start"] or 0, reverse=True)
        tool = [{"time": e.get("t"), "kind": str(e.get("kind") or ""), "target": str(e.get("target") or ""), "name": str(e.get("name") or "")[:120],
                 "result": str(e.get("result") or "")[:300], "user": str(e["user"])[:64] if isinstance(e.get("user"), str) else None}
                for e in state.events(time.time() - 30 * 86400) if e.get("node") == node]
        return {"node": node, "uptime": listed.get("uptime"), "ip": node_ips(api).get(node),
                "services": sorted(({k: s.get(k) for k in ("name", "desc", "state", "active-state", "unit-state")}
                                    for s in services if isinstance(s, dict)), key=lambda s: str(s.get("name"))),
                "tasks": tasks[:400],
                "cluster": [{"time": e.get("time"), "pri": e.get("pri") if isinstance(e.get("pri"), int) else 6, "tag": e.get("tag"),
                             "user": e.get("user"), "msg": str(e.get("msg") or "")[:500]} for e in clog][:500],
                "tool": sorted(tool, key=lambda e: e["time"] or 0, reverse=True)[:300]}
    return pve.run(f)


# ---------------------------------------------------------------- tabblad Netwerken
# Lezen: de interfaces en DNS van elke node, VLAN's uit SDN (zones en VNets), de netwerkkaarten van alle guests en het
# netwerk van het cluster zelf. Aanmaken gaat in twee stappen, net als in Proxmox: eerst klaarzetten, dan toepassen.
# Toepassen laadt de netwerkinstellingen opnieuw (van één node, of bij SDN van alle nodes) en is daarom altijd een
# eigen, bewuste stap waarbij de pagina eerst laat zien wat er klaarstaat.
SDN_ID_RE = re.compile(r"^[a-z][a-z0-9]{1,7}$")
DEVICE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_\-]{0,14}$")
ALIAS_RE = re.compile(r"^[A-Za-z0-9 _.()\-]{0,60}$")
VLAN_PARENTS = ("bridge", "bond", "eth")
IFACE_ORDER = {"bridge": 0, "OVSBridge": 0, "bond": 1, "OVSBond": 1, "vlan": 2, "eth": 3}


def node_pending(api, node: str):
    """De netwerkwijzigingen die op een node klaarstaan maar nog niet zijn toegepast, als verschiltekst; None = geen.

    Proxmox geeft die naast de lijst van interfaces mee; de gewone aanroep laat dat deel weg, vandaar deze."""
    reply = api._store["session"].request("GET", f"{api._store['base_url']}/nodes/{node}/network", timeout=10)
    if reply.status_code != 200:
        raise HTTPException(502, "De netwerkinstellingen van deze node zijn niet op te vragen")
    changes = reply.json().get("changes")
    return str(changes)[:20000] if changes else None


def iface_row(i: dict) -> dict:
    return {"iface": i.get("iface"), "type": i.get("type"), "active": bool(i.get("active")), "autostart": bool(i.get("autostart")),
            "cidr": i.get("cidr"), "cidr6": i.get("cidr6"), "gateway": i.get("gateway"), "gateway6": i.get("gateway6"),
            "ports": " ".join(str(i[k]) for k in ("bridge_ports", "slaves", "ovs_ports") if i.get(k)) or None,
            "vlan_aware": bool(i.get("bridge_vlan_aware")), "vlan_id": i.get("vlan-id"), "vlan_raw": i.get("vlan-raw-device"),
            "bond_mode": i.get("bond_mode"), "mtu": i.get("mtu"), "comment": str(i.get("comments") or "").strip()[:120] or None}


def node_net(api, node: str):
    """Interfaces, DNS en klaarstaande wijzigingen van één node; None als de node niet antwoordt."""
    try:
        ifaces = sorted((iface_row(i) for i in api.nodes(node).network.get()),
                        key=lambda i: (IFACE_ORDER.get(i["type"], 9), str(i["iface"])))
    except ResourceException:
        return None
    try:
        dns = api.nodes(node).dns.get() or {}
    except ResourceException:
        dns = {}
    try:
        pending = node_pending(api, node)
    except (HTTPException, ValueError):
        pending = None
    return {"ifaces": ifaces, "pending": pending,
            "dns": {"search": dns.get("search"), "servers": [dns[k] for k in ("dns1", "dns2", "dns3") if dns.get(k)]}}


def sdn_list(api, what: str):
    """Zones of VNets, met wat is klaargezet maar nog niet toegepast (state: new, changed of deleted); None = geen SDN."""
    try:
        rows = getattr(api.cluster.sdn, what).get(pending=1)
    except ResourceException:
        try:
            rows = getattr(api.cluster.sdn, what).get()
        except ResourceException:
            return None
    out = []
    for r in rows or []:
        merged = {**r, **(r.get("pending") if isinstance(r.get("pending"), dict) else {})}
        merged.pop("pending", None)
        merged["state"] = r.get("state")
        out.append(merged)
    return out


def sdn_overview(api, nodes: list):
    """De VLAN-zones en VNets van het cluster, en per node of een VNet daar werkt; None als er geen SDN is."""
    zones, vnets = sdn_list(api, "zones"), sdn_list(api, "vnets")
    if zones is None or vnets is None:
        return None

    def status(node):
        found = {}
        for z in zones:
            if z.get("state") == "new":
                continue
            try:
                for v in api.nodes(node).sdn.zones(z["zone"]).content.get():
                    found[v.get("vnet")] = v.get("status")
            except ResourceException:
                pass
        return found

    per_node = dict(zip(nodes, POOL.map(status, nodes))) if zones else {}

    def tag(value):
        return int(value) if str(value or "").isdigit() else None

    return {"zones": [{"zone": z.get("zone"), "type": z.get("type"), "bridge": z.get("bridge"), "state": z.get("state")} for z in zones],
            "vnets": [{"vnet": v.get("vnet"), "zone": v.get("zone"), "tag": tag(v.get("tag")), "alias": v.get("alias"), "state": v.get("state"),
                       "status": {n: per_node[n][v.get("vnet")] for n in per_node if v.get("vnet") in per_node[n]}} for v in vnets],
            "pending": any(x.get("state") for x in zones + vnets)}


def guest_nics(api, g: dict, live: bool = True) -> list:
    """De netwerkkaarten van één guest uit zijn instellingen. Met live=True komen daar, voor een draaiende guest die
    zijn adres niet vast heeft ingesteld, de adressen bij die hij op dit moment heeft."""
    kind, node, vmid = g.get("type"), g.get("node"), g.get("vmid")
    try:
        target = guest(api, node, kind, vmid)
        cfg = target.config.get()
    except ResourceException:
        return []
    nics = []
    for key in sorted((k for k in cfg if NET_RE.match(k)), key=lambda k: (len(k), k)):
        o = parse_options(cfg[key])
        model = next((m for m in NIC_MODELS if m in o), "")
        ip = o.get("ip") if kind == "lxc" else parse_options(cfg.get("ipconfig" + key[3:])).get("ip")
        nics.append({"vmid": vmid, "name": g.get("name"), "kind": kind, "node": node, "status": g.get("status"), "key": key,
                     "ifname": o.get("name") or key, "bridge": o.get("bridge"), "tag": int(o["tag"]) if str(o.get("tag") or "").isdigit() else None,
                     "ip": ip, "gw": o.get("gw"), "mac": (o.get("hwaddr") or o.get(model) or None), "firewall": o.get("firewall") == "1",
                     "live": []})
    fixed = lambda ip: bool(ip) and ip not in ("dhcp", "manual", "auto")  # noqa: E731
    if live and g.get("status") == "running" and any(not fixed(n["ip"]) for n in nics):
        try:
            if kind == "lxc":
                for i in target.interfaces.get():
                    for nic in nics:
                        if nic["ifname"] == i.get("name"):
                            nic["live"] += [a for a in (i.get("inet"), i.get("inet6")) if a and not a.lower().startswith("fe80")]
            elif parse_options(cfg.get("agent")).get("", cfg.get("agent")) not in (None, "", "0"):
                for i in (target.agent("network-get-interfaces").get() or {}).get("result") or []:
                    for nic in nics:
                        if nic["mac"] and str(i.get("hardware-address") or "").lower() == nic["mac"].lower():
                            nic["live"] += [a["ip-address"] for a in i.get("ip-addresses") or []
                                            if a.get("ip-address") and not a["ip-address"].lower().startswith("fe80")]
        except ResourceException:
            pass  # oudere Proxmox-versie, of de guest agent antwoordt niet
    for nic in nics:
        nic["live"] = nic["live"][:6]
    return nics[:16]


def cluster_net(api, node: str) -> dict:
    """Het netwerk van het cluster zelf: de adressen waarover de nodes elkaar bewaken (Corosync) en die van Ceph."""
    out = {"name": None, "links": [], "ceph": None}
    try:
        out["name"] = next((e.get("name") for e in api.cluster.status.get() if e.get("type") == "cluster"), None)
        out["links"] = sorted(({"node": n.get("name") or n.get("node"),
                                "addrs": [n[k] for k in sorted(n) if re.fullmatch(r"ring\d+_addr", k) and n[k]]}
                               for n in api.cluster.config.nodes.get()), key=lambda x: str(x["node"]))
    except ResourceException:
        pass  # één losse node zonder cluster
    try:
        cfg = (api.nodes(node).ceph.cfg.value.get(**{"config-keys": "global:public_network;global:cluster_network"}) or {}).get("global") or {}
        public, private = cfg.get("public-network") or cfg.get("public_network"), cfg.get("cluster-network") or cfg.get("cluster_network")
        if public or private:
            out["ceph"] = {"public": public, "cluster": private}
    except ResourceException:
        pass  # geen Ceph, of een oudere Proxmox-versie
    return out


@app.get("/api/network")
def network_info(_: str = Depends(auth)):
    def f(api):
        nodes = online_nodes(api)
        guests = sorted((g for g in api.cluster.resources.get(type="vm") if not g.get("template") and g.get("node") in nodes),
                        key=lambda g: g["vmid"])
        return {"nodes": dict(zip(nodes, POOL.map(lambda n: node_net(api, n), nodes))), "sdn": sdn_overview(api, nodes),
                "guests": [nic for nics in POOL.map(lambda g: guest_nics(api, g), guests) for nic in nics],
                "cluster": cluster_net(api, nodes[0]) if nodes else None}
    return pve.run(f)


def all_online(api) -> list:
    """De nodes van het cluster; weigert als er een uit staat, want dan komt een netwerkwijziging niet overal aan."""
    nodes = api.nodes.get()
    if not nodes or any(n.get("status") != "online" for n in nodes):
        raise HTTPException(409, "Niet alle nodes zijn online; een netwerkwijziging kan nu niet overal worden doorgevoerd")
    return sorted(n["node"] for n in nodes)


class VnetIn(BaseModel):
    name: str = Field(max_length=16)
    tag: int
    bridge: str = Field(max_length=15)
    alias: str | None = Field(None, max_length=60)


def vnet_plan(net: dict, body: VnetIn) -> dict:
    """Kijkt een nieuw VLAN voor guests (een VNet) na tegen wat het cluster nu heeft, en geeft terug wat er moet
    worden aangemaakt. Verandert zelf niets. net = {"nodes": {node: node_net()}, "sdn": sdn_overview()}."""
    name, alias = body.name.strip().lower(), (body.alias or "").strip()
    if not SDN_ID_RE.match(name):
        raise HTTPException(400, "Ongeldige naam: 2-8 tekens, kleine letters en cijfers, beginnend met een letter")
    if not 1 <= body.tag <= 4094:
        raise HTTPException(400, "Het VLAN-nummer moet tussen 1 en 4094 liggen")
    if not ALIAS_RE.match(alias):
        raise HTTPException(400, "Ongeldige omschrijving: hooguit 60 tekens, alleen letters, cijfers, spaties en . _ - ( )")
    sdn, nodes = net.get("sdn"), net.get("nodes") or {}
    if sdn is None:
        raise HTTPException(409, "Dit cluster heeft geen SDN (nodig: Proxmox VE 8.1 of nieuwer); maak het VLAN in Proxmox zelf")
    if not nodes or any(n is None for n in nodes.values()):
        raise HTTPException(409, "Niet elke node gaf zijn netwerkinstellingen; probeer het opnieuw")
    if not DEVICE_RE.match(body.bridge) or any(
            not any(i["iface"] == body.bridge and i["type"] in ("bridge", "OVSBridge") for i in n["ifaces"]) for n in nodes.values()):
        raise HTTPException(400, "Deze bridge bestaat niet op elke node")
    if any(v["vnet"] == name for v in sdn["vnets"]) or any(z["zone"] == name for z in sdn["zones"]) \
            or any(i["iface"] == name for n in nodes.values() for i in n["ifaces"]):
        raise HTTPException(409, "Deze naam is al in gebruik voor een VLAN of een interface")
    zone = next((z for z in sdn["zones"] if z["type"] == "vlan" and z["bridge"] == body.bridge and z["state"] != "deleted"), None)
    if zone:
        twin = next((v for v in sdn["vnets"] if v["zone"] == zone["zone"] and v["tag"] == body.tag and v["state"] != "deleted"), None)
        if twin:
            raise HTTPException(409, f"VLAN {body.tag} bestaat al op deze bridge, onder de naam {twin['vnet']}")
        return {"name": name, "tag": body.tag, "alias": alias, "zone": zone["zone"], "new_zone": None}
    taken = {z["zone"] for z in sdn["zones"]} | {v["vnet"] for v in sdn["vnets"]} | {i["iface"] for n in nodes.values() for i in n["ifaces"]}
    fresh = next((z for z in ["vlans"] + [f"vlans{i}" for i in range(2, 10)] if z not in taken), None)
    if not fresh:
        raise HTTPException(409, "Er zijn te veel VLAN-zones; ruim er eerst een op in Proxmox")
    return {"name": name, "tag": body.tag, "alias": alias, "zone": fresh,
            "new_zone": {"zone": fresh, "type": "vlan", "bridge": body.bridge}}


@app.post("/api/network/vnet")
def network_vnet_create(body: VnetIn, request: Request, _: str = Depends(manage_network)):
    """Zet een VLAN voor guests klaar: een VNet in een VLAN-zone van SDN, waardoor het op alle nodes bestaat. Is er
    voor de gekozen bridge nog geen zone, dan komt die erbij. Actief wordt het pas na toepassen."""
    same_origin(request)

    def f(api):
        nodes = all_online(api)
        plan = vnet_plan({"nodes": dict(zip(nodes, POOL.map(lambda n: node_net(api, n), nodes))), "sdn": sdn_overview(api, [])}, body)
        if plan["new_zone"]:
            api.cluster.sdn.zones.post(**plan["new_zone"])
        params = {"vnet": plan["name"], "zone": plan["zone"], "tag": plan["tag"]}
        if plan["alias"]:
            params["alias"] = plan["alias"]
        api.cluster.sdn.vnets.post(**params)
        return {"ok": True, "vnet": plan["name"], "zone": plan["zone"], "tag": plan["tag"], "zone_created": bool(plan["new_zone"])}
    return pve.run(f)


@app.delete("/api/network/vnet/{name}")
def network_vnet_delete(name: str, request: Request, _: str = Depends(manage_network)):
    """Zet het verwijderen van een VLAN voor guests klaar; alleen als geen enkele guest het nog gebruikt."""
    same_origin(request)
    if not SDN_ID_RE.match(name):
        raise HTTPException(400, "Ongeldige naam: 2-8 tekens, kleine letters en cijfers, beginnend met een letter")

    def f(api):
        all_online(api)
        vnets = sdn_list(api, "vnets")
        if not vnets or not any(v.get("vnet") == name for v in vnets):
            raise HTTPException(404, "Dit VLAN bestaat niet")
        guests = sorted(api.cluster.resources.get(type="vm"), key=lambda g: g["vmid"])
        users = sorted({nic["vmid"] for nics in POOL.map(lambda g: guest_nics(api, g, live=False), guests) for nic in nics if nic["bridge"] == name})
        if users:
            raise HTTPException(409, f"Dit VLAN is nog in gebruik door: {', '.join(str(u) for u in users[:20])}. Koppel die eerst aan een ander netwerk")
        api.cluster.sdn.vnets(name).delete()
        return {"ok": True}
    return pve.run(f)


@app.post("/api/network/sdn/apply")
def network_sdn_apply(request: Request, _: str = Depends(manage_network)):
    """Maakt alles wat bij de VLAN's voor guests klaarstaat actief. Proxmox herlaadt daarvoor de netwerkinstellingen
    op alle nodes; het antwoord is de taak die dat doet."""
    same_origin(request)

    def f(api):
        all_online(api)
        sdn = sdn_overview(api, [])
        if sdn is None or not sdn["pending"]:
            raise HTTPException(409, "Er staat niets klaar om toe te passen")
        upid = str(api.cluster.sdn.put())
        return {"upid": upid, "node": upid.split(":")[1] if upid.startswith("UPID:") else None}
    return pve.run(f)


class VlanIn(BaseModel):
    node: str = Field(max_length=63)
    device: str = Field(max_length=15)
    tag: int
    cidr: str | None = Field(None, max_length=18)
    comment: str | None = Field(None, max_length=60)


def vlan_plan(net: dict | None, body: VlanIn) -> dict:
    """Kijkt een nieuwe VLAN-interface voor één node na tegen wat die node nu heeft (net = node_net()), en geeft de
    opdracht voor Proxmox terug. Verandert zelf niets. Bewust zonder gateway: de node houdt zijn bestaande route."""
    if net is None:
        raise HTTPException(409, "Deze node gaf zijn netwerkinstellingen niet; probeer het opnieuw")
    if net["pending"]:
        raise HTTPException(409, "Op deze node staan al netwerkwijzigingen klaar; pas die eerst toe of draai ze terug")
    if not 1 <= body.tag <= 4094:
        raise HTTPException(400, "Het VLAN-nummer moet tussen 1 en 4094 liggen")
    ifaces = net["ifaces"]
    parent = next((i for i in ifaces if i["iface"] == body.device), None)
    if not DEVICE_RE.match(body.device) or not parent or parent["type"] not in VLAN_PARENTS:
        raise HTTPException(400, "Kies een bridge, bond of netwerkkaart die op deze node bestaat")
    name = f"{body.device}.{body.tag}"
    if len(name) > 15:
        raise HTTPException(400, "De naam van de interface wordt te lang (hooguit 15 tekens)")
    if any(i["iface"] == name or (i["type"] == "vlan" and i["vlan_raw"] == body.device and str(i["vlan_id"]) == str(body.tag)) for i in ifaces):
        raise HTTPException(409, "Dit VLAN bestaat al op deze node")
    comment = (body.comment or "").strip()
    if not ALIAS_RE.match(comment):
        raise HTTPException(400, "Ongeldige omschrijving: hooguit 60 tekens, alleen letters, cijfers, spaties en . _ - ( )")
    params = {"iface": name, "type": "vlan", "autostart": 1}
    cidr = (body.cidr or "").strip()
    if cidr:
        try:
            ip = ipaddress.ip_interface(cidr)
        except ValueError:
            ip = None
        if (ip is None or "/" not in cidr or ip.version != 4 or not 8 <= ip.network.prefixlen <= 30
                or ip.ip in (ip.network.network_address, ip.network.broadcast_address)
                or ip.ip.is_loopback or ip.ip.is_multicast or ip.ip.is_link_local or ip.ip.is_unspecified):
            raise HTTPException(400, "Ongeldig adres; gebruik de vorm 192.168.20.5/24")
        for i in ifaces:
            try:
                other = ipaddress.ip_interface(i["cidr"]) if i.get("cidr") else None
            except ValueError:
                other = None
            if other is not None and other.version == 4 and other.network.overlaps(ip.network):
                raise HTTPException(409, f"Dit adres valt in een netwerk dat deze node al heeft ({i['iface']}); kies een adres uit het netwerk van het VLAN")
        params["cidr"] = ip.with_prefixlen
    if comment:
        params["comments"] = comment
    return params


@app.post("/api/network/vlan")
def network_vlan_create(body: VlanIn, request: Request, _: str = Depends(manage_network)):
    """Zet op één node een VLAN-interface klaar (bijvoorbeeld vmbr0.20), waarmee de node zelf in dat VLAN komt.
    Actief wordt hij pas na toepassen op die node."""
    same_origin(request)
    if not NODE_RE.match(body.node):
        raise HTTPException(400, "Ongeldige nodenaam")

    def f(api):
        if body.node not in online_nodes(api):
            raise HTTPException(409, "Deze node is niet online")
        params = vlan_plan(node_net(api, body.node), body)
        api.nodes(body.node).network.post(**params)
        return {"ok": True, "node": body.node, "iface": params["iface"]}
    return pve.run(f)


@app.post("/api/network/node/{node}/apply")
def network_node_apply(node: str, request: Request, _: str = Depends(manage_network)):
    """Past de klaarstaande netwerkwijzigingen van één node toe; Proxmox herlaadt daarvoor zijn netwerkinstellingen."""
    same_origin(request)
    if not NODE_RE.match(node):
        raise HTTPException(400, "Ongeldige nodenaam")

    def f(api):
        if node not in online_nodes(api):
            raise HTTPException(409, "Deze node is niet online")
        if not node_pending(api, node):
            raise HTTPException(409, "Er staat niets klaar om toe te passen")
        return {"upid": api.nodes(node).network.put(), "node": node}
    return pve.run(f)


@app.delete("/api/network/node/{node}/pending")
def network_node_revert(node: str, request: Request, _: str = Depends(manage_network)):
    """Gooit de klaarstaande, nog niet toegepaste netwerkwijzigingen van één node weg. Aan het netwerk verandert niets."""
    same_origin(request)
    if not NODE_RE.match(node):
        raise HTTPException(400, "Ongeldige nodenaam")

    def f(api):
        if node not in online_nodes(api):
            raise HTTPException(409, "Deze node is niet online")
        if not node_pending(api, node):
            raise HTTPException(409, "Er staat niets klaar om toe te passen")
        api.nodes(node).network.delete()
        return {"ok": True}
    return pve.run(f)


# ---------------------------------------------------------------- aandachtspunten: triggers en drempels
# Wat er op dit moment aandacht vraagt. Elke trigger hoort bij één tabblad (de knop van dat tabblad kleurt oranje of
# rood) en is in te stellen: een aan/uit-trigger krijgt een niveau, een drempeltrigger een waarde voor oranje en een
# voor rood. De standaard staat hieronder; wat de beheerder anders wil staat in state.json onder "alerts".
LEVELS = ("off", "info", "warning", "error")
ALERT_LIMITS = {"percent": (1, 100), "days": (1, 365)}
ALERTS = {   # code: (tabblad, soort, standaard)
    "node_offline": ("overview", "level", "error"),
    "node_unreachable": ("overview", "level", "error"),
    "no_quorum": ("overview", "level", "error"),
    "ha": ("overview", "level", "error"),
    "no_agent": ("overview", "level", "warning"),
    "reboot": ("overview", "level", "info"),
    "node_mem": ("overview", "percent", (90, 97)),
    "node_root": ("overview", "percent", (85, 95)),
    "guest_disk": ("overview", "percent", (90, 97)),
    "storage_unavailable": ("storage", "level", "warning"),
    "storage_full": ("storage", "percent", (90, 97)),
    "ceph_warn": ("storage", "level", "warning"),
    "ceph_err": ("storage", "level", "error"),
    "disk": ("storage", "level", "error"),
    "disk_wear": ("storage", "percent", (90, 97)),
    "net_pending": ("network", "level", "warning"),
    "ip_double": ("network", "level", "warning"),
    "vnet_error": ("network", "level", "error"),
    "backup_failed": ("backups", "level", "error"),
    "backup_warning": ("backups", "level", "warning"),
    "backup_old": ("backups", "days", (None, None)),
    "autoupdate_failed": ("overview", "level", "warning"),
    "balance_failed": ("ha", "level", "warning"),
    "ha_disarmed": ("ha", "level", "warning"),
}
BAD_HA = ("error", "fence", "recovery")
BACKUP_WINDOW = 14 * 86400   # zo ver terug telt de afloop van de laatste back-up nog mee


def alert_value(code: str, value):
    """Een geldige instelling voor deze trigger, of None als value niet klopt."""
    kind = ALERTS[code][1]
    if kind == "level":
        return value if value in LEVELS else None
    low, high = ALERT_LIMITS[kind]
    if not isinstance(value, dict) or set(value) - {"warning", "error"}:
        return None
    pair = [value.get("warning"), value.get("error")]
    if any(n is not None and (not isinstance(n, int) or isinstance(n, bool) or not low <= n <= high) for n in pair):
        return None
    return {"warning": pair[0], "error": pair[1]}


def alert_settings() -> dict:
    """code -> niveau, of {"warning": n, "error": n} voor een drempel: de standaard met de eigen instellingen eroverheen."""
    saved = state.load().get("alerts")
    saved = saved if isinstance(saved, dict) else {}
    out = {}
    for code, (_tab, kind, default) in ALERTS.items():
        value = alert_value(code, saved[code]) if code in saved else None
        out[code] = value if value is not None else (default if kind == "level" else {"warning": default[0], "error": default[1]})
    return out


def gather_issues(api) -> list:
    """Loopt alle triggers na. Elke regel is een code met gegevens; de pagina maakt er een zin van in haar taal.
    Waar een trigger uit staat wordt er ook niets voor opgehaald."""
    cfg, out = alert_settings(), []

    def add(code, value=None, **fields):
        setting = cfg[code]
        if isinstance(setting, dict):
            level = ("error" if setting["error"] is not None and value >= setting["error"]
                     else "warning" if setting["warning"] is not None and value >= setting["warning"] else "off")
            fields["value"] = value
        else:
            level = setting
        if level != "off":
            out.append({"level": level, "code": code, "tab": ALERTS[code][0], **fields})

    def on(*codes) -> bool:
        return any(any(v is not None for v in cfg[c].values()) if isinstance(cfg[c], dict) else cfg[c] != "off" for c in codes)

    listed = sorted(api.nodes.get(), key=lambda n: n["node"])
    nodes = [n["node"] for n in listed if n.get("status") == "online"]
    for n in listed:
        if n.get("status") != "online":
            add("node_offline", node=n["node"])
            continue
        if n.get("maxmem"):
            add("node_mem", round((n.get("mem") or 0) / n["maxmem"] * 100), node=n["node"])
        if n.get("maxdisk"):
            add("node_root", round((n.get("disk") or 0) / n["maxdisk"] * 100), node=n["node"])
    # Online, maar via de API geen antwoord (zie NodeTrouble): melden met het adres waaronder het cluster hem kent, en
    # hieronder overslaan; anders loopt elke vraag aan die node hier vast en blijven alle aandachtspunten oud.
    answers = dict(zip(nodes, POOL.map(lambda n: node_answers(api, n), nodes)))
    stuck = [n for n in nodes if not answers[n]]
    if stuck:
        try:
            ips = node_ips(api)
        except ResourceException:
            ips = {}
        for n in stuck:
            add("node_unreachable", node=n, ip=ips.get(n))
        nodes = [n for n in nodes if answers[n]]
    try:
        if any(e.get("type") == "cluster" and not e.get("quorate") for e in api.cluster.status.get()):
            add("no_quorum")
    except ResourceException:
        pass
    try:
        for e in api.cluster.ha.status.current.get():
            if e.get("type") == "service" and e.get("state") in BAD_HA:
                add("ha", sid=e.get("sid"), state=e.get("state"), node=e.get("node"))
    except ResourceException:
        pass
    if on("ha_disarmed"):   # HA voor onderhoud uitgeschakeld en niet weer aangezet: dan beschermt HA niets
        try:
            fencing = next((e for e in api.cluster.ha.status.current.get() if e.get("type") == "fencing"), {})
            if str(fencing.get("armed-state") or "") in ("disarming", "disarmed"):
                add("ha_disarmed", state=str(fencing.get("armed-state")))
        except ResourceException:
            pass
    for node, u in sorted((updates.info.get("nodes") or {}).items()):
        if u and node in nodes:
            if u.get("agent") == 0:
                add("no_agent", node=node)
            if u.get("reboot"):
                add("reboot", node=node, text=str(u["reboot"]))
    guests = sorted(api.cluster.resources.get(type="vm"), key=lambda g: g.get("vmid", 0))
    names = {g.get("vmid"): g.get("name") for g in guests}
    for g in guests:
        if g.get("status") == "running" and g.get("maxdisk") and g.get("disk") and not g.get("template"):
            add("guest_disk", round(g["disk"] / g["maxdisk"] * 100), vmid=g.get("vmid"), name=g.get("name"))

    # --- opslag
    seen = set()
    for s in sorted(api.cluster.resources.get(type="storage"), key=lambda s: (s.get("storage", ""), s.get("node", ""))):
        if s.get("node") not in nodes:
            continue
        name, where = s.get("storage"), None if s.get("shared") else s.get("node")
        if s.get("status") != "available":
            add("storage_unavailable", storage=name, node=s.get("node"))
        elif s.get("maxdisk") and (name, where) not in seen:
            seen.add((name, where))
            add("storage_full", round((s.get("disk") or 0) / s["maxdisk"] * 100), storage=name, node=where)
    if nodes and on("ceph_warn", "ceph_err"):
        try:
            health = api.nodes(nodes[0]).ceph.status.get().get("health") or {}
            status = health.get("status")
            if status not in (None, "HEALTH_OK"):
                checks = sorted((health.get("checks") or {}).items())
                for code, c in checks[:20]:
                    add("ceph_err" if c.get("severity") == "HEALTH_ERR" else "ceph_warn",
                        text=f"{code}: {str((c.get('summary') or {}).get('message') or '')[:300]}")
                if not checks:
                    add("ceph_err" if status == "HEALTH_ERR" else "ceph_warn", text=str(status))
        except ResourceException:
            pass  # geen Ceph
    if on("disk", "disk_wear"):
        for node, disks in zip(nodes, POOL.map(lambda n: node_disks(api, n), nodes)):
            for d in disks or []:
                if d.get("health") and str(d["health"]).upper() not in ("PASSED", "OK", "UNKNOWN"):
                    add("disk", node=node, dev=d.get("dev"), text=str(d["health"])[:40])
                if isinstance(d.get("wearout"), int) and not isinstance(d.get("wearout"), bool):
                    add("disk_wear", 100 - d["wearout"], node=node, dev=d.get("dev"))

    # --- netwerk
    if on("net_pending", "ip_double", "vnet_error"):
        try:
            nets = dict(zip(nodes, POOL.map(lambda n: node_net(api, n), nodes)))
            for node, net in nets.items():
                if net and net["pending"]:
                    add("net_pending", node=node)
            sdn = sdn_overview(api, nodes)
            if sdn:
                if sdn["pending"]:
                    add("net_pending", node=None)
                for v in sdn["vnets"]:
                    for node, status in sorted(v["status"].items()):
                        if status and status != "available":
                            add("vnet_error", vnet=v["vnet"], node=node)
            if on("ip_double"):
                users = {}
                reachable = [g for g in guests if not g.get("template") and g.get("node") in nodes]
                for nics in POOL.map(lambda g: guest_nics(api, g, live=False), reachable):
                    for nic in nics:
                        ip = str(nic.get("ip") or "").split("/")[0]
                        if ip[:1].isdigit():
                            users.setdefault(ip, set()).add(f"{nic['vmid']} {nic.get('name') or ''}".strip())
                for node, net in nets.items():
                    for i in (net or {}).get("ifaces", []):
                        ip = str(i.get("cidr") or "").split("/")[0]
                        if ip in users:
                            users[ip].add(node)
                for ip, who in sorted(users.items()):
                    if len(who) > 1:
                        add("ip_double", ip=ip, who=sorted(who))
        except ResourceException:
            pass

    # --- back-ups: de afloop van de laatste back-up per guest (of per schema met meer guests)
    if on("backup_failed", "backup_warning"):
        since = int(time.time()) - BACKUP_WINDOW

        def dumps(node):
            try:
                return api.nodes(node).tasks.get(typefilter="vzdump", since=since, limit=500, source="archive")
            except ResourceException:
                return []

        latest = {}
        for node, tasks in zip(nodes, POOL.map(dumps, nodes)):
            for task in tasks or []:
                key = str(task.get("id") or "")
                if key not in latest or (task.get("starttime") or 0) > (latest[key].get("starttime") or 0):
                    latest[key] = dict(task, node=task.get("node") or node)
        for key, task in sorted(latest.items()):
            status = str(task.get("status") or "")
            if task.get("endtime") is None or status == "OK":
                continue
            add("backup_warning" if status.startswith("WARNINGS") else "backup_failed", id=key, name=names.get(int(key)) if key.isdigit() else None,
                node=task["node"], text=status[:200], time=task.get("starttime"), upid=task.get("upid"))
    if on("backup_old"):
        try:
            newest = {}
            for s in backup_storages(api) if nodes else []:
                for f in api.nodes(nodes[0]).storage(s["storage"]).content.get(content="backup"):
                    if str(f.get("vmid") or "").isdigit():
                        newest[int(f["vmid"])] = max(newest.get(int(f["vmid"]), 0), f.get("ctime") or 0)
            everyone = {g["vmid"] for g in guests if not g.get("template")}
            covered = set()
            ids = lambda text: {int(v) for v in str(text or "").split(",") if v.strip().isdigit()}  # noqa: E731
            for job in api.cluster.backup.get():
                if job.get("enabled") == 0:
                    continue
                covered |= (everyone - ids(job.get("exclude"))) if job.get("all") else (ids(job.get("vmid")) & everyone)
            for vmid in sorted(covered):
                days = int((time.time() - newest[vmid]) // 86400) if vmid in newest else 9999
                add("backup_old", days, vmid=vmid, name=names.get(vmid), never=vmid not in newest)
        except ResourceException:
            pass

    # --- automatisch bijwerken: mislukt in de laatste ronde (van de afgelopen week)
    if on("autoupdate_failed"):   # per schema de laatste ronde; wat daarna wel lukte telt niet meer
        saved = state.load()
        lasts = [x for x in auto_state(saved)[2].values() if isinstance(x, dict)] or [saved.get("autoupdate_last") or {}]
        recent = [x for x in lasts if time.time() - (x.get("finished") or 0) < 7 * 86400]
        bad = sorted({r.get("target") for x in recent for r in x.get("results") or [] if isinstance(r, dict) and r.get("ok") is False}, key=str)
        if bad:
            add("autoupdate_failed", count=len(bad), who=bad[:6], when=max(x.get("finished") or 0 for x in recent))

    # --- loadbalancer: het meedoen van containers (tijdvenster) kon niet worden aangepast
    if on("balance_failed"):
        err = state.load().get("balance_error")
        if isinstance(err, dict) and time.time() - (err.get("t") or 0) < 86400:
            add("balance_failed", who=[str(s) for s in err.get("who") or []][:12], detail=str(err.get("text") or "")[:300], when=err.get("t"))
    return out


class Issues:
    """De aandachtspunten van dit moment. Nalopen kost tientallen aanroepen, dus dat gebeurt hooguit eens per minuut,
    op de achtergrond; de pagina's lezen het laatste resultaat (het overzicht geeft het mee voor de tabbladen)."""

    def __init__(self):
        self.items, self.at, self.busy, self.lock = [], 0.0, False, threading.Lock()

    def refresh(self):
        try:
            self.items = pve.run(gather_issues)
            self.at = time.time()
        except Exception:  # noqa: BLE001 - het laatste resultaat blijft staan; over een minuut opnieuw
            self.at = self.at or 1.0
        finally:
            self.busy = False

    def get(self, max_age: float = 60, wait: bool = False) -> list:
        if time.time() - self.at > max_age:
            with self.lock:
                start, self.busy = not self.busy, True
            if start and wait:
                self.refresh()
            elif start:
                threading.Thread(target=self.refresh, daemon=True).start()
            elif wait and not self.at:   # vlak na het starten loopt de eerste ronde al: wacht daar even op (hooguit 15 s)
                for _ in range(150):
                    if not self.busy:
                        break
                    time.sleep(0.1)
        return self.items


issues = Issues()


def alerts_view() -> dict:
    cfg = alert_settings()
    return {"levels": list(LEVELS), "limits": ALERT_LIMITS,
            "alerts": [{"code": code, "tab": tab, "kind": kind, "value": cfg[code],
                        "default": default if kind == "level" else {"warning": default[0], "error": default[1]}}
                       for code, (tab, kind, default) in ALERTS.items()]}


@app.get("/api/alerts")
def alerts_get(_: str = Depends(auth)):
    return alerts_view()


class AlertsIn(BaseModel):
    alerts: dict


@app.put("/api/alerts")
def alerts_put(body: AlertsIn, request: Request, _: str = Depends(manage_events)):
    """Bewaart instellingen van triggers: een niveau ("off", "info", "warning", "error") of, bij een drempel,
    {"warning": getal of null, "error": getal of null}. Wat niet wordt meegestuurd blijft zoals het is."""
    same_origin(request)
    clean = {}
    for code, value in body.alerts.items():
        if code not in ALERTS:
            raise HTTPException(400, f"Onbekende trigger: {str(code)[:40]}")
        checked = alert_value(code, value)
        if checked is None:
            raise HTTPException(400, f"Ongeldige instelling voor {code}")
        if isinstance(checked, dict) and None not in checked.values() and checked["warning"] >= checked["error"]:
            raise HTTPException(400, f"Bij {code} moet de waarde voor oranje lager zijn dan die voor rood")
        clean[code] = checked
    try:
        state.change(lambda d: d.update(alerts={**(d.get("alerts") if isinstance(d.get("alerts"), dict) else {}), **clean}))
    except OSError:
        raise HTTPException(500, "De instelling kon niet bewaard worden")
    issues.at = 0.0   # meteen opnieuw nalopen met de nieuwe instellingen
    return alerts_view()


@app.delete("/api/alerts")
def alerts_reset(request: Request, _: str = Depends(manage_events)):
    """Zet alle triggers en drempels terug naar de standaard."""
    same_origin(request)
    try:
        state.change(lambda d: d.pop("alerts", None))
    except OSError:
        raise HTTPException(500, "De instelling kon niet bewaard worden")
    issues.at = 0.0
    return alerts_view()


# ---------------------------------------------------------------- tabblad Events
# Twee dingen: wat er nu aan de hand is (aandachtspunten, zie hierboven) en wat er gebeurd is. Het laatste komt uit
# de takenlijst van elke node, het logboek van het cluster en het eigen logboekje van de tool (updates en herstarts
# via de tool zijn geen Proxmox-taken). Alles is alleen lezen.
EVENT_DAYS = (1, 7, 30)
EVENT_MAX_RANGE = 400 * 86400
TASK_ECHO_RE = re.compile(r"^(starting|end) task UPID:")   # staat al als taak in de lijst


def event_rows(api, nodes: list, since: int, until: int | None = None) -> list:
    rows, last = [], until if until is not None else float("inf")
    period = {"since": since} if until is None else {"since": since, "until": until}

    def tasks(node):
        try:
            return on_node(node, lambda: api.nodes(node).tasks.get(limit=1000, source="all", **period))
        except ResourceException:
            return None

    for node, found in zip(nodes, POOL.map(tasks, nodes)):
        for task in found or []:
            if task.get("type") in NOISE:
                continue
            status, done = task.get("status"), task.get("endtime") is not None
            level = "running" if not done else "info" if status == "OK" else "warning" if str(status).startswith("WARNINGS") else "error"
            rows.append({"time": task.get("starttime"), "end": task.get("endtime"), "node": task.get("node") or node, "source": "task",
                         "level": level, "type": task.get("type"), "id": str(task.get("id") or ""), "user": task.get("user"),
                         "text": None if status in (None, "OK") else str(status)[:300], "upid": task.get("upid")})
    try:
        for e in api.cluster.log.get(max=2000):
            msg = str(e.get("msg") or "")
            if TASK_ECHO_RE.match(msg):
                continue
            pri = e.get("pri") if isinstance(e.get("pri"), int) else 6
            rows.append({"time": e.get("time"), "end": None, "node": e.get("node"), "source": "log",
                         "level": "error" if pri <= 3 else "warning" if pri == 4 else "info", "type": e.get("tag"), "id": "",
                         "user": e.get("user"), "text": msg[:300], "upid": None})
    except ResourceException:
        pass
    for e in state.events(since):
        result = str(e.get("result") or "")
        rows.append({"time": e.get("t"), "end": None, "node": e.get("node"), "source": "tool",
                     "level": "error" if result.startswith("mislukt") else "warning" if "onbekend" in result else "info",
                     "type": str(e.get("kind") or ""), "id": str(e.get("target") or ""),
                     "user": str(e["user"])[:64] if isinstance(e.get("user"), str) else None, "text": result[:300], "upid": None,
                     "name": str(e.get("name") or "")[:120]})
    return sorted((r for r in rows if isinstance(r.get("time"), (int, float)) and since <= r["time"] <= last),
                  key=lambda r: r["time"], reverse=True)


@app.get("/api/events")
def events_info(days: int = 7, since: int | None = None, until: int | None = None, _: str = Depends(auth)):
    """De gebeurtenissen van de laatste 1, 7 of 30 dagen, of van een eigen periode (since en until in seconden)."""
    now = int(time.time())
    if since is not None:
        until = now if until is None else until
        if not 0 < since < until <= now + 2 * 86400 or until - since > EVENT_MAX_RANGE:
            raise HTTPException(400, "Ongeldige periode")
        days = None
    else:
        days = days if days in EVENT_DAYS else 7
        since, until = now - days * 86400, None

    def f(api):
        nodes = online_nodes(api)
        rows = event_rows(api, nodes, since, until)
        return {"events": rows[:1500], "truncated": len(rows) > 1500, "days": days, "since": since, "until": until}
    data = pve.run(f)
    data["now"] = issues.get(max_age=15, wait=True)
    return data


# ---------------------------------------------------------------- een guest bewerken (de steeksleutel in het overzicht)
# Naam, cores, geheugen, swap (alleen containers), starten bij opstarten, bescherming en de notitie. Bij een draaiende
# container gaan cores en geheugen direct in; bij een draaiende VM wacht wat niet direct kan tot de volgende herstart.
# --- IP-adressen van een guest (steeksleutel). Bij een container staan ze in de regel van de netwerkkaart (ip, gw, ip6,
# gw6); bij een VM alleen via cloud-init (ipconfigN), anders stel je ze in de VM zelf in. Alleen die vier delen van een
# regel veranderen, op hun eigen plek; al het andere (naam, bridge, VLAN, MAC-adres, firewall) blijft letterlijk staan.
CLOUDINIT_DISK_RE = re.compile(r"^(ide|sata|scsi|virtio)\d{1,2}$")
IP_PARTS = ("ip", "gw", "ip6", "gw6")
SEARCH_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def has_cloudinit(cfg: dict) -> bool:
    return any(CLOUDINIT_DISK_RE.match(k) and "cloudinit" in str(v) for k, v in cfg.items())


def guest_ip_settings(kind: str, cfg: dict) -> dict:
    """De netwerkkaarten met hun IP-instellingen, en de DNS-instellingen, zoals ze nu in de configuratie staan."""
    nets = []
    for key in sorted((k for k in cfg if NET_RE.match(k)), key=lambda k: (len(k), k)):
        o = parse_options(cfg[key])
        src = o if kind == "lxc" else parse_options(cfg.get("ipconfig" + key[3:]) or "")
        nets.append({"key": key, "name": o.get("name") or key, "bridge": o.get("bridge") or "",
                     "tag": int(o["tag"]) if str(o.get("tag") or "").isdigit() else None, **{p: src.get(p) or "" for p in IP_PARTS}})
    return {"nets": nets[:32], "cloudinit": kind == "qemu" and has_cloudinit(cfg),
            "nameserver": str(cfg.get("nameserver") or ""), "searchdomain": str(cfg.get("searchdomain") or "")}


class NicIp(BaseModel):
    ip: str = Field("", max_length=64)    # "", "dhcp", "manual" (alleen CT) of adres/voorvoegsel, bv. 192.168.1.50/24
    gw: str = Field("", max_length=64)
    ip6: str = Field("", max_length=64)   # "", "auto", "dhcp", "manual" (alleen CT) of adres/voorvoegsel
    gw6: str = Field("", max_length=64)


def ip_plan(kind: str, key: str, want: NicIp) -> dict:
    """Nagekeken IP-instellingen voor één netwerkkaart: {ip, gw, ip6, gw6}, leeg = niet ingesteld."""
    modes4 = ("dhcp", "manual") if kind == "lxc" else ("dhcp",)
    modes6 = ("auto", "dhcp", "manual") if kind == "lxc" else ("auto", "dhcp")
    ip, gw, ip6, gw6 = (str(x or "").strip() for x in (want.ip, want.gw, want.ip6, want.gw6))
    iface = None
    if ip and ip not in modes4:
        try:
            iface = ipaddress.IPv4Interface(ip)
        except ValueError:
            iface = None
        if iface is None or "/" not in ip:
            raise HTTPException(400, f"Ongeldig IPv4-adres bij {key}: gebruik adres/voorvoegsel, bijvoorbeeld 192.168.1.50/24")
        a, net = iface.ip, iface.network
        if a.is_loopback or a.is_multicast or a.is_unspecified or a.is_link_local or a.is_reserved:
            raise HTTPException(400, f"{key}: het adres {a} kan niet voor een guest")
        if net.prefixlen <= 30 and a in (net.network_address, net.broadcast_address):
            raise HTTPException(400, f"{key}: {a} is het adres van het netwerk zelf of het broadcastadres")
        ip = f"{a}/{net.prefixlen}"
    if gw:
        if iface is None:
            raise HTTPException(400, f"{key}: een gateway hoort alleen bij een vast IPv4-adres")
        try:
            g = ipaddress.IPv4Address(gw)
        except ValueError:
            raise HTTPException(400, f"Ongeldige gateway bij {key}")
        if g == iface.ip:
            raise HTTPException(400, f"{key}: de gateway kan niet hetzelfde zijn als het adres")
        if iface.network.prefixlen < 32 and g not in iface.network:
            raise HTTPException(400, f"{key}: de gateway {g} ligt niet in het netwerk {iface.network}")
        gw = str(g)
    iface6 = None
    if ip6 and ip6 not in modes6:
        try:
            iface6 = ipaddress.IPv6Interface(ip6)
        except ValueError:
            iface6 = None
        if iface6 is None or "/" not in ip6 or iface6.ip.is_multicast or iface6.ip.is_unspecified or iface6.ip.is_loopback:
            raise HTTPException(400, f"Ongeldig IPv6-adres bij {key}: gebruik adres/voorvoegsel, bijvoorbeeld 2001:db8::50/64")
        ip6 = f"{iface6.ip.compressed}/{iface6.network.prefixlen}"
    if gw6:
        if iface6 is None:
            raise HTTPException(400, f"{key}: een IPv6-gateway hoort alleen bij een vast IPv6-adres")
        try:
            gw6 = ipaddress.IPv6Address(gw6).compressed
        except ValueError:
            raise HTTPException(400, f"Ongeldige IPv6-gateway bij {key}")
    return {"ip": ip, "gw": gw, "ip6": ip6, "gw6": gw6}


def ct_net_line(value: str, plan: dict) -> str:
    """De regel van de netwerkkaart van een container met nieuwe IP-instellingen; elk deel op zijn eigen plek."""
    parts = [x for x in str(value).split(",") if x]
    out, done = [], set()
    for part in parts:
        name = part.partition("=")[0]
        if name in IP_PARTS:
            done.add(name)
            if plan[name]:
                out.append(f"{name}={plan[name]}")
        else:
            out.append(part)
    out += [f"{p}={plan[p]}" for p in IP_PARTS if p not in done and plan[p]]
    return ",".join(out)


def dns_plan(nameserver: str | None, searchdomain: str | None) -> tuple:
    """Nagekeken DNS-servers (hooguit drie IP-adressen) en zoekdomeinen; leeg = zoals de node."""
    servers = None
    if nameserver is not None:
        items = [x for x in re.split(r"[\s,;]+", nameserver.strip()) if x]
        if len(items) > 3:
            raise HTTPException(400, "Vul hooguit drie DNS-servers in")
        for x in items:
            try:
                ipaddress.ip_address(x)
            except ValueError:
                raise HTTPException(400, f"Ongeldige DNS-server: {x[:60]} (vul een IP-adres in)")
        servers = " ".join(items)
    domains = None
    if searchdomain is not None:
        items = [x for x in re.split(r"[\s,;]+", searchdomain.strip()) if x]
        if len(items) > 3 or any(len(x) > 253 or not SEARCH_RE.match(x) for x in items):
            raise HTTPException(400, "Ongeldig zoekdomein; bijvoorbeeld thuis.lan")
        domains = " ".join(items)
    return servers, domains


def ip_changes(kind: str, cfg: dict, body, own: bool, params: dict, delete: list):
    """Voegt de gewijzigde IP- en DNS-instellingen toe aan de opdracht voor Proxmox (params, delete)."""
    asked_nets = {k: v for k, v in (body.nets or {}).items()}
    servers, domains = dns_plan(body.nameserver, body.searchdomain)
    now = guest_ip_settings(kind, cfg)
    by_key = {n["key"]: n for n in now["nets"]}
    changes = {}
    for key, want in asked_nets.items():
        if not NIC_RE.match(key) or key not in by_key:
            raise HTTPException(400, "Deze netwerkkaart bestaat niet bij deze guest")
        plan = ip_plan(kind, key, want)
        if plan != {p: by_key[key][p] for p in IP_PARTS}:
            changes[key] = plan
    dns = {}
    if servers is not None and servers != now["nameserver"]:
        dns["nameserver"] = servers
    if domains is not None and domains != now["searchdomain"]:
        dns["searchdomain"] = domains
    if not changes and not dns:
        return {}
    if own:   # een fout hier snijdt de tool van het cluster af
        raise HTTPException(409, "De tool wijzigt het IP-adres van zijn eigen container niet")
    if kind == "qemu" and not now["cloudinit"]:
        raise HTTPException(409, "Bij deze VM stel je het IP-adres in de VM zelf in; zonder cloud-init kan de tool dat niet")
    statics = [p["ip"].split("/")[0] for k, p in changes.items()] + [n["ip"].split("/")[0] for n in now["nets"] if n["key"] not in changes]
    statics = [x for x in statics if x[:1].isdigit()]
    if len(statics) != len(set(statics)):
        raise HTTPException(400, "Twee netwerkkaarten van deze guest kunnen niet hetzelfde adres hebben")
    for key, plan in changes.items():
        if kind == "lxc":
            params[key] = ct_net_line(cfg[key], plan)
        else:
            line = ",".join(f"{p}={plan[p]}" for p in IP_PARTS if plan[p])
            if line:
                params["ipconfig" + key[3:]] = line
            elif cfg.get("ipconfig" + key[3:]):
                delete.append("ipconfig" + key[3:])
    for name, value in dns.items():
        if value:
            params[name] = value
        else:
            delete.append(name)
    return {k: p["ip"].split("/")[0] for k, p in changes.items() if p["ip"][:1].isdigit()}


def ip_in_use(api, vmid: int, addresses: dict) -> str | None:
    """Of een nieuw vast adres al bij een andere guest of een node hoort; zo ja, een melding."""
    if not addresses:
        return None
    others = [g for g in api.cluster.resources.get(type="vm") if g.get("vmid") != vmid and not g.get("template")]
    used = {}
    for nics in POOL.map(lambda g: guest_nics(api, g, live=False), others):
        for nic in nics:
            ip = str(nic.get("ip") or "").split("/")[0]
            if ip[:1].isdigit():
                used.setdefault(ip, f"{nic['vmid']} {nic.get('name') or ''}".strip())
    for name, ip in node_ips(api).items():
        used.setdefault(str(ip), f"node {name}")
    for key, ip in addresses.items():
        if ip in used:
            return f"Adres {ip} ({key}) is al in gebruik bij {used[ip]}; kies een ander adres"
    return None


class GuestEdit(BaseModel):
    digest: str | None = Field(None, max_length=64)
    name: str | None = Field(None, max_length=63)
    cores: int | None = None
    memory: int | None = None       # MB
    swap: int | None = None         # MB, alleen containers
    onboot: bool | None = None
    protection: bool | None = None
    description: str | None = Field(None, max_length=2000)
    nets: dict[str, NicIp] | None = Field(None, max_length=32)   # per netwerkkaart (net0, ...): IP-adres en gateway
    nameserver: str | None = Field(None, max_length=200)          # DNS-servers; "" = zoals de node
    searchdomain: str | None = Field(None, max_length=300)
    tags: list[str] | None = Field(None, max_length=20)           # labels, zoals in Proxmox (1.4)


# Labels (tags) van een guest, zoals Proxmox ze toestaat: een letter, cijfer of _ en daarna ook - + en punt. Proxmox
# bewaart ze in de configuratie als "a;b;c". Het setup-bestand herkent de container van de tool aan zijn label.
TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_+.\-]{0,63}$")
OWN_TAG = "maintool"


def tag_list(text) -> list:
    """'a;b, c' -> ['a', 'b', 'c']: zoals Proxmox ze opslaat (met ; of , of spaties ertussen), zonder dubbele."""
    out = []
    for x in re.split(r"[;, ]+", str(text or "")):
        if x and x.lower() not in (y.lower() for y in out):
            out.append(x)
    return out[:40]


def guest_settings(kind: str, cfg: dict) -> dict:
    """De instellingen van een guest die hier te wijzigen zijn, uit zijn configuratie."""
    def number(key, default):
        try:
            return int(str(cfg.get(key, default)).split(",")[0].replace("current=", ""))
        except ValueError:
            return default
    return {"name": str(cfg.get("hostname" if kind == "lxc" else "name") or ""),
            "cores": number("cores", 0 if kind == "lxc" else 1) * (number("sockets", 1) if kind == "qemu" else 1),
            "sockets": number("sockets", 1) if kind == "qemu" else None,
            "memory": number("memory", 512), "swap": number("swap", 512) if kind == "lxc" else None,
            "onboot": bool(cfg.get("onboot")), "protection": bool(cfg.get("protection")),
            "description": str(cfg.get("description") or ""), "tags": tag_list(cfg.get("tags"))}


def edit_plan(kind: str, cfg: dict, body: GuestEdit, limits: dict, own: bool) -> dict:
    """Kijkt de gevraagde wijzigingen na tegen de guest zoals hij nu is en wat de node aankan (limits: cores en
    geheugen in MB), en geeft de opdracht voor Proxmox terug. Verandert zelf niets. Wat gelijk blijft gaat niet mee."""
    if cfg.get("template"):
        raise HTTPException(409, "Een sjabloon wordt hier niet gewijzigd; doe dat in Proxmox zelf")
    if cfg.get("lock"):
        raise HTTPException(409, f"Deze guest is vergrendeld ({cfg['lock']}); er is niets gewijzigd")
    now, params, delete = guest_settings(kind, cfg), {}, []
    if body.name is not None and body.name.strip() != now["name"]:
        name = body.name.strip()
        if not NAME_RE.match(name):
            raise HTTPException(400, "Ongeldige naam: letters, cijfers en streepjes, hooguit 63 tekens")
        if own:   # de tool herkent zijn eigen container aan de naam; die blijft dus zoals hij is
            raise HTTPException(409, "De tool wijzigt de naam van zijn eigen container niet")
        params["hostname" if kind == "lxc" else "name"] = name
    if body.cores is not None and body.cores != now["cores"]:
        if not 1 <= body.cores <= limits["cores"]:
            raise HTTPException(400, f"Het aantal cores moet tussen 1 en {limits['cores']} liggen (zoveel heeft de node)")
        params["cores"] = body.cores
        if kind == "qemu" and now["sockets"] != 1:
            params["sockets"] = 1   # het gevraagde aantal is het totaal: alles op één socket
    if body.memory is not None and body.memory != now["memory"]:
        low = 512 if own else 64 if kind == "lxc" else 128
        if not low <= body.memory <= limits["memory"]:
            raise HTTPException(400, f"Het geheugen moet tussen {low} en {limits['memory']} MB liggen")
        params["memory"] = body.memory
    if body.swap is not None and body.swap != now["swap"]:
        if kind != "lxc":
            raise HTTPException(400, "Een VM heeft hier geen swap-instelling")
        if not 0 <= body.swap <= limits["memory"]:
            raise HTTPException(400, f"De swap moet tussen 0 en {limits['memory']} MB liggen")
        params["swap"] = body.swap
    if body.onboot is not None and body.onboot != now["onboot"]:
        params["onboot"] = int(body.onboot)
    if body.protection is not None and body.protection != now["protection"]:
        params["protection"] = int(body.protection)
    if body.description is not None:
        text = body.description.replace("\r\n", "\n").strip()
        if any(ord(ch) < 32 and ch not in "\n\t" or ord(ch) == 127 for ch in text):
            raise HTTPException(400, "Ongeldige notitie: hooguit 2000 tekens, zonder stuurtekens")
        if text != now["description"].replace("\r\n", "\n").strip():
            if text:
                params["description"] = text
            else:
                delete.append("description")
    if body.tags is not None:
        tags = tag_list(";".join(x.strip() for x in body.tags))
        if any(not TAG_RE.match(x) for x in tags) or len(tags) > 20:
            raise HTTPException(400, "Ongeldig label: begin met een letter, cijfer of _, daarna ook - + of een punt; hooguit 64 tekens en 20 labels")
        if own and OWN_TAG in [x.lower() for x in now["tags"]] and OWN_TAG not in [x.lower() for x in tags]:
            raise HTTPException(409, "De tool houdt het label maintool op zijn eigen container: daaraan herkent het setup-bestand hem bij bijwerken en verwijderen")
        if tags != now["tags"]:
            if tags:
                params["tags"] = ";".join(tags)
            else:
                delete.append("tags")
    ip_changes(kind, cfg, body, own, params, delete)
    if not params and not delete:
        raise HTTPException(400, "Er is niets gewijzigd")
    if delete:
        params["delete"] = ",".join(delete)
    if body.digest:
        params["digest"] = body.digest
    return params


def guest_for_edit(api, node: str, kind: str, vmid: int):
    """De guest zoals het cluster hem kent, zijn configuratie en wat de node aankan; 404 als hij daar niet staat."""
    found = next((g for g in api.cluster.resources.get(type="vm") if g.get("vmid") == vmid), None)
    if not found or found.get("node") != node or found.get("type") != kind:
        raise HTTPException(404, "Deze guest bestaat niet (meer) op deze node")
    cfg = guest(api, node, kind, vmid).config.get()
    status = api.nodes(node).status.get()
    limits = {"cores": int((status.get("cpuinfo") or {}).get("cpus") or 1),
              "memory": int(((status.get("memory") or {}).get("total") or 0) // 2**20) or 1024}
    own = kind == "lxc" and found.get("name") == socket.gethostname()
    return found, {**cfg, "template": found.get("template") or cfg.get("template")}, limits, own


@app.get("/api/guest/{node}/{kind}/{vmid}/config")
def guest_config(node: str, kind: str, vmid: int, _: str = Depends(manage_overview)):
    check_target(node, kind, vmid)

    def f(api):
        found, cfg, limits, own = guest_for_edit(api, node, kind, vmid)
        return {**guest_settings(kind, cfg), "digest": cfg.get("digest"), "status": found.get("status"), "lock": cfg.get("lock"),
                "template": bool(cfg.get("template")), "own": own, "limits": limits,
                "min_memory": 512 if own else 64 if kind == "lxc" else 128, "disks": disks_with_free(api, node, kind, cfg),
                **guest_ip_settings(kind, cfg)}
    return pve.run(f)


@app.put("/api/guest/{node}/{kind}/{vmid}/config")
def guest_config_save(node: str, kind: str, vmid: int, body: GuestEdit, request: Request, _: str = Depends(manage_overview)):
    """Past de instellingen van een guest aan. Het antwoord zegt wat er gewijzigd is en wat pas na een herstart geldt."""
    same_origin(request)
    check_target(node, kind, vmid)

    def f(api):
        found, cfg, limits, own = guest_for_edit(api, node, kind, vmid)
        params = edit_plan(kind, cfg, body, limits, own)
        clash = ip_in_use(api, vmid, ip_changes(kind, cfg, body, own, {}, []))   # een nieuw vast adres dat al bij een ander hoort
        if clash:
            raise HTTPException(409, clash)
        try:
            guest(api, node, kind, vmid).config.put(**params)
        except ResourceException as e:
            if "digest" in f"{e.status_message} {e.content or ''}".lower():
                raise HTTPException(409, "De instellingen van deze guest zijn intussen door iemand anders gewijzigd; open het venster opnieuw")
            raise
        changed = sorted([k for k in params if k not in ("digest", "delete")] + [k for k in str(params.get("delete") or "").split(",") if k])
        waiting = []
        if found.get("status") == "running":
            if kind == "qemu":
                try:
                    waiting = sorted(x["key"] for x in guest(api, node, kind, vmid).pending.get()
                                     if x.get("key") in params and "pending" in x)
                except (ResourceException, KeyError, TypeError):
                    waiting = []
            elif "hostname" in params:
                waiting = ["hostname"]   # de naam in de container zelf verandert bij de volgende start
            if kind == "qemu":   # cloud-init past het adres pas toe als de VM opnieuw opstart
                waiting = sorted(set(waiting) | {k for k in changed if k.startswith("ipconfig") or k in ("nameserver", "searchdomain")})
        return {"ok": True, "changed": changed, "pending": waiting}
    return pve.run(f)


# ---------------------------------------------------------------- een schijf van een guest vergroten (steeksleutel)
# Proxmox kan een schijf alleen groter maken, nooit kleiner. Bij een container groeit het bestandssysteem mee; in een
# VM moet de partitie daarna in de VM zelf worden vergroot. De opslag moet de extra ruimte vrij hebben.
DISK_KEY_RE = re.compile(r"^(rootfs|mp\d{1,3}|(scsi|virtio|sata|ide)\d{1,2})$")
VM_DATA_DISK_RE = re.compile(r"^(scsi|virtio|sata|ide)\d{1,2}$")
SIZE_RE = re.compile(r"^(\d+(?:\.\d+)?)([KMGT]?)$")
SIZE_UNITS = {"": 1, "K": 2**10, "M": 2**20, "G": 2**30, "T": 2**40}
MAX_GROW_GB = 16384


def size_bytes(text) -> int | None:
    """'8G' -> 8589934592; None als het geen grootte is."""
    m = SIZE_RE.match(str(text or "").strip().upper())
    return int(float(m.group(1)) * SIZE_UNITS[m.group(2)]) if m else None


def resizable_disks(kind: str, cfg: dict) -> list:
    """De schijven van een guest die te vergroten zijn: met een volume op een opslag en een bekende grootte. Geen
    cd-rom, cloud-init, EFI- of TPM-schijf, en geen map of apparaat van de node."""
    out = []
    for key in sorted(cfg, key=lambda k: (len(k), k)):
        if not (LXC_DISK_RE.match(key) if kind == "lxc" else VM_DATA_DISK_RE.match(key)):
            continue
        o = parse_options(cfg[key])
        volume = o.get("") or o.get("volume") or o.get("file") or ""
        storage, _, name = volume.partition(":")
        if not name or volume.startswith("/") or o.get("media") == "cdrom" or "cloudinit" in name:
            continue
        size = size_bytes(o.get("size"))
        if size is not None:
            out.append({"key": key, "storage": storage, "volume": name, "size": size,
                        "mount": o.get("mp") or ("/" if key == "rootfs" else None)})
    return out[:32]


def storage_free(api, node: str, storage: str):
    try:
        avail = api.nodes(node).storage(storage).status.get().get("avail")
    except ResourceException:
        return None
    return int(avail) if isinstance(avail, (int, float)) and not isinstance(avail, bool) else None


class DiskGrowIn(BaseModel):
    grow_gb: int = Field(strict=True)   # alleen een echt geheel getal: geen true, geen 1.5, geen "10"
    digest: str | None = Field(None, max_length=64)


@app.put("/api/guest/{node}/{kind}/{vmid}/disk/{disk}")
def guest_disk_grow(node: str, kind: str, vmid: int, disk: str, body: DiskGrowIn, request: Request, _: str = Depends(manage_overview)):
    """Maakt een schijf groter met grow_gb GB. Het antwoord geeft de taak terug als Proxmox er een start."""
    same_origin(request)
    check_target(node, kind, vmid)
    if not DISK_KEY_RE.match(disk):
        raise HTTPException(400, "Deze schijf kan hier niet vergroot worden")
    if isinstance(body.grow_gb, bool) or not 1 <= body.grow_gb <= MAX_GROW_GB:
        raise HTTPException(400, "Vergroot met 1 tot 16384 GB")

    def f(api):
        _found, cfg, _limits, _own = guest_for_edit(api, node, kind, vmid)
        if cfg.get("template"):
            raise HTTPException(409, "Een sjabloon wordt hier niet gewijzigd; doe dat in Proxmox zelf")
        if cfg.get("lock"):
            raise HTTPException(409, f"Deze guest is vergrendeld ({cfg['lock']}); er is niets gewijzigd")
        if body.digest and cfg.get("digest") and not hmac.compare_digest(body.digest, str(cfg["digest"])):
            raise HTTPException(409, "De instellingen van deze guest zijn intussen door iemand anders gewijzigd; open het venster opnieuw")
        d = next((x for x in resizable_disks(kind, cfg) if x["key"] == disk), None)
        if not d:
            raise HTTPException(400, "Deze schijf kan hier niet vergroot worden")
        free = storage_free(api, node, d["storage"])
        if free is not None and body.grow_gb * 2**30 > free:
            raise HTTPException(409, f"Op opslag {d['storage']} is nog {free / 2**30:.0f} GB vrij; vergroot met minder")
        params = {"disk": disk, "size": f"+{body.grow_gb}G"}
        if cfg.get("digest"):
            params["digest"] = cfg["digest"]
        try:
            result = guest(api, node, kind, vmid).resize.put(**params)
        except ResourceException as e:
            if "digest" in f"{e.status_message} {e.content or ''}".lower():
                raise HTTPException(409, "De instellingen van deze guest zijn intussen door iemand anders gewijzigd; open het venster opnieuw")
            raise
        return {"ok": True, "disk": disk, "size": d["size"] + body.grow_gb * 2**30,
                "task": result if isinstance(result, str) and result.startswith("UPID:") else None}
    return pve.run(f)


def disks_with_free(api, node: str, kind: str, cfg: dict) -> list:
    free = {}
    out = []
    for d in resizable_disks(kind, cfg):
        if d["storage"] not in free:
            free[d["storage"]] = storage_free(api, node, d["storage"])
        out.append({**d, "free": free[d["storage"]]})
    return out


# ---------------------------------------------------------------- het netwerk van een guest (tabblad Netwerken)
NIC_RE = re.compile(r"^net\d{1,2}$")


class NicIn(BaseModel):
    bridge: str = Field(max_length=15)
    tag: int | None = None
    digest: str | None = Field(None, max_length=64)


def nic_plan(value: str, body: NicIn, networks: dict) -> str:
    """Geeft de regel van een netwerkkaart terug met een ander netwerk en/of VLAN-nummer; al het andere (MAC-adres,
    IP-adres, firewall, ...) blijft letterlijk staan. networks = {naam: soort} van wat op de node te kiezen is."""
    if not DEVICE_RE.match(body.bridge) or body.bridge not in networks:
        raise HTTPException(400, "Dit netwerk bestaat niet op de node van deze guest")
    if body.tag is not None and not 1 <= body.tag <= 4094:
        raise HTTPException(400, "Het VLAN-nummer moet tussen 1 en 4094 liggen")
    if body.tag is not None and networks[body.bridge] == "vnet":
        raise HTTPException(400, "Een VLAN-netwerk heeft zijn nummer al; kies bij VLAN 'geen'")
    parts = [x for x in str(value).split(",") if x and not x.startswith("tag=")]
    place = next((i for i, x in enumerate(parts) if x.startswith("bridge=")), None)
    if place is None:
        parts.append(f"bridge={body.bridge}")
        place = len(parts) - 1
    else:
        parts[place] = f"bridge={body.bridge}"
    if body.tag is not None:
        parts.insert(place + 1, f"tag={body.tag}")
    new = ",".join(parts)
    old = parse_options(value)
    if old.get("bridge") == body.bridge and (int(old["tag"]) if str(old.get("tag") or "").isdigit() else None) == body.tag:
        raise HTTPException(400, "Er is niets gewijzigd")
    return new


@app.put("/api/network/guest/{node}/{kind}/{vmid}/{nic}")
def network_guest_nic(node: str, kind: str, vmid: int, nic: str, body: NicIn, request: Request, _: str = Depends(manage_network)):
    """Zet een netwerkkaart van een guest op een ander netwerk (bridge of VLAN-netwerk) en/of een ander VLAN-nummer.
    Bij een draaiende guest gaat dat direct in."""
    same_origin(request)
    check_target(node, kind, vmid)
    if not NIC_RE.match(nic):
        raise HTTPException(400, "Deze netwerkkaart bestaat niet bij deze guest")

    def f(api):
        found, cfg, _limits, own = guest_for_edit(api, node, kind, vmid)
        if own:   # een fout hier snijdt de tool van het cluster af
            raise HTTPException(409, "De tool wijzigt het netwerk van zijn eigen container niet")
        if cfg.get("lock"):
            raise HTTPException(409, f"Deze guest is vergrendeld ({cfg['lock']}); er is niets gewijzigd")
        if nic not in cfg:
            raise HTTPException(404, "Deze netwerkkaart bestaat niet bij deze guest")
        networks = {b["iface"]: b.get("type") for b in api.nodes(node).network.get(type="any_bridge")}
        new = nic_plan(cfg[nic], body, networks)
        params = {nic: new}
        if body.digest:
            params["digest"] = body.digest
        try:
            guest(api, node, kind, vmid).config.put(**params)
        except ResourceException as e:
            if "digest" in f"{e.status_message} {e.content or ''}".lower():
                raise HTTPException(409, "De instellingen van deze guest zijn intussen door iemand anders gewijzigd; open het venster opnieuw")
            raise
        return {"ok": True, "nic": nic, "bridge": body.bridge, "tag": body.tag, "running": found.get("status") == "running"}
    return pve.run(f)


# ---------------------------------------------------------------- dashboard voor aan de muur
# Het dashboard gebruikt dezelfde gegevens als de rest van de pagina (overzicht, live cijfers, aandachtspunten). Dit
# adres levert daarbij het verloop van het laatste uur per node, uit de meetgegevens die Proxmox zelf bijhoudt, en
# houdt de sessie in leven zolang het dashboard open staat: een scherm aan de muur moet niet na een paar uur uitloggen.
def token_expiry(token) -> float:
    try:
        payload = (token or "").partition(".")[0]
        return float(json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))).get("e") or 0)
    except (ValueError, TypeError, AttributeError):
        return 0.0


def node_history(api, node: str):
    """Het laatste uur van een node, per minuut: tijd, CPU (0-1), geheugen (0-1), netwerk in en uit (bytes per seconde)."""
    try:
        points = api.nodes(node).rrddata.get(timeframe="hour", cf="AVERAGE")
    except ResourceException:
        return None
    out = {"t": [], "cpu": [], "mem": [], "netin": [], "netout": []}
    for x in sorted(points, key=lambda x: x.get("time") or 0):
        if x.get("cpu") is None and x.get("memused") is None:
            continue
        total = x.get("memtotal") or 0
        out["t"].append(int(x.get("time") or 0))
        out["cpu"].append(round(float(x.get("cpu") or 0), 4))
        out["mem"].append(round(float(x.get("memused") or 0) / total, 4) if total else 0)
        out["netin"].append(round(float(x.get("netin") or 0)))
        out["netout"].append(round(float(x.get("netout") or 0)))
    return out


@app.get("/api/dashboard")
def dashboard(request: Request, response: Response, user: str = Depends(auth)):
    def f(api):
        nodes = online_nodes(api)
        return {"history": dict(zip(nodes, POOL.map(lambda n: node_history(api, n), nodes)))}
    data = pve.run(f)
    data["issues"] = issues.get()
    # het dashboard aan de muur blijft ingelogd: halverwege de sessie een nieuwe, op dezelfde manier (wel of niet blijvend)
    kept = token_remembered(request.cookies.get(SESSION_COOKIE)) and session_policy()["remember"]
    pol = session_policy()
    if token_expiry(request.cookies.get(SESSION_COOKIE)) - time.time() < (pol["remember_days"] * 86400 if kept else pol["session_hours"] * 3600) / 2:
        set_session_cookie(response, user, kept)
    return data
