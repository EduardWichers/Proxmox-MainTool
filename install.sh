#!/usr/bin/env bash
# Installeert de Proxmox Maintool in een Debian 12/13 LXC. Wordt aangeroepen door maintool-setup.sh (dat ook de
# instellingen, het certificaat van het cluster en de agent op de nodes regelt), bij installeren en bij bijwerken.
# Los gebruiken kan ook (als root, in de map met deze bestanden):  bash install.sh
#
# Bij bijwerken staat de nieuwe versie eerst helemaal klaar naast de oude; pas dan wordt er gewisseld en herstart.
# Antwoordt de nieuwe versie daarna niet, dan gaat de oude vanzelf terug: exitcode 3 (de oude draait weer) of 4 (ook
# de oude antwoordt niet). Alles onder /opt/maintool is van root: de dienst kan zijn eigen programma niet wijzigen.
set -euo pipefail
umask 022

# De MT_*-variabelen bestaan alleen om dit bestand te kunnen testen (tests/install).
ROOT="${MT_ROOT:-}"
APP_DIR="$ROOT/opt/maintool"
CONF_DIR="$ROOT/etc/maintool"
UNIT="$ROOT/etc/systemd/system/maintool.service"
DROPIN="$ROOT/etc/systemd/system/maintool.service.d"
HEALTH_WAIT="${MT_HEALTH_WAIT:-60}"
VERSION=$(tr -d ' \n' <app/VERSION)
# De Python-pakketten komen in een eigen map per pakketlijst (requirements.txt, met vaste versies en controlesommen);
# /opt/maintool/venv wijst naar de map die in gebruik is. Een nieuwe lijst krijgt dus een nieuwe map naast de oude.
VENV="venvs/$(sha256sum requirements.txt | cut -c1-16)"

echo "==> Pakketten installeren"
apt-get update -qq
apt-get install -y -qq python3 python3-venv openssl ca-certificates openssh-client

echo "==> Systeemgebruiker 'maintool' aanmaken"
id maintool >/dev/null 2>&1 || useradd --system --home /opt/maintool --shell /usr/sbin/nologin maintool

UPDATE=""   # er draait al een tool: dan wisselen, herstarten en nakijken
if [ -f "$APP_DIR/app/main.py" ] && [ -f "$CONF_DIR/maintool.env" ]; then UPDATE=1; fi
OLD_VERSION=$(tr -d ' \n' <"$APP_DIR/app/VERSION" 2>/dev/null || true)

echo "==> Python-pakketten: vaste versies, elk met zijn controlesom"
mkdir -p "$APP_DIR/venvs"
if [ ! -f "$APP_DIR/$VENV/.klaar" ]; then
    rm -rf "${APP_DIR:?}/$VENV"
    python3 -m venv "$APP_DIR/$VENV"
    # Alleen kant-en-klare pakketten (geen code die bij het installeren draait), en elk moet precies zijn wat in
    # requirements.txt staat; anders weigert pip.
    if ! "$APP_DIR/$VENV/bin/pip" install -q --no-input --disable-pip-version-check --require-hashes --only-binary :all: \
            -r requirements.txt; then
        rm -rf "${APP_DIR:?}/$VENV"
        echo "!! De Python-pakketten konden niet worden geïnstalleerd (heeft de container internet?)" >&2
        exit 1
    fi
    touch "$APP_DIR/$VENV/.klaar"
fi

echo "==> Bestanden klaarzetten"
rm -rf "$APP_DIR/app.new"
cp -r app "$APP_DIR/app.new"
cp requirements.txt "$APP_DIR/requirements.txt"
mkdir -p "$CONF_DIR"

if [ ! -f "$CONF_DIR/maintool.env" ]; then
  cp maintool.env.example "$CONF_DIR/maintool.env"
  echo "    -> $CONF_DIR/maintool.env aangemaakt, VUL DEZE NOG IN"
fi

if [ ! -f "$CONF_DIR/tls.crt" ]; then
  echo "==> Self-signed TLS-certificaat maken"
  ( umask 077
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout "$CONF_DIR/tls.key" -out "$CONF_DIR/tls.crt" \
      -subj "/CN=$(hostname -f)" 2>/dev/null )
fi

if [ ! -f "$CONF_DIR/ssh/id_ed25519" ]; then
  echo "==> SSH-sleutel voor de agent op de nodes maken (zie node/setup-nodes.sh)"
  mkdir -p "$CONF_DIR/ssh"
  ssh-keygen -q -t ed25519 -N "" -C maintool -f "$CONF_DIR/ssh/id_ed25519"
fi

chown -R root:maintool "$CONF_DIR"
chmod 750 "$CONF_DIR" "$CONF_DIR/ssh"
find "$CONF_DIR" -maxdepth 1 -type f -exec chmod 640 {} +
chown maintool:maintool "$CONF_DIR/ssh/id_ed25519"
chmod 600 "$CONF_DIR/ssh/id_ed25519"

echo "==> De afscherming van de dienst bepalen (wat deze container toelaat)"
# Elke regel probeert systemd hier eerst met een klein programma dat doet wat de tool ook doet (de Python-pakketten
# laden, een naam opzoeken, ssh starten), als gebruiker maintool. Alleen wat werkt komt in maintool.service.d; zo
# start de dienst in elke container, en krijgt hij de strengste afscherming die daar kan.
HARDEN=(
    "PrivateDevices=yes"
    "ProtectKernelTunables=yes"
    "ProtectKernelModules=yes"
    "ProtectKernelLogs=yes"
    "ProtectControlGroups=yes"
    "ProtectClock=yes"
    "ProtectHostname=yes"
    "ProtectProc=invisible"
    "RestrictNamespaces=yes"
    "RestrictRealtime=yes"
    "RestrictSUIDSGID=yes"
    "LockPersonality=yes"
    "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK"
    "CapabilityBoundingSet="
    "SystemCallArchitectures=native"
    "SystemCallFilter=@system-service|SystemCallErrorNumber=EPERM"
)
PROBE='import asyncio, socket, ssl, subprocess, uvloop, httptools, pydantic_core
uvloop.run(asyncio.sleep(0))
socket.getaddrinfo("localhost", 443)
subprocess.run(["ssh", "-V"], capture_output=True, check=True)'
probe() {   # probe [-p EIGENSCHAP]...: start het programma hierboven met de basis-afscherming van maintool.service erbij
    systemd-run --quiet --wait --collect --uid=maintool --gid=maintool -p NoNewPrivileges=yes -p ProtectSystem=strict \
        -p ProtectHome=yes -p PrivateTmp=yes -p UMask=0077 "$@" "$APP_DIR/$VENV/bin/python" -c "$PROBE" >/dev/null 2>&1
}
GOOD=()
if probe; then
    for line in "${HARDEN[@]}"; do
        args=()
        IFS='|' read -r -a parts <<<"$line"
        for part in "${parts[@]}"; do args+=(-p "$part"); done
        if probe "${args[@]}"; then GOOD+=("${parts[@]}"); fi
    done
    args=()
    for part in "${GOOD[@]+"${GOOD[@]}"}"; do args+=(-p "$part"); done
    if [ ${#GOOD[@]} -gt 0 ] && ! probe "${args[@]}"; then GOOD=(); fi   # samen moet het ook werken
fi
echo "    ${#GOOD[@]} afschermingen gaan aan"
NEW_HARDENING=$(mktemp)
trap 'rm -f "$NEW_HARDENING"' EXIT
{
    echo "# Gemaakt door install.sh: de afscherming die deze container toelaat (elke regel is eerst geprobeerd)."
    echo "[Service]"
    for part in "${GOOD[@]+"${GOOD[@]}"}"; do echo "$part"; done
} >"$NEW_HARDENING"

healthy() {   # healthy VERSIE SECONDEN: antwoordt de tool binnen die tijd met deze versie op zijn inlogpagina?
    if [ -n "${MT_HEALTH_CMD:-}" ]; then "$MT_HEALTH_CMD" "$1" "$2"; return; fi
    python3 - "$1" "$2" <<'PY'
import re, ssl, sys, time, urllib.request
want, until = sys.argv[1], time.monotonic() + int(sys.argv[2])
ctx = ssl.create_default_context()
ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE   # de eigen tool, op 127.0.0.1
while time.monotonic() < until:
    try:
        with urllib.request.urlopen("https://127.0.0.1:8443/login", context=ctx, timeout=5) as reply:
            found = re.search(r"Proxmox Maintool v(\d+(?:\.\d+){1,2})", reply.read(200000).decode("utf-8", "replace"))
        if found and found.group(1) == want:
            sys.exit(0)
    except Exception:
        pass
    time.sleep(2)
sys.exit(1)
PY
}

OLD_VENV=""   # waar /opt/maintool/venv naar wees (of venv.old: de map van vóór 1.5.3)
place() {     # de nieuwe versie op haar plek: programma, Python-pakketten, dienst
    if [ -d "$APP_DIR/app" ]; then rm -rf "$APP_DIR/app.old"; mv "$APP_DIR/app" "$APP_DIR/app.old"; fi
    mv "$APP_DIR/app.new" "$APP_DIR/app"
    if [ -L "$APP_DIR/venv" ]; then
        OLD_VENV=$(readlink "$APP_DIR/venv")
        rm -f "$APP_DIR/venv"
    elif [ -d "$APP_DIR/venv" ]; then
        rm -rf "$APP_DIR/venv.old"; mv "$APP_DIR/venv" "$APP_DIR/venv.old"; OLD_VENV=venv.old
    fi
    ln -s "$VENV" "$APP_DIR/venv"
    mkdir -p "$(dirname "$UNIT")" "$DROPIN"
    if [ -f "$UNIT" ]; then cp -p "$UNIT" "$UNIT.old"; fi
    if [ -f "$DROPIN/hardening.conf" ]; then cp -p "$DROPIN/hardening.conf" "$DROPIN/hardening.conf.old"; fi
    cp maintool.service "$UNIT"
    install -m 644 "$NEW_HARDENING" "$DROPIN/hardening.conf"
    systemctl daemon-reload
}
put_back() {   # de vorige versie terug, precies zoals ze was
    rm -rf "$APP_DIR/app.failed"
    mv "$APP_DIR/app" "$APP_DIR/app.failed"
    mv "$APP_DIR/app.old" "$APP_DIR/app"
    rm -f "$APP_DIR/venv"
    if [ "$OLD_VENV" = venv.old ]; then mv "$APP_DIR/venv.old" "$APP_DIR/venv"; elif [ -n "$OLD_VENV" ]; then ln -s "$OLD_VENV" "$APP_DIR/venv"; fi
    if [ -f "$UNIT.old" ]; then mv -f "$UNIT.old" "$UNIT"; fi
    if [ -f "$DROPIN/hardening.conf.old" ]; then mv -f "$DROPIN/hardening.conf.old" "$DROPIN/hardening.conf"; else rm -f "$DROPIN/hardening.conf"; fi
    rm -rf "$APP_DIR/app.failed"
    systemctl daemon-reload
}

if [ -n "$UPDATE" ]; then
    echo "==> Wisselen naar versie $VERSION en herstarten"
    place
    systemctl restart maintool || true
    if ! healthy "$VERSION" "$HEALTH_WAIT"; then
        echo "!! Versie $VERSION antwoordt niet na de herstart; de vorige versie (${OLD_VERSION:-?}) wordt teruggezet" >&2
        journalctl -u maintool -n 20 --no-pager -o cat 2>/dev/null | sed 's/^/   | /' >&2 || true
        put_back
        systemctl restart maintool || true
        if [ -n "$OLD_VERSION" ] && healthy "$OLD_VERSION" "$HEALTH_WAIT"; then exit 3; fi
        exit 4
    fi
    rm -rf "$APP_DIR/app.old" "$APP_DIR/venv.old"
    rm -f "$UNIT.old" "$DROPIN/hardening.conf.old"
else
    place
    rm -rf "$APP_DIR/app.old"
fi
# Alleen de map in gebruik en de vorige blijven staan.
for dir in "$APP_DIR"/venvs/*/; do
    dir=${dir%/}
    case "venvs/${dir##*/}" in "$VENV" | "$OLD_VENV") ;; *) rm -rf "$dir" ;; esac
done

chown -R root:root "$APP_DIR"
chmod -R u=rwX,go=rX "$APP_DIR/app"

echo "==> systemd-service inschakelen"
systemctl enable maintool >/dev/null

echo "==> Bijwerken via de pagina inschakelen"
# Een apart programma van root vervangt de bestanden van de tool; de webdienst zelf kan dat niet. Het neemt alleen
# pakketten aan waarin de bestanden hieronder gelijk zijn aan wat hier nu wordt neergezet (baseline.sums); voor
# alles wat dieper ingrijpt is het setup-bestand op een node nodig (de pagina kan dat daar zelf starten).
mkdir -p "$ROOT/usr/local/sbin" "$ROOT/etc/systemd/system"
install -o root -g root -m 755 updater/maintool-updater "$ROOT/usr/local/sbin/maintool-updater"
install -o root -g root -m 644 updater/maintool-update.service updater/maintool-update.path "$ROOT/etc/systemd/system/"
mkdir -p "$ROOT/usr/local/lib/maintool" "$ROOT/var/lib/maintool-update" "$ROOT/var/lib/maintool-backup"
chmod 755 "$ROOT/usr/local/lib/maintool" "$ROOT/var/lib/maintool-update"
chmod 700 "$ROOT/var/lib/maintool-backup"
sha256sum requirements.txt maintool.service install.sh updater/maintool-updater updater/maintool-update.service \
    updater/maintool-update.path node/maintool-agent >"$ROOT/usr/local/lib/maintool/baseline.sums"
chmod 644 "$ROOT/usr/local/lib/maintool/baseline.sums"
systemctl daemon-reload
systemctl enable --now maintool-update.path >/dev/null

[ "${MAINTOOL_SETUP:-}" = 1 ] && exit 0   # het setup-bestand doet de rest

echo
echo "Klaar. Volgende stappen:"
echo "  1. Vul $CONF_DIR/maintool.env in"
echo "  2. Kopieer /etc/pve/pve-root-ca.pem van een node naar $CONF_DIR/"
echo "  3. systemctl restart maintool && journalctl -u maintool -f"
echo "  4. Open https://$(hostname -I | awk '{print $1}'):8443"
