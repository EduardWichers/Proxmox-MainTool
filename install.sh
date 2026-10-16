#!/usr/bin/env bash
# Installeert de Proxmox Maintool in een Debian 12/13 LXC. Wordt aangeroepen door maintool-setup.sh (dat ook de
# instellingen, het certificaat van het cluster en de agent op de nodes regelt), bij installeren en bij bijwerken.
# Los gebruiken kan ook (als root, in de map met deze bestanden):  bash install.sh
set -euo pipefail

APP_DIR=/opt/maintool
CONF_DIR=/etc/maintool

echo "==> Pakketten installeren"
apt-get update -qq
apt-get install -y -qq python3 python3-venv openssl ca-certificates openssh-client

echo "==> Systeemgebruiker 'maintool' aanmaken"
id maintool >/dev/null 2>&1 || useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin maintool

echo "==> Bestanden kopiëren"
mkdir -p "$APP_DIR" "$CONF_DIR"
cp -r app requirements.txt "$APP_DIR"/
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install -q --upgrade pip
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

if [ ! -f "$CONF_DIR/maintool.env" ]; then
  cp maintool.env.example "$CONF_DIR/maintool.env"
  echo "    -> $CONF_DIR/maintool.env aangemaakt, VUL DEZE NOG IN"
fi

if [ ! -f "$CONF_DIR/tls.crt" ]; then
  echo "==> Self-signed TLS-certificaat maken"
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$CONF_DIR/tls.key" -out "$CONF_DIR/tls.crt" \
    -subj "/CN=$(hostname -f)" 2>/dev/null
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
chown -R maintool:maintool "$APP_DIR"

echo "==> systemd-service installeren"
cp maintool.service /etc/systemd/system/maintool.service
systemctl daemon-reload
systemctl enable maintool >/dev/null

echo "==> Bijwerken via de pagina inschakelen"
# Een apart programma van root vervangt de bestanden van de tool; de webdienst zelf kan dat niet. Het neemt alleen
# pakketten aan waarin de bestanden hieronder gelijk zijn aan wat hier nu wordt neergezet (baseline.sums); voor
# alles wat dieper ingrijpt is het setup-bestand op een node nodig.
install -o root -g root -m 755 updater/maintool-updater /usr/local/sbin/maintool-updater
install -o root -g root -m 644 updater/maintool-update.service updater/maintool-update.path /etc/systemd/system/
mkdir -p /usr/local/lib/maintool /var/lib/maintool-update /var/lib/maintool-backup
chmod 755 /usr/local/lib/maintool /var/lib/maintool-update
chmod 700 /var/lib/maintool-backup
sha256sum requirements.txt maintool.service install.sh updater/maintool-updater updater/maintool-update.service \
    updater/maintool-update.path node/maintool-agent >/usr/local/lib/maintool/baseline.sums
chmod 644 /usr/local/lib/maintool/baseline.sums
systemctl daemon-reload
systemctl enable --now maintool-update.path >/dev/null

[ "${MAINTOOL_SETUP:-}" = 1 ] && exit 0   # het setup-bestand doet de rest

echo
echo "Klaar. Volgende stappen:"
echo "  1. Vul $CONF_DIR/maintool.env in"
echo "  2. Kopieer /etc/pve/pve-root-ca.pem van een node naar $CONF_DIR/"
echo "  3. systemctl restart maintool && journalctl -u maintool -f"
echo "  4. Open https://$(hostname -I | awk '{print $1}'):8443"
