#!/bin/bash
# Uitvoeren als root op de Proxmox-node waar de Maintool-container op dat moment draait (met HA kan dat
# wisselen; de tool toont het in de kolom Node). Opnieuw nodig na elke wijziging van de agent:
#
#   pct pull 109 /root/maintool/node/setup-nodes.sh /root/maintool-setup-nodes.sh
#   bash /root/maintool-setup-nodes.sh 109
#
# Wat dit doet:
#   1. zet /usr/local/sbin/maintool-agent op elke node van het cluster;
#   2. laat de SSH-sleutel van de Maintool toe in /etc/pve/priv/authorized_keys (geldt clusterbreed),
#      beperkt tot die agent en tot het IP-adres van de container;
#   3. zet de SSH-hostsleutels van de nodes in de container, zodat de tool de nodes kan verifiëren.
# Opnieuw draaien kan: het vervangt de agent en de bestaande regel.
set -euo pipefail

CTID=${1:-109}
AGENT=/usr/local/sbin/maintool-agent
AUTH=/etc/pve/priv/authorized_keys
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

pct pull "$CTID" /root/maintool/node/maintool-agent "$TMP/agent"
pct pull "$CTID" /etc/maintool/ssh/id_ed25519.pub "$TMP/key.pub"
bash -n "$TMP/agent"
KEY=$(awk '{ print $1 " " $2 }' "$TMP/key.pub")
[[ $KEY == "ssh-ed25519 AAAA"* ]] || { echo "Onverwachte sleutel in de container, gestopt."; exit 1; }
CT_IP=$(pct exec "$CTID" -- hostname -I | awk '{ print $1 }')
[[ $CT_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "IP-adres van CT $CTID niet gevonden, gestopt."; exit 1; }

python3 - >"$TMP/nodes" <<'EOF'
import json
for name, node in sorted(json.load(open("/etc/pve/.members"))["nodelist"].items()):
    print(name, node["ip"])
EOF

echo "== 1. agent installeren"
: >"$TMP/known_hosts"
while read -r name ip; do
    # Dezelfde opties die Proxmox zelf tussen nodes gebruikt.
    opts=(-o BatchMode=yes -o HostKeyAlias="$name")
    if [[ -f /etc/pve/nodes/$name/ssh_known_hosts ]]; then
        opts+=(-o UserKnownHostsFile="/etc/pve/nodes/$name/ssh_known_hosts" -o GlobalKnownHostsFile=none)
    fi
    scp -q "${opts[@]}" "$TMP/agent" "root@$ip:$AGENT"
    hostkey=$(ssh "${opts[@]}" "root@$ip" "chmod 755 $AGENT && mkdir -p /var/log/maintool && cat /etc/ssh/ssh_host_ed25519_key.pub" </dev/null)
    echo "$ip $(awk '{ print $1 " " $2 }' <<<"$hostkey")" >>"$TMP/known_hosts"
    echo "   $name ($ip): ok"
done <"$TMP/nodes"

echo "== 2. sleutel toelaten (alleen de agent, alleen vanaf $CT_IP)"
cp "$AUTH" "/root/authorized_keys.voor-maintool.$(date +%Y%m%d-%H%M%S)"
{ grep -vF "$KEY" "$AUTH" || true; } >"$TMP/auth"
echo "command=\"$AGENT\",from=\"$CT_IP\",restrict $KEY maintool" >>"$TMP/auth"
cat "$TMP/auth" >"$AUTH"

echo "== 3. hostsleutels naar de container"
pct exec "$CTID" -- mkdir -p /etc/maintool/ssh
pct push "$CTID" "$TMP/known_hosts" /etc/maintool/ssh/known_hosts --perms 644

echo
echo "Klaar. De Maintool kan nu via de agent updates opvragen en installeren."
