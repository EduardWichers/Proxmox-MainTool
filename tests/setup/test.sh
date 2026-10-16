#!/usr/bin/env bash
# Test het setup-bestand tegen nagebootste Proxmox-opdrachten (bin/) en echte, alleen-gelezen antwoorden van het
# cluster. Draaien als root op de toolcontainer:  bash /root/maintool/tests/setup/test.sh
# De tests zelf draaien als gebruiker "nobody" in /tmp/mt-test en kunnen het echte systeem niet raken.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
rm -rf /tmp/mt-test && mkdir -p /tmp/mt-test/fix && cp -r "$HERE"/bin "$HERE"/run.sh "$HERE"/capture.py /tmp/mt-test/
cd /root/maintool && bash build.sh >/dev/null
cp dist/maintool-setup.sh /tmp/mt-test/setup.sh && cp node/maintool-agent /tmp/mt-test/agent.ref
chmod 777 /tmp/mt-test/fix
( cd /opt/maintool/app && runuser -u maintool -- /opt/maintool/venv/bin/python /tmp/mt-test/capture.py /tmp/mt-test/fix >/dev/null )
# De tests gebruiken ID 111 voor de nieuwe container; een echte guest met dat ID zou ze verstoren.
python3 -c "import json; f=\"/tmp/mt-test/fix/guests.json\"; g=json.load(open(f)); json.dump([x for x in g if x[\"vmid\"] != 111], open(f, \"w\"))"
chown -R nobody:nogroup /tmp/mt-test && chmod -R go-w /tmp/mt-test
RC=0; ( cd /tmp/mt-test && runuser -u nobody -- env QUIET="${QUIET-1}" bash run.sh ) || RC=$?
rm -rf /tmp/mt-test   # de testgegevens bevatten gegevens van het eigen cluster
exit $RC
