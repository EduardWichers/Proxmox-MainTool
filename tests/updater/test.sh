#!/usr/bin/env bash
# Test het bijwerkprogramma (updater/maintool-updater) met goede, kapotte en kwaadaardige bestanden.
# Draaien als root op de toolcontainer:  bash /root/maintool/tests/updater/test.sh
# De tests zelf draaien als gebruiker "nobody" in een tijdelijke map en raken het echte systeem niet.
set -e
cd /root/maintool && bash build.sh >/dev/null
T=$(mktemp -d /tmp/mt-upd-test.XXXXXX)
cp dist/maintool-setup.sh updater/maintool-updater tests/updater/test.py "$T/" && chown -R nobody:nogroup "$T" && chmod 755 "$T"
RC=0; ( cd "$T" && runuser -u nobody -- env QUIET="${QUIET-1}" TMPDIR="$T" python3 test.py "$T/maintool-setup.sh" "$T/maintool-updater" ) || RC=$?
rm -rf "$T"; exit $RC
