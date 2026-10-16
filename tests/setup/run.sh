#!/usr/bin/env bash
# Tests maintool-setup.sh against stand-in Proxmox commands (bin/) and saved real API answers (fix/).
# Run as an unprivileged user: nothing here can touch the real system.
set -uo pipefail
BASE=$(cd "$(dirname "$0")" && pwd)
PASS=0; FAIL=0; EXTRA=()
FAKE_SECRET="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
CT_KEY="AAAAC3NzaC1lZDI1NTE5AAAAIMaintoolContainerSleutelVoorDeTest00000000000"
PW='Goed-Wachtwoord_2026!'
LOCAL=$(python3 -c 'import json,sys; print(next(e["name"] for e in json.load(open(sys.argv[1])) if e.get("type")=="node" and e.get("local")))' "$BASE/fix/status.json")
OTHER=$(python3 -c 'import json,sys; print(next(e["name"] for e in json.load(open(sys.argv[1])) if e.get("type")=="node" and not e.get("local")))' "$BASE/fix/status.json")

ok()    { PASS=$((PASS + 1)); [[ -n ${QUIET:-} ]] || printf '  ok    %s\n' "$1"; }
bad()   { FAIL=$((FAIL + 1)); printf '  FOUT  %s\n' "$1"; }
check() { local label=$1; shift; if "$@" >/dev/null 2>&1; then ok "$label"; else bad "$label"; fi; }
has()   { grep -qF -- "$2" "$1"; }
hasnt() { ! grep -qF -- "$2" "$1"; }
lines() { [[ $(grep -cF -- "$2" "$1") == "$3" ]]; }
rc()    { [[ $RC == "$1" ]]; }
nothing_changed() {   # geen enkele opdracht die iets aanmaakt, wijzigt of verwijdert
    ! grep -qE "^(pct (create|start|stop|destroy|push)|pct exec .* (sh -c|systemctl)|pvesh (create|set|delete)|scp |ssh |pveam download|ha-manager)" "$W/calls" \
        && cmp -s "$W/pve/priv/authorized_keys" "$W/auth.orig" && [[ ! -e $W/sbin/maintool-agent || -e $W/agent.seeded ]]
}
edit() { python3 - "$W/fix" "$LOCAL" "$OTHER" "$@"; }   # past de testgegevens van deze situatie aan (Python van stdin)
alltexts() {   # alltexts TAAL: alle meldingen van het setup-bestand in die taal, als ID<tab>tekst
    bash -c 'eval "$(sed -n "/^declare -A M/,/^# -* hulpjes/p" "$1")"
        for k in "${!M[@]}"; do [[ $k == "$2":* ]] && printf "%s\t%s\n" "${k#*:}" "${M[$k]}"; done' _ "$BASE/setup.sh" "$1" | sort
}
nodutch() {   # nodutch en|de: geen Nederlandse melding van het setup-bestand (die in die taal anders luidt) in de uitvoer
    alltexts nl >"$W/nl-texts"; alltexts "$1" >"$W/xx-texts"
    printf '%s\t%s\n' kop "LEES DIT EERST" kop "Dit gaat er gebeuren" kop "Klaar. Open de tool op" kop "Dit wordt verwijderd" \
        kop "Gebruik (als root" kop "GEBRUIK OP EIGEN RISICO" kop "Inloggen met gebruiker" kop "geen meerderheid" >>"$W/nl-texts"
    python3 - "$W/nl-texts" "$W/xx-texts" "$W/out" "$W" <<'PY'
import re, sys
read = lambda f: dict(l.split("\t", 1) for l in open(f, encoding="utf-8").read().splitlines() if "\t" in l)
nl, xx = read(sys.argv[1]), read(sys.argv[2])
out = open(sys.argv[3], encoding="utf-8").read().replace(sys.argv[4], "")   # de testmap telt niet mee
shared = "\n".join(xx.values())   # woorden die de andere taal zelf ook gebruikt (Container, router, Proxmox VE)
hits = sorted({p for k, t in nl.items() if xx.get(k) != t
               for p in (x.strip(" .:;,'\"()") for x in re.split(r"%s|\\n", t))
               if len(p) >= 6 and p in out and p not in shared})
print("\n".join(hits)); sys.exit(1 if hits else 0)
PY
}

prepare() {
    W=$BASE/work/$1; rm -rf "$W"; mkdir -p "$W"/{pve/priv,pve/nodes,ct,root,sbin,log,tmp}
    cp -r "$BASE/fix" "$W/fix"; : >"$W/calls"; EXTRA=(); LANGARGS=(--lang nl)   # standaard Nederlands, zonder taalvraag
    echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostKeyVanDezeNodeVoorDeTest000000000000000 root@node" >"$W/hostkey.pub"
    {   echo "ssh-rsa AAAAB3BeheerderSleutel root@laptop"
        echo "command=\"$W/sbin/maintool-agent\",from=\"192.168.30.202\",restrict ssh-ed25519 AAAAC3AndereMaintoolSleutel maintool"
    } >"$W/pve/priv/authorized_keys"
    cp "$W/pve/priv/authorized_keys" "$W/auth.orig"
    echo "dummy-ca" >"$W/pve/pve-root-ca.pem"
    cp "$BASE/setup.sh" "$W/maintool-setup.sh"
    A=$W/pve/priv/authorized_keys; E=$W/ct/etc/maintool/maintool.env
    printf '\n--- %s\n' "$1"
}
addrs() {   # addrs local|all: het adres van deze node, of van alle nodes, volgens de testgegevens van deze situatie
    python3 -c 'import json,sys; n=[e for e in json.load(open(sys.argv[1])) if e.get("type")=="node" and e.get("ip")]; print(" ".join(e["ip"] for e in n if sys.argv[2]=="all" or e.get("local")))' "$W/fix/status.json" "$1"
}
run() {   # run "invoer" [argumenten]
    printf '%s' "$1" >"$W/input"; shift
    local own all; own=$(addrs local); all=$(addrs all)
    ( cd "$W" && env -i PATH="$BASE/bin:/usr/bin:/bin:/usr/sbin:/sbin" HOME="$W" TMPDIR="$W/tmp" CALLS="$W/calls" FIX="$W/fix" CTROOT="$W/ct" \
        FAKE_SECRET="$FAKE_SECRET" CT_KEY="$CT_KEY" MT_PVE_DIR="$W/pve" MT_AGENT="$W/sbin/maintool-agent" MT_AGENT_LOG_DIR="$W/log/agent" \
        MT_HOSTKEY="$W/hostkey.pub" MT_BACKUP_DIR="$W/root" MT_LOG="$W/setup.log" MT_SKIP_ROOT_CHECK=1 \
        MT_LOCAL_ADDRS="127.0.0.1 $own ::1" MT_ANSWERS="$all" "${EXTRA[@]}" \
        bash "$W/maintool-setup.sh" "${LANGARGS[@]}" "$@" <"$W/input" >"$W/out" 2>&1 )
    RC=$?
    check "geen tijdelijke bestanden achtergebleven" test -z "$(ls -A "$W/tmp")"
    check "geen geheimen in uitvoer, logboek of opdrachten" bash -c "! grep -qF -e '$FAKE_SECRET' -e '$PW' '$W/out' '$W/setup.log' '$W/calls' 2>/dev/null"
}
show() { sed 's/^/        | /' "$W/out" | tail -"${1:-12}"; }
# Echte taalinstellingen zoals op een Proxmox-node (en_US.UTF-8, nl_NL.UTF-8), alleen voor deze tests gemaakt. Daaronder
# rekent bash [!-~], [a-z] en [0-9] anders dan in de kale omgeving van de andere tests: tot 1.4 weigerde de setup daar
# elk wachtwoord.
LOC=$BASE/work/locale; rm -rf "$LOC"; mkdir -p "$LOC"
for l in en_US nl_NL; do localedef -i "$l" -f UTF-8 "$LOC/$l.UTF-8" >/dev/null 2>&1 || true; done
GOOD=$'akkoord\n\n\nlocal-lvm\n\n192.168.30.240/24\n\n\n\n'"$PW"$'\n'"$PW"$'\n'   # geldige antwoorden, tot vóór de bevestiging

# =============================================================== installeren op het cluster, met eerst foute invoer
prepare installeren-cluster
run $'akkoord\nabc\n109\n\nSlechte Naam\n\n9\nlocal-lvm\n\n192.168.30.300/24\n192.168.30.2/24\n192.168.30.77/24\n192.168.30.240\n192.168.30.240/24\n10.0.0.1\n\n5000\n\n\nkort\nmet spatie erin 123\n'"$PW"$'\nx\n'"$PW"$'\n'"$PW"$'\nja\n'
check "afgerond zonder fout" rc 0
check "eindmelding met het adres" has "$W/out" "Klaar. Open de tool op:   https://192.168.30.240:8443"
check "waarschuwing getoond" has "$W/out" "GEBRUIK OP EIGEN RISICO"
for msg in "Een ID is een getal vanaf 100." "ID 109 is al in gebruik." "Gebruik kleine letters" "Dat staat niet in de lijst." \
           "Dat is geen geldig adres" "Dat is het adres van een node." "antwoordt al een apparaat" "ligt niet in hetzelfde netwerk" \
           "Een VLAN-nummer ligt tussen" "Te kort." "geen spaties" "niet gelijk"; do
    check "foute invoer opnieuw gevraagd: $msg" has "$W/out" "$msg"
done
check "container: ID, sjabloon Debian 13" has "$W/calls" "pct create 111 local:vztmpl/debian-13-standard_"
check "container: naam, schijf, netwerk" grep -qE "pct create 111 .*--hostname maintool .*--rootfs local-lvm:4 --net0 name=eth0,bridge=vmbr0,ip=192.168.30.240/24,gw=192.168.30.254 --unprivileged 1 .*--tags maintool" "$W/calls"
check "container: geen VLAN" hasnt "$W/calls" "tag="
check "sjabloonlijst ververst" has "$W/calls" "pveam update"
if has "$W/out" "ophalen..."; then check "sjabloon opgehaald" has "$W/calls" "pveam download local debian-13-standard_"; else check "sjabloon stond er al, niet opnieuw opgehaald" hasnt "$W/calls" "pveam download"; fi
check "installatie in de container gestart" has "$W/calls" "MAINTOOL_SETUP=1 bash install.sh"
check "instellingen: alle drie de nodes" grep -qE "^PVE_HOSTS=192\.168\.30\.[123],192\.168\.30\.[123],192\.168\.30\.[123]$" "$E"
check "instellingen: eigen toegangssleutel" has "$E" "PVE_TOKEN_NAME=ct111"
check "instellingen: geheim van de sleutel ingevuld" has "$E" "PVE_TOKEN_VALUE=$FAKE_SECRET"
check "instellingen: gebruiker en wachtwoord" bash -c "grep -qxF 'APP_USER=admin' '$E' && grep -qxF 'APP_PASSWORD=$PW' '$E'"
check "instellingen: tijdzone van de node" has "$E" "REPORT_TZ=Europe/Amsterdam"
check "instellingen: nette kop, geen dubbele regels" bash -c "[[ \$(grep -c 'Na een wijziging' '$E') == 1 && \$(head -1 '$E') == '# Instellingen van de Proxmox Maintool, ingevuld door maintool-setup. Hier staan geheimen in.' ]]"
check "samenvatting noemt alle 3 de nodes" has "$W/out" " Op alle 3 nodes:"
check "instellingen: mail staat uit" bash -c "grep -q '^#MAIL_USER=' '$E' && ! grep -q '^MAIL_' '$E'"
check "instellingen: alleen leesbaar voor root en de tool" has "$W/calls" "/etc/maintool/maintool.env --perms 640 --user root --group maintool"
check "certificaat van het cluster in de container" test -f "$W/ct/etc/maintool/pve-root-ca.pem"
check "hostsleutels van 3 nodes in de container" bash -c "[[ \$(grep -cE '^192\.168\.30\.[123] ssh-ed25519 AAAA' '$W/ct/etc/maintool/ssh/known_hosts') == 3 ]]"
check "hulpscript op deze node, uitvoerbaar en ongewijzigd" bash -c "[[ -x '$W/sbin/maintool-agent' ]] && cmp -s '$W/sbin/maintool-agent' '$BASE/agent.ref'"
check "hulpscript naar de 2 andere nodes" bash -c "[[ \$(grep -c '^scp ' '$W/calls') == 2 && \$(grep -c '^ssh ' '$W/calls') == 2 ]]"
check "authorized_keys: bestaande regels ongemoeid" bash -c "grep -qxF 'ssh-rsa AAAAB3BeheerderSleutel root@laptop' '$A' && grep -qF 'AAAAC3AndereMaintoolSleutel maintool' '$A' && [[ \$(wc -l <'$A') == 3 ]]"
check "authorized_keys: één nieuwe, beperkte regel" grep -qxF "command=\"$W/sbin/maintool-agent\",from=\"192.168.30.240\",restrict ssh-ed25519 $CT_KEY maintool-ct111" "$A"
check "authorized_keys: kopie van het oude bestand" bash -c "cmp -s '$W/root/'authorized_keys.voor-maintool.* '$W/auth.orig'"
check "gebruiker bestond al: niet opnieuw aangemaakt" hasnt "$W/calls" "pvesh create /access/users --userid"
check "rol Administrator op het hele cluster" has "$W/calls" "pvesh set /access/acl --path / --users maintool@pve --roles Administrator"
check "sleutel ct111 erbij, bestaande sleutel blijft" bash -c "python3 -c 'import json,sys; t={x[\"tokenid\"] for x in json.load(open(sys.argv[1]))}; sys.exit(0 if t=={\"webtool\",\"ct111\"} else 1)' '$W/fix/tokens.json'"
check "volgorde: eerst container, dan toegang, dan starten" bash -c "c=\$(grep -n '^pct create' '$W/calls' | cut -d: -f1); t=\$(grep -n 'token/ct111 --privsep' '$W/calls' | cut -d: -f1); s=\$(grep -n 'systemctl restart maintool' '$W/calls' | cut -d: -f1); (( c < t && t < s ))"
check "zelftest gedraaid" has "$W/out" "Zelftest (nagebootst)"
check "logboek geschreven" has "$W/setup.log" "installatie klaar, zelftest: ok"

# =============================================================== weigeren en afbreken
prepare weigeren-bij-waarschuwing; run $'nee\n'
check "gestopt" rc 1; check "melding" has "$W/out" "Niet akkoord: er is niets veranderd."; check "er is niets veranderd" nothing_changed

prepare weigeren-bij-samenvatting; run "$GOOD"$'nee\n'
check "gestopt" rc 1; check "samenvatting getoond" has "$W/out" "Dit gaat er gebeuren"; check "melding" has "$W/out" "er is niets veranderd"; check "er is niets veranderd" nothing_changed

prepare invoer-houdt-op; run $'akkoord\n'
check "gestopt" rc 1; check "melding" has "$W/out" "Geen invoer meer"; check "er is niets veranderd" nothing_changed

prepare bestand-beschadigd; head -c -3000 "$BASE/setup.sh" >"$W/maintool-setup.sh"; run "$GOOD"$'ja\n'
check "gestopt" rc 1; check "melding" has "$W/out" "GESTOPT: Dit bestand is beschadigd geraakt"; check "er is niets veranderd" nothing_changed

prepare bestand-onvolledig; sed '/^__PAYLOAD__$/,$d' "$BASE/setup.sh" >"$W/maintool-setup.sh"; run "$GOOD"$'ja\n'
check "gestopt" rc 1; check "melding" has "$W/out" "GESTOPT: Dit bestand is onvolledig: de ingepakte tool ontbreekt."; check "er is niets veranderd" nothing_changed

prepare setup-uit-de-broncode; sed -e 's/^VERSION=".*"$/VERSION="@VERSION@"/' -e '/^__DOCS__$/,$d' "$BASE/setup.sh" >"$W/maintool-setup.sh"; run "$GOOD"$'ja\n'
check "gestopt" rc 1; check "melding: het goede bestand of zelf bouwen" has "$W/out" "GESTOPT: Dit is het sjabloon van het setup-bestand uit de broncode, nog zonder de tool erin. Gebruik het bestand maintool-setup.sh bovenin de ZIP (naast LEESMIJ.md), of maak het zelf: draai in de uitgepakte map  bash build.sh  en daarna  bash dist/maintool-setup.sh"
check "er is niets veranderd" nothing_changed
LANGARGS=(--lang en); run '' --readme; check "ook bij --readme, in het Engels" has "$W/out" "STOPPED: This is the template of the setup file from the source code, still without the tool in it. Use the file maintool-setup.sh at the top of the ZIP"

# Op een ander cluster stond een node in het cluster nog op zijn oude adres (uit /etc/hosts op die node). Alles werkte
# half: de API van de andere node wachtte tevergeefs op hem en de tool bereikte het hulpscript niet. Nu meldt de setup
# dat vóór de vragen, met wat je eraan doet, en vraagt of je toch doorgaat.
prepare adres-van-deze-node-klopt-niet; EXTRA=(MT_LOCAL_ADDRS="127.0.0.1 192.168.30.99 ::1 fe80::1"); run $'akkoord\nnee\n'
OWN=$(addrs local)
check "gestopt" rc 1; check "melding: gestopt op jouw verzoek" has "$W/out" "Gestopt op jouw verzoek: er is niets veranderd."
check "kop van de waarschuwing" has "$W/out" " Let op: het adres van een node klopt waarschijnlijk niet"
check "wat er mis is (volledig in het logboek)" has "$W/setup.log" "Deze node ($LOCAL) staat in het cluster bekend als $OWN, maar heeft dat adres zelf niet (wel: 192.168.30.99)."
check "wat je eraan doet" bash -c "tr '\n' ' ' <'$W/out' | tr -s ' ' | grep -qF 'zet in /etc/hosts op die node het juiste adres achter zijn naam en herstart daarna die node (of alleen de dienst: systemctl restart pve-cluster).'"
check "nog geen vragen gesteld" hasnt "$W/out" "Een paar vragen"
check "er is niets veranderd" nothing_changed
check "regels van de waarschuwing niet breder dan 86 tekens" python3 -c 'import sys; t = open(sys.argv[1], encoding="utf-8").read(); sys.exit(0 if all(len(l) <= 86 for l in t[t.index(" Let op: het adres"):].splitlines()) else 1)' "$W/out"

prepare adres-van-deze-node-klopt-niet-toch-door; EXTRA=(MT_LOCAL_ADDRS="192.168.30.99"); run $'akkoord\nja\n'"${GOOD#akkoord$'\n'}"$'ja\n'
check "afgerond" rc 0; check "logboek: doorgegaan" has "$W/setup.log" "doorgegaan ondanks het adres van een node"

prepare andere-node-antwoordt-niet; SILENT=$(python3 -c 'import json,sys; print(next(e["ip"] for e in json.load(open(sys.argv[1])) if e.get("type")=="node" and e["name"]==sys.argv[2]))' "$W/fix/status.json" "$OTHER")
EXTRA=(MT_ANSWERS="$(addrs all | tr ' ' '\n' | grep -vxF "$SILENT" | paste -sd' ' -)"); run $'akkoord\nstop\n'
check "gestopt" rc 1; check "melding (volledig in het logboek)" has "$W/setup.log" "Node $OTHER staat in het cluster bekend als $SILENT, maar dat adres antwoordt niet vanaf deze node."
check "er is niets veranderd" nothing_changed

prepare adressen-kloppen; run $'akkoord\n'
check "geen waarschuwing als alles klopt" hasnt "$W/out" "Let op: het adres van een node"

prepare geen-proxmox-node; EXTRA=(PATH=/usr/bin:/bin); run "$GOOD"$'ja\n'
check "gestopt" rc 1; check "melding" has "$W/out" "hoort op een Proxmox VE-node te draaien"

prepare cluster-zonder-meerderheid; edit <<'PY'
import json, sys
f = sys.argv[1] + "/status.json"; s = json.load(open(f))
for e in s:
    if e.get("type") == "cluster": e["quorate"] = 0
json.dump(s, open(f, "w"))
PY
run "$GOOD"$'ja\n'
check "gestopt" rc 1; check "melding" has "$W/out" "geen meerderheid"; check "er is niets veranderd" nothing_changed

prepare proxmox-7; echo '{"version": "7.4-17", "release": "7.4"}' >"$W/fix/version.json"; run "$GOOD"$'ja\n'
check "gestopt" rc 1; check "melding" has "$W/out" "Proxmox VE 8 of nieuwer is nodig"

# =============================================================== storingen onderweg
prepare container-aanmaken-mislukt; EXTRA=(CREATE_FAIL=1); run "$GOOD"$'ja\n'
check "gestopt" rc 1; check "melding" has "$W/out" "De container kon niet worden aangemaakt"; check "geen opruimadvies (er is niets aangemaakt)" hasnt "$W/out" "Opruimen kan met"
check "geen toegangssleutel aangemaakt" hasnt "$W/calls" "token/ct111"

prepare container-zonder-internet; EXTRA=(NO_NET=1); run "$GOOD"$'ja\n'
check "gestopt" rc 1; check "melding" has "$W/out" "geen werkend internet of DNS"; check "opruimadvies" has "$W/out" "--uninstall 111"
check "geen toegangssleutel aangemaakt" hasnt "$W/calls" "token/ct111"; check "authorized_keys ongemoeid" cmp -s "$W/pve/priv/authorized_keys" "$W/auth.orig"

prepare installatie-in-container-mislukt; EXTRA=(INSTALL_FAIL=1); run "$GOOD"$'ja\n'
check "gestopt" rc 1; check "melding" has "$W/out" "Het installeren in de container is mislukt"; check "opruimadvies" has "$W/out" "--uninstall 111"

prepare andere-node-onbereikbaar; EXTRA=(SSH_FAIL=1); run "$GOOD"$'ja\n'
check "gestopt" rc 1; check "melding" has "$W/out" "Kan het hulpscript niet naar node"; check "authorized_keys ongemoeid" cmp -s "$W/pve/priv/authorized_keys" "$W/auth.orig"

prepare zelftest-meldt-fout; EXTRA=(SELFTEST_FAIL=1); run "$GOOD"$'ja\n'
check "installatie wel afgerond" rc 0; check "duidelijke waarschuwing" has "$W/out" "LET OP: de zelftest meldde een fout"

# =============================================================== bijzondere omgevingen
prepare node-met-eigen-certificaat-en-node-offline; mkdir -p "$W/pve/nodes/$OTHER"; : >"$W/pve/nodes/$OTHER/pveproxy-ssl.pem"; edit <<'PY'
import json, sys
f = sys.argv[1] + "/status.json"; s = json.load(open(f))
last = [e for e in s if e.get("type") == "node" and not e.get("local")][-1]
last["online"] = 0
open(sys.argv[1] + "/offline", "w").write(last["name"])
json.dump(s, open(f, "w"))
PY
OFF=$(cat "$W/fix/offline"); run "$GOOD"$'ja\n'
check "afgerond" rc 0; check "waarschuwing eigen certificaat" has "$W/out" "eigen certificaat op de webinterface"
check "waarschuwing node offline" has "$W/out" "niet online: $OFF"; check "offline node overgeslagen" has "$W/out" "$OFF: niet online, overgeslagen"
check "hostsleutels van de 2 bereikbare nodes" bash -c "[[ \$(wc -l <'$W/ct/etc/maintool/ssh/known_hosts') == 2 ]]"
check "instellingen noemen wel alle 3 de nodes" grep -qE "^PVE_HOSTS=[0-9.]+,[0-9.]+,[0-9.]+$" "$W/ct/etc/maintool/maintool.env"

prepare losse-node-proxmox-8-zonder-gebruiker; edit <<'PY'
import json, sys
d = sys.argv[1]
def put(name, value): json.dump(value, open(f"{d}/{name}.json", "w"))
put("status", [{"type": "node", "id": "node/pve", "name": "pve", "ip": "10.20.30.40", "online": 1, "local": 1, "nodeid": 0, "level": ""}])
put("version", {"version": "8.4.1", "release": "8.4", "repoid": "x"})
put("guests", []); put("ha", []); put("tmplcontent", []); put("tokens", [])
put("disks", [{"storage": "local-lvm", "type": "lvmthin", "active": 1, "enabled": 1, "shared": 0, "avail": 80 * 2**30, "content": "rootdir,images"},
              {"storage": "klein", "type": "dir", "active": 1, "enabled": 1, "shared": 0, "avail": 2 * 2**30, "content": "rootdir"}])
put("tmplstores", [{"storage": "local", "type": "dir", "active": 1, "enabled": 1, "content": "vztmpl,iso,backup"}])
put("bridges", [{"iface": "vmbr0", "type": "bridge", "active": 1, "cidr": "10.20.30.40/24", "address": "10.20.30.40", "gateway": "10.20.30.1"}])
import os; os.remove(f"{d}/user.json")
PY
run $'akkoord\n\n\n10.20.30.50/24\n\n7\nbeheer\n'"$PW"$'\n'"$PW"$'\nja\n'
check "afgerond" rc 0; check "waarschuwing: versie 8 niet getest" has "$W/out" "LET OP: Proxmox VE 8.4.1 is niet getest"
check "Debian 12 gekozen op Proxmox VE 8" has "$W/calls" "pct create 111 local:vztmpl/debian-12-standard_"
check "sjabloon opgehaald" has "$W/calls" "pveam download local debian-12-standard_"
check "te kleine opslag niet aangeboden, enige opslag gekozen" bash -c "grep -qF -- '--rootfs local-lvm:4' '$W/calls' && ! grep -qF 'klein' '$W/out'"
check "VLAN in het netwerk" has "$W/calls" "ip=10.20.30.50/24,gw=10.20.30.1,tag=7"
check "gebruiker aangemaakt" has "$W/calls" "pvesh create /access/users --userid maintool@pve --comment Proxmox Maintool"
check "instellingen: één node, eigen gebruikersnaam" bash -c "grep -qxF 'PVE_HOSTS=10.20.30.40' '$W/ct/etc/maintool/maintool.env' && grep -qxF 'APP_USER=beheer' '$W/ct/etc/maintool/maintool.env'"
check "samenvatting bij één node" has "$W/out" " Op deze node:"
check "geen SSH naar andere nodes" bash -c "! grep -qE '^(ssh|scp) ' '$W/calls'"
check "één hostsleutel in de container" bash -c "[[ \$(wc -l <'$W/ct/etc/maintool/ssh/known_hosts') == 1 ]] && grep -q '^10.20.30.40 ssh-ed25519 ' '$W/ct/etc/maintool/ssh/known_hosts'"
check "authorized_keys: regel met het nieuwe adres" has "$W/pve/priv/authorized_keys" "from=\"10.20.30.50\",restrict ssh-ed25519 $CT_KEY maintool-ct111"

# =============================================================== bijwerken
here() { edit "$@" <<'PY'
import json, sys
d, local, other, vmid, node, tags = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5], sys.argv[6]
f = d + "/guests.json"; g = [x for x in json.load(open(f)) if x.get("vmid") != vmid]
g.append({"vmid": vmid, "type": "lxc", "node": local if node == "hier" else other, "status": "running", "name": "tool", "tags": tags})
json.dump(g, open(f, "w"))
PY
}
prepare bijwerken-bestaande-109; here 109 hier ""
sed -i "s|AAAAC3AndereMaintoolSleutel maintool|$CT_KEY maintool|" "$W/pve/priv/authorized_keys"; cp "$W/pve/priv/authorized_keys" "$W/auth.orig"
run $'ja\n' --update 109
check "afgerond" rc 0; check "melding met versies" has "$W/out" "bijwerken van versie 0.9 naar $(bash $BASE/setup.sh --version)"
check "geen nieuwe container, geen nieuwe sleutel" bash -c "! grep -qE '^pct create|token/|pvesh (create|set|delete)' '$W/calls'"
check "nieuwe bestanden in de container gezet" has "$W/calls" "pct push 109 "; check "installatie in de container gedraaid" has "$W/calls" "MAINTOOL_SETUP=1 bash install.sh"
check "instellingen niet overschreven" test ! -e "$W/ct/etc/maintool/maintool.env"
check "hulpscript ververst" test -x "$W/sbin/maintool-agent"
check "authorized_keys: precies één regel voor deze sleutel, met het adres van de container" bash -c "[[ \$(grep -cF '$CT_KEY' '$A') == 1 && \$(wc -l <'$A') == 2 ]] && grep -qF 'from=\"192.168.30.202\",restrict ssh-ed25519 $CT_KEY maintool-ct109' '$A'"
check "herstart en zelftest" bash -c "grep -qF 'systemctl restart maintool' '$W/calls' && grep -qF 'Zelftest' '$W/out'"

prepare bijwerken-met-node-op-verkeerd-adres; here 109 hier ""; EXTRA=(MT_LOCAL_ADDRS="192.168.30.99"); run $'ja\n' --update 109
check "afgerond (geen extra vraag)" rc 0; check "waarschuwing getoond" has "$W/out" " Let op: het adres van een node klopt waarschijnlijk niet"
check "waarschuwing in het logboek" has "$W/setup.log" "Deze node ($LOCAL) staat in het cluster bekend als"

prepare bijwerken-geweigerd; here 109 hier ""; run $'nee\n' --update 109
check "gestopt" rc 1; check "er is niets veranderd" nothing_changed

prepare bijwerken-op-verkeerde-node; here 109 elders ""; run $'ja\n' --update 109
check "gestopt" rc 1; check "zegt op welke node het wel kan" has "$W/out" "Container 109 staat op node $OTHER. Voer dit bestand daar uit."; check "er is niets veranderd" nothing_changed

prepare bijwerken-zonder-id-niets-gevonden; run $'ja\n' --update
check "gestopt" rc 1; check "melding" has "$W/out" "Geen container met het label 'maintool' gevonden"

prepare bijwerken-zonder-id-gevonden-via-label; here 111 hier "maintool"; run $'ja\n' --update
check "afgerond" rc 0; check "juiste container gekozen" has "$W/out" "Container 111 ("

prepare bijwerken-geen-maintool-in-container; here 105 hier ""; EXTRA=(NO_TOOL=1); run $'ja\n' --update 105
check "gestopt" rc 1; check "melding" has "$W/out" "In container 105 staat geen Proxmox Maintool."; check "er is niets veranderd" nothing_changed

# =============================================================== verwijderen
seed_installed() {   # doet alsof CT 111 eerder met dit bestand is geïnstalleerd
    here 111 hier "maintool"; printf 'arch: amd64\nhostname: maintool\ntags: maintool\n' >"$W/fix/config-111"
    echo "command=\"$W/sbin/maintool-agent\",from=\"192.168.30.240\",restrict ssh-ed25519 $CT_KEY maintool-ct111" >>"$W/pve/priv/authorized_keys"
    cp "$W/pve/priv/authorized_keys" "$W/auth.orig"; echo agent >"$W/sbin/maintool-agent"; : >"$W/agent.seeded"
    edit <<'PY'
import json, sys
f = sys.argv[1] + "/tokens.json"; t = json.load(open(f)); t.append({"tokenid": "ct111", "privsep": 0, "expire": 0}); json.dump(t, open(f, "w"))
f = sys.argv[1] + "/ha.json"; h = json.load(open(f)); h.append({"sid": "ct:111", "type": "ct", "state": "started"}); json.dump(h, open(f, "w"))
PY
}
prepare verwijderen-naast-een-andere-maintool; seed_installed; run $'111\n' --uninstall 111
check "afgerond" rc 0
check "eerst uit HA gehaald" has "$W/calls" "ha-manager remove ct:111"
check "container gestopt en verwijderd" bash -c "grep -qxF 'pct stop 111' '$W/calls' && grep -qxF 'pct destroy 111 --purge 1 --destroy-unreferenced-disks 1' '$W/calls'"
check "alleen de eigen sleutel ingetrokken" bash -c "python3 -c 'import json,sys; t=[x[\"tokenid\"] for x in json.load(open(sys.argv[1]))]; sys.exit(0 if t==[\"webtool\"] else 1)' '$W/fix/tokens.json'"
check "gebruiker blijft (andere sleutel in gebruik)" bash -c "[[ -f '$W/fix/user.json' ]] && grep -qF 'gebruiker maintool@pve blijft staan' '$W/out'"
check "authorized_keys: alleen de eigen regel eruit" bash -c "[[ \$(wc -l <'$A') == 2 ]] && ! grep -qF 'maintool-ct111' '$A' && grep -qF 'AAAAC3AndereMaintoolSleutel maintool' '$A' && grep -qF 'BeheerderSleutel' '$A'"
check "hulpscript blijft voor de andere Maintool" bash -c "[[ -e '$W/sbin/maintool-agent' ]] && grep -qF 'een andere Maintool gebruikt het nog' '$W/out' && ! grep -q '^ssh ' '$W/calls'"

prepare verwijderen-laatste-maintool; seed_installed
grep -v "AndereMaintoolSleutel" "$W/pve/priv/authorized_keys" >"$W/x" && cat "$W/x" >"$W/pve/priv/authorized_keys"
echo '{"comment": "Proxmox Maintool", "enable": 1}' >"$W/fix/user.json"; echo '[{"tokenid": "ct111", "privsep": 0}]' >"$W/fix/tokens.json"
run $'111\n' --uninstall 111
check "afgerond" rc 0
check "gebruiker verwijderd (door dit bestand aangemaakt, geen sleutels meer)" bash -c "[[ ! -e '$W/fix/user.json' ]] && grep -qxF 'pvesh delete /access/users/maintool@pve' '$W/calls'"
check "authorized_keys: alleen de beheerdersregel over" bash -c "[[ \$(cat '$A') == 'ssh-rsa AAAAB3BeheerderSleutel root@laptop' ]]"
check "hulpscript van alle nodes gehaald" bash -c "[[ ! -e '$W/sbin/maintool-agent' && \$(grep -c '^ssh .*rm -f' '$W/calls') == 2 ]]"

prepare verwijderen-verkeerde-bevestiging; seed_installed; run $'ja\n' --uninstall 111
check "gestopt" rc 1; check "er is niets veranderd" nothing_changed

prepare verwijderen-container-zonder-label; here 109 hier ""; printf 'arch: amd64\nhostname: andere-container\n' >"$W/fix/config-109"; run $'109\n' --uninstall 109
check "geweigerd" rc 1; check "melding" has "$W/out" "niet door dit bestand aangemaakt. Ik verwijder hem niet."; check "er is niets veranderd" nothing_changed

prepare verwijderen-zonder-id; run $'\n' --uninstall
check "gestopt" rc 1; check "melding" has "$W/out" "Geef het ID van de container mee"

prepare verwijderen-op-verkeerde-node; here 111 elders "maintool"; run $'111\n' --uninstall 111
check "gestopt" rc 1; check "zegt op welke node het wel kan" has "$W/out" "staat op node $OTHER"; check "er is niets veranderd" nothing_changed

# =============================================================== talen
prepare alle-meldingen-in-drie-talen
check "elke melding heeft drie talen, en Engels en Duits wijken af van het Nederlands (behalve 'ja')" python3 - "$BASE/setup.sh" <<'PY'
import re, subprocess, sys
src = open(sys.argv[1], encoding="utf-8").read()
used = set(re.findall(r"\b(?:T|tf|retry) (\w+)", src))
dump = subprocess.run(["bash", "-c", 'eval "$(sed -n "/^declare -A M/,/^# -* hulpjes/p" "$1")"; for k in "${!M[@]}"; do printf "%s\t%s\n" "$k" "${M[$k]}"; done', "_", sys.argv[1]],
                      capture_output=True, text=True, check=True).stdout
m = dict(l.split("\t", 1) for l in dump.splitlines())
ids = {k.split(":", 1)[1] for k in m}
same = sorted(f"{lang}:{i}" for i in ids for lang in ("en", "de") if m.get(f"{lang}:{i}") == m.get(f"nl:{i}"))
ok = used == ids and all(m.get(f"{lang}:{i}") for i in ids for lang in ("nl", "en", "de")) and same == ["de:yes_word"]
print(sorted(used ^ ids), same); sys.exit(0 if ok else 1)
PY

prepare installeren-in-het-engels-via-de-taalvraag; LANGARGS=()
run $'\nagree\n\n\nlocal-lvm\n\n192.168.30.240/24\n\n\n\n'"$PW"$'\n'"$PW"$'\nyes\n'
check "afgerond" rc 0
check "taalkeuze getoond" bash -c "grep -qxF '  1) English' '$W/out' && grep -qxF '  2) Nederlands' '$W/out' && grep -qxF '  3) Deutsch' '$W/out'"
check "Enter = Engels (geen taal in de omgeving)" has "$W/out" "USE AT YOUR OWN RISK"
check "stappen en samenvatting in het Engels" bash -c "grep -qF '== A few questions' '$W/out' && grep -qF 'This is what will happen' '$W/out' && grep -qF ' On all 3 nodes:' '$W/out'"
check "eindmelding in het Engels" has "$W/out" "Done. Open the tool at:   https://192.168.30.240:8443"
check "zelftest in het Engels" has "$W/calls" "selftest.py --lang en"
check "omschrijving van de container in het Engels" has "$W/calls" "--description Proxmox Maintool - created with maintool-setup"
check "kop van de instellingen in het Engels" bash -c "[[ \$(head -1 '$E') == '# Settings of the Proxmox Maintool, filled in by maintool-setup. This file contains secrets.' ]]"
check "logboek in het Engels" has "$W/setup.log" "installation done, self-test: ok"
check "geen Nederlands in de uitvoer" nodutch en

prepare installeren-in-het-duits-met-foute-invoer; LANGARGS=()
run $'3\neinverstanden\nabc\n109\n\nSlechte Naam\n\n9\nlocal-lvm\n\n192.168.30.300/24\n192.168.30.2/24\n192.168.30.77/24\n192.168.30.240\n192.168.30.240/24\n10.0.0.1\n\n5000\n\n\nkort\nmet spatie erin 123\n'"$PW"$'\nx\n'"$PW"$'\n'"$PW"$'\nja\n'
check "afgerond" rc 0
for msg in "Eine ID ist eine Zahl ab 100." "ID 109 ist bereits vergeben." "Verwende Kleinbuchstaben" "Das steht nicht in der Liste." \
           "Das ist keine gültige Adresse" "Das ist die Adresse eines Nodes." "antwortet bereits ein Gerät" "liegt nicht im selben Netz" \
           "Eine VLAN-Nummer liegt zwischen" "Zu kurz." "keine Leerzeichen" "nicht gleich"; do
    check "foute invoer in het Duits: $msg" has "$W/out" "$msg"
done
check "waarschuwing, samenvatting en eindmelding in het Duits" bash -c "grep -qF 'ZUERST LESEN' '$W/out' && grep -qF ' Auf allen 3 Nodes:' '$W/out' && grep -qF 'Fertig. Öffne das Tool unter:   https://192.168.30.240:8443' '$W/out'"
check "zelftest in het Duits" has "$W/calls" "selftest.py --lang de"
check "geen Nederlands in de uitvoer" nodutch de

prepare taal-uit-de-omgeving; LANGARGS=(); EXTRA=(LANG=de_DE.UTF-8); run $'\n' --uninstall
check "Enter = Duits als de omgeving Duits is" has "$W/out" "Gib die ID des Containers mit an"

prepare taal-foute-keuze; LANGARGS=(); EXTRA=(LANG=nl_NL.UTF-8); run $'7\nfrans\n\n' --uninstall
check "foute keuze opnieuw gevraagd" lines "$W/out" "1 = English, 2 = Nederlands, 3 = Deutsch" 2
check "daarna Enter = Nederlands als de omgeving Nederlands is" has "$W/out" "Geef het ID van de container mee"

prepare taal-onbekend; LANGARGS=(--lang fr); run '' --help
check "geweigerd met foutcode 2" bash -c "[[ $RC == 2 ]] && grep -qF 'Unknown language / Onbekende taal / Unbekannte Sprache: fr' '$W/out'"
LANGARGS=(--lang=EN); run $'\n' --uninstall; check "--lang=EN werkt ook, zonder taalvraag" bash -c "grep -qF 'Give the ID of the container' '$W/out' && ! grep -qF '1) English' '$W/out'"
LANGARGS=(--taal); run '' --help; check "--taal zonder taal: geweigerd" bash -c "[[ $RC == 2 ]]"

prepare weigeren-in-het-engels; LANGARGS=(--lang en); run $'akkoord\n'
check "het Nederlandse woord telt niet in het Engels" bash -c "[[ $RC == 1 ]] && grep -qF 'Not agreed: nothing has been changed.' '$W/out'"
check "er is niets veranderd" nothing_changed

prepare weigeren-bij-samenvatting-in-het-duits; LANGARGS=(--sprache de); run $'Einverstanden\n\n\nlocal-lvm\n\n192.168.30.240/24\n\n\n\n'"$PW"$'\n'"$PW"$'\nyes\n'
check "'yes' telt niet in het Duits (en Einverstanden met hoofdletter wel)" bash -c "[[ $RC == 1 ]] && grep -qF 'Das wird passieren' '$W/out' && grep -qF 'Auf deinen Wunsch abgebrochen: Es wurde nichts geändert.' '$W/out'"
check "er is niets veranderd" nothing_changed

prepare bijwerken-in-het-engels; here 111 hier "maintool"; LANGARGS=(--lang en); run $'YES\n' --update
check "afgerond (YES in hoofdletters telt ook)" rc 0
check "meldingen in het Engels" bash -c "grep -qF 'Updating container 111 (' '$W/out' && grep -qF 'Done: container 111 now runs version' '$W/out'"
check "zelftest in het Engels" has "$W/calls" "selftest.py --lang en"; check "geen Nederlands in de uitvoer" nodutch en

prepare verwijderen-in-het-duits; seed_installed; LANGARGS=(--lang de); run $'111\n' --uninstall 111
check "afgerond" rc 0
check "lijst en slotmelding in het Duits" bash -c "grep -qF 'Das wird entfernt:' '$W/out' && grep -qF 'Fertig: Das Proxmox Maintool in Container 111 wurde entfernt.' '$W/out'"
check "geen Nederlands in de uitvoer" nodutch de

prepare wachtwoord-van-8-tekens; P8='Abcd-123'
run $'akkoord\n\n\nlocal-lvm\n\n192.168.30.240/24\n\n\n\nAbc-123\n'"$P8"$'\n'"$P8"$'\nja\n'
check "afgerond" rc 0
check "7 tekens te kort, 8 tekens goed" lines "$W/out" "Te kort." 1
check "wachtwoord van 8 tekens in de instellingen, niet in de uitvoer" bash -c "grep -qxF 'APP_PASSWORD=$P8' '$E' && ! grep -qF '$P8' '$W/out'"
check "de vraag noemt 8 tekens" bash -c "grep -qxF 'MIN_PASS=8                        # minimale lengte van het eerste wachtwoord; daarna geldt de instelling in de tool' '$BASE/setup.sh'"

prepare wachtwoord-met-engelse-taalinstelling; P1='Welkom123'
check "taalinstelling en_US.UTF-8 voor de test gemaakt" test -f "$LOC/en_US.UTF-8/LC_COLLATE"
check "die taalinstelling rekent echt anders: daar valt Welkom123 buiten [!-~]" env -i LOCPATH="$LOC" LC_ALL=en_US.UTF-8 bash -c '[[ ! Welkom123 =~ ^[\!-~]+$ ]]'
EXTRA=(LOCPATH="$LOC" LANG=en_US.UTF-8)
run $'akkoord\n\nmäintool\n\nlocal-lvm\n\n192.168.30.240/24\n\n\n\ncafé1234\n'"$P1"$'\n'"$P1"$'\nja\n'
check "afgerond" rc 0
check "gewoon wachtwoord aangenomen" grep -qxF "APP_PASSWORD=$P1" "$E"
check "é in het wachtwoord geweigerd" lines "$W/out" "Gebruik letters, cijfers en leestekens, maar geen spaties, aanhalingstekens of backslash." 1
check "ä in de naam geweigerd, daarna de standaardnaam" bash -c "grep -qF 'Gebruik kleine letters' '$W/out' && grep -qF -- '--hostname maintool ' '$W/calls'"
check "geen meldingen over de taalinstelling" bash -c "! grep -qiE 'setlocale|cannot change locale' '$W/out'"

prepare wachtwoord-met-leestekens-en-nederlandse-taalinstelling; P2='P@ssw0rd#~'
EXTRA=(LOCPATH="$LOC" LANG=nl_NL.UTF-8 LC_ALL=nl_NL.UTF-8)
run $'akkoord\n\n\nlocal-lvm\n\n192.168.30.240/24\n\n\n\nmet spatie 1\naa\'bbcccc\naa"bbcccc\naa\\bbcccc\n'"$P2"$'\n'"$P2"$'\nja\n'
check "afgerond" rc 0
check "leestekens aangenomen" grep -qxF "APP_PASSWORD=$P2" "$E"
check "spatie, aanhalingstekens en backslash geweigerd" lines "$W/out" "Gebruik letters, cijfers en leestekens, maar geen spaties, aanhalingstekens of backslash." 4
check "taal blijft Nederlands" has "$W/out" "Klaar. Open de tool op:"

prepare hulp-en-uitleg-in-drie-talen; LANGARGS=()
run '' --help;   check "hulp standaard in het Engels" has "$W/out" "Usage (as root, on a Proxmox VE node):"
run '' --hilfe;  check "Hilfe in het Duits" has "$W/out" "Verwendung (als root, auf einem Proxmox-VE-Node):"
run '' --hulp;   check "hulp in het Nederlands" has "$W/out" "Gebruik (als root, op een Proxmox VE-node):"
LANGARGS=(--lang de); run '' --help; check "--lang de --help" has "$W/out" "Verwendung (als root"
LANGARGS=()
run '' --readme;   check "readme: Engels" has "$W/out" "Made by Eduard Wichers."
check "readme: zonder de regel voor GitHub" hasnt "$W/out" "<!-- github -->"
run '' --liesmich; check "liesmich: Duits" has "$W/out" "Erstellt von Eduard Wichers."
run '' --leesmij;  check "leesmij: Nederlands" has "$W/out" "Gemaakt door Eduard Wichers."
run '' --lizenz;   check "licentie ook met --lizenz" has "$W/out" "Copyright (c) 2026 Eduard Wichers"
check "er is niets veranderd" nothing_changed

prepare uitleg-ontbreekt; sed '/^__DOCS__$/,/^__PAYLOAD__$/{/^__PAYLOAD__$/!d}' "$BASE/setup.sh" >"$W/maintool-setup.sh"; LANGARGS=(--lang en)
run '' --readme; check "uitleg ontbreekt: nette melding" bash -c "[[ $RC == 1 ]] && grep -qF 'STOPPED: This file is incomplete' '$W/out'"
run '' --leesmij; check "de ingepakte tool en zijn uitleg werken nog" has "$W/out" "Gemaakt door Eduard Wichers."

# =============================================================== overig
prepare hulp-en-licentie; run '' --help
check "hulp" has "$W/out" "bash $W/maintool-setup.sh --uninstall ID"
run '' --licentie; check "licentie" has "$W/out" "Copyright (c) 2026 Eduard Wichers"
run '' --leesmij; check "leesmij" has "$W/out" "Gebruik op eigen risico"
run '' --onzin; check "onbekende optie: uitleg en foutcode" bash -c "[[ $RC == 2 ]] && grep -qF 'Gebruik (als root' '$W/out'"
check "er is niets veranderd" nothing_changed

printf '\n=== %d geslaagd, %d mislukt ===\n' "$PASS" "$FAIL"
[[ $FAIL == 0 ]]
