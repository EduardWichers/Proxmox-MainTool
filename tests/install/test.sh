#!/usr/bin/env bash
# Test install.sh als gewone gebruiker, in een eigen map (MT_ROOT) met nagebootste systeemopdrachten: apt-get, systemctl,
# systemd-run, chown enzovoort schrijven alleen op wat ze gevraagd worden. De Python-pakketten worden echt geïnstalleerd
# (met controlesommen), uit een map met pakketten die de eerste keer van PyPI wordt gehaald.
#   bash tests/install/test.sh [WHEELMAP]
set -uo pipefail
SRC=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d /tmp/mt-install.XXXX)
WHEELS=${1:-/tmp/mt-wheels}
PASS=0; FAIL=0
ok()    { PASS=$((PASS + 1)); [[ -n ${QUIET:-} ]] || printf '  ok    %s\n' "$1"; }
bad()   { FAIL=$((FAIL + 1)); printf '  FOUT  %s\n' "$1"; }
check() { local label=$1; shift; if "$@" >/dev/null 2>&1; then ok "$label"; else bad "$label"; fi; }

if [[ ! -d $WHEELS ]] || ! ls "$WHEELS"/*.whl >/dev/null 2>&1; then
    mkdir -p "$WHEELS"
    python3 -m venv "$WORK/dl" && "$WORK/dl/bin/pip" download -q --disable-pip-version-check --require-hashes --only-binary :all: \
        -r "$SRC/requirements.txt" -d "$WHEELS" || { echo "pakketten konden niet worden opgehaald"; exit 1; }
fi

# ---------------------------------------------------------------- nagebootste systeemopdrachten
STUB=$WORK/stub; mkdir -p "$STUB"
for c in apt-get useradd chown journalctl; do printf '#!/bin/bash\necho "%s $*" >>"$CALLS"\n' "$c" >"$STUB/$c"; done
printf '#!/bin/bash\necho "id $*" >>"$CALLS"\nexit 0\n' >"$STUB/id"
printf '#!/bin/bash\necho maintool\n' >"$STUB/hostname"
cat >"$STUB/systemctl" <<'S'
#!/bin/bash
echo "systemctl $*" >>"$CALLS"
S
cat >"$STUB/install" <<'S'
#!/bin/bash
# zoals install, maar zonder eigenaar te zetten (dat kan alleen root)
args=(); while (($#)); do case $1 in -o | -g) shift 2 ;; *) args+=("$1"); shift ;; esac; done
exec /usr/bin/install "${args[@]}"
S
cat >"$STUB/openssl" <<'S'
#!/bin/bash
echo "openssl $*" >>"$CALLS"
while (($#)); do case $1 in -keyout | -out) : >"$2"; shift 2 ;; *) shift ;; esac; done
S
cat >"$STUB/ssh-keygen" <<'S'
#!/bin/bash
echo "ssh-keygen $*" >>"$CALLS"
while (($#)); do case $1 in -f) : >"$2"; echo "ssh-ed25519 AAAA test" >"$2.pub"; shift 2 ;; *) shift ;; esac; done
S
cat >"$STUB/systemd-run" <<'S'
#!/bin/bash
# Een proef van install.sh: mislukt als een eigenschap uit PROBE_FAIL erbij zit (of COMBINED_FAIL en er veel bij zitten);
# anders draait het programma echt (zonder afscherming), zodat ook de proef zelf wordt getest.
echo "systemd-run $*" >>"$CALLS"
props=(); while (($#)); do case $1 in -p) props+=("$2"); shift 2 ;; --*) shift ;; *) break ;; esac; done
for p in "${props[@]}"; do for f in ${PROBE_FAIL:-}; do [[ ${p%%=*} == "$f" ]] && exit 1; done; done
[[ -n ${COMBINED_FAIL:-} && ${#props[@]} -gt 10 ]] && exit 1
"$@"
S
cat >"$STUB/healthy" <<'S'
#!/bin/bash
# antwoordt de tool met versie $1? Ja als die in HEALTHY staat
echo "healthy $1" >>"$CALLS"
for v in ${HEALTHY:-}; do [[ $v == "$1" ]] && exit 0; done
exit 1
S
chmod +x "$STUB"/*

PKG=$WORK/pkg; mkdir -p "$PKG"
( cd "$SRC" && cp -r app requirements.txt maintool.service maintool.env.example install.sh updater node "$PKG"/ )
NEW=$(tr -d ' \n' <"$PKG/app/VERSION")
VENV="venvs/$(sha256sum "$PKG/requirements.txt" | cut -c1-16)"

run() {   # run NAAM [VAR=WAARDE ...]: install.sh in een eigen map; R is die map, RC de exitcode
    R=$WORK/$1; shift; mkdir -p "$R"; CALLS=$R/calls; : >"$CALLS"
    ( cd "$PKG" && env PATH="$STUB:/usr/bin:/bin" CALLS="$CALLS" MT_ROOT="$R" MT_HEALTH_CMD="$STUB/healthy" MT_HEALTH_WAIT=1 \
        PIP_NO_INDEX=1 PIP_FIND_LINKS="$WHEELS" MAINTOOL_SETUP=1 "$@" bash install.sh >"$R/out" 2>&1 )
    RC=$?
}
old_install() {   # old_install MAP VERSIE: een installatie zoals vóór 1.5.3 (venv als gewone map, alles van maintool)
    local r=$WORK/$1; mkdir -p "$r/opt/maintool/app" "$r/opt/maintool/venv/bin" "$r/etc/maintool/ssh" "$r/etc/systemd/system" "$r/usr/local/lib/maintool"
    echo "$2" >"$r/opt/maintool/app/VERSION"; echo "# oud" >"$r/opt/maintool/app/main.py"
    echo "#!/oud" >"$r/opt/maintool/venv/bin/uvicorn"; echo "APP_PASSWORD=x" >"$r/etc/maintool/maintool.env"
    : >"$r/etc/maintool/tls.crt"; : >"$r/etc/maintool/ssh/id_ed25519"
    echo "[Service] # oud" >"$r/etc/systemd/system/maintool.service"; echo "oud" >"$r/usr/local/lib/maintool/baseline.sums"
}
has()  { grep -qF -- "$2" "$1"; }
o()    { echo "$R/opt/maintool/$1"; }

printf '\n--- nieuwe installatie\n'
run nieuw
check "afgerond" test $RC = 0
check "pakketten in een eigen map, compleet" test -f "$(o "$VENV/.klaar")"
check "... met de juiste versies" bash -c "'$(o "$VENV/bin/python")' -c 'import fastapi, uvicorn, uvloop, httptools, websockets, proxmoxer, requests'"
check "venv wijst naar die map" test "$(readlink "$(o venv)")" = "$VENV"
check "programma op zijn plek, geen restanten" bash -c "test -f '$(o app/main.py)' && ! test -e '$(o app.new)' && ! test -e '$(o app.old)'"
check "dienst en afscherming neergezet" bash -c "cmp -s '$PKG/maintool.service' '$R/etc/systemd/system/maintool.service' && test -f '$R/etc/systemd/system/maintool.service.d/hardening.conf'"
check "alle 17 afschermingen geprobeerd en aan" test "$(grep -c '=' "$R/etc/systemd/system/maintool.service.d/hardening.conf")" = 17
check "de proef draaide als maintool met de basis-afscherming" has "$CALLS" "--uid=maintool --gid=maintool -p NoNewPrivileges=yes -p ProtectSystem=strict"
check "niet herstart (de setup start de dienst als de instellingen er zijn)" bash -c "! grep -q 'systemctl restart' '$CALLS'"
check "alles onder /opt/maintool van root" has "$CALLS" "chown -R root:root $R/opt/maintool"
check "bijwerkprogramma en baseline" bash -c "test -x '$R/usr/local/sbin/maintool-updater' && grep -q ' maintool.service$' '$R/usr/local/lib/maintool/baseline.sums'"
check "instellingen aangemaakt" test -f "$R/etc/maintool/maintool.env"

printf '\n--- bijwerken van een installatie van vóór 1.5.3\n'
old_install update 1.5.2
run update HEALTHY="$NEW"
check "afgerond" test $RC = 0
check "herstart en nagekeken" bash -c "grep -q 'systemctl restart maintool' '$CALLS' && grep -q 'healthy $NEW' '$CALLS'"
check "venv is nu een verwijzing naar de nieuwe map" test "$(readlink "$(o venv)")" = "$VENV"
check "oude venv, oud programma en oude dienst opgeruimd" bash -c "! test -e '$(o venv.old)' && ! test -e '$(o app.old)' && ! test -e '$R/etc/systemd/system/maintool.service.old'"
check "nieuwe versie op haar plek" test "$(cat "$(o app/VERSION)")" = "$NEW"
check "nieuwe baseline" has "$R/usr/local/lib/maintool/baseline.sums" "install.sh"
check "instellingen niet overschreven" test "$(cat "$R/etc/maintool/maintool.env")" = "APP_PASSWORD=x"

printf '\n--- bijwerken, maar de nieuwe versie start niet: de oude terug\n'
old_install terug 1.5.2
run terug HEALTHY="1.5.2"
check "exitcode 3: de oude draait weer" test $RC = 3
check "oude programma terug" test "$(cat "$(o app/VERSION)")" = "1.5.2"
check "oude venv terug, als gewone map" bash -c "test -d '$(o venv)' && ! test -L '$(o venv)' && test -f '$(o venv/bin/uvicorn)'"
check "oude dienst terug, zonder nieuwe afscherming" bash -c "grep -q oud '$R/etc/systemd/system/maintool.service' && ! test -e '$R/etc/systemd/system/maintool.service.d/hardening.conf'"
check "oude baseline blijft (de pagina werkt nog zoals voorheen)" test "$(cat "$R/usr/local/lib/maintool/baseline.sums")" = "oud"
check "nieuwe versie weer weg" bash -c "! test -e '$(o app.failed)' && ! test -e '$(o app.new)'"
check "twee keer herstart, beide versies nagekeken" bash -c "[[ \$(grep -c 'systemctl restart maintool' '$CALLS') == 2 ]] && grep -q 'healthy 1.5.2' '$CALLS'"
check "melding in de uitvoer" has "$R/out" "de vorige versie (1.5.2) wordt teruggezet"

printf '\n--- bijwerken, en ook de oude start niet\n'
old_install kapot 1.5.2
run kapot HEALTHY=""
check "exitcode 4" test $RC = 4
check "toch de oude bestanden terug" test "$(cat "$(o app/VERSION)")" = "1.5.2"

printf '\n--- afscherming die de container niet toelaat\n'
run deels PROBE_FAIL="PrivateDevices ProtectClock SystemCallFilter"
H=$R/etc/systemd/system/maintool.service.d/hardening.conf
check "afgerond" test $RC = 0
check "wat niet werkt staat er niet in" bash -c "! grep -qE '^(PrivateDevices|ProtectClock|SystemCallFilter|SystemCallErrorNumber)=' '$H'"
check "de rest wel" bash -c "grep -q '^ProtectKernelTunables=yes' '$H' && grep -q '^RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK' '$H'"
run samen COMBINED_FAIL=1
check "werkt alles apart maar niet samen: geen extra afscherming" test "$(grep -c '=' "$R/etc/systemd/system/maintool.service.d/hardening.conf")" = 0

printf '\n--- nog een keer bijwerken met dezelfde pakketlijst\n'
cp -r "$WORK/update" "$WORK/opnieuw"; touch -d '2000-01-01' "$WORK/opnieuw/opt/maintool/$VENV/.klaar"
run opnieuw HEALTHY="$NEW"
check "afgerond" test $RC = 0
check "pakketten niet opnieuw geïnstalleerd" test "$(stat -c %Y "$WORK/opnieuw/opt/maintool/$VENV/.klaar")" = "$(date -d '2000-01-01' +%s)"

printf '\n--- een andere pakketlijst: nieuwe map, de vorige blijft, oudere gaan weg\n'
cp -r "$WORK/update" "$WORK/lijst"; mkdir -p "$WORK/lijst/opt/maintool/venvs/oudste0000000000" "$WORK/lijst/opt/maintool/venvs/vorige0000000000"
ln -sfn venvs/vorige0000000000 "$WORK/lijst/opt/maintool/venv"
run lijst HEALTHY="$NEW"
check "afgerond" test $RC = 0
check "nieuwe map in gebruik, vorige bewaard, oudste weg" bash -c "test \"\$(readlink '$WORK/lijst/opt/maintool/venv')\" = '$VENV' && test -d '$WORK/lijst/opt/maintool/venvs/vorige0000000000' && ! test -e '$WORK/lijst/opt/maintool/venvs/oudste0000000000'"

printf '\n--- pakketten niet te krijgen\n'
old_install geennet 1.5.2
run geennet PIP_FIND_LINKS="$WORK/leeg"
check "exitcode 1, met uitleg" bash -c "[[ $RC == 1 ]] && grep -q 'konden niet worden geïnstalleerd' '$R/out'"
check "niets veranderd: oude programma, oude venv, geen halve pakketmap" bash -c "test \"\$(cat '$(o app/VERSION)')\" = 1.5.2 && test -d '$(o venv)' && ! test -L '$(o venv)' && ! test -e '$(o "$VENV")' && ! grep -q 'systemctl restart' '$CALLS'"

if [[ $FAIL == 0 ]]; then rm -rf "$WORK"; else echo "werkmap: $WORK"; fi
printf '\n=== %d geslaagd, %d mislukt ===\n' "$PASS" "$FAIL"
[[ $FAIL == 0 ]]
