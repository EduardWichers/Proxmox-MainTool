#!/usr/bin/env bash
# Bouwt dist/maintool-setup.sh: het setup-bestand om te delen, met de hele tool erin.
# Draaien in de bronmap:  bash build.sh
# Er gaat alleen mee wat in FILES staat, en de bouw stopt als daar iets persoonlijks in staat
# (adressen, namen, mailadressen, sleutels van de omgeving waar de tool is gemaakt).
set -euo pipefail
cd "$(dirname "$0")"

FILES=(
    app/main.py app/VERSION app/static/index.html app/static/login.html
    app/static/xterm/xterm.js app/static/xterm/xterm.css app/static/xterm/addon-fit.js
    node/maintool-agent install.sh maintool.service maintool.env.example requirements.txt
    selftest.py LICENSE THIRD-PARTY.md
    updater/maintool-updater updater/maintool-update.service updater/maintool-update.path
)
VERSION=$(tr -d ' \n' <app/VERSION)
[[ $VERSION =~ ^[0-9]+(\.[0-9]+){1,2}$ ]] || { echo "Ongeldige versie in app/VERSION: $VERSION"; exit 1; }
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

for f in "${FILES[@]}"; do install -D -m 644 "$f" "$STAGE/pkg/$f"; done
# De uitleg heet in de bron zoals naast het setup-bestand: README.md (Engels, ook de voorpagina van de repository),
# LEESMIJ.md (Nederlands) en LIESMICH.md (Duits). In het pakket zit alleen de Nederlandse, als README.md: de updater
# kent alleen die naam als uitleg en weigert een pakket met bestanden die hij niet kent. De andere twee komen naast het
# setup-bestand en gaan wel door de controle hieronder.
# Een regel die eindigt op <!-- github --> (met de lege regel erna) is alleen voor de repository op GitHub: de link naar
# de ZIP van deze versie (GitHub zet het versienummer alleen in de naam van de ZIP van een tag). Die regel gaat niet
# mee in het pakket en niet naast het setup-bestand, en moet het versienummer uit app/VERSION noemen.
for f in README.md LEESMIJ.md LIESMICH.md; do
    grep -q " $VERSION .*(\.\./\.\./archive/refs/tags/v$VERSION\.zip).*<!-- github -->\$" "$f" \
        || { echo "De downloadregel in $f noemt niet versie $VERSION: zet daar v$VERSION in."; exit 1; }
done
nogithub() { sed '/<!-- github -->$/{N;d;}' "$1"; }
mkdir -p "$STAGE/share"
nogithub LEESMIJ.md >"$STAGE/pkg/README.md"
nogithub README.md >"$STAGE/share/README.md"
nogithub LIESMICH.md >"$STAGE/share/LIESMICH.md"
chmod 644 "$STAGE/pkg/README.md" "$STAGE/share/README.md" "$STAGE/share/LIESMICH.md"
sed "s/@VERSION@/$VERSION/g" setup/maintool-setup.template.sh >"$STAGE/setup.sh"

echo "== controles"
python3 -m py_compile "$STAGE/pkg/app/main.py" "$STAGE/pkg/selftest.py"
python3 -c 'import sys; compile(open(sys.argv[1], encoding="utf-8").read(), sys.argv[1], "exec")' "$STAGE/pkg/updater/maintool-updater"
find "$STAGE" -name __pycache__ -prune -exec rm -rf {} +
bash -n "$STAGE/pkg/install.sh"
bash -n "$STAGE/pkg/node/maintool-agent"
bash -n "$STAGE/setup.sh"
grep -q "Eduard Wichers" "$STAGE/pkg/app/static/index.html" "$STAGE/pkg/app/static/login.html" "$STAGE/pkg/LICENSE"
grep -q "Eduard Wichers" "$STAGE/share/README.md"
grep -q "Eduard Wichers" "$STAGE/share/LIESMICH.md"

python3 - "$STAGE" "$PWD/privacy-words.txt" <<'PY'
"""Zoekt in alles wat meegaat naar gegevens van de omgeving waar de tool is gemaakt, en naar geheimen."""
import pathlib
import re
import sys

# Voorbeelden in de uitleg en in de formulieren (niet het netwerk van de maker).
ALLOWED_IPS = {"192.168.1.1", "192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.50",
               "192.168.20.5", "10.10.10.0"}   # voorbeeldadressen in formulierteksten en meldingen (10.10.10.0/24: het Ceph-netwerk)
ALLOWED_MAIL = {"jij@voorbeeld.nl", "you@example.com", "du@beispiel.de"}   # voorbeelden in formulierteksten
CHECKS = [
    # Wel toegestaan: het adres van de repository op GitHub (naam/Proxmox-MainTool), waar de tool naar nieuwe versies kijkt.
    ("naam buiten de credits", re.compile(r"(?<!Eduard )wichers(?!/Proxmox-MainTool\b)", re.I), None),
    ("privé-IP-adres", re.compile(r"(?<![\d.])(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?![\d.])"), ALLOWED_IPS),
    ("mailadres", re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"), ALLOWED_MAIL),
    ("privésleutel", re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"), None),
    ("sleutel of token", re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"), None),
    ("SSH-sleutel", re.compile(r"ssh-(?:ed25519|rsa) AAAA[A-Za-z0-9+/]{30,}"), None),
]
# Namen uit de omgeving van de maker staan niet hier maar in privacy-words.txt naast build.sh: niet in git en niet in
# het pakket. Per regel een reguliere expressie; "i:" ervoor = hoofdletters maakt niet uit, "c:" = precies zo
# (eigennamen; anders valt gewone tekst als "het Proxmox-cluster" erin).
words = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else None
if words and words.is_file():
    for line in words.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            CHECKS.insert(0, ("naam uit de eigen omgeving", re.compile(line[2:] if line[:2] in ("i:", "c:") else line, re.I if line.startswith("i:") else 0), None))
else:
    print("   let op: geen privacy-words.txt naast build.sh; alleen de algemene controles")
stage, found = pathlib.Path(sys.argv[1]), []
for path in sorted(p for p in stage.rglob("*") if p.is_file()):
    name = str(path.relative_to(stage))
    if re.search(r"CLAUDE\.md|\.bak$|\.pem$|\.key$|state\.json|maintool\.env$", name):
        found.append(f"{name}: dit bestand hoort niet in het pakket")
    text = path.read_text(encoding="utf-8", errors="replace")
    for label, pattern, allowed in CHECKS:
        for m in pattern.finditer(text):
            if allowed and m.group(0) in allowed:
                continue
            line = text.count("\n", 0, m.start()) + 1
            found.append(f"{name}:{line}: {label}: {m.group(0)[:60]}")
if found:
    print("NIET GEBOUWD - dit mag niet in een pakket om te delen:")
    print("\n".join("   " + f for f in found[:40]))
    sys.exit(1)
print(f"   niets persoonlijks gevonden in {sum(1 for p in stage.rglob('*') if p.is_file())} bestanden")
PY

( cd "$STAGE/pkg" && find . -type f ! -name SHA256SUMS | sort | xargs sha256sum >SHA256SUMS )
mkdir -p dist
# Opbouw: het script, dan tussen __DOCS__ en __PAYLOAD__ de Engelse en Duitse uitleg (voor --readme en --liesmich;
# het script stopt bij exit 0 en de updater kijkt alleen na __PAYLOAD__), en als laatste de ingepakte tool.
{
    cat "$STAGE/setup.sh"
    echo "__DOCS__"
    tar czf - -C "$STAGE/share" --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$(date +%s)" README.md LIESMICH.md | base64 -w 76
    echo "__PAYLOAD__"
    tar czf - -C "$STAGE/pkg" --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$(date +%s)" . | base64 -w 76
} >dist/maintool-setup.sh
chmod 755 dist/maintool-setup.sh
install -m 644 "$STAGE/pkg/README.md" dist/LEESMIJ.md
install -m 644 "$STAGE/share/README.md" "$STAGE/share/LIESMICH.md" dist/

# Proef op de som: het gebouwde bestand moet zichzelf kunnen uitpakken en de licentie tonen.
bash -n dist/maintool-setup.sh
[[ $(bash dist/maintool-setup.sh --version) == "$VERSION" ]]
bash dist/maintool-setup.sh --licentie | grep -q "Eduard Wichers"
bash dist/maintool-setup.sh --readme | grep -q "^Made by Eduard Wichers"
bash dist/maintool-setup.sh --liesmich | grep -q "^Erstellt von Eduard Wichers"
bash dist/maintool-setup.sh --leesmij | grep -q "^Gemaakt door Eduard Wichers"
# Ook bovenin de bronmap: dat bestand gaat mee naar GitHub, zodat de ZIP van een versie meteen een setup-bestand bevat
# dat Tool bijwerken accepteert (de rest van de ZIP is de broncode). Het sjabloon in setup/ heet daarom anders.
cp dist/maintool-setup.sh maintool-setup.sh
echo "== gebouwd: dist/maintool-setup.sh (versie $VERSION, $(du -k dist/maintool-setup.sh | cut -f1) KB), ook als maintool-setup.sh"
sha256sum dist/maintool-setup.sh | tee dist/maintool-setup.sh.sha256
