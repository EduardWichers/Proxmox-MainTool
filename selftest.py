#!/usr/bin/env python3
"""Zelftest van de Proxmox Maintool. Draait in de container als gebruiker 'maintool' en meldt wat werkt en wat
niet; maintool-setup.sh roept hem aan na installeren en bijwerken, met --lang nl|en|de voor de taal van de
meldingen (zonder: Nederlands). Leest alleen, verandert niets aan het cluster en toont geen geheimen."""
import os
import subprocess
import sys
import urllib.request

for line in open("/etc/maintool/maintool.env", encoding="utf-8"):
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())
sys.path.insert(0, "/opt/maintool/app")

errors = warnings = 0
LANG = sys.argv[sys.argv.index("--lang") + 1] if "--lang" in sys.argv[1:-1] else "nl"
# Nederlands -> (Engels, Duits); {0}, {1} ... worden ingevuld met t(tekst, ...).
TEXTS = {
    "let op": ("note", "Achtung"),
    "FOUT": ("ERROR", "FEHLER"),
    "de tool kan niet starten: {0}": ("the tool cannot start: {0}", "das Tool kann nicht starten: {0}"),
    "Zelftest Proxmox Maintool v{0}": ("Self-test Proxmox Maintool v{0}", "Selbsttest Proxmox Maintool v{0}"),
    "verbinding met Proxmox VE {0} via {1}": ("connection with Proxmox VE {0} through {1}", "Verbindung mit Proxmox VE {0} über {1}"),
    "de tool is alleen getest op Proxmox VE 9; op deze versie kan iets anders werken dan bedoeld":
        ("the tool has only been tested on Proxmox VE 9; on this version something may work differently than intended",
         "das Tool wurde nur auf Proxmox VE 9 getestet; auf dieser Version kann etwas anders funktionieren als gedacht"),
    "{0} node(s), waarvan {1} online": ("{0} node(s), of which {1} online", "{0} Node(s), davon {1} online"),
    "{0} container(s) en {1} VM('s) gevonden": ("{0} container(s) and {1} VM(s) found", "{0} Container und {1} VM(s) gefunden"),
    "VM's worden getoond en kun je starten, stoppen, migreren en back-uppen; updates en de console werken alleen voor containers":
        ("VMs are shown and you can start, stop, migrate and back them up; updates and the console only work for containers",
         "VMs werden angezeigt und lassen sich starten, stoppen, migrieren und sichern; Updates und die Konsole funktionieren nur für Container"),
    "Ceph gevonden: de node-kaarten tonen het gebruik per OSD": ("Ceph found: the node cards show the use per OSD",
                                                                 "Ceph gefunden: Die Node-Karten zeigen die Belegung pro OSD"),
    "geen Ceph: de node-kaarten tonen de lokale schijven": ("no Ceph: the node cards show the local disks",
                                                           "kein Ceph: Die Node-Karten zeigen die lokalen Platten"),
    "back-upopslag: {0}": ("backup storage: {0}", "Backup-Speicher: {0}"),
    "geen bruikbare back-upopslag gevonden; in een cluster moet die gedeeld zijn (NFS, CIFS, PBS). De rest van de tool werkt wel":
        ("no usable backup storage found; in a cluster it has to be shared (NFS, CIFS, PBS). The rest of the tool does work",
         "kein brauchbarer Backup-Speicher gefunden; in einem Cluster muss er gemeinsam sein (NFS, CIFS, PBS). Der Rest des Tools funktioniert"),
    "geen verbinding met de Proxmox-API: {0}": ("no connection with the Proxmox API: {0}", "keine Verbindung mit der Proxmox-API: {0}"),
    "hulpscript op node {0} ({1}) antwoordt": ("helper script on node {0} ({1}) answers", "Hilfsskript auf Node {0} ({1}) antwortet"),
    "hulpscript op node {0} is te oud (versie {1}); draai het setup-bestand met --update":
        ("helper script on node {0} is too old (version {1}); run the setup file with --update",
         "Hilfsskript auf Node {0} ist zu alt (Version {1}); führe die Setup-Datei mit --update aus"),
    "hulpscript op node {0} ({1}) is niet bereikbaar: {2}. Updates en herstarten werken voor die node niet":
        ("helper script on node {0} ({1}) cannot be reached: {2}. Updates and restarts do not work for that node",
         "Hilfsskript auf Node {0} ({1}) ist nicht erreichbar: {2}. Updates und Neustarts funktionieren für diesen Node nicht"),
    "node {0} antwoordt niet via de Proxmox-API: het cluster zoekt hem op {1} en krijgt geen antwoord. Meestal staat in /etc/hosts op {0} nog een oud adres; zet daar het juiste adres achter de naam en herstart die node":
        ("node {0} does not answer through the Proxmox API: the cluster looks for it at {1} and gets no answer. Usually /etc/hosts on {0} still holds an old address; put the right address after the name there and restart that node",
         "Node {0} antwortet nicht über die Proxmox-API: der Cluster sucht ihn unter {1} und bekommt keine Antwort. Meist steht in /etc/hosts auf {0} noch eine alte Adresse; trage dort die richtige Adresse hinter dem Namen ein und starte den Node neu"),
    "klopt {1} nog als adres van {0}? Proxmox neemt het uit /etc/hosts op die node; staat daar een oud adres, zet dan het juiste erin en herstart die node":
        ("is {1} still the address of {0}? Proxmox takes it from /etc/hosts on that node; if an old address is there, put the right one in and restart that node",
         "ist {1} noch die Adresse von {0}? Proxmox nimmt sie aus /etc/hosts auf diesem Node; steht dort eine alte Adresse, trage die richtige ein und starte den Node neu"),
    "de webpagina antwoordt (HTTP {0})": ("the web page answers (HTTP {0})", "die Webseite antwortet (HTTP {0})"),
    "de webpagina antwoordt niet: {0}": ("the web page does not answer: {0}", "die Webseite antwortet nicht: {0}"),
    "bijwerken via de pagina staat aan (menu > Tool bijwerken)": ("updating through the page is on (menu > Update the tool)",
                                                                  "Aktualisieren über die Seite ist eingeschaltet (Menü > Tool aktualisieren)"),
    "bijwerken via de pagina staat niet aan; draai het setup-bestand op een node met --update":
        ("updating through the page is not on; run the setup file on a node with --update",
         "Aktualisieren über die Seite ist nicht eingeschaltet; führe die Setup-Datei auf einem Node mit --update aus"),
    "catalogus van helper-scripts bereikbaar ({0} scripts)": ("catalogue of helper scripts reachable ({0} scripts)",
                                                             "Katalog der Helper-Scripts erreichbar ({0} Scripts)"),
    "de catalogus van helper-scripts is niet bereikbaar ({0}); alleen het zoekveld werkt dan niet":
        ("the catalogue of helper scripts cannot be reached ({0}); only the search field does not work then",
         "der Katalog der Helper-Scripts ist nicht erreichbar ({0}); nur das Suchfeld funktioniert dann nicht"),
    "Uitslag: {0} fout(en), {1} aandachtspunt(en).": ("Result: {0} error(s), {1} note(s).",
                                                       "Ergebnis: {0} Fehler, {1} Hinweis(e)."),
}


def t(text, *args):
    pair = TEXTS.get(text)
    if pair and LANG in ("en", "de"):
        text = pair[0 if LANG == "en" else 1]
    return text.format(*args)


def ok(text):
    print("  [ok]      " + text)


def warn(text):
    global warnings
    warnings += 1
    print(f"  [{t('let op')}]".ljust(12) + text)


def bad(text):
    global errors
    errors += 1
    print(f"  [{t('FOUT')}]".ljust(12) + text)


def reason(err) -> str:
    return str(getattr(err, "detail", None) or err).strip().splitlines()[-1][:200]


try:
    import main
except Exception as err:  # noqa: BLE001 - alles wat het starten breekt hoort hier gemeld te worden
    bad(t("de tool kan niet starten: {0}", reason(err)))
    sys.exit(1)

print(t("Zelftest Proxmox Maintool v{0}", main.VERSION))


def cluster(api):
    node = main.online_node(api)
    return (api.version.get(), api.nodes.get(), api.cluster.resources.get(type="vm"), main.node_ips(api),
            main.backup_storages(api), main.ceph_osds(api, node))


ips = {}
try:
    version, nodes, guests, ips, stores, osds = main.pve.run(cluster)
    ok(t("verbinding met Proxmox VE {0} via {1}", version.get("version"), main.pve.host))
    if not str(version.get("version", "")).startswith("9."):
        warn(t("de tool is alleen getest op Proxmox VE 9; op deze versie kan iets anders werken dan bedoeld"))
    online = [n for n in nodes if n.get("status") == "online"]
    (ok if len(online) == len(nodes) else warn)(t("{0} node(s), waarvan {1} online", len(nodes), len(online)))
    cts = sum(1 for g in guests if g.get("type") == "lxc")
    vms = len(guests) - cts
    ok(t("{0} container(s) en {1} VM('s) gevonden", cts, vms))
    if vms:
        warn(t("VM's worden getoond en kun je starten, stoppen, migreren en back-uppen; updates en de console werken alleen voor containers"))
    ok(t("Ceph gevonden: de node-kaarten tonen het gebruik per OSD") if osds
       else t("geen Ceph: de node-kaarten tonen de lokale schijven"))
    if stores:
        ok(t("back-upopslag: {0}", ", ".join(s["storage"] for s in stores)))
    else:
        warn(t("geen bruikbare back-upopslag gevonden; in een cluster moet die gedeeld zijn (NFS, CIFS, PBS). De rest van de tool werkt wel"))
    # Een node die online is maar via de API niet antwoordt: het cluster kent hem dan meestal onder een oud adres.
    for n in sorted(x["node"] for x in online):
        if not main.pve.run(lambda api, n=n: main.node_answers(api, n)):
            warn(t("node {0} antwoordt niet via de Proxmox-API: het cluster zoekt hem op {1} en krijgt geen antwoord. Meestal staat in /etc/hosts op {0} nog een oud adres; zet daar het juiste adres achter de naam en herstart die node",
                   n, ips.get(n) or "?"))
except Exception as err:  # noqa: BLE001
    bad(t("geen verbinding met de Proxmox-API: {0}", reason(err)))

for name, ip in sorted(ips.items()):
    try:
        found = main.agent_version(ip)
        if found >= 3:
            ok(t("hulpscript op node {0} ({1}) antwoordt", name, ip))
        else:
            warn(t("hulpscript op node {0} is te oud (versie {1}); draai het setup-bestand met --update", name, found))
    except Exception as err:  # noqa: BLE001
        warn(t("hulpscript op node {0} ({1}) is niet bereikbaar: {2}. Updates en herstarten werken voor die node niet", name, ip, reason(err)))
        if any(s in str(err) for s in ("No route to host", "timed out", "Network is unreachable")):
            print("            " + t("klopt {1} nog als adres van {0}? Proxmox neemt het uit /etc/hosts op die node; staat daar een oud adres, zet dan het juiste erin en herstart die node", name, ip))

try:
    context = main.cluster_ssl_context("/etc/maintool/tls.crt")  # het eigen certificaat van de tool
    context.check_hostname = False
    with urllib.request.urlopen("https://127.0.0.1:8443/login", context=context, timeout=10) as reply:
        (ok if reply.status == 200 else bad)(t("de webpagina antwoordt (HTTP {0})", reply.status))
except Exception as err:  # noqa: BLE001
    bad(t("de webpagina antwoordt niet: {0}", reason(err)))

watching = subprocess.run(["systemctl", "is-active", "maintool-update.path"], capture_output=True, text=True).stdout.strip()
if os.path.isfile("/usr/local/sbin/maintool-updater") and os.path.isfile("/usr/local/lib/maintool/baseline.sums") and watching == "active":
    ok(t("bijwerken via de pagina staat aan (menu > Tool bijwerken)"))
else:
    warn(t("bijwerken via de pagina staat niet aan; draai het setup-bestand op een node met --update"))

try:
    ok(t("catalogus van helper-scripts bereikbaar ({0} scripts)", main.scripts_catalog.get()["count"]))
except Exception as err:  # noqa: BLE001
    warn(t("de catalogus van helper-scripts is niet bereikbaar ({0}); alleen het zoekveld werkt dan niet", reason(err)))

print(t("Uitslag: {0} fout(en), {1} aandachtspunt(en).", errors, warnings))
sys.exit(1 if errors else 0)
