#!/usr/bin/env bash
# Proxmox Maintool - setup file (version @VERSION@)
# (c) 2026 Eduard Wichers - MIT license - USE AT YOUR OWN RISK
#
# Run as root on a Proxmox VE node. It asks in English, Nederlands or Deutsch:
#     bash maintool-setup.sh                  install (asks a few questions and asks for confirmation)
#     bash maintool-setup.sh --update [ID]    update the tool in an existing container
#     bash maintool-setup.sh --uninstall ID   remove everything this file created
#     bash maintool-setup.sh --help           explanation
#
# This one file holds the whole tool: it is packed below the line __PAYLOAD__ at the end.
set -Eeuo pipefail

VERSION="@VERSION@"
PVE_USER="maintool@pve"
USER_COMMENT="Proxmox Maintool"   # alleen een gebruiker met precies deze omschrijving ruimt --uninstall weer op
TAG="maintool"                    # label op de container; zonder dit label verwijdert --uninstall niets
MIN_PASS=8                        # minimale lengte van het eerste wachtwoord; daarna geldt de instelling in de tool
# Vaste plekken op een node. De MT_*-variabelen bestaan alleen om dit bestand te kunnen testen.
PVE_DIR="${MT_PVE_DIR:-/etc/pve}"
AGENT="${MT_AGENT:-/usr/local/sbin/maintool-agent}"
AGENT_LOG_DIR="${MT_AGENT_LOG_DIR:-/var/log/maintool}"
HOSTKEY="${MT_HOSTKEY:-/etc/ssh/ssh_host_ed25519_key.pub}"
BACKUP_DIR="${MT_BACKUP_DIR:-/root}"
LOG="${MT_LOG:-/var/log/maintool-setup.log}"
AUTH="$PVE_DIR/priv/authorized_keys"
SELF="$0"
TMP=""
MODE=""
CTID=""
CREATED=""
UI=en          # taal van de vragen en meldingen: nl, en of de (zie het begin, onderaan)
LANG_FIXED=""  # met --lang meegegeven: dan wordt niet naar de taal gevraagd
STEP=""

# ---------------------------------------------------------------- teksten (Nederlands, Engels, Duits)

declare -A M
msg() { (( $# == 4 )) || { printf 'msg %s: drie talen verwacht\n' "$1" >&2; exit 3; }; M[nl:$1]=$2; M[en:$1]=$3; M[de:$1]=$4; }
T()  { printf '%s' "${M[$UI:$1]-[$1]}"; }                                  # de tekst in de gekozen taal
tf() { local __f=${M[$UI:$1]-[$1]}; shift; printf -- "$__f" "$@"; }       # idem, als printf-opmaak met %s

msg stopped        "GESTOPT" "STOPPED" "ABGEBROCHEN"
msg no_input       "Geen invoer meer; dit bestand moet je zelf in een terminal starten." \
                   "No more input; you have to start this file yourself in a terminal." \
                   "Keine Eingabe mehr; diese Datei musst du selbst in einem Terminal starten."
msg hint_cleanup   "De container %s is al aangemaakt. Opruimen kan met:  bash %s --uninstall %s" \
                   "Container %s has already been created. To clean up:  bash %s --uninstall %s" \
                   "Der Container %s wurde bereits angelegt. Aufräumen mit:  bash %s --uninstall %s"
msg went_wrong     "Er ging iets mis tijdens: %s (regel %s van dit bestand)." \
                   "Something went wrong during: %s (line %s of this file)." \
                   "Etwas ist schiefgegangen bei: %s (Zeile %s dieser Datei)."
msg logbook        "Logboek: %s" "Log: %s" "Protokoll: %s"
msg log_error      "FOUT tijdens: %s (regel %s)" "ERROR during: %s (line %s)" "FEHLER bei: %s (Zeile %s)"
msg step_prepare   "voorbereiden" "preparing" "Vorbereitung"
msg only_option    "(enige mogelijkheid)" "(the only option)" "(einzige Möglichkeit)"
msg pick           "Kies een nummer of typ de naam" "Choose a number or type the name" "Wähle eine Nummer oder tippe den Namen"
msg not_in_list    "Dat staat niet in de lijst." "That is not in the list." "Das steht nicht in der Liste."
msg save_first     "Sla dit bestand eerst op en start het dan met: bash maintool-setup.sh" \
                   "Save this file first and then start it with: bash maintool-setup.sh" \
                   "Speichere diese Datei zuerst und starte sie dann mit: bash maintool-setup.sh"
msg incomplete     "Dit bestand is onvolledig: de ingepakte tool ontbreekt. Haal het opnieuw op." \
                   "This file is incomplete: the packed tool is missing. Download it again." \
                   "Diese Datei ist unvollständig: Das eingepackte Tool fehlt. Lade sie erneut herunter."
msg from_source    "Dit is het sjabloon van het setup-bestand uit de broncode, nog zonder de tool erin. Gebruik het bestand maintool-setup.sh bovenin de ZIP (naast LEESMIJ.md), of maak het zelf: draai in de uitgepakte map  bash build.sh  en daarna  bash dist/maintool-setup.sh" \
                   "This is the template of the setup file from the source code, still without the tool in it. Use the file maintool-setup.sh at the top of the ZIP (next to README.md), or make it yourself: in the unpacked folder run  bash build.sh  and then  bash dist/maintool-setup.sh" \
                   "Das ist die Vorlage der Setup-Datei aus dem Quellcode, noch ohne das Tool darin. Benutze die Datei maintool-setup.sh oben in der ZIP (neben LIESMICH.md), oder erstelle sie selbst: Führe im entpackten Ordner  bash build.sh  und danach  bash dist/maintool-setup.sh  aus"
msg damaged_copy  "Dit bestand is beschadigd geraakt (bij het kopiëren of versturen). Haal het opnieuw op." \
                   "This file has been damaged (while copying or sending it). Download it again." \
                   "Diese Datei wurde beschädigt (beim Kopieren oder Versenden). Lade sie erneut herunter."
msg damaged_sums   "Dit bestand is beschadigd geraakt (de inhoud klopt niet meer). Haal het opnieuw op." \
                   "This file has been damaged (its contents no longer match). Download it again." \
                   "Diese Datei wurde beschädigt (der Inhalt stimmt nicht mehr). Lade sie erneut herunter."
msg need_root      "Voer dit uit als root." "Run this as root." "Führe dies als root aus."
msg missing_cmd    "'%s' ontbreekt. Dit bestand hoort op een Proxmox VE-node te draaien, niet in een container of op je eigen computer." \
                   "'%s' is missing. This file must run on a Proxmox VE node, not in a container or on your own computer." \
                   "'%s' fehlt. Diese Datei muss auf einem Proxmox-VE-Node laufen, nicht in einem Container oder auf deinem eigenen Computer."
msg arch_unknown   "onbekend" "unknown" "unbekannt"
msg arch           "Alleen gewone 64-bits pc-hardware (amd64) wordt ondersteund; deze node is '%s'." \
                   "Only ordinary 64-bit PC hardware (amd64) is supported; this node is '%s'." \
                   "Nur gewöhnliche 64-Bit-PC-Hardware (amd64) wird unterstützt; dieser Node ist '%s'."
msg pve_unknown    "Onbekende Proxmox-versie: %s" "Unknown Proxmox version: %s" "Unbekannte Proxmox-Version: %s"
msg pve_old        "Proxmox VE 8 of nieuwer is nodig; deze node draait %s." \
                   "Proxmox VE 8 or newer is needed; this node runs %s." \
                   "Proxmox VE 8 oder neuer ist nötig; auf diesem Node läuft %s."
msg no_quorum      "Het cluster heeft nu geen meerderheid (quorum); in die toestand kan er niets worden ingesteld." \
                   "The cluster has no majority (quorum) right now; nothing can be set up in that state." \
                   "Der Cluster hat gerade keine Mehrheit (Quorum); in diesem Zustand lässt sich nichts einrichten."
msg which_node     "Kan niet bepalen welke node dit is." "Cannot tell which node this is." "Kann nicht feststellen, welcher Node das ist."
msg addr_title     "Let op: het adres van een node klopt waarschijnlijk niet" "Note: the address of a node is probably wrong" \
                   "Achtung: die Adresse eines Nodes stimmt wahrscheinlich nicht"
msg addr_here      "Deze node (%s) staat in het cluster bekend als %s, maar heeft dat adres zelf niet (wel: %s)." \
                   "This node (%s) is known in the cluster as %s, but does not have that address itself (it does have: %s)." \
                   "Dieser Node (%s) ist im Cluster als %s bekannt, hat diese Adresse aber selbst nicht (sondern: %s)."
msg addr_silent    "Node %s staat in het cluster bekend als %s, maar dat adres antwoordt niet vanaf deze node." \
                   "Node %s is known in the cluster as %s, but that address does not answer from this node." \
                   "Node %s ist im Cluster als %s bekannt, aber diese Adresse antwortet von diesem Node aus nicht."
msg addr_why       "Proxmox neemt het adres van een node uit /etc/hosts op die node. Staat daar een oud adres, dan bereiken de andere nodes en de tool die node niet: pagina's laden traag of geven een fout, en updates en herstarten werken voor die node niet." \
                   "Proxmox takes the address of a node from /etc/hosts on that node. If an old address is there, the other nodes and the tool cannot reach that node: pages load slowly or give an error, and updates and restarts do not work for that node." \
                   "Proxmox nimmt die Adresse eines Nodes aus /etc/hosts auf diesem Node. Steht dort eine alte Adresse, erreichen die anderen Nodes und das Tool diesen Node nicht: Seiten laden langsam oder melden einen Fehler, und Updates und Neustarts funktionieren für diesen Node nicht."
msg addr_fix       "Oplossen: zet in /etc/hosts op die node het juiste adres achter zijn naam en herstart daarna die node (of alleen de dienst: systemctl restart pve-cluster). Start dit bestand dan opnieuw." \
                   "To fix it: put the right address after its name in /etc/hosts on that node and then restart that node (or just the service: systemctl restart pve-cluster). Then start this file again." \
                   "Lösung: Trage in /etc/hosts auf diesem Node die richtige Adresse hinter seinem Namen ein und starte den Node danach neu (oder nur den Dienst: systemctl restart pve-cluster). Starte diese Datei dann erneut."
msg addr_go        'Typ "%s" om toch door te gaan (iets anders stopt; er is nog niets veranderd)' \
                   'Type "%s" to continue anyway (anything else stops; nothing has been changed yet)' \
                   'Tippe "%s", um trotzdem fortzufahren (alles andere bricht ab; es wurde noch nichts geändert)'
msg log_addr_go    "doorgegaan ondanks het adres van een node" "continued despite the address of a node" "trotz der Adresse eines Nodes fortgefahren"
msg no_auth        "%s ontbreekt; is dit wel een Proxmox VE-node?" "%s is missing; is this really a Proxmox VE node?" \
                   "%s fehlt; ist das wirklich ein Proxmox-VE-Node?"
msg log_start      "start (%s) versie %s op node %s, Proxmox VE %s, %s node(s), taal %s" \
                   "start (%s) version %s on node %s, Proxmox VE %s, %s node(s), language %s" \
                   "Start (%s) Version %s auf Node %s, Proxmox VE %s, %s Node(s), Sprache %s"
msg agree_word     "akkoord" "agree" "einverstanden"
msg agree_prompt   'Typ "%s" om door te gaan (iets anders stopt)' 'Type "%s" to continue (anything else stops)' \
                   'Tippe "%s", um fortzufahren (alles andere bricht ab)'
msg not_agreed     "Niet akkoord: er is niets veranderd." "Not agreed: nothing has been changed." "Nicht einverstanden: Es wurde nichts geändert."
msg log_agreed     "waarschuwing geaccepteerd" "warning accepted" "Warnung akzeptiert"
msg step_questions "Een paar vragen" "A few questions" "Ein paar Fragen"
msg ask_id         "ID voor de nieuwe container" "ID for the new container" "ID für den neuen Container"
msg bad_id         "Een ID is een getal vanaf 100." "An ID is a number from 100 up." "Eine ID ist eine Zahl ab 100."
msg id_taken       "ID %s is al in gebruik." "ID %s is already in use." "ID %s ist bereits vergeben."
msg ask_name       "Naam van de container" "Name of the container" "Name des Containers"
msg bad_name       "Gebruik kleine letters, cijfers en streepjes." "Use lower-case letters, digits and hyphens." \
                   "Verwende Kleinbuchstaben, Ziffern und Bindestriche."
msg name_taken     "Er bestaat al een container of VM met die naam." "A container or VM with that name already exists." \
                   "Es gibt bereits einen Container oder eine VM mit diesem Namen."
msg gb_free        "vrij" "free" "frei"
msg shared         "gedeeld" "shared" "gemeinsam"
msg no_disk_store  "Geen opslag op deze node gevonden waar een container op kan staan (met minstens 5 GB vrij)." \
                   "No storage found on this node that can hold a container (with at least 5 GB free)." \
                   "Auf diesem Node wurde kein Speicher gefunden, auf dem ein Container liegen kann (mit mindestens 5 GB frei)."
msg ask_disk       "Op welke opslag komt de schijf van de container (4 GB)?" "On which storage should the container's disk (4 GB) go?" \
                   "Auf welchen Speicher kommt die Platte des Containers (4 GB)?"
msg no_tmpl_store  "Geen opslag gevonden voor containersjablonen (inhoud 'CT Templates'). Zet dat aan op bijvoorbeeld 'local'." \
                   "No storage found for container templates (content 'CT Templates'). Turn that on for 'local', for example." \
                   "Kein Speicher für Container-Vorlagen gefunden (Inhalt 'CT Templates'). Schalte das zum Beispiel für 'local' ein."
msg ask_tmpl       "Op welke opslag mag het Debian-sjabloon (ca. 130 MB) staan?" "On which storage may the Debian template (about 130 MB) be kept?" \
                   "Auf welchem Speicher darf die Debian-Vorlage (ca. 130 MB) liegen?"
msg no_address     "zonder eigen adres" "without its own address" "ohne eigene Adresse"
msg no_bridge      "Geen actieve netwerkbrug (zoals vmbr0) op deze node gevonden." "No active network bridge (such as vmbr0) found on this node." \
                   "Keine aktive Netzwerkbrücke (wie vmbr0) auf diesem Node gefunden."
msg ask_bridge     "Aan welk netwerk komt de container?" "Which network should the container connect to?" "An welches Netzwerk kommt der Container?"
msg ip_intro       "De container krijgt een vast IP-adres. Kies een adres dat nog vrij is en buiten het bereik\nvalt dat je router zelf uitdeelt." \
                   "The container gets a fixed IP address. Choose an address that is still free and outside the range\nyour router hands out itself." \
                   "Der Container bekommt eine feste IP-Adresse. Wähle eine Adresse, die noch frei ist und außerhalb des Bereichs\nliegt, den dein Router selbst vergibt."
msg ip_node_has    " Deze node zelf heeft %s." " This node itself has %s." " Dieser Node selbst hat %s."
msg ask_ip         "IP-adres met netwerkgrootte, bijvoorbeeld 192.168.1.50/24" "IP address with network size, for example 192.168.1.50/24" \
                   "IP-Adresse mit Netzgröße, zum Beispiel 192.168.1.50/24"
msg bad_ip         "Dat is geen geldig adres. Vergeet de /24 (of een andere netwerkgrootte) niet." \
                   "That is not a valid address. Do not forget the /24 (or another network size)." \
                   "Das ist keine gültige Adresse. Vergiss das /24 (oder eine andere Netzgröße) nicht."
msg ip_is_node     "Dat is het adres van een node." "That is the address of a node." "Das ist die Adresse eines Nodes."
msg ip_answers     "Op %s antwoordt al een apparaat. Kies een ander adres." "A device already answers on %s. Choose another address." \
                   "Unter %s antwortet bereits ein Gerät. Wähle eine andere Adresse."
msg ask_gw         "Adres van de router (gateway)" "Address of the router (gateway)" "Adresse des Routers (Gateway)"
msg bad_gw         "Dat is geen geldig adres." "That is not a valid address." "Das ist keine gültige Adresse."
msg gw_outside     "Dat adres ligt niet in hetzelfde netwerk als %s." "That address is not in the same network as %s." \
                   "Diese Adresse liegt nicht im selben Netz wie %s."
msg ask_vlan       "VLAN-nummer (leeg laten als je geen VLAN's gebruikt)" "VLAN number (leave empty if you do not use VLANs)" \
                   "VLAN-Nummer (leer lassen, wenn du keine VLANs benutzt)"
msg bad_vlan       "Een VLAN-nummer ligt tussen 1 en 4094." "A VLAN number is between 1 and 4094." "Eine VLAN-Nummer liegt zwischen 1 und 4094."
msg login_intro    "Inloggen op de tool zelf:" "Logging in to the tool itself:" "Anmelden am Tool selbst:"
msg ask_user       "Gebruikersnaam" "User name" "Benutzername"
msg bad_user       "Gebruik letters, cijfers, punt, streepje of @." "Use letters, digits, dot, hyphen or @." \
                   "Verwende Buchstaben, Ziffern, Punkt, Bindestrich oder @."
msg ask_pass       "Wachtwoord (minstens %s tekens; wat je typt blijft onzichtbaar)" "Password (at least %s characters; what you type stays invisible)" \
                   "Passwort (mindestens %s Zeichen; was du tippst, bleibt unsichtbar)"
msg too_short      "Te kort." "Too short." "Zu kurz."
msg bad_pass       "Gebruik letters, cijfers en leestekens, maar geen spaties, aanhalingstekens of backslash." \
                   "Use letters, digits and punctuation, but no spaces, quotes or backslash." \
                   "Verwende Buchstaben, Ziffern und Satzzeichen, aber keine Leerzeichen, Anführungszeichen oder Backslash."
msg ask_pass2      "Nog een keer hetzelfde wachtwoord" "The same password again" "Noch einmal dasselbe Passwort"
msg pass_differ    "De twee wachtwoorden zijn niet gelijk." "The two passwords are not the same." "Die beiden Passwörter sind nicht gleich."
msg not_online     "LET OP: niet online:%s. Daar komt het hulpscript nu niet; draai later --update." \
                   "NOTE: not online:%s. The helper script does not go there now; run --update later." \
                   "ACHTUNG: nicht online:%s. Dort kommt das Hilfsskript jetzt nicht hin; führe später --update aus."
msg own_cert       " LET OP: deze node(s) hebben een eigen certificaat op de webinterface (bijvoorbeeld van\n Let's Encrypt):%s. De tool controleert nodes met het certificaat van het cluster en kan\n zo'n node daardoor waarschijnlijk niet bereiken. De zelftest aan het eind laat het zien." \
                   " NOTE: these node(s) have their own certificate on the web interface (for example from\n Let's Encrypt):%s. The tool checks nodes against the certificate of the cluster and can\n therefore probably not reach such a node. The self-test at the end will show it." \
                   " ACHTUNG: Diese Node(s) haben ein eigenes Zertifikat auf der Weboberfläche (zum Beispiel von\n Let's Encrypt):%s. Das Tool prüft Nodes mit dem Zertifikat des Clusters und kann\n einen solchen Node deshalb wahrscheinlich nicht erreichen. Der Selbsttest am Ende zeigt es."
msg pve_untested   "LET OP: Proxmox VE %s is niet getest; de tool is gemaakt op versie 9." \
                   "NOTE: Proxmox VE %s has not been tested; the tool was made on version 9." \
                   "ACHTUNG: Proxmox VE %s wurde nicht getestet; das Tool wurde auf Version 9 erstellt."
msg yes_word       "ja" "yes" "ja"
msg run_prompt     'Typ "%s" om dit uit te voeren (iets anders stopt)' 'Type "%s" to carry this out (anything else stops)' \
                   'Tippe "%s", um das auszuführen (alles andere bricht ab)'
msg stopped_by_you "Gestopt op jouw verzoek: er is niets veranderd." "Stopped at your request: nothing has been changed." \
                   "Auf deinen Wunsch abgebrochen: Es wurde nichts geändert."
msg log_confirmed  "bevestigd: CT %s %s op %s, %s %s via %s, gebruiker %s" "confirmed: CT %s %s on %s, %s %s via %s, user %s" \
                   "bestätigt: CT %s %s auf %s, %s %s über %s, Benutzer %s"
msg step_template  "Debian-sjabloon zoeken" "Looking for the Debian template" "Debian-Vorlage suchen"
msg tmpl_list_old  "de lijst met sjablonen kon niet worden ververst; verder met de bestaande lijst" \
                   "the list of templates could not be refreshed; continuing with the existing list" \
                   "die Liste der Vorlagen konnte nicht aktualisiert werden; weiter mit der vorhandenen Liste"
msg no_debian      "Geen Debian 12- of 13-sjabloon gevonden in de lijst van Proxmox (pveam available)." \
                   "No Debian 12 or 13 template found in the list of Proxmox (pveam available)." \
                   "Keine Debian-12- oder -13-Vorlage in der Liste von Proxmox gefunden (pveam available)."
msg tmpl_there     "%s staat er al" "%s is already there" "%s ist bereits vorhanden"
msg tmpl_fetch     "%s ophalen..." "downloading %s..." "%s wird heruntergeladen..."
msg tmpl_failed    "Het sjabloon kon niet worden opgehaald (heeft deze node internet?). Zie %s." \
                   "The template could not be downloaded (does this node have internet?). See %s." \
                   "Die Vorlage konnte nicht heruntergeladen werden (hat dieser Node Internet?). Siehe %s."
msg step_create    "Container %s aanmaken" "Creating container %s" "Container %s anlegen"
msg ct_description "Proxmox Maintool - aangemaakt met maintool-setup %s" "Proxmox Maintool - created with maintool-setup %s" \
                   "Proxmox Maintool - angelegt mit maintool-setup %s"
msg create_failed  "De container kon niet worden aangemaakt. Zie %s." "The container could not be created. See %s." \
                   "Der Container konnte nicht angelegt werden. Siehe %s."
msg start_failed   "De container start niet. Zie %s." "The container does not start. See %s." "Der Container startet nicht. Siehe %s."
msg wait_net       "wachten op het netwerk in de container..." "waiting for the network in the container..." "warten auf das Netzwerk im Container..."
msg no_internet    "De container heeft geen werkend internet of DNS (adres %s, router %s). Controleer die gegevens." \
                   "The container has no working internet or DNS (address %s, router %s). Check those details." \
                   "Der Container hat kein funktionierendes Internet oder DNS (Adresse %s, Router %s). Prüfe diese Angaben."
msg step_install   "De tool in de container zetten (dit duurt een paar minuten)" "Putting the tool into the container (this takes a few minutes)" \
                   "Das Tool in den Container bringen (das dauert ein paar Minuten)"
msg install_failed "Het installeren in de container is mislukt (heeft de container internet?). Zie %s." \
                   "Installing in the container failed (does the container have internet?). See %s." \
                   "Die Installation im Container ist fehlgeschlagen (hat der Container Internet?). Siehe %s."
msg installed      "geïnstalleerd" "installed" "installiert"
msg step_access    "Toegang tot Proxmox regelen" "Arranging access to Proxmox" "Zugriff auf Proxmox einrichten"
msg user_created   "gebruiker %s aangemaakt" "user %s created" "Benutzer %s angelegt"
msg token_created  "toegangssleutel %s aangemaakt" "access key %s created" "Zugriffsschlüssel %s angelegt"
msg env_head1      "# Instellingen van de Proxmox Maintool, ingevuld door maintool-setup. Hier staan geheimen in." \
                   "# Settings of the Proxmox Maintool, filled in by maintool-setup. This file contains secrets." \
                   "# Einstellungen des Proxmox Maintool, ausgefüllt von maintool-setup. Hier stehen Geheimnisse drin."
msg env_head2      "# Na een wijziging: systemctl restart maintool" "# After a change: systemctl restart maintool" \
                   "# Nach einer Änderung: systemctl restart maintool"
msg settings_put   "instellingen en het certificaat van het cluster staan in de container" \
                   "the settings and the certificate of the cluster are in the container" \
                   "die Einstellungen und das Zertifikat des Clusters liegen im Container"
msg step_agent     "Hulpscript op de nodes zetten" "Putting the helper script on the nodes" "Hilfsskript auf die Nodes bringen"
msg node_offline   "%s: niet online, overgeslagen (draai later --update)" "%s: not online, skipped (run --update later)" \
                   "%s: nicht online, übersprungen (führe später --update aus)"
msg scp_failed     "Kan het hulpscript niet naar node %s (%s) kopiëren." "Cannot copy the helper script to node %s (%s)." \
                   "Kann das Hilfsskript nicht auf Node %s (%s) kopieren."
msg ssh_failed     "Node %s (%s) reageert niet via SSH." "Node %s (%s) does not respond over SSH." "Node %s (%s) antwortet nicht über SSH."
msg bad_hostkey    "Onverwachte hostsleutel van node %s." "Unexpected host key from node %s." "Unerwarteter Host-Schlüssel von Node %s."
msg bad_key        "Onverwachte sleutel in de container." "Unexpected key in the container." "Unerwarteter Schlüssel im Container."
msg key_allowed    "sleutel toegelaten voor het hulpscript, alleen vanaf %s (kopie van het oude bestand: %s)" \
                   "key allowed for the helper script, only from %s (copy of the old file: %s)" \
                   "Schlüssel für das Hilfsskript zugelassen, nur von %s aus (Kopie der alten Datei: %s)"
msg step_start     "Starten en nakijken" "Starting and checking" "Starten und prüfen"
msg no_such_ct     "Er bestaat geen container met ID %s." "There is no container with ID %s." "Es gibt keinen Container mit der ID %s."
msg is_vm          "%s is een VM, geen container." "%s is a VM, not a container." "%s ist eine VM, kein Container."
msg other_node     "Container %s staat op node %s. Voer dit bestand daar uit." "Container %s is on node %s. Run this file there." \
                   "Container %s liegt auf Node %s. Führe diese Datei dort aus."
msg selftest_warn  "LET OP: de zelftest meldde een fout (zie hierboven). De tool werkt mogelijk niet goed." \
                   "NOTE: the self-test reported an error (see above). The tool may not work properly." \
                   "ACHTUNG: Der Selbsttest hat einen Fehler gemeldet (siehe oben). Das Tool funktioniert möglicherweise nicht richtig."
msg log_installed  "installatie klaar, zelftest: %s" "installation done, self-test: %s" "Installation fertig, Selbsttest: %s"
msg no_tagged      "Geen container met het label '%s' gevonden. Geef het ID mee: bash %s --update ID" \
                   "No container with the tag '%s' found. Give the ID: bash %s --update ID" \
                   "Kein Container mit dem Tag '%s' gefunden. Gib die ID mit an: bash %s --update ID"
msg many_tagged    "Meerdere containers met het label '%s' (%s). Geef het ID mee: bash %s --update ID" \
                   "Several containers with the tag '%s' (%s). Give the ID: bash %s --update ID" \
                   "Mehrere Container mit dem Tag '%s' (%s). Gib die ID mit an: bash %s --update ID"
msg bad_id_arg     "Ongeldig ID: %s" "Invalid ID: %s" "Ungültige ID: %s"
msg not_running    "Container %s draait niet. Start hem eerst." "Container %s is not running. Start it first." \
                   "Container %s läuft nicht. Starte ihn zuerst."
msg no_tool        "In container %s staat geen Proxmox Maintool." "Container %s does not hold a Proxmox Maintool." \
                   "In Container %s ist kein Proxmox Maintool."
msg older_than     "ouder dan 1.0" "older than 1.0" "älter als 1.0"
msg no_ct_ip       "Het IP-adres van container %s is niet te vinden." "The IP address of container %s cannot be found." \
                   "Die IP-Adresse von Container %s ist nicht zu finden."
msg update_intro   "Container %s (%s) bijwerken van versie %s naar %s. Instellingen en gegevens blijven staan." \
                   "Updating container %s (%s) from version %s to %s. Settings and data stay." \
                   "Container %s (%s) wird von Version %s auf %s aktualisiert. Einstellungen und Daten bleiben erhalten."
msg go_prompt      'Typ "%s" om door te gaan' 'Type "%s" to continue' 'Tippe "%s", um fortzufahren'
msg update_done    "Klaar: container %s draait nu versie %s. Herlaad de pagina in je browser." \
                   "Done: container %s now runs version %s. Reload the page in your browser." \
                   "Fertig: Container %s läuft jetzt mit Version %s. Lade die Seite in deinem Browser neu."
msg selftest_bad   "LET OP: de zelftest meldde een fout (zie hierboven)." "NOTE: the self-test reported an error (see above)." \
                   "ACHTUNG: Der Selbsttest hat einen Fehler gemeldet (siehe oben)."
msg log_updated    "bijwerken klaar, zelftest: %s" "update done, self-test: %s" "Aktualisierung fertig, Selbsttest: %s"
msg give_id        "Geef het ID van de container mee: bash %s --uninstall ID" "Give the ID of the container: bash %s --uninstall ID" \
                   "Gib die ID des Containers mit an: bash %s --uninstall ID"
msg no_label       "Container %s heeft het label '%s' niet en is dus niet door dit bestand aangemaakt. Ik verwijder hem niet." \
                   "Container %s does not have the tag '%s', so it was not created by this file. I will not remove it." \
                   "Container %s hat das Tag '%s' nicht und wurde also nicht von dieser Datei angelegt. Ich entferne ihn nicht."
msg type_id        "Typ het ID (%s) om dit definitief te verwijderen" "Type the ID (%s) to remove this for good" \
                   "Tippe die ID (%s), um das endgültig zu entfernen"
msg step_remove    "Container %s verwijderen" "Removing container %s" "Container %s entfernen"
msg destroy_failed "De container kon niet worden verwijderd. Zie %s." "The container could not be removed. See %s." \
                   "Der Container konnte nicht entfernt werden. Siehe %s."
msg ct_removed     "container verwijderd" "container removed" "Container entfernt"
msg step_revoke    "Toegang intrekken" "Revoking access" "Zugriff entziehen"
msg token_removed  "toegangssleutel %s verwijderd" "access key %s removed" "Zugriffsschlüssel %s entfernt"
msg token_gone     "toegangssleutel %s bestond niet meer" "access key %s no longer existed" "Zugriffsschlüssel %s existierte nicht mehr"
msg user_removed   "gebruiker %s verwijderd" "user %s removed" "Benutzer %s entfernt"
msg user_stays     "gebruiker %s blijft staan (nog in gebruik, of niet door dit bestand aangemaakt)" \
                   "user %s stays (still in use, or not created by this file)" \
                   "Benutzer %s bleibt bestehen (noch in Gebrauch oder nicht von dieser Datei angelegt)"
msg rule_removed   "regel voor container %s uit %s gehaald" "line for container %s removed from %s" "Zeile für Container %s aus %s entfernt"
msg step_rm_agent  "Hulpscript van de nodes halen" "Removing the helper script from the nodes" "Hilfsskript von den Nodes entfernen"
msg rm_failed      "%s: niet gelukt, verwijder %s daar zelf" "%s: did not work, remove %s there yourself" \
                   "%s: hat nicht geklappt, entferne %s dort selbst"
msg rm_offline     "%s: niet online, verwijder %s daar later zelf" "%s: not online, remove %s there yourself later" \
                   "%s: nicht online, entferne %s dort später selbst"
msg rm_done        "%s: verwijderd" "%s: removed" "%s: entfernt"
msg agent_stays    "het hulpscript blijft op de nodes staan: een andere Maintool gebruikt het nog" \
                   "the helper script stays on the nodes: another Maintool still uses it" \
                   "das Hilfsskript bleibt auf den Nodes: ein anderes Maintool benutzt es noch"
msg removed_all    "Klaar: de Proxmox Maintool in container %s is verwijderd." "Done: the Proxmox Maintool in container %s has been removed." \
                   "Fertig: Das Proxmox Maintool in Container %s wurde entfernt."
msg logs_stay      "Logboeken van updates blijven op de nodes staan in %s; die mag je weggooien." \
                   "Logs of updates stay on the nodes in %s; you may delete them." \
                   "Protokolle von Updates bleiben auf den Nodes in %s; die darfst du löschen."
msg log_removed    "verwijderen klaar" "removal done" "Entfernen fertig"

# ---------------------------------------------------------------- hulpjes

log()  { printf '%s %s\n' "$(date '+%F %T')" "$*" >>"$LOG" 2>/dev/null || true; }   # nooit geheimen meegeven
say()  { printf '%s\n' "$*"; log "$*"; }
note() { printf '   %s\n' "$*"; log "   $*"; }
retry() { printf '   %s\n' "$(tf "$@")"; }   # foute invoer: melding, daarna wordt opnieuw gevraagd
step() { STEP="$*"; printf '\n== %s\n' "$*"; log "== $*"; }
hint() {   # na een afgebroken installatie: zeggen hoe je de half aangemaakte container weer kwijtraakt
    if [[ $MODE == install && -n $CREATED ]]; then
        { tf hint_cleanup "$CTID" "$SELF" "$CTID"; printf '\n'; } >&2
    fi
}
die()  { printf '\n%s: %s\n' "$(T stopped)" "$*" >&2; log "$(T stopped): $*"; hint; exit 1; }

cleanup() { if [[ -n $TMP && -d $TMP ]]; then rm -rf "$TMP"; fi; }
on_error() {
    (( BASH_SUBSHELL == 0 )) || return 0
    { printf '\n'; tf went_wrong "$STEP" "$1"; printf '\n'; } >&2
    hint
    { tf logbook "$LOG"; printf '\n'; } >&2
    log "$(tf log_error "$STEP" "$1")"
}
trap cleanup EXIT
trap 'on_error $LINENO' ERR

api() { pvesh get "$1" --output-format json "${@:2}"; }   # hetzelfde antwoord als de Proxmox-API
py()  { python3 -c "$1" "${@:2}"; }                        # klein stukje Python; leest meestal JSON van stdin

read_line() {   # read_line VAR "vraag" ["standaard"]
    local __var=$1 __q=$2 __def=${3:-} __ans
    if [[ -n $__def ]]; then __q+=" [$__def]"; fi
    IFS= read -r -p "$__q: " __ans || die "$(T no_input)"
    __ans=${__ans#"${__ans%%[![:space:]]*}"}
    __ans=${__ans%"${__ans##*[![:space:]]}"}
    printf -v "$__var" '%s' "${__ans:-$__def}"
}

read_secret() {   # read_secret VAR "vraag"  (wat je typt verschijnt niet op het scherm)
    local __var=$1 __ans
    IFS= read -r -s -p "$2: " __ans || die "$(T no_input)"
    printf '\n'
    printf -v "$__var" '%s' "$__ans"
}

choose() {   # choose VAR "vraag" "standaard" optie... ; elke optie is "waarde|toelichting"
    local __var=$1 __q=$2 __def=$3 __i=0 __pick __opt
    shift 3
    local __options=("$@")
    if (( ${#__options[@]} == 1 )); then
        printf -v "$__var" '%s' "${__options[0]%%|*}"
        note "$__q ${__options[0]%%|*} $(T only_option)"
        return
    fi
    printf '\n%s\n' "$__q"
    for __opt in "${__options[@]}"; do
        __i=$((__i + 1))
        printf '  %d) %-20s %s\n' "$__i" "${__opt%%|*}" "${__opt#*|}"
    done
    while true; do
        read_line __pick "$(T pick)" "$__def"
        if [[ $__pick =~ ^[0-9]+$ ]] && (( __pick >= 1 && __pick <= ${#__options[@]} )); then
            __pick=${__options[__pick - 1]%%|*}
        fi
        for __opt in "${__options[@]}"; do
            if [[ ${__opt%%|*} == "$__pick" ]]; then
                printf -v "$__var" '%s' "$__pick"
                return
            fi
        done
        retry not_in_list
    done
}

lang_from_env() {   # de taal van de omgeving als voorstel: Nederlands of Duits als die dat zegt, anders Engels
    case "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}" in
        nl*) echo nl ;;
        de*) echo de ;;
        *)   echo en ;;
    esac
}

ask_language() {   # de eerste vraag, tenzij de taal met --lang is meegegeven
    local ans def
    [[ -z $LANG_FIXED ]] || return 0
    case $UI in nl) def=2 ;; de) def=3 ;; *) def=1 ;; esac
    printf '\n  1) English\n  2) Nederlands\n  3) Deutsch\n'
    while true; do
        read_line ans "Language / Taal / Sprache" "$def"
        case ${ans,,} in
            1 | en | english)            UI=en ;;
            2 | nl | nederlands | dutch) UI=nl ;;
            3 | de | deutsch | german)   UI=de ;;
            *) printf '   1 = English, 2 = Nederlands, 3 = Deutsch\n'; continue ;;
        esac
        break
    done
    STEP=$(T step_prepare)
}

usage() {
    case $UI in
        nl) cat <<EOF
Proxmox Maintool $VERSION - onderhoudstool voor Proxmox VE, door Eduard Wichers

Gebruik (als root, op een Proxmox VE-node):
  bash $SELF                  installeren: maakt een kleine container en zet de tool erin
  bash $SELF --update [ID]    de tool in een bestaande container bijwerken naar versie $VERSION
  bash $SELF --uninstall ID   de container, de toegangssleutel en het hulpscript weer verwijderen
  bash $SELF --leesmij        de volledige uitleg tonen (Engels: --readme, Duits: --liesmich)
  bash $SELF --licentie       de licentie tonen
  bash $SELF --lang nl ...    de taal vastzetten, zonder dat ernaar gevraagd wordt (nl, en of de)

LET OP: de tool krijgt beheerdersrechten op je hele cluster. Geen garantie, gebruik op eigen risico.
EOF
        ;;
        de) cat <<EOF
Proxmox Maintool $VERSION - Wartungstool für Proxmox VE, von Eduard Wichers

Verwendung (als root, auf einem Proxmox-VE-Node):
  bash $SELF                  installieren: legt einen kleinen Container an und bringt das Tool hinein
  bash $SELF --update [ID]    das Tool in einem vorhandenen Container auf Version $VERSION aktualisieren
  bash $SELF --uninstall ID   den Container, den Zugriffsschlüssel und das Hilfsskript wieder entfernen
  bash $SELF --liesmich       die vollständige Anleitung zeigen (Niederländisch: --leesmij, Englisch: --readme)
  bash $SELF --lizenz         die Lizenz zeigen
  bash $SELF --lang de ...    die Sprache festlegen, ohne danach gefragt zu werden (de, nl oder en)

ACHTUNG: Das Tool bekommt Administratorrechte auf deinem ganzen Cluster. Keine Garantie, Benutzung auf eigene Gefahr.
EOF
        ;;
        *) cat <<EOF
Proxmox Maintool $VERSION - maintenance tool for Proxmox VE, by Eduard Wichers

Usage (as root, on a Proxmox VE node):
  bash $SELF                  install: creates a small container and puts the tool in it
  bash $SELF --update [ID]    update the tool in an existing container to version $VERSION
  bash $SELF --uninstall ID   remove the container, the access key and the helper script again
  bash $SELF --readme         show the full explanation (Dutch: --leesmij, German: --liesmich)
  bash $SELF --license        show the license
  bash $SELF --lang en ...    fix the language, without being asked for it (en, nl or de)

NOTE: the tool gets administrator rights on your whole cluster. No warranty, use at your own risk.
EOF
        ;;
    esac
}

# ---------------------------------------------------------------- de ingepakte tool uitpakken

unpack() {
    local line
    [[ -f $SELF ]] || die "$(T save_first)"
    TMP=$(mktemp -d)
    line=$(grep -an '^__PAYLOAD__$' "$SELF" | head -1 | cut -d: -f1 || true)   # geen treffer: nette melding hieronder
    [[ -n $line || $VERSION != *@* ]] || die "$(T from_source)"   # build.sh vult het versienummer in; de bron heeft nog @...@
    [[ -n $line ]] || die "$(T incomplete)"
    mkdir "$TMP/pkg"
    tail -n +"$((line + 1))" "$SELF" | base64 -d 2>/dev/null | tar xz -C "$TMP/pkg" 2>/dev/null \
        || die "$(T damaged_copy)"
    ( cd "$TMP/pkg" && sha256sum --quiet -c SHA256SUMS >/dev/null 2>&1 ) \
        || die "$(T damaged_sums)"
}

show_doc() {   # show_doc README.md|LIESMICH.md: de Engelse of Duitse uitleg, uit het blok tussen __DOCS__ en __PAYLOAD__
    local from to
    [[ -f $SELF ]] || die "$(T save_first)"
    from=$(grep -an '^__DOCS__$' "$SELF" | head -1 | cut -d: -f1 || true)
    to=$(grep -an '^__PAYLOAD__$' "$SELF" | head -1 | cut -d: -f1 || true)
    [[ -n $to || $VERSION != *@* ]] || die "$(T from_source)"
    [[ -n $from && -n $to ]] && (( from < to )) || die "$(T incomplete)"
    TMP=$(mktemp -d)   # eerst uitpakken: wie de uitvoer vroeg afkapt (| head) laat het uitpakken dan niet mislukken
    sed -n "$((from + 1)),$((to - 1))p" "$SELF" | base64 -d 2>/dev/null | tar xz -C "$TMP" "$1" 2>/dev/null || die "$(T damaged_copy)"
    cat "$TMP/$1"
}

# ---------------------------------------------------------------- controles vooraf

need_node() {
    local cmd arch major
    [[ ${MT_SKIP_ROOT_CHECK:-} == 1 || $(id -u) -eq 0 ]] || die "$(T need_root)"
    for cmd in pveversion pvesh pct pveam python3 ssh scp sha256sum base64; do
        command -v "$cmd" >/dev/null 2>&1 || die "$(tf missing_cmd "$cmd")"
    done
    arch=$(dpkg --print-architecture 2>/dev/null || T arch_unknown)
    [[ $arch == amd64 ]] || die "$(tf arch "$arch")"
    PVE_VERSION=$(api /version | py 'import json, sys; print(json.load(sys.stdin)["version"])')
    major=${PVE_VERSION%%.*}
    [[ $major =~ ^[0-9]+$ ]] || die "$(tf pve_unknown "$PVE_VERSION")"
    (( major >= 8 )) || die "$(tf pve_old "$PVE_VERSION")"
    unpack
    api /cluster/status >"$TMP/status.json"
    py '
import json, sys
status = json.load(open(sys.argv[1]))
cluster = next((e for e in status if e.get("type") == "cluster"), None)
if cluster and not cluster.get("quorate"):
    sys.exit("geen meerderheid")
for e in status:
    if e.get("type") == "node":
        print(e["name"], e.get("ip") or "-", int(bool(e.get("online"))), int(bool(e.get("local"))))
' "$TMP/status.json" >"$TMP/nodes" 2>/dev/null \
        || die "$(T no_quorum)"
    NODE=$(awk '$4 == 1 { print $1 }' "$TMP/nodes" | head -1)
    NODE_IP=$(awk '$4 == 1 { print $2 }' "$TMP/nodes" | head -1)
    [[ -n $NODE && $NODE_IP != - ]] || die "$(T which_node)"
    NODE_COUNT=$(wc -l <"$TMP/nodes" | tr -d ' ')
    [[ -f $AUTH ]] || die "$(tf no_auth "$AUTH")"
    log "$(tf log_start "$MODE" "$VERSION" "$NODE" "$PVE_VERSION" "$NODE_COUNT" "$UI")"
}

# Het adres waaronder een node in het cluster bekend staat, is waar de andere nodes en de tool hem zoeken. Proxmox
# neemt het uit /etc/hosts op die node; staat daar nog een oud adres, dan loopt elke vraag aan die node vast (de API van
# een andere node wacht dan tevergeefs op hem) en bereikt de tool zijn hulpscript niet. Dat komt voor na het wijzigen van
# het adres van een node. De MT_-variabelen bestaan alleen om dit bestand te kunnen testen.
own_addresses() {
    if [[ -n ${MT_LOCAL_ADDRS+x} ]]; then printf '%s\n' $MT_LOCAL_ADDRS; return; fi
    ip -o addr show 2>/dev/null | awk '{ sub(/\/.*/, "", $4); print $4 }' || true
}
answers() {   # antwoordt de Proxmox-API (poort 8006) op dit adres binnen 3 seconden?
    if [[ -n ${MT_ANSWERS+x} ]]; then [[ " $MT_ANSWERS " == *" $1 "* ]]; return; fi
    timeout 3 bash -c 'exec 3<>"/dev/tcp/$1/8006"' _ "$1" </dev/null 2>/dev/null
}
check_addresses() {   # bij installeren: melden en vragen of je toch doorgaat; bij bijwerken alleen melden
    local name ip online here mine shown answer problem problems=()
    mine=" $(own_addresses | paste -sd' ' -) "
    shown=$(own_addresses | grep -vE '^(127\.|::1$|fe80:)' | paste -sd, - | sed 's/,/, /g' || true)
    while read -r name ip online here; do
        [[ $ip != - && $online == 1 ]] || continue
        if [[ $here == 1 ]]; then
            [[ $mine == "  " || $mine == *" $ip "* ]] || problems+=("$(tf addr_here "$name" "$ip" "${shown:--}")")
        elif ! answers "$ip"; then
            problems+=("$(tf addr_silent "$name" "$ip")")
        fi
    done <"$TMP/nodes"
    (( ${#problems[@]} )) || return 0
    printf '\n%s\n %s\n%s\n' "$(printf '=%.0s' {1..86})" "$(T addr_title)" "$(printf '=%.0s' {1..86})"
    for problem in "${problems[@]}"; do
        printf '%s\n' "* $problem" | fold -s -w 84 | sed '2,$s/^/  /;s/^/ /'
        log "$problem"
    done
    printf '\n'
    { T addr_why; printf '\n\n'; T addr_fix; printf '\n'; } | fold -s -w 85 | sed 's/^/ /'
    printf '%s\n' "$(printf '=%.0s' {1..86})"
    [[ $MODE == install ]] || return 0
    read_line answer "$(tf addr_go "$(T yes_word)")"
    [[ ${answer,,} == "$(T yes_word)" ]] || die "$(T stopped_by_you)"
    log "$(T log_addr_go)"
}

warning() {
    case $UI in
        nl) cat <<EOF

======================================================================================
 Proxmox Maintool $VERSION  -  LEES DIT EERST
======================================================================================
 * De tool krijgt BEHEERDERSRECHTEN op je hele Proxmox-cluster: een toegangssleutel
   (API-token) met de rol Administrator. Daarnaast mag hij als root op elke node een
   vast hulpscript starten, dat updates installeert en de node kan herstarten.
 * Wie in de tool kan inloggen, kan containers en VM's stoppen, migreren, terugzetten
   uit een back-up en nodes herstarten. Kies een sterk wachtwoord en zet de tool niet
   zonder extra beveiliging open naar het internet.
 * De tool is gemaakt voor en getest op precies één omgeving: Proxmox VE 9, een cluster
   van drie nodes met Ceph en alleen containers. Andere opstellingen (één node, geen
   Ceph, VM's, Proxmox VE 8) zijn NIET getest.
 * GEBRUIK OP EIGEN RISICO. Er is geen enkele garantie en de maker is niet aansprakelijk
   voor schade, gegevensverlies of storingen (MIT-licentie: bash $SELF --licentie).
   Zorg dat je goede back-ups hebt voordat je de tool iets laat doen.
======================================================================================
EOF
        ;;
        de) cat <<EOF

======================================================================================
 Proxmox Maintool $VERSION  -  ZUERST LESEN
======================================================================================
 * Das Tool bekommt ADMINISTRATORRECHTE auf deinem ganzen Proxmox-VE-Cluster: einen
   Zugriffsschlüssel (API-Token) mit der Rolle Administrator. Außerdem darf es als root
   auf jedem Node ein festes Hilfsskript starten, das Updates installiert und den Node
   neu starten kann.
 * Wer sich am Tool anmelden kann, kann Container und VMs stoppen, migrieren, aus einem
   Backup wiederherstellen und Nodes neu starten. Wähle ein starkes Passwort und stelle
   das Tool nicht ohne zusätzlichen Schutz ins Internet.
 * Das Tool wurde für genau eine Umgebung gemacht und darauf getestet: Proxmox VE 9, ein
   Cluster aus drei Nodes mit Ceph und nur Containern. Andere Aufbauten (ein Node, kein
   Ceph, VMs, Proxmox VE 8) wurden NICHT getestet.
 * BENUTZUNG AUF EIGENE GEFAHR. Es gibt keinerlei Garantie, und der Ersteller haftet
   nicht für Schäden, Datenverlust oder Störungen (MIT-Lizenz: bash $SELF --lizenz).
   Sorge für gute Backups, bevor du das Tool etwas tun lässt.
======================================================================================
EOF
        ;;
        *) cat <<EOF

======================================================================================
 Proxmox Maintool $VERSION  -  READ THIS FIRST
======================================================================================
 * The tool gets ADMINISTRATOR RIGHTS on your whole Proxmox cluster: an access key
   (API token) with the Administrator role. On top of that it may start a fixed helper
   script as root on every node, which installs updates and can restart the node.
 * Anyone who can log in to the tool can stop and migrate containers and VMs, restore
   them from a backup and restart nodes. Choose a strong password and do not open the
   tool to the internet without extra protection.
 * The tool was made for and tested on exactly one environment: Proxmox VE 9, a cluster
   of three nodes with Ceph and only containers. Other setups (one node, no Ceph, VMs,
   Proxmox VE 8) have NOT been tested.
 * USE AT YOUR OWN RISK. There is no warranty whatsoever and the maker is not liable
   for damage, data loss or outages (MIT license: bash $SELF --license).
   Make sure you have good backups before you let the tool do anything.
======================================================================================
EOF
        ;;
    esac
    local answer
    read_line answer "$(tf agree_prompt "$(T agree_word)")"
    [[ ${answer,,} == "$(T agree_word)" ]] || die "$(T not_agreed)"
    log "$(T log_agreed)"
}

# ---------------------------------------------------------------- vragen

ask_questions() {
    local names taken used default opts=() line free ip_hint
    api /cluster/resources --type vm >"$TMP/guests.json"

    step "$(T step_questions)"
    default=$(api /cluster/nextid | tr -d '" \n')
    while true; do
        read_line CTID "$(T ask_id)" "$default"
        [[ $CTID =~ ^[1-9][0-9]{2,8}$ ]] || { retry bad_id; continue; }
        taken=$(py 'import json, sys; print(int(any(str(g.get("vmid")) == sys.argv[2] for g in json.load(open(sys.argv[1])))))' "$TMP/guests.json" "$CTID")
        [[ $taken == 0 ]] || { retry id_taken "$CTID"; continue; }
        break
    done
    TOKEN="ct$CTID"

    names=$(py 'import json, sys; print(" ".join(str(g.get("name", "")) for g in json.load(open(sys.argv[1]))))' "$TMP/guests.json")
    default=maintool
    [[ " $names " != *" maintool "* ]] || default="maintool-$CTID"
    while true; do
        read_line CT_NAME "$(T ask_name)" "$default"
        [[ $CT_NAME =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || { retry bad_name; continue; }
        # De tool herkent zijn eigen container aan de naam; die moet dus uniek zijn.
        [[ " $names " != *" $CT_NAME "* ]] || { retry name_taken; continue; }
        break
    done

    api "/nodes/$NODE/storage" --content rootdir >"$TMP/disks.json"
    mapfile -t opts < <(py '
import json, sys
for s in sorted(json.load(sys.stdin), key=lambda s: s["storage"]):
    free = (s.get("avail") or 0) / 2**30
    if s.get("active") and s.get("enabled", 1) and free >= 5:
        print("%s|%s, %.0f GB %s%s" % (s["storage"], s.get("type"), free, sys.argv[1], ", " + sys.argv[2] if s.get("shared") else ""))
' "$(T gb_free)" "$(T shared)" <"$TMP/disks.json")
    (( ${#opts[@]} )) || die "$(T no_disk_store)"
    choose DISK_STORE "$(T ask_disk)" "${opts[0]%%|*}" "${opts[@]}"

    api "/nodes/$NODE/storage" --content vztmpl >"$TMP/tmpl.json"
    mapfile -t opts < <(py '
import json, sys
for s in sorted(json.load(sys.stdin), key=lambda s: (s["storage"] != "local", s["storage"])):
    if s.get("active") and s.get("enabled", 1):
        print("%s|%s" % (s["storage"], s.get("type")))
' <"$TMP/tmpl.json")
    (( ${#opts[@]} )) || die "$(T no_tmpl_store)"
    choose TMPL_STORE "$(T ask_tmpl)" "${opts[0]%%|*}" "${opts[@]}"

    api "/nodes/$NODE/network" --type any_bridge >"$TMP/bridges.json"
    mapfile -t opts < <(py '
import json, sys
for b in sorted(json.load(sys.stdin), key=lambda b: b["iface"]):
    if b.get("active"):
        print("%s|%s" % (b["iface"], b.get("cidr") or sys.argv[1]))
' "$(T no_address)" <"$TMP/bridges.json")
    (( ${#opts[@]} )) || die "$(T no_bridge)"
    choose BRIDGE "$(T ask_bridge)" "${opts[0]%%|*}" "${opts[@]}"
    ip_hint=$(py 'import json, sys; print(next((b.get("cidr") or "" for b in json.load(open(sys.argv[1])) if b["iface"] == sys.argv[2]), ""))' "$TMP/bridges.json" "$BRIDGE")
    default=$(py 'import json, sys; print(next((b.get("gateway") or "" for b in json.load(open(sys.argv[1])) if b["iface"] == sys.argv[2]), ""))' "$TMP/bridges.json" "$BRIDGE")
    [[ -n $default ]] || default=$(ip -4 route show default 2>/dev/null | awk '{ print $3; exit }')

    printf '\n'; tf ip_intro
    [[ -z $ip_hint ]] || tf ip_node_has "$ip_hint"
    printf '\n'
    while true; do
        read_line CT_CIDR "$(T ask_ip)"
        CT_IP=$(py '
import ipaddress, sys
try:
    i = ipaddress.ip_interface(sys.argv[1])
    ok = i.version == 4 and "/" in sys.argv[1] and 8 <= i.network.prefixlen <= 30 and i.ip not in (i.network.network_address, i.network.broadcast_address)
    print(i.ip if ok else "")
except ValueError:
    print("")
' "$CT_CIDR")
        [[ -n $CT_IP ]] || { retry bad_ip; continue; }
        used=$(py 'import sys; print(int(sys.argv[2] in open(sys.argv[1]).read().split()))' "$TMP/nodes" "$CT_IP")
        [[ $used == 0 ]] || { retry ip_is_node; continue; }
        if ping -c 1 -W 1 "$CT_IP" >/dev/null 2>&1; then
            retry ip_answers "$CT_IP"
            continue
        fi
        break
    done
    while true; do
        read_line CT_GW "$(T ask_gw)" "$default"
        line=$(py '
import ipaddress, sys
try:
    net, gw = ipaddress.ip_interface(sys.argv[1]).network, ipaddress.ip_address(sys.argv[2])
    print("ok" if gw in net else "buiten")
except ValueError:
    print("fout")
' "$CT_CIDR" "$CT_GW")
        [[ $line != fout ]] || { retry bad_gw; continue; }
        [[ $line != buiten ]] || { retry gw_outside "$CT_CIDR"; continue; }
        break
    done
    while true; do
        read_line CT_VLAN "$(T ask_vlan)"
        [[ -z $CT_VLAN ]] && break
        [[ $CT_VLAN =~ ^[0-9]+$ ]] && (( CT_VLAN >= 1 && CT_VLAN <= 4094 )) && break
        retry bad_vlan
    done

    printf '\n%s\n' "$(T login_intro)"
    while true; do
        read_line APP_USER "$(T ask_user)" "admin"
        [[ $APP_USER =~ ^[A-Za-z0-9._@-]{1,64}$ ]] && break
        retry bad_user
    done
    while true; do
        read_secret APP_PASS "$(tf ask_pass "$MIN_PASS")"
        if (( ${#APP_PASS} < MIN_PASS )); then retry too_short; continue; fi
        if [[ ! $APP_PASS =~ ^[\!-~]+$ || $APP_PASS == *\'* || $APP_PASS == *\"* || $APP_PASS == *\\* ]]; then
            retry bad_pass
            continue
        fi
        read_secret line "$(T ask_pass2)"
        [[ $line == "$APP_PASS" ]] && break
        retry pass_differ
    done
}

summary() {
    local name ip online _local custom="" offline="" answer
    while read -r name ip online _local; do
        [[ $online == 1 ]] || offline+=" $name"
        [[ ! -f $PVE_DIR/nodes/$name/pveproxy-ssl.pem ]] || custom+=" $name"
    done <"$TMP/nodes"
    case $UI in
        nl) cat <<EOF

--------------------------------------------------------------------------------------
 Dit gaat er gebeuren
--------------------------------------------------------------------------------------
 Op node $NODE:
   - container $CTID "$CT_NAME" aanmaken: Debian, 1 kern, 512 MB geheugen, 4 GB schijf op $DISK_STORE
   - netwerk: $BRIDGE, adres $CT_CIDR, router $CT_GW${CT_VLAN:+, VLAN $CT_VLAN}
   - het Debian-sjabloon ophalen naar $TMPL_STORE (als het er nog niet staat)
 In de container (heeft internet nodig, voor Debian-pakketten en Python-pakketten):
   - de tool installeren en starten op https://$CT_IP:8443, met inlog "$APP_USER"
 In Proxmox:
   - gebruiker $PVE_USER (als die nog niet bestaat) met de rol Administrator op het hele cluster
   - toegangssleutel (API-token) $PVE_USER!$TOKEN, alleen bekend in de container
 Op $( (( NODE_COUNT == 1 )) && echo "deze node" || echo "alle $NODE_COUNT nodes" ):
   - het hulpscript $AGENT
   - één regel in $AUTH: de sleutel van de container mag alleen dat hulpscript
     starten, en alleen vanaf $CT_IP (er wordt eerst een kopie van het bestand gemaakt in $BACKUP_DIR)
--------------------------------------------------------------------------------------
EOF
        ;;
        de) cat <<EOF

--------------------------------------------------------------------------------------
 Das wird passieren
--------------------------------------------------------------------------------------
 Auf Node $NODE:
   - Container $CTID "$CT_NAME" anlegen: Debian, 1 Kern, 512 MB Arbeitsspeicher, 4 GB Platte auf $DISK_STORE
   - Netzwerk: $BRIDGE, Adresse $CT_CIDR, Router $CT_GW${CT_VLAN:+, VLAN $CT_VLAN}
   - die Debian-Vorlage nach $TMPL_STORE herunterladen (falls sie noch nicht da ist)
 Im Container (braucht Internet, für Debian-Pakete und Python-Pakete):
   - das Tool installieren und starten unter https://$CT_IP:8443, mit der Anmeldung "$APP_USER"
 In Proxmox:
   - Benutzer $PVE_USER (falls er noch nicht existiert) mit der Rolle Administrator auf dem ganzen Cluster
   - Zugriffsschlüssel (API-Token) $PVE_USER!$TOKEN, nur im Container bekannt
 Auf $( (( NODE_COUNT == 1 )) && echo "diesem Node" || echo "allen $NODE_COUNT Nodes" ):
   - das Hilfsskript $AGENT
   - eine Zeile in $AUTH: Der Schlüssel des Containers darf nur dieses Hilfsskript
     starten, und nur von $CT_IP aus (vorher wird eine Kopie der Datei in $BACKUP_DIR angelegt)
--------------------------------------------------------------------------------------
EOF
        ;;
        *) cat <<EOF

--------------------------------------------------------------------------------------
 This is what will happen
--------------------------------------------------------------------------------------
 On node $NODE:
   - create container $CTID "$CT_NAME": Debian, 1 core, 512 MB memory, 4 GB disk on $DISK_STORE
   - network: $BRIDGE, address $CT_CIDR, router $CT_GW${CT_VLAN:+, VLAN $CT_VLAN}
   - download the Debian template to $TMPL_STORE (if it is not there yet)
 In the container (needs internet, for Debian packages and Python packages):
   - install and start the tool on https://$CT_IP:8443, with the login "$APP_USER"
 In Proxmox:
   - user $PVE_USER (if it does not exist yet) with the Administrator role on the whole cluster
   - access key (API token) $PVE_USER!$TOKEN, only known inside the container
 On $( (( NODE_COUNT == 1 )) && echo "this node" || echo "all $NODE_COUNT nodes" ):
   - the helper script $AGENT
   - one line in $AUTH: the key of the container may only start that helper
     script, and only from $CT_IP (a copy of the file is made in $BACKUP_DIR first)
--------------------------------------------------------------------------------------
EOF
        ;;
    esac
    [[ -z $offline ]] || printf ' %s\n' "$(tf not_online "$offline")"
    if [[ -n $custom ]]; then tf own_cert "$custom"; printf '\n'; fi
    [[ ${PVE_VERSION%%.*} -ge 9 ]] || printf ' %s\n' "$(tf pve_untested "$PVE_VERSION")"
    read_line answer "$(tf run_prompt "$(T yes_word)")"
    [[ ${answer,,} == "$(T yes_word)" ]] || die "$(T stopped_by_you)"
    log "$(tf log_confirmed "$CTID" "$CT_NAME" "$DISK_STORE" "$BRIDGE" "$CT_CIDR" "$CT_GW" "$APP_USER")"
}

# ---------------------------------------------------------------- bouwstenen

create_container() {
    local template volid tries
    step "$(T step_template)"
    pveam update >/dev/null 2>&1 || note "$(T tmpl_list_old)"
    # Proxmox VE 9 krijgt Debian 13; op versie 8 Debian 12, want niet elke 8.x kent Debian 13 al.
    template=$(api "/nodes/$NODE/aplinfo" | py '
import json, re, sys
newest, best = int(sys.argv[1]), {}
for a in json.load(sys.stdin):
    m = re.match(r"^debian-(1[23])-standard_([0-9.]+)-([0-9]+)_amd64\.tar\.(zst|xz|gz)$", a.get("template", ""))
    if m and a.get("section") == "system" and int(m.group(1)) <= newest:
        best[(int(m.group(1)), tuple(int(x) for x in m.group(2).split(".")), int(m.group(3)))] = a["template"]
print(best[max(best)] if best else "")
' "$(( ${PVE_VERSION%%.*} >= 9 ? 13 : 12 ))")
    [[ -n $template ]] || die "$(T no_debian)"
    volid="$TMPL_STORE:vztmpl/$template"
    if api "/nodes/$NODE/storage/$TMPL_STORE/content" --content vztmpl | grep -qF "\"$volid\""; then
        note "$(tf tmpl_there "$template")"
    else
        note "$(tf tmpl_fetch "$template")"
        pveam download "$TMPL_STORE" "$template" >>"$LOG" 2>&1 || die "$(tf tmpl_failed "$LOG")"
    fi

    step "$(tf step_create "$CTID")"
    pct create "$CTID" "$volid" --hostname "$CT_NAME" --cores 1 --memory 512 --swap 512 \
        --rootfs "$DISK_STORE:4" --net0 "name=eth0,bridge=$BRIDGE,ip=$CT_CIDR,gw=$CT_GW${CT_VLAN:+,tag=$CT_VLAN}" \
        --unprivileged 1 --features nesting=1 --onboot 1 --ostype debian --timezone host --tags "$TAG" \
        --description "$(tf ct_description "$VERSION")" >>"$LOG" 2>&1 \
        || die "$(tf create_failed "$LOG")"
    CREATED=1
    pct start "$CTID" >>"$LOG" 2>&1 || die "$(tf start_failed "$LOG")"
    note "$(T wait_net)"
    for tries in $(seq 1 30); do
        if pct exec "$CTID" -- getent hosts deb.debian.org >/dev/null 2>&1; then return; fi
        sleep 2
    done
    die "$(tf no_internet "$CT_CIDR" "$CT_GW")"
}

install_in_container() {   # zet de bestanden van de tool in de container en draait daar install.sh
    step "$(T step_install)"
    tar czf "$TMP/pkg.tar.gz" -C "$TMP/pkg" .
    pct push "$CTID" "$TMP/pkg.tar.gz" /root/maintool-pkg.tar.gz
    pct exec "$CTID" -- sh -c 'rm -rf /root/maintool-pkg && mkdir /root/maintool-pkg && tar xzf /root/maintool-pkg.tar.gz -C /root/maintool-pkg && rm /root/maintool-pkg.tar.gz'
    pct exec "$CTID" -- sh -c 'cd /root/maintool-pkg && MAINTOOL_SETUP=1 bash install.sh' >>"$LOG" 2>&1 \
        || die "$(tf install_failed "$LOG")"
    pct exec "$CTID" -- sh -c 'install -m 644 /root/maintool-pkg/selftest.py /root/maintool-pkg/LICENSE /root/maintool-pkg/README.md /root/maintool-pkg/THIRD-PARTY.md /opt/maintool/ && rm -rf /root/maintool-pkg'
    note "$(T installed)"
}

make_token() {   # het geheim van de sleutel komt alleen in een bestand dat direct de container in gaat
    step "$(T step_access)"
    if ! pvesh get "/access/users/$PVE_USER" --output-format json >/dev/null 2>&1; then
        pvesh create /access/users --userid "$PVE_USER" --comment "$USER_COMMENT" >/dev/null
        note "$(tf user_created "$PVE_USER")"
    fi
    pvesh set /access/acl --path / --users "$PVE_USER" --roles Administrator >/dev/null
    pvesh delete "/access/users/$PVE_USER/token/$TOKEN" >/dev/null 2>&1 || true
    ( umask 077
      pvesh create "/access/users/$PVE_USER/token/$TOKEN" --privsep 0 --comment "Proxmox Maintool in CT $CTID" \
          --output-format json >"$TMP/token.json" )
    note "$(tf token_created "$PVE_USER!$TOKEN")"
}

write_settings() {
    local hosts zone
    hosts=$(awk '$2 != "-" { print $2 }' "$TMP/nodes" | paste -sd, -)
    zone=$(api "/nodes/$NODE/time" | py 'import json, sys; print(json.load(sys.stdin).get("timezone") or "Europe/Amsterdam")')
    ( umask 077
      MT_HOSTS="$hosts" MT_PVE_USER="$PVE_USER" MT_TOKEN="$TOKEN" MT_APP_USER="$APP_USER" MT_APP_PASS="$APP_PASS" MT_ZONE="$zone" \
      MT_HEAD1="$(T env_head1)" MT_HEAD2="$(T env_head2)" \
      python3 - "$TMP/token.json" "$TMP/pkg/maintool.env.example" "$TMP/maintool.env" <<'PY'
import json, os, re, sys
secret = json.load(open(sys.argv[1]))["value"]
values = {"PVE_HOSTS": os.environ["MT_HOSTS"], "PVE_USER": os.environ["MT_PVE_USER"], "PVE_TOKEN_NAME": os.environ["MT_TOKEN"],
          "PVE_TOKEN_VALUE": secret, "APP_USER": os.environ["MT_APP_USER"], "APP_PASSWORD": os.environ["MT_APP_PASS"],
          "REPORT_TZ": os.environ["MT_ZONE"]}
template = open(sys.argv[2], encoding="utf-8").read().split("\n\n", 1)[1]   # zonder de kop van het sjabloon
out = [""]
for line in template.splitlines():
    m = re.match(r"^([A-Z_]+)=", line)
    out.append(f"{m.group(1)}={values[m.group(1)]}" if m and m.group(1) in values else line)
head = [os.environ["MT_HEAD1"], os.environ["MT_HEAD2"]]
open(sys.argv[3], "w", encoding="utf-8").write("\n".join(head + out) + "\n")
PY
    )
    pct push "$CTID" "$TMP/maintool.env" /etc/maintool/maintool.env --perms 640 --user root --group maintool
    rm -f "$TMP/token.json" "$TMP/maintool.env"
    pct push "$CTID" "$PVE_DIR/pve-root-ca.pem" /etc/maintool/pve-root-ca.pem --perms 644
    note "$(T settings_put)"
}

install_agent() {   # het hulpscript op elke node, en de hostsleutels van de nodes naar de container
    local name ip online is_local hostkey opts
    step "$(T step_agent)"
    bash -n "$TMP/pkg/node/maintool-agent"
    : >"$TMP/known_hosts"
    while read -r name ip online is_local; do
        if [[ $online != 1 || $ip == - ]]; then
            note "$(tf node_offline "$name")"
            continue
        fi
        if [[ $is_local == 1 ]]; then
            install -m 755 "$TMP/pkg/node/maintool-agent" "$AGENT"
            mkdir -p "$AGENT_LOG_DIR"
            hostkey=$(cat "$HOSTKEY")
        else
            # Dezelfde opties die Proxmox zelf tussen nodes gebruikt.
            opts=(-o BatchMode=yes -o ConnectTimeout=10 -o HostKeyAlias="$name")
            if [[ -f $PVE_DIR/nodes/$name/ssh_known_hosts ]]; then
                opts+=(-o UserKnownHostsFile="$PVE_DIR/nodes/$name/ssh_known_hosts" -o GlobalKnownHostsFile=none)
            fi
            scp -q "${opts[@]}" "$TMP/pkg/node/maintool-agent" "root@$ip:$AGENT" </dev/null \
                || die "$(tf scp_failed "$name" "$ip")"
            hostkey=$(ssh "${opts[@]}" "root@$ip" "chmod 755 $AGENT && mkdir -p $AGENT_LOG_DIR && cat $HOSTKEY" </dev/null) \
                || die "$(tf ssh_failed "$name" "$ip")"
        fi
        [[ $hostkey == "ssh-ed25519 AAAA"* ]] || die "$(tf bad_hostkey "$name")"
        printf '%s %s\n' "$ip" "$(awk '{ print $1 " " $2 }' <<<"$hostkey")" >>"$TMP/known_hosts"
        note "$name ($ip): ok"
    done <"$TMP/nodes"
    pct exec "$CTID" -- mkdir -p /etc/maintool/ssh
    pct push "$CTID" "$TMP/known_hosts" /etc/maintool/ssh/known_hosts --perms 644
}

allow_key() {   # de sleutel van de container mag alleen het hulpscript starten, alleen vanaf zijn eigen adres
    local key comment="maintool-ct$CTID" backup
    key=$(pct exec "$CTID" -- cat /etc/maintool/ssh/id_ed25519.pub | awk '{ print $1 " " $2 }')
    [[ $key == "ssh-ed25519 AAAA"* ]] || die "$(T bad_key)"
    backup="$BACKUP_DIR/authorized_keys.voor-maintool.$(date +%Y%m%d-%H%M%S)"
    cp "$AUTH" "$backup"
    # Eerdere regels van deze container (zelfde sleutel of zelfde naam) eruit, de nieuwe erbij.
    { grep -vF "$key" "$AUTH" | grep -v " $comment\$" || true; } >"$TMP/auth"
    printf 'command="%s",from="%s",restrict %s %s\n' "$AGENT" "$CT_IP" "$key" "$comment" >>"$TMP/auth"
    cat "$TMP/auth" >"$AUTH"
    note "$(tf key_allowed "$CT_IP" "$backup")"
}

start_and_test() {   # de zelftest meldt in de gekozen taal wat werkt en wat niet
    step "$(T step_start)"
    pct exec "$CTID" -- systemctl restart maintool
    sleep 3
    SELFTEST=ok
    pct exec "$CTID" -- runuser -u maintool -- /opt/maintool/venv/bin/python /opt/maintool/selftest.py --lang "$UI" 2>&1 | tee -a "$LOG" \
        || SELFTEST=fout
}

container_here() {   # stopt met uitleg als de container niet (draaiend) op deze node staat
    local where
    where=$(api /cluster/resources --type vm | py '
import json, sys
g = next((g for g in json.load(sys.stdin) if str(g.get("vmid")) == sys.argv[1]), None)
print("%s %s %s" % (g.get("type"), g.get("node"), g.get("status")) if g else "geen")
' "$CTID")
    [[ $where != geen ]] || die "$(tf no_such_ct "$CTID")"
    [[ $where == lxc\ * ]] || die "$(tf is_vm "$CTID")"
    read -r _ CT_NODE CT_STATUS <<<"$where"
    [[ $CT_NODE == "$NODE" ]] || die "$(tf other_node "$CTID" "$CT_NODE")"
}

# ---------------------------------------------------------------- installeren

done_text() {
    case $UI in
        nl) cat <<EOF

======================================================================================
 Klaar. Open de tool op:   https://$CT_IP:8443
 Inloggen met gebruiker "$APP_USER" en het wachtwoord dat je net hebt gekozen.
======================================================================================
 * Je browser waarschuwt de eerste keer voor het certificaat: de tool maakt zijn eigen
   certificaat. Dat is normaal; kies "toch doorgaan".
 * Bijwerken:    in de tool zelf via het menu > Tool bijwerken (met een nieuwere versie van dit bestand),
                 of hier op de node:  bash $SELF --update $CTID
 * Verwijderen:  bash $SELF --uninstall $CTID
 * Uitleg, ook over het weekoverzicht per mail:  bash $SELF --leesmij
 * Instellingen staan in de container in /etc/maintool/maintool.env
EOF
        ;;
        de) cat <<EOF

======================================================================================
 Fertig. Öffne das Tool unter:   https://$CT_IP:8443
 Melde dich mit dem Benutzer "$APP_USER" und dem Passwort an, das du gerade gewählt hast.
======================================================================================
 * Dein Browser warnt beim ersten Mal vor dem Zertifikat: Das Tool erstellt sein eigenes
   Zertifikat. Das ist normal; wähle "trotzdem fortfahren".
 * Aktualisieren: im Tool selbst über das Menü > Tool aktualisieren (mit einer neueren Version dieser Datei),
                  oder hier auf dem Node:  bash $SELF --update $CTID
 * Entfernen:     bash $SELF --uninstall $CTID
 * Anleitung, auch zum Bericht per Mail:  bash $SELF --liesmich
 * Die Einstellungen liegen im Container in /etc/maintool/maintool.env
EOF
        ;;
        *) cat <<EOF

======================================================================================
 Done. Open the tool at:   https://$CT_IP:8443
 Log in with user "$APP_USER" and the password you have just chosen.
======================================================================================
 * The first time, your browser warns about the certificate: the tool makes its own
   certificate. That is normal; choose "continue anyway".
 * Updating:     in the tool itself through the menu > Update the tool (with a newer version of this file),
                 or here on the node:  bash $SELF --update $CTID
 * Removing:     bash $SELF --uninstall $CTID
 * Explanation, also about the report by mail:  bash $SELF --readme
 * The settings are in the container in /etc/maintool/maintool.env
EOF
        ;;
    esac
}

do_install() {
    MODE=install
    ask_language
    need_node
    warning
    check_addresses
    ask_questions
    summary
    create_container
    install_in_container
    make_token
    write_settings
    install_agent
    allow_key
    start_and_test
    done_text
    [[ $SELFTEST == ok ]] || printf '\n %s\n' "$(T selftest_warn)"
    log "$(tf log_installed "$SELFTEST")"
}

# ---------------------------------------------------------------- bijwerken

do_update() {
    local found old answer
    MODE=update
    CTID=${1:-}
    ask_language
    need_node
    check_addresses
    if [[ -z $CTID ]]; then
        found=$(api /cluster/resources --type vm | py '
import json, sys
print(" ".join(str(g["vmid"]) for g in json.load(sys.stdin) if g.get("type") == "lxc" and sys.argv[1] in str(g.get("tags", "")).split(";")))
' "$TAG")
        [[ -n $found ]] || die "$(tf no_tagged "$TAG" "$SELF")"
        [[ $found != *" "* ]] || die "$(tf many_tagged "$TAG" "$found" "$SELF")"
        CTID=$found
    fi
    [[ $CTID =~ ^[1-9][0-9]{2,8}$ ]] || die "$(tf bad_id_arg "$CTID")"
    container_here
    [[ $CT_STATUS == running ]] || die "$(tf not_running "$CTID")"
    pct exec "$CTID" -- test -f /opt/maintool/app/main.py || die "$(tf no_tool "$CTID")"
    old=$(pct exec "$CTID" -- cat /opt/maintool/app/VERSION 2>/dev/null || T older_than)
    CT_IP=$(pct exec "$CTID" -- hostname -I | awk '{ print $1 }')
    [[ $CT_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "$(tf no_ct_ip "$CTID")"
    say ""
    say "$(tf update_intro "$CTID" "$CT_IP" "$old" "$VERSION")"
    read_line answer "$(tf go_prompt "$(T yes_word)")"
    [[ ${answer,,} == "$(T yes_word)" ]] || die "$(T stopped_by_you)"
    install_in_container
    install_agent
    allow_key
    start_and_test
    say ""
    say "$(tf update_done "$CTID" "$VERSION")"
    [[ $SELFTEST == ok ]] || say "$(T selftest_bad)"
    log "$(tf log_updated "$SELFTEST")"
}

# ---------------------------------------------------------------- verwijderen

uninstall_text() {
    case $UI in
        nl) cat <<EOF

Dit wordt verwijderd:
  - container $CTID op node $NODE, met alles wat erin staat (ook de instellingen van de tool)
  - de toegangssleutel $PVE_USER!$TOKEN
  - de regel voor deze container in $AUTH
  - de gebruiker $PVE_USER en het hulpscript op de nodes, maar alleen als geen andere Maintool ze nog gebruikt
EOF
        ;;
        de) cat <<EOF

Das wird entfernt:
  - Container $CTID auf Node $NODE, mit allem, was darin ist (auch den Einstellungen des Tools)
  - der Zugriffsschlüssel $PVE_USER!$TOKEN
  - die Zeile für diesen Container in $AUTH
  - der Benutzer $PVE_USER und das Hilfsskript auf den Nodes, aber nur, wenn kein anderes Maintool sie noch benutzt
EOF
        ;;
        *) cat <<EOF

This will be removed:
  - container $CTID on node $NODE, with everything in it (including the settings of the tool)
  - the access key $PVE_USER!$TOKEN
  - the line for this container in $AUTH
  - the user $PVE_USER and the helper script on the nodes, but only if no other Maintool still uses them
EOF
        ;;
    esac
}

do_uninstall() {
    local answer config key="" left name ip online is_local opts tokens comment
    MODE=uninstall
    CTID=${1:-}
    ask_language
    [[ $CTID =~ ^[1-9][0-9]{2,8}$ ]] || die "$(tf give_id "$SELF")"
    TOKEN="ct$CTID"
    need_node
    container_here
    config=$(pct config "$CTID")
    grep -qE "^tags:.*\b$TAG\b" <<<"$config" || die "$(tf no_label "$CTID" "$TAG")"
    uninstall_text
    read_line answer "$(tf type_id "$CTID")"
    [[ $answer == "$CTID" ]] || die "$(T stopped_by_you)"

    step "$(tf step_remove "$CTID")"
    if [[ $CT_STATUS == running ]]; then
        key=$(pct exec "$CTID" -- cat /etc/maintool/ssh/id_ed25519.pub 2>/dev/null | awk '{ print $1 " " $2 }' || true)
    fi
    if api /cluster/ha/resources | grep -qE "\"sid\" ?: ?\"ct:$CTID\""; then
        ha-manager remove "ct:$CTID" >>"$LOG" 2>&1 || true
        sleep 5
    fi
    if [[ $CT_STATUS == running ]]; then pct stop "$CTID" >>"$LOG" 2>&1 || true; fi
    pct destroy "$CTID" --purge 1 --destroy-unreferenced-disks 1 >>"$LOG" 2>&1 || die "$(tf destroy_failed "$LOG")"
    note "$(T ct_removed)"

    step "$(T step_revoke)"
    if pvesh delete "/access/users/$PVE_USER/token/$TOKEN" >/dev/null 2>&1; then note "$(tf token_removed "$TOKEN")"; else note "$(tf token_gone "$TOKEN")"; fi
    tokens=$(api "/access/users/$PVE_USER/token" 2>/dev/null | py 'import json, sys; print(len(json.load(sys.stdin)))' 2>/dev/null || echo "?")
    comment=$(api "/access/users/$PVE_USER" 2>/dev/null | py 'import json, sys; print(json.load(sys.stdin).get("comment") or "")' 2>/dev/null || echo "")
    if [[ $tokens == 0 && $comment == "$USER_COMMENT" ]]; then
        pvesh delete "/access/users/$PVE_USER" >/dev/null && note "$(tf user_removed "$PVE_USER")"
    else
        note "$(tf user_stays "$PVE_USER")"
    fi
    cp "$AUTH" "$BACKUP_DIR/authorized_keys.voor-maintool.$(date +%Y%m%d-%H%M%S)"
    { if [[ -n $key ]]; then grep -vF "$key" "$AUTH"; else cat "$AUTH"; fi | grep -v " maintool-ct$CTID\$" || true; } >"$TMP/auth"
    cat "$TMP/auth" >"$AUTH"
    note "$(tf rule_removed "$CTID" "$AUTH")"

    left=$(grep -cF "command=\"$AGENT\"" "$AUTH" || true)
    if [[ $left == 0 ]]; then
        step "$(T step_rm_agent)"
        while read -r name ip online is_local; do
            if [[ $is_local == 1 ]]; then
                rm -f "$AGENT"
            elif [[ $online == 1 && $ip != - ]]; then
                opts=(-o BatchMode=yes -o ConnectTimeout=10 -o HostKeyAlias="$name")
                if [[ -f $PVE_DIR/nodes/$name/ssh_known_hosts ]]; then
                    opts+=(-o UserKnownHostsFile="$PVE_DIR/nodes/$name/ssh_known_hosts" -o GlobalKnownHostsFile=none)
                fi
                ssh "${opts[@]}" "root@$ip" "rm -f $AGENT" </dev/null || { note "$(tf rm_failed "$name" "$AGENT")"; continue; }
            else
                note "$(tf rm_offline "$name" "$AGENT")"
                continue
            fi
            note "$(tf rm_done "$name")"
        done <"$TMP/nodes"
    else
        note "$(T agent_stays)"
    fi
    say ""
    say "$(tf removed_all "$CTID")"
    say "$(tf logs_stay "$AGENT_LOG_DIR")"
    log "$(T log_removed)"
}

# ---------------------------------------------------------------- start

# De taal: met --lang (of --taal, --sprache) vooraan vast, anders een voorstel uit de omgeving waar bij installeren,
# bijwerken en verwijderen eerst naar gevraagd wordt.
case "${1:-}" in
    --lang | --taal | --sprache)       LANG_FIXED=${2:--}; shift $(( $# >= 2 ? 2 : 1 )) ;;
    --lang=* | --taal=* | --sprache=*) LANG_FIXED=${1#*=}; LANG_FIXED=${LANG_FIXED:--}; shift ;;
esac
if [[ -n $LANG_FIXED ]]; then
    case ${LANG_FIXED,,} in
        nl | en | de) UI=${LANG_FIXED,,} ;;
        *) printf 'Unknown language / Onbekende taal / Unbekannte Sprache: %s (en, nl, de)\n' "$LANG_FIXED" >&2; exit 2 ;;
    esac
else
    UI=$(lang_from_env)
fi
# Vanaf hier rekent alles met de taalinstelling C.UTF-8. De controles van wat je typt (wachtwoord, naam, nummers) gaan
# uit van gewone ASCII-tekens, en onder bijvoorbeeld en_US.UTF-8 rekent bash [!-~], [a-z] en [0-9] anders: daar werd
# elk wachtwoord geweigerd en kwam "mäintool" als naam door. C.UTF-8 rekent zoals bedoeld, leest ë of é nog steeds als
# één teken en zit in elke Debian- en Proxmox-installatie (anders C). Wat in de container draait erft dit, en kent die
# taalinstelling dan ook zelf (geen meldingen van perl en apt over een ontbrekende locale).
if locale -a 2>/dev/null | grep -ixE 'c\.utf-?8' >/dev/null; then export LC_ALL=C.UTF-8; else export LC_ALL=C; fi
unset LANGUAGE
STEP=$(T step_prepare)

case "${1:-}" in
    "" | install | --install)          do_install ;;
    update | --update)                 do_update "${2:-}" ;;
    uninstall | --uninstall)           do_uninstall "${2:-}" ;;
    --leesmij)                         unpack; cat "$TMP/pkg/README.md" ;;
    --readme)                          show_doc README.md ;;
    --liesmich)                        show_doc LIESMICH.md ;;
    --licentie | --license | --lizenz) unpack; cat "$TMP/pkg/LICENSE" ;;
    --version)                         printf '%s\n' "$VERSION" ;;
    -h | --help | help)                usage ;;
    --hulp)                            UI=nl; usage ;;
    --hilfe)                           UI=de; usage ;;
    *)                                 usage; exit 2 ;;
esac
exit 0
