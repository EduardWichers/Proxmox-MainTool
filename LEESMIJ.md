# Proxmox Maintool

Een webpagina voor het dagelijkse onderhoud van een Proxmox VE-omgeving, in het Nederlands, Engels of Duits.
Gemaakt door Eduard Wichers.

Deze uitleg is er ook in het Engels ([README.md](README.md)) en het Duits ([LIESMICH.md](LIESMICH.md)). Alle drie komen mee met het setup-bestand.

**[Download versie 1.4.1 als ZIP](../../archive/refs/tags/v1.4.1.zip)**: de bestandsnaam bevat het versienummer (de groene knop Code geeft altijd …-main.zip). Deze ZIP kun je in één keer aanleveren bij **Tool bijwerken**. Uitgepakt staat bovenin het setup-bestand `maintool-setup.sh`, om de tool op een node te installeren; de rest is de broncode. <!-- github -->

## Lees dit eerst

- **De tool krijgt beheerdersrechten op je hele cluster.** Hij gebruikt een toegangssleutel (API-token) met de
  rol Administrator en mag als root op elke node een vast hulpscript starten (updates installeren, node
  herstarten). Wie als beheerder in de tool kan inloggen, kan dus containers en VM's stoppen, migreren,
  terugzetten uit een back-up en nodes herstarten. Wie de rol van één tabblad heeft kan dat op dat onderdeel. Wie
  alleen mag lezen kan niets veranderen, maar ziet wel alles.
- **Alleen getest op één omgeving:** Proxmox VE 9, een cluster van drie nodes met Ceph en alleen containers.
  Eén losse node, een cluster zonder Ceph, VM's en Proxmox VE 8 zijn niet getest.
- **Gebruik op eigen risico.** Er is geen garantie en de maker is niet aansprakelijk voor schade,
  gegevensverlies of storingen (MIT-licentie, zie `LICENSE`). Zorg voor goede back-ups.
- **Zet de tool niet zomaar open naar het internet.** Gebruik hem thuis op je eigen netwerk, of zet er een VPN of
  een extra toegangslaag voor.

## Wat kan de tool

- Overzicht van nodes, containers en VM's, met live CPU, geheugen en schijfgebruik (Ceph of lokale schijven).
- Een tabblad Opslag: elke opslag met vulling en inhoud (met de knop Bladeren zie je wat erop staat), de gezondheid en
  pools van Ceph, en de schijven in de nodes met hun gezondheid en slijtage. Met de steeksleutel bij Ceph beheer je
  monitors, managers, OSD's, pools en vlaggen, en bouw je Ceph op waar het nog niet draait.
- Een bibliotheek van ISO's en containersjablonen (tabblad Opslag, knop ISO's en sjablonen): de tool zoekt ze zelf op elke opslag en laat zien op
  welke nodes ze te gebruiken zijn. Een ISO laat je downloaden via een webadres (Proxmox haalt hem zelf op), een
  sjabloon haal je uit de lijst van Proxmox, en wat je niet meer nodig hebt verwijder je (een ISO alleen als geen VM hem
  in de cd-speler heeft). Bij een nieuwe VM of container kies je hieruit.
- Per node een ballonnetje met beknopte informatie (de kleine i naast de naam), en een steeksleutel voor de
  instellingen van die node: notitie, tijdzone, DNS, Wake-on-LAN, de wachttijd voor het starten van de guests en de
  pakketbronnen (aan of uit zetten, of een standaardbron van Proxmox erbij).
- Per node een logboek (de knop naast de console): zijn systeemlog met een filter op periode, bron, tekst en
  problemen (ook op te slaan als bestand), zijn taken met het log van elke taak, de toestand van zijn diensten, wat het
  cluster over hem meldt en wat de tool op hem deed.
- Een tabblad Netwerken: de interfaces van elke node, VLAN's, de netwerkkaarten en adressen van alle guests (met een
  waarschuwing bij een dubbel adres) en het netwerk van het cluster zelf. Met de plusknop zet je een VLAN klaar:
  voor containers en VM's op alle nodes tegelijk, of als extra aansluiting voor één node. Per netwerkkaart van een
  guest kies je in de kolommen Netwerk en VLAN een ander netwerk of een aangemaakt VLAN.
- Op het tabblad Netwerken een topologie: de router, de gedeelde opslag, de nodes met hun bridges en de guests daaraan, met bewegende
  stromen die laten zien hoeveel verkeer er nu over elke verbinding gaat.
- Een tabblad Events: wat er nu aandacht vraagt (node weg, Ceph, volle opslag, HA, schijven) en wat er gebeurd is:
  de taken van elke node, meldingen van het cluster en wat via de tool is gedaan, met filters (ook op een eigen
  periode van datum tot datum) en het log per taak.
- Aandachtspunten per tabblad: de knop van een tabblad wordt oranje bij een waarschuwing en rood bij een fout op dat
  onderdeel; zonder kleur is alles in orde. Events telt alles bij elkaar. Met Drempels en triggers (tabblad Events)
  bepaal je zelf wat een waarschuwing of fout is, bij welk percentage, of dat een melding helemaal uit staat.
- Per guest een steeksleutel om hem te bewerken: naam, cores, geheugen, swap, starten met de node, bescherming en de
  notitie, de labels, de IP-adressen en DNS van zijn netwerkkaarten, en zijn schijven groter maken.
- Labels (tags) van containers en VM's, in de kleuren van Proxmox: naast de naam, te bewerken met de steeksleutel,
  en met een klik op een label (of de keuzelijst Alle labels) zie je alleen de guests met dat label.
- De knop SXY: een schermvullend dashboard voor aan de muur, met toerentellers, grafieken van het laatste uur,
  aandachtspunten, de drukste guests, de opslag, een klok en naar keuze VM's en CT's met hun eigen tellers. Elke
  teller en tegel is een widget die je kunt
  verplaatsen en groter of kleiner maken; je kiest zelf wat er staat en hoe vaak het ververst.
- Starten, afsluiten, herstarten en geforceerd stoppen van meerdere guests tegelijk; migreren naar een andere node.
  Met Selecteer guests bij een node vink je in één keer alles aan wat daar draait; nog een keer klikken (Selectie
  opheffen) vinkt het weer uit.
- Per guest een uitklapregel met meer informatie: IP-adres, netwerk, schijven, geheugen, HA en de laatste back-up.
- Guests definitief verwijderen (alleen als ze uit staan, na het overtypen van hun ID's).
- Met de plusknop een container of VM aanmaken (met de eerstvolgende vrije ID's en een ISO of sjabloon uit de bibliotheek), een NFS- of SMB-share als opslag koppelen of een back-upschema maken.
- Snapshots maken, terugzetten en verwijderen.
- Updates zoeken en installeren op de nodes en in containers met Debian of Ubuntu, met vooraf een duidelijke
  waarschuwing en de keuze voor een back-up (volledig, alleen een snapshot, of al een recente); een node veilig
  herstarten.
- Automatisch bijwerken volgens een of meer schema's: per schema de gekozen containers en eventueel de nodes, een
  eigen moment en een snapshot of back-up vooraf.
- Een container naar de volgende Debian-versie brengen, met een volledige back-up naar keuze en altijd een snapshot
  vooraf.
- Via Cloudflare Zero Trust een waarschuwing en de keuze om de tool alleen te bekijken.
- Een tabblad Back-ups: schema's beheren, direct een back-up maken en terugzetten. Het zijn gewone Proxmox-back-ups, die je
  ook zonder deze tool kunt terugzetten. Onder Log staat per schema de laatste keer en de afloop, en elke back-upronde
  met de guests, de opslag, de duur, wat er misging en het log.
- Een tabblad HA: hoe High Availability er per node voor staat, welke guests HA bewaakt, en guests in HA zetten,
  hun HA-instellingen aanpassen of ze er weer uit halen, ook voor meerdere guests tegelijk. Onder Loadbalancer
  verdeelt Proxmox de HA-guests automatisch over de nodes, desgewenst met containers alleen 's nachts. Met de
  steeksleutel zie je of het cluster klaar is voor HA, beheer je de HA-regels, kies je wat HA doet bij het uitzetten
  van een node en schakel je HA tijdelijk uit voor onderhoud.
- Een tabblad Gebruikers (alleen voor beheerders): de gebruikers en groepen van Proxmox zelf aanmaken, bewerken en
  verwijderen, wachtwoorden zetten en rechten toekennen of intrekken, en API-tokens met hun eigen rechten.
- Een terminal naar een container, en voor beheerders een console (shell) op een node, in de pagina zelf.
- Tabellen naar je hand zetten: kolommen aan en uit (bij de guests ook extra kolommen, zoals schijf, kernen en labels)
  en een tabel op zijn tabblad omhoog of omlaag.
- Zoeken in de catalogus van Proxmox VE Helper-Scripts (community-scripts.org).
- Optioneel een overzicht per mail: elke dag, elke week, om de week of elke maand, met de onderdelen die jij kiest, en
  eventueel alleen als er iets aan de hand is. De mail stel je in de pagina in, voor Gmail, Outlook, Microsoft 365,
  iCloud, Yahoo, Ziggo, KPN of een eigen mailserver, en je kunt een testmail sturen.
- Een eigen achtergrondkleur, en de taal van de pagina (Nederlands, Engels, Duits) via het menu.
- De tool zelf bijwerken door het setup-bestand van een nieuwere versie, of meteen de ZIP van GitHub, in de pagina aan
  te leveren.
- Het wachtwoord van de tool wijzigen via het menu.
- Inloggen met een beveiligingssleutel (YubiKey of passkey): zonder wachtwoord, of als extra stap na het wachtwoord.
- Meer gebruikers, elk met een eigen wachtwoord: als beheerder, met alleen lezen, of met de rol van een of meer
  tabbladen (menu, Gebruikers). De beheerder bepaalt daar ook hoe lang een wachtwoord minstens moet zijn.
- Inloggen met SSO: OpenID Connect (Microsoft Entra ID/Azure, Google, Authentik, Keycloak en dergelijke), Cloudflare
  Access of een Proxmox-account. Per gebruiker koppel je zijn account, en of hij daarnaast nog met een wachtwoord mag
  inloggen.

## Wat heb je nodig

- Proxmox VE 9 (versie 8 kan werken, maar is niet getest), op gewone pc-hardware (amd64).
- Root-toegang tot de shell van één node.
- Een vrij, vast IP-adres in je netwerk voor de container.
- Internet voor de container tijdens het installeren (Debian- en Python-pakketten).
- Ongeveer 5 GB vrije opslag en 512 MB geheugen.

## Installeren

1. Zet `maintool-setup.sh` op een node, bijvoorbeeld vanaf je eigen computer:

       scp maintool-setup.sh root@ADRES-VAN-JE-NODE:/root/

   Heb je de ZIP van GitHub gedownload, pak hem dan uit: het setup-bestand is `maintool-setup.sh`, bovenin naast deze
   uitleg. De andere bestanden zijn de broncode; wie wil, maakt daar met `bash build.sh` zelf een setup-bestand van
   (`dist/maintool-setup.sh`). In ZIP's tot en met versie 1.4 staat het kant-en-klare setup-bestand nog niet.

2. Open de shell van die node (in de webinterface van Proxmox: node > Shell) en start:

       bash /root/maintool-setup.sh

3. Kies de taal (English, Nederlands of Deutsch; Enter neemt het voorstel), lees de waarschuwing, beantwoord de
   vragen (container-ID, opslag, netwerk, vast IP-adres, gebruikersnaam en een wachtwoord van minstens 8 tekens) en
   bevestig de samenvatting. Tot die bevestiging verandert er niets.

Vóór de vragen kijkt het setup-bestand of elke node bereikbaar is op het adres waaronder het cluster hem kent. Klopt
dat niet, meestal door een oud adres in `/etc/hosts` op die node na het wijzigen van zijn adres, dan zegt het wat je
eraan doet en vraagt het of je toch doorgaat. Het werkt met elke taalinstelling van de node (ook `en_US.UTF-8`).

Wil je de taalvraag overslaan, zet de taal dan vooraan: `bash maintool-setup.sh --lang nl` (of `en`, `de`).
`bash maintool-setup.sh --leesmij` toont deze uitleg (`--readme` in het Engels, `--liesmich` in het Duits).

Na een paar minuten staat de tool klaar op `https://HET-GEKOZEN-ADRES:8443`. Je browser waarschuwt de eerste keer
voor het certificaat, omdat de tool zijn eigen certificaat maakt. Dat is normaal.

Aan het eind draait een zelftest die meldt wat werkt en wat niet.

## Wat het setup-bestand aanmaakt

- Een container (Debian, 1 kern, 512 MB, 4 GB) met het label `maintool`, waarin de tool draait.
- In Proxmox de gebruiker `maintool@pve` met de rol Administrator, en een toegangssleutel `ct<ID>` die alleen in
  de container bekend is. Elke installatie krijgt een eigen sleutel.
- Op elke node het hulpscript `/usr/local/sbin/maintool-agent`.
- Eén regel in `/etc/pve/priv/authorized_keys`: de SSH-sleutel van de container mag alleen dat hulpscript
  starten, en alleen vanaf het adres van de container. Van het bestand wordt eerst een kopie gemaakt in `/root`.
- Een logboek van de installatie in `/var/log/maintool-setup.log` (zonder wachtwoorden of sleutels).

## Bijwerken en verwijderen

Het eenvoudigst: open in de tool het menu, kies **Tool bijwerken** en lever daar het setup-bestand van de nieuwere
versie aan, of meteen de ZIP van die versie van GitHub: de tool haalt het setup-bestand er dan zelf uit. Dat laatste
kan vanaf versie 1.4.1 (zowel de tool die draait als de ZIP); draait er nog een oudere versie, pak de ZIP dan eerst uit
en kies `maintool-setup.sh`. De tool controleert het bestand, vraagt je wachtwoord, bewaart een kopie van de oude versie en zet die
vanzelf terug als de nieuwe niet goed start. Dit vervangt alleen de tool zelf. Verandert een nieuwe versie meer
(het hulpscript op de nodes, de dienst, Python-pakketten), dan meldt de pagina dat en gebruik je het setup-bestand
op de node:

    bash maintool-setup.sh --update ID

Het vraagt eerst de taal en daarna of je door wilt gaan: typ `ja`.

Alles weer weghalen (de container, de toegangssleutel, de regel in `authorized_keys` en, als geen andere Maintool
ze gebruikt, de gebruiker en het hulpscript):

    bash maintool-setup.sh --uninstall ID

Beide moeten draaien op de node waar de container op dat moment staat.

## Wachtwoord vergeten

Een wachtwoord dat je in de tool hebt gewijzigd staat alleen als hash in de container. Ben je het kwijt, gooi dat
bestand dan weg op de node; daarna geldt weer het wachtwoord dat je bij de installatie koos:

    pct exec ID -- rm /var/lib/maintool/auth.json

Dat eerste wachtwoord staat als `APP_PASSWORD` in `/etc/maintool/maintool.env` en kun je daar ook aanpassen
(daarna `systemctl restart maintool` in de container).

Dit gaat over het hoofdaccount, dat je bij de installatie koos. Het wachtwoord van een andere gebruiker zet een
beheerder opnieuw in de tool, via het menu bij Gebruikers. Alle extra gebruikers in één keer weghalen kan ook:

    pct exec ID -- rm /var/lib/maintool/users.json

## Gebruikers en rollen

In het menu onder Gebruikers maakt een beheerder extra gebruikers aan. Iedereen die kan inloggen mag alles bekijken.
Wat iemand mag veranderen hangt af van zijn rollen; de namen komen overeen met de tabbladen:

- **Overzicht-beheerder**: guests starten, stoppen, migreren, bewerken (ook hun IP-adres en schijven), aanmaken en
  verwijderen, snapshots, updates (ook automatisch bijwerken), de console en nodes herstarten, HA (ook de regels en het onderhoud) en de loadbalancer.
- **Opslag-beheerder**: een NFS- of SMB-share als opslag koppelen, de bibliotheek van ISO's en sjablonen beheren, en
  Ceph instellen.
- **Netwerk-beheerder**: VLAN's klaarzetten, toepassen en verwijderen, en het netwerk van een guest wijzigen.
- **Backup-beheerder**: schema's, direct een back-up maken, terugzetten en back-ups verwijderen.
- **Events-beheerder**: de mail, de planning en inhoud van het overzicht per mail, en de drempels en triggers.

Rollen kun je combineren. Zonder rol mag iemand alleen lezen. Alleen een beheerder mag gebruikers beheren, de tool
bijwerken en de minimale lengte van wachtwoorden instellen (8 tot 128 tekens, standaard 12). Die lengte geldt voor
elk wachtwoord dat daarna wordt gekozen; bestaande wachtwoorden blijven werken.

Bovenaan de pagina staat als wie je bent ingelogd en wat je mag. Uitloggen doe je met de knop rechtsboven.

## Ingelogd blijven en uitloggen

- Op de inlogpagina staat het vinkje **Ingelogd blijven**: de sessie blijft dan ook na het sluiten van de browser,
  standaard 30 dagen. Zonder vinkje verdwijnt de sessie als je de browser sluit, en verloopt hij uiterlijk na 12 uur.
  Het vinkje geldt ook voor inloggen met SSO.
- Een beheerder stelt in het menu bij Gebruikers, onder Sessies, in: na hoeveel tijd zonder activiteit de pagina
  uitlogt (nooit, of van 15 minuten tot 8 uur), hoe lang een gewone sessie hooguit duurt (1 tot 24 uur), en of en hoe
  lang Ingelogd blijven mag (7, 14, 30 of 90 dagen).
- Een minuut voor het uitloggen vraagt de pagina of je nog aan het werk bent. Activiteit is de muis, het toetsenbord,
  aanraken of scrollen in een tabblad van de tool; het verversen op de achtergrond telt niet. Het dashboard aan de muur
  (SXY) en wie ingelogd blijft, worden niet uitgelogd. Het uitloggen doet de pagina zelf; een sessie die nergens open
  staat, verloopt op zijn eigen tijd.

## Beveiligingssleutels (YubiKey, passkey)

In het menu onder **Beveiligingssleutels** voeg je een sleutel toe: een YubiKey of een andere FIDO2-sleutel, of een
passkey op je telefoon of computer. Daarna kun je:

- **inloggen met alleen de sleutel**, met de knop Inloggen met beveiligingssleutel op de inlogpagina. De sleutel vraagt
  dan zijn pincode of je vingerafdruk. Vul je eerst je gebruikersnaam in, dan biedt de browser alleen jouw sleutels aan.
- **de sleutel na je wachtwoord laten vragen**, met het vinkje bij Na het wachtwoord. Inloggen met alleen een
  wachtwoord kan dan niet meer, ook niet met een Proxmox-account. Bij OpenID Connect en Cloudflare Access regelt die
  dienst zelf een extra stap.

Goed om te weten:

- Een sleutel werkt op het adres waarop je hem hebt toegevoegd, bijvoorbeeld je Cloudflare-adres. Browsers staan
  beveiligingssleutels niet toe op een IP-adres of bij een certificaatfout, dus via het IP-adres in je eigen netwerk
  lukt het niet. Is de sleutel bij jou verplicht, dan log je via dat IP-adres ook niet meer met alleen je wachtwoord in.
- Een wijziging aan je sleutels bevestig je met je wachtwoord. De tool bewaart alleen de openbare sleutel, niets
  waarmee iemand anders zou kunnen inloggen.
- Sleutel kwijt? Een beheerder haalt in het menu bij Gebruikers met **Sleutels weghalen** al je sleutels weg. Ben je
  zelf de enige beheerder, haal dan op de node de sleutels van iedereen weg:

      pct exec ID -- rm /var/lib/maintool/webauthn.json

## Console van een node

Beheerders hebben op elke nodekaart een knop **>_** voor een console (shell) op die node, in een venster in de pagina.
Proxmox geeft zo'n console alleen aan een account van de node zelf (realm pam), zoals root, en niet aan de
toegangssleutel van de tool. De eerste keer log je daarom met zo'n account in, met de code uit je authenticator-app als
het account tweestapsverificatie heeft. De tool bewaart het wachtwoord niet en onthoudt het inloggen alleen voor deze
browsersessie, hooguit een uur; uitloggen uit de tool vergeet het ook. Bij Events staat wie inlogde en wie een console
opende.

Staat root@pam in Proxmox uit (een veelgebruikte extra beveiliging), dan zegt het venster dat. Gebruik dan een ander
pam-account dat een console mag openen: een Linux-account op de nodes, dat in Proxmox (tabblad Gebruikers) bestaat en
het recht Sys.Console op de nodes heeft, bijvoorbeeld met de rol PVEAdmin. Omdat Proxmox alleen root meteen binnenlaat,
vraagt de console daarna zelf nog een keer om in te loggen.

## Tabellen aanpassen

Rechtsboven in elke tabel op een tabblad staat een klein knopje. Daarmee:

- zet je kolommen aan of uit. Bij de guests op het Overzicht kun je ook extra kolommen toevoegen: schijf, kernen,
  labels, pool en HA-status;
- zet je de tabel op zijn tabblad een plek omhoog of omlaag (op het Overzicht ook boven of onder de nodekaarten);
- zet **Standaard** alles van dat tabblad terug.

Je keuzes horen bij jouw gebruiker en gelden op elk apparaat waarop je inlogt.

## Logboek van een node

De knop met de streepjes op de kaart van een node (naast de console) opent zijn logboek. Alles gaat over precies die
ene node, en de tool leest alleen:

- **Systeemlog**: het logboek van de node (journal) over het laatste kwartier, uur, 6 of 24 uur, of de laatste 5000
  regels. Kies een bron (een programma of dienst, zoals corosync of pveproxy), zoek op tekst of toon alleen
  problemen: fouten in rood, waarschuwingen in oranje. Met Opslaan als bestand krijg je wat je ziet als tekstbestand.
- **Taken**: de laatste taken van de node, ook oudere die mislukten, met het log van elke taak.
- **Diensten**: welke diensten draaien en welke niet; een dienst die mee hoort te starten maar niet draait is rood.
- **Clusterlog**: wat het cluster over deze node meldt, zoals mislukte aanmeldingen.
- **Door de tool**: wat de tool de afgelopen 30 dagen op deze node deed (updates, herstarts).

## Topologie

Bovenaan het tabblad Netwerken tekent de topologie hoe het cluster in elkaar zit: boven de router en de gedeelde
opslag (Ceph, NFS, SMB, PBS), daaronder de nodes met hun bridges en onder elke node zijn containers en VM's, elk aan
zijn bridge. Over elke verbinding loopt een stroom: blauw naar binnen (naar de node of guest toe), groen naar buiten.
Hoe dikker en sneller, hoe meer verkeer; in de vakken staan de cijfers. Het verkeer van een node is het gemiddelde
van de laatste minuut (uit Proxmox), dat van een guest wordt elke 2 seconden bijgewerkt. Het verkeer naar een opslag
is een schatting uit de schijven van de guests; bij Ceph staat het verkeer van het hele cluster in het vak. Klik op
een guest om hem in het overzicht te tonen. Met Verbergen klap je de topologie in; deze browser onthoudt dat.

## Labels

De labels (tags) van containers en VM's staan naast hun naam, in dezelfde kleuren als in Proxmox (eigen kleuren stel
je in Proxmox in: Datacenter, Options, Tag Style). Met de steeksleutel van een guest wijzig je ze: gescheiden door
spaties of komma's, en de labels die elders al gebruikt worden kun je met een klik toevoegen. Een klik op een label
in de tabel (of de keuzelijst Alle labels) toont alleen de guests met dat label; nog een klik toont weer alles. De
container van de tool zelf houdt zijn label `maintool`: daaraan herkent het setup-bestand hem.

## Updates en automatisch bijwerken

Klik je bij een container op Update of op de knop voor een nieuwe Debian-versie (bijvoorbeeld → 13), dan komt er eerst
een venster met een waarschuwing en de keuze hoe je je indekt:

- **Een volledige back-up maken (aanbevolen)**, naar een back-upopslag die je kiest. De tool maakt de back-up zelf en
  begint pas aan de update als die gelukt is; mislukt de back-up, dan gebeurt er niets. Dat loopt door, ook als je de
  pagina sluit.
- **Alleen een snapshot**: snel, maar een snapshot staat op dezelfde opslag als de container. Bij een nieuwe
  Debian-versie maakt de tool die snapshot altijd al.
- **Geen extra back-up**, omdat je al een recente hebt; het venster laat zien van wanneer de laatste back-up is.

Je moet aanvinken dat je het risico begrijpt. Bij een node kan Proxmox zelf geen back-up maken; daar blijft het bij de
waarschuwing.

Met de knop met de klok naast Zoek updates (tabblad Overzicht) stel je **automatisch bijwerken** in, met een of meer
schema's. Elk schema heeft een eigen naam, hoe vaak (elke dag, elke week, om de week of elke maand), op welke dag en
hoe laat, welke containers (alle, ook nieuwe, of een keuze) en of de nodes ook mee moeten, en wat er vooraf gebeurt
(een snapshot, een volledige back-up of niets). Zo werk je bijvoorbeeld de websites elke nacht bij en de rest één keer
per week. Zit een container in meer schema's, dan staat er bij de keuze een sterretje en zie je met de muis erop in
welke. Er draait één ronde tegelijk; vallen twee schema's samen, dan na elkaar. Een schema van voor versie 1.4 is
vanzelf het eerste schema. Op het moment zelf:

- verversen eerst alle pakketlijsten;
- worden de containers één voor één bijgewerkt, alleen als ze aan staan, Debian of Ubuntu hebben, updates hebben en niet
  vergrendeld zijn (bijvoorbeeld door een back-up). Een mislukte back-up vooraf betekent: die container niet bijwerken;
- bij een snapshot vooraf ruimt de tool daarna de vorige automatische snapshot (`auto_update_...`) van die container op;
  andere snapshots blijven altijd staan;
- daarna de nodes, één tegelijk, alleen als alle nodes online zijn, het cluster een meerderheid heeft en Ceph klaar is
  met herstellen. Na elke node wacht de tool tot alles weer in orde is. Nodes worden nooit vanzelf herstart; een
  node die herstart moet worden verschijnt bij de aandachtspunten.

Stond de tool op het geplande moment uit, dan gebeurt het alsnog tot drie uur later. De lijst laat per schema zien
wanneer het de volgende keer draait en hoe de laatste ronde ging (met Bewerken zie je elke uitkomst); elke uitkomst
komt ook bij Events en in het overzicht per mail, en een mislukte ronde wordt een aandachtspunt. Met Nu draai je een
ronde van dat schema meteen.

## Via Cloudflare Zero Trust

Via Cloudflare Zero Trust is de tool trager en kan een verbinding halverwege wegvallen, bijvoorbeeld tijdens een
update, een back-up of in de console. Opent iemand de tool via Cloudflare, dan komt er daarom eerst een venster met
een waarschuwing en de keuze **Alleen bekijken (aanbevolen)** of **Toch volledig gebruiken**. Wie alleen bekijkt ziet
alles, maar kan niets wijzigen; de tool weigert het ook zelf. Bovenaan de pagina kun je wisselen. De keuze geldt tot
je de browser sluit. In het venster kies je ook de taal. Komt er via Cloudflare geen antwoord, dan zegt het venster dat
na 20 seconden en kun je het opnieuw proberen.

Verloopt je inlog bij Cloudflare Access terwijl de pagina open staat, dan meldt de tool dat bovenaan, met de knop
Opnieuw inloggen. Hoe lang die inlog geldt, stel je in Cloudflare Zero Trust in: Access, Applications, de applicatie
van de tool, Session Duration (bijvoorbeeld 24 uur).

Een beheerder kan in het venster Gebruikers bij Toegang via Cloudflare ook kiezen voor **altijd alleen bekijken** (dan
kan via Cloudflare niemand iets wijzigen) of **niets vragen**. In je eigen netwerk, zonder Cloudflare, geldt dit niet.

## HA (High Availability)

Een guest in HA wordt door Proxmox bewaakt: loopt hij vast, dan herstart HA hem, en valt zijn node uit, dan start HA
hem na een paar minuten op een andere node. Het tabblad HA laat zien of het cluster een meerderheid heeft, welke node
HA aanstuurt, hoe HA er per node voor staat (bijvoorbeeld in bedrijf of in onderhoudsmodus) en welke guests erin staan,
met hun toestand, wat HA met ze moet doen en hoe vaak HA opnieuw mag proberen.

- **Toevoegen** met de plusknop op het tabblad, of in het overzicht via Actie voor selectie, Aan HA toevoegen. Je
  kiest een of meer guests en wat HA met ze doet. Standaard blijft alles zoals het is: een guest die aan staat komt op
  Aan, een guest die uit staat op Uit. Kies je iets anders, dan meldt het venster vooraf welke guests HA meteen start
  of uitzet.
- Staat een schijf (of een cd-rom met een ISO) van een guest niet op gedeelde opslag zoals Ceph of een NAS, dan meldt
  de tool dat: HA kan zo'n guest bij uitval van zijn node niet op een andere node starten.
- **Aanpassen**: Aan (HA houdt hem aan), Uit (HA houdt hem uit, maar verhuist hem wel bij uitval van de node),
  Uitgeschakeld (uit en niet verhuizen; zo ruim je ook een fout op: eerst Uitgeschakeld, daarna weer Aan) of Genegeerd
  (HA laat hem met rust, bijvoorbeeld tijdens onderhoud). Verder hoe vaak HA een guest die niet wil starten opnieuw
  probeert op dezelfde node en daarna op een andere node, en een opmerking.
- **Uit HA halen**: de guest blijft zoals hij is (aan blijft aan, uit blijft uit), maar wordt niet meer bewaakt.

Wie het mag: beheerders en iedereen met de rol Overzicht. Elke wijziging komt bij Events, met wie het deed. De
container van de tool zelf zet de tool niet via HA uit. Een HA-guest in het overzicht heeft een knopje HA; daarmee
ga je naar het tabblad.

## Loadbalancer (tabblad HA)

Proxmox VE 9.2 kan de guests in HA zelf over de nodes verdelen (Cluster Resource Scheduling). Op het tabblad HA, onder
Loadbalancer, zie je hoe dat ervoor staat en stel je het in; de tool verplaatst zelf niets.

- **Instellen**: of Proxmox automatisch verdeelt, waar hij naar kijkt (Dynamisch: het echte gebruik van processor en
  geheugen, aanbevolen; Statisch: de ingestelde kernen en het geheugen; Basis: alleen het aantal guests, en dan kan
  automatisch verdelen niet) en of een HA-guest die start op de rustigste node komt. Onder Fijnafstelling: vanaf
  welke onbalans Proxmox verdeelt (standaard 30%), hoeveel beter het minstens moet worden (10%), hoeveel rondes van
  ongeveer 10 seconden de onbalans moet aanhouden (3) en de rekenmethode.
- **Per guest** zet je aan of uit of hij meedoet. Alleen guests in HA doen mee; de guests die niet in HA staan zie je
  eronder, met een knop om ze aan HA toe te voegen. Een guest met een schijf op lokale opslag kan niet verhuizen; de
  tool meldt dat.
- **Containers alleen 's nachts**: een VM verhuist terwijl hij doorloopt, een container gaat ongeveer 10 tot 20
  seconden uit. Met het tijdvenster (bijvoorbeeld van 02:00 tot 05:00) doen containers alleen binnen die uren mee:
  daarbuiten zet de tool hun meedoen in Proxmox uit, binnen het venster weer aan. Lukt dat niet, dan wordt het
  tabblad HA oranje.
- Je ziet de belasting per node, de onbalans volgens Proxmox, en de verplaatsingen van de afgelopen week: van welke
  node naar welke, wie ze startte (de HA-manager, de tool of een gebruiker) en hoe het afliep.

Wie het mag: beheerders en iedereen met de rol Overzicht. Elke wijziging komt bij Events. De instelling staat in
Proxmox zelf (Datacenter > Opties > Cluster Resource Scheduling), dus ze werkt ook als de tool uit staat; alleen het
tijdvenster heeft de tool nodig.

## HA instellen (steeksleutel op het tabblad HA)

- **Gereedheid**: of het cluster klaar is voor HA: minstens drie nodes, een meerderheid, gedeelde opslag voor guests,
  de HA-manager en de bewaking op elke node, en welke guests in HA een schijf op lokale opslag hebben.
- **Regels** (Proxmox VE 9): voorkeur voor nodes (met prioriteit, en strikt: alleen daar), niet op bepaalde nodes,
  samen op één node, of niet samen op één node. Proxmox zet de guests meteen volgens een nieuwe regel; een container
  die daarvoor moet verhuizen, gaat even uit. Op Proxmox VE 8 stel je de HA-groepen in Proxmox zelf in.
- **Instellingen**: wat HA doet als een node wordt uitgezet of herstart.
- **Onderhoud**: HA tijdelijk uitschakelen (Proxmox VE 9.2), bijvoorbeeld voor werk aan het netwerk of aan het cluster
  zelf, zodat een node die even onbereikbaar is niet wordt afgeschoten. Je kiest of de guests blijven zoals ze zijn of
  dat je ze zelf kunt starten, stoppen en verhuizen. Zolang HA uit staat, is het tabblad HA oranje; zet HA na het
  onderhoud meteen weer aan.

## Ceph instellen (steeksleutel op het tabblad Opslag)

- **Overzicht**: de gezondheid, het netwerk, de versie per node, en per node de monitor, de manager, de OSD's en de
  vrije schijven. Draait Ceph nog niet, dan staan hier de stappen om het op te bouwen. De pakketten installeer je per
  node in de shell (`pveceph install --repository no-subscription`); daarna richt de tool Ceph in met het netwerk dat je
  opgeeft, en voeg je monitors, managers, OSD's en een pool toe.
- **Monitors en managers** toevoegen en verwijderen. De laatste monitor of manager haalt de tool niet weg, en een
  monitor alleen als Ceph zegt dat de meerderheid blijft.
- **OSD's**: in of uit gebruik nemen, stoppen en starten, van een vrije schijf een OSD maken en een OSD verwijderen.
  Voor stoppen en verwijderen vraagt de tool Ceph eerst of het veilig is; uit gebruik nemen weigert de tool als er dan
  te weinig nodes overblijven voor de pools. Een OSD maken of verwijderen wist de schijf; ter bevestiging typ je de
  naam van de schijf of de OSD.
- **Pools** aanmaken (meteen als opslag in Proxmox), aanpassen (kopieën, minimum, automatisch schalen) en verwijderen.
  Een pool waar nog schijven op staan, of een pool van Ceph zelf, verwijdert de tool niet.
- **Vlaggen** voor onderhoud, zoals noout. Vlaggen die alles stilzetten (pause, noup, nodown) zet de tool niet.

Wie het mag: HA instellen beheerders en de rol Overzicht, Ceph instellen beheerders en de rol Opslag. Elke wijziging
komt bij Events.

## Proxmox-gebruikers en groepen (tabblad Gebruikers)

Het tabblad Gebruikers gaat over de gebruikers van Proxmox zelf, waarmee je inlogt op Proxmox (in Proxmox: Datacenter,
Permissions). De gebruikers van deze tool zelf beheer je via het menu (de drie streepjes linksboven), bij Gebruikers. Het tabblad is er alleen voor
beheerders van de tool.

- **Gebruikers**: aanmaken in een realm (bij **pve** kies je een wachtwoord; bij **pam** moet het Linux-account op
  elke node al bestaan; bij een andere realm regelt die het inloggen), met naam, e-mail, opmerking, een datum waarop
  het account verloopt, aan of uit, en de groepen. Bewerken, een nieuw wachtwoord (realm pve) en verwijderen.
- **Groepen**: aanmaken met een opmerking en leden, bewerken en verwijderen. De gebruikers zelf blijven bestaan.
- **Rechten**: per gebruiker of groep een rol op een plek: alles, alle guests of één guest, opslag, een node of een
  pool. Bij een rol staat wat die mag. Een gebruiker krijgt ook de rechten van zijn groepen; dat staat erbij.
- **API-tokens**: voor scripts en andere programma's. Je maakt een token bij een gebruiker, met een opmerking en een
  datum waarop het verloopt. Met **eigen rechten** (aanbevolen) mag het token alleen wat je het met de knop Rechten
  geeft, en nooit meer dan zijn gebruiker; zonder mag het precies wat de gebruiker mag. Het geheim van een nieuw token
  zie je één keer, met de regel voor in een script; de tool bewaart het niet. Tokens van root@pam en van de gebruiker
  van de tool wijzigt de tool niet.

De tool beschermt je tegen jezelf buitensluiten. root@pam en de gebruiker waarmee de tool zelf werkt wijzigt hij niet,
en een wijziging waarna niemand meer alles mag in Proxmox (Administrator op /), behalve de tool zelf, weigert hij:
de laatste beheerder uitzetten, laten verlopen, verwijderen, zijn recht afnemen of NoAccess geven. Bij vergaande
rechten op alles vraagt de pagina eerst om bevestiging. Wachtwoorden gaan alleen door naar Proxmox; de tool bewaart
en logt ze niet. Elke wijziging komt bij Events, met wie het deed.

## Inloggen met SSO

Naast het eigen wachtwoord kan een beheerder in het venster Gebruikers met de knop SSO instellen drie manieren aanzetten.
Daarna koppel je per gebruiker (knop Bewerken, bij het hoofdaccount en bij jezelf de knop SSO) welk account bij hem
hoort. Alleen wie gekoppeld is komt binnen, met de rechten die hij in de tool heeft; er worden nooit vanzelf
gebruikers aangemaakt. Een account hoort bij één gebruiker. Bij een gebruiker kun je inloggen met een wachtwoord
uitzetten; hij komt dan alleen nog via SSO binnen. Het hoofdaccount houdt altijd zijn wachtwoord, zodat je er nooit
uit kunt raken.

- **OpenID Connect** (Microsoft Entra ID/Azure, Google, Authentik, Keycloak of een andere OpenID-dienst). Maak bij die
  dienst een app aan met als redirect-URI het adres dat de tool toont (`https://ADRES/api/sso/oidc/callback`), en vul
  in de tool de uitgever (issuer), de client-ID en het client secret in, plus het adres waarop je de tool opent. Bij
  Microsoft is de uitgever `https://login.microsoftonline.com/<tenant-ID>/v2.0`, met je eigen tenant-ID. Google en
  Microsoft willen een echt webadres, zoals je Cloudflare-adres; een IP-adres werkt daar niet. Je koppelt per
  gebruiker het mailadres waarmee hij bij de dienst inlogt. Bij de eerste inlog legt de tool vast welk account bij
  de dienst dat was; daarna komt alleen dat account binnen, ook als een ander account later hetzelfde mailadres
  laat zien. Het client secret staat leesbaar in `/var/lib/maintool/sso.json` (de tool moet het meesturen); dat
  bestand is alleen voor de tool leesbaar en het secret wordt nooit in de pagina getoond.
- **Cloudflare Access**. Staat de tool achter Cloudflare Access, dan heb je daar al ingelogd. Vul de teamnaam (het
  eerste deel van `jouwteam.cloudflareaccess.com`) en de Application Audience (AUD) Tag van de applicatie in; je
  vindt ze in Cloudflare Zero Trust bij Access, Applications. Wie de tool via het Cloudflare-adres opent en met een
  gekoppeld mailadres bij Cloudflare is ingelogd, komt meteen binnen. De tool controleert het token van Cloudflare
  met de openbare sleutels van je team. Na Uitloggen gaat dat niet meer vanzelf; dan is er een knop op de
  inlogpagina. Via het adres in je eigen netwerk is het gewone wachtwoord nodig.
- **Proxmox-account**. Op de inlogpagina kies je dan Proxmox-account, de realm (bijvoorbeeld pam) en log je in met
  gebruikersnaam en wachtwoord van Proxmox zelf. Proxmox controleert het wachtwoord; de tool vraagt dat alleen voor
  accounts die aan een gebruiker zijn gekoppeld (bijvoorbeeld `jan@pam`). Accounts met tweestapsverificatie kunnen
  (nog) niet.

## Drempels en triggers

Op het tabblad Events opent de knop Drempels en triggers de lijst met alles waar de tool op let, per tabblad. Bij
elke regel kies je of het een fout, een waarschuwing of alleen een mededeling is, of dat het uit staat. Bij
percentages (geheugen van een node, volle schijf of opslag, slijtage van een schijf) vul je in vanaf welk percentage
het een waarschuwing en vanaf welk percentage het een fout is. De melding over oude back-ups staat standaard uit; je
zet hem aan door een aantal dagen in te vullen. Met Standaard gaat alles terug naar hoe het was.

De kleur van de tabbladen, de lijst met aandachtspunten en het dashboard volgen deze instellingen. De tool rekent de
aandachtspunten ongeveer één keer per minuut opnieuw uit.

## Dashboard voor aan de muur (SXY)

De knop SXY in de kop opent een donker, schermvullend dashboard. Alles erop is een widget: per node een toerenteller
voor processor en geheugen, grafieken van het laatste uur (processor, geheugen, netwerkverkeer), het cluster in
cijfers, de aandachtspunten, de drukste guests, de opslag en een klok. Onder VM's en CT's kies je daarnaast guests
die een eigen widget krijgen: met toerentellers voor processor en geheugen, of hij aan staat, op welke node, hoe
lang al, en bij een container hoe vol zijn schijf is.

- **Indeling aanpassen**: zet het slot rechtsboven open. Sleep een widget naar een andere plek; de andere schuiven
  dan op, zoals widgets op een telefoon. Met het hoekje rechtsonder maak je een widget groter of kleiner, met het
  kruisje haal je hem weg. Met het toetsenbord kan het ook: pijltjes verplaatsen, Shift met pijltjes verandert de
  maat. Zet het slot weer dicht als je klaar bent (of druk op Esc).
- **Wat er te zien is en hoe vaak het ververst**: de knop met de schuifjes. Daar zet je widgets aan of uit, kies je
  hoe vaak tellers en cijfers verversen (elke 2 seconden tot elke minuut) en de grafieken (elke 30 seconden tot elke
  10 minuten), en of alles op één scherm moet passen. Standaardindeling zet alle widgets terug op hun eigen plek en maat.
- De indeling en de verversing worden bewaard bij je gebruiker, dus ze gelden op elk scherm waar je met die
  gebruiker inlogt. Op een telefoon staan de widgets onder elkaar en is het slot er niet.

Sluiten kan met het kruis of Esc.

Zet je `#sxy` achter het adres van de tool (bijvoorbeeld `https://ADRES:8443/#sxy`), dan opent het dashboard direct
na het inloggen. Zolang het dashboard open staat blijft die browser ingelogd en probeert hij het scherm aan te
houden. Gebruik voor een scherm aan de muur daarom een gebruiker zonder rollen (alleen lezen), en vink bij het inloggen
Ingelogd blijven aan; dan blijft het scherm ook na een herstart van de browser ingelogd.

## Overzicht per mail (optioneel)

Op het tabblad Events staat het blok Overzicht per mail. Daar zie je of het is ingesteld, kun je bekijken hoe het
overzicht eruitziet, het direct versturen of een korte testmail sturen.

Met Planning en inhoud kies je hoe vaak het komt (elke dag, elke week, om de week, elke maand of niet vanzelf), op
welke dag en hoe laat, welke onderdelen erin staan (aandachtspunten, nodes, VM's en CT's, back-ups, updates, opslag
en Ceph, mislukte taken) en of het alleen verstuurd wordt als er aandachtspunten zijn. Het overzicht gaat steeds
over de afgelopen periode; aandachtspunten van een onderdeel dat uit staat tellen niet mee. Zonder eigen planning
komt het elke week op de dag en tijd uit `maintool.env` (standaard zondag 05:00). Stond de tool op het geplande
moment uit, dan komt het alsnog, tot een dag later (bij elke dag: een halve dag).

Met Mail instellen kies je eerst de soort
mailserver: Gmail, Outlook.com, Microsoft 365, iCloud, Yahoo, Ziggo, KPN of een andere of eigen server. Bij een
bekende soort vult de tool de server, de poort en de versleuteling zelf in. Bij een eigen server kies je die zelf:
STARTTLS, SSL/TLS of geen versleuteling, met of zonder inloggen, en zo nodig een aparte inlognaam of een server met
een eigen certificaat. Je kunt ook een afzendernaam opgeven. Bij opslaan maakt de tool één keer verbinding met de
mailserver om te controleren of het klopt; lukt dat niet, dan wordt er niets bewaard.

Voor Gmail heb je een app-wachtwoord nodig, niet je gewone wachtwoord: maak het aan in je Google-account onder
Beveiliging, Verificatie in twee stappen, App-wachtwoorden. iCloud en Yahoo werken ook met een app-wachtwoord.
Wil je alleen een ander ontvangstadres, dan laat je het wachtwoord leeg. Verander je de server of de inlognaam, dan
moet je het wachtwoord opnieuw invullen: de tool stuurt een bewaard wachtwoord nooit naar een andere server. Over
een verbinding zonder versleuteling wordt geen wachtwoord verstuurd.

Het wachtwoord staat leesbaar in `/var/lib/maintool/mail.json` in de container (de tool moet ermee inloggen); dat
bestand is alleen voor de tool leesbaar en het wachtwoord wordt nooit in de pagina getoond. Je kunt de mail ook nog
instellen met de `MAIL_`-regels in `/etc/maintool/maintool.env`; wat in de pagina is ingesteld gaat voor.

## Bekende beperkingen

- De pagina, het setup-bestand en deze uitleg zijn er in het Nederlands, Engels en Duits. Het overzicht per mail is
  alleen in het Nederlands, net als het logboek van een update in een container en de toelichting in het
  instellingenbestand `maintool.env`.
- Verwijderen kan alleen voor guests die uit staan en niet in Proxmox beschermd zijn; de container van de tool zelf
  kan zichzelf niet verwijderen. Back-ups op de back-upopslag blijven staan.
- Updates en de console werken voor containers; VM's kun je wel starten, stoppen, migreren en back-uppen.
- Updates werken in containers met Debian of Ubuntu (apt). Andere systemen worden getoond zonder updateknop.
- In een cluster gebruikt de tool voor back-ups alleen gedeelde opslag (NFS, CIFS, PBS). Met één node telt
  elke back-upopslag.
- Nodes met een eigen certificaat op de webinterface (bijvoorbeeld Let's Encrypt) kan de tool waarschijnlijk niet
  bereiken: hij controleert nodes met het certificaat van het cluster.
- Een VM maak je hier aan, maar installeren doe je daarna in Proxmox zelf via de console van de VM. Een ISO laat je
  downloaden via de bibliotheek; uploaden vanaf je eigen computer doe je in Proxmox zelf (opslag > ISO Images).
  Opslag koppelen kan voor NFS en SMB; andere soorten doe je in Proxmox. Bladeren door een opslag is alleen kijken.
- Automatisch bijwerken werkt voor containers met Debian of Ubuntu en voor de nodes; VM's werkt de tool niet bij, en
  nodes worden nooit vanzelf herstart. Of iemand via Cloudflare komt, ziet de tool aan wat Cloudflare zelf aan elk
  verzoek toevoegt.
- Komt er een node bij het cluster, dan toont de tool hem vanzelf en gebruikt hij hem ook als uitwijk voor de
  verbinding; een node die uit het cluster is gehaald verdwijnt vanzelf. Voor updates en herstarten moet op een
  nieuwe node nog wel het hulpscript komen: draai op een node `bash maintool-setup.sh --update`. De tool meldt
  dat op de kaart van die node.
- Een VLAN wordt eerst klaargezet en pas actief na Toepassen. Bij toepassen laadt Proxmox de netwerkinstellingen
  opnieuw: van één node, of bij een VLAN voor containers en VM's van alle nodes. De tool laat eerst zien wat er
  verandert. Doe dit niet tijdens een back-up, migratie of update, en zorg dat je bij een node kunt als de verbinding
  wegvalt. Een VLAN voor containers en VM's gebruikt SDN (Proxmox VE 8.1 of nieuwer). Bridges, bonds en het wijzigen
  of verwijderen van interfaces van een node doe je in Proxmox zelf.
- Het netwerk of VLAN van een guest wijzigen gaat bij een draaiende guest direct in; hij kan daardoor even of
  blijvend onbereikbaar worden als het nieuwe netwerk niet klopt. De tool vraagt eerst om bevestiging, laat de rest
  van de netwerkkaart (MAC-adres, IP-adres, firewall) ongemoeid en wijzigt het netwerk van zijn eigen container niet.
- Bij het bewerken van een guest kun je geen schijven of netwerkkaarten toevoegen; dat doe je in Proxmox zelf. Bij
  een draaiende VM gaan cores en geheugen meestal pas in na opnieuw starten; de tool meldt dat. Een vergrendelde
  guest en een sjabloon worden niet gewijzigd, en de tool hernoemt zijn eigen container niet.
- Het IP-adres van een guest wijzig je in het venster van de steeksleutel, per netwerkkaart: een vast adres met
  gateway (bijvoorbeeld `192.168.1.50/24` en `192.168.1.1`), DHCP of geen, en voor IPv6 ook automatisch, plus de
  DNS-servers en het zoekdomein (leeg: zoals de node). Bij een draaiende container gaat het direct in en vallen
  verbindingen met het oude adres weg; de tool vraagt eerst om bevestiging. Bij een VM kan het alleen als die een
  cloud-init-schijf heeft (en geldt het na een herstart); anders stel je het in de VM zelf in. De tool weigert een
  adres dat al bij een andere guest of een node hoort, laat de rest van de netwerkkaart ongemoeid en wijzigt het
  adres van zijn eigen container niet.
- Een schijf kan alleen groter, nooit kleiner (dat kan Proxmox niet), en hooguit met wat er op de opslag vrij is. In
  een container groeit het bestandssysteem vanzelf mee; in een VM moet je daarna de partitie en het bestandssysteem
  in de VM zelf vergroten. EFI-, TPM- en cloud-init-schijven, cd-roms en mappen of apparaten van de node vergroot de
  tool niet.
- SSO met Google of Microsoft werkt alleen via een echt webadres (bijvoorbeeld je Cloudflare-adres). Een
  Proxmox-account met tweestapsverificatie kan niet inloggen. Wordt een SSO-koppeling weggehaald of veranderd, dan
  moet die gebruiker opnieuw inloggen; bij het hoofdaccount lopen bestaande sessies gewoon af (na 12 uur).
- HA-groepen (Proxmox 8) en de onderhoudsmodus van één node stel je in Proxmox zelf in (Datacenter, HA). HA-regels
  (Proxmox 9), wat HA doet bij het uitzetten van een node en HA tijdelijk uitschakelen kunnen in de tool.
- Ceph-pakketten installeren, CephFS en metadataservers, en OSD's met een aparte schijf voor DB of WAL doe je in
  Proxmox zelf.
- De loadbalancer is die van Proxmox zelf (vanaf Proxmox VE 9.2): hij verdeelt alleen guests in HA, één tegelijk.
  Het tijdvenster voor containers regelt de tool; staat de tool uit op het moment dat het venster opent of sluit,
  dan gebeurt dat zodra hij weer draait.
- Op het tabblad Gebruikers beheer je geen tweestapsverificatie, realms of eigen rollen; dat doe je in Proxmox
  zelf. Vraagt Proxmox bij een nieuw wachtwoord het eigen wachtwoord van wie het wijzigt, dan kan de tool dat niet
  (hij werkt met een toegangssleutel) en zegt hij dat je het in Proxmox zelf doet.
- Bij de instellingen van een node wijzigt de tool de naam en het netwerk van de node niet (het netwerk staat op het
  tabblad Netwerken). Een verkeerde DNS-server of het uitzetten van alle Proxmox-bronnen kan de updates van die node
  blokkeren; het venster waarschuwt daarvoor. Elke node stel je apart in.
- Het tabblad Events gaat hooguit 30 dagen terug en toont wat Proxmox zelf bijhoudt; consolesessies staan er niet in.
- Wie alleen mag lezen ziet alles wat de tool toont, ook namen, IP-adressen, back-ups en het weekoverzicht.
- De console komt uit bij de loginprompt van de container; je hebt daar het root-wachtwoord van die container nodig.
- De container van de tool zelf heeft geen root-wachtwoord. Je komt erin met `pct enter ID` op de node.

## Als iets niet werkt

    pct exec ID -- runuser -u maintool -- /opt/maintool/venv/bin/python /opt/maintool/selftest.py
    pct exec ID -- journalctl -u maintool -n 50 --no-pager
    less /var/log/maintool-setup.log

Laadt de pagina traag, geeft hij fouten, of meldt de tool dat een node niet antwoordt via de API, kijk dan of het
cluster die node onder het goede adres kent. Proxmox neemt dat adres uit `/etc/hosts` op die node; na het wijzigen
van het adres van een node staat daar vaak nog het oude. Zet daar het juiste adres achter de naam en herstart die node
(of alleen de dienst: `systemctl restart pve-cluster`). De tool slaat zo'n node intussen over, zodat de rest van de
pagina gewoon werkt, en het setup-bestand controleert dit vóór het installeren.

## Licentie en credits

Proxmox Maintool is gemaakt door Eduard Wichers en valt onder de MIT-licentie (zie `LICENSE`).
Software van anderen staat in `THIRD-PARTY.md`. Proxmox is een merk van Proxmox Server Solutions GmbH;
deze tool is daar niet aan verbonden.
