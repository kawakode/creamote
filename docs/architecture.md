# Architecture

Vue d'ensemble ; les décisions détaillées sont dans `docs/adr/`.

## Flux d'une session

1. **Enregistrement** : host et client ouvrent une connexion persistante vers le serveur de rendezvous choisi et s'annoncent avec leur identité (`RegisterPeer`).
2. **Signalisation** : le client demande à joindre un ID (`ConnectRequest`) ; le serveur transmet l'offre au host (`ConnectOffer`) et échange les adresses observées.
3. **Session acceptée** : le serveur envoie à chacun un `RelayGrant` portant les adresses candidates de l'autre pair et un jeton relay.
4. **P2P puis repli relay** : les deux pairs tentent une connexion QUIC directe (adresse publique par hole punching UDP, adresses LAN) ; le viewer rejoint le relay en parallèle et l'utilise si le direct n'aboutit pas en 3 s. Le relay recopie des octets opaques. Repli TCP/WebSocket 443 si l'UDP est bloqué (à venir).
5. **Handshake Noise XX** entre les deux pairs, à l'intérieur du transport, authentifié par les identités d'appareil (`creamote-crypto`). Les `SessionMessage` circulent ensuite chiffrés.

## Authentification du serveur et des pairs

- **Serveur** : certificat auto-signé conservé dans son dossier de données. Les pairs l'épinglent par son empreinte (BLAKE3 du certificat), communiquée avec l'adresse du serveur. Pas d'autorité de certification.
- **Enregistrement** : le pair signe avec sa clé d'identité l'exporteur TLS de la connexion QUIC (`RegisterPeer.proof`). La preuve est liée à cette connexion et ne peut pas être rejouée.
- **Session** : le host et le viewer vérifient l'identité de l'autre à l'issue du handshake Noise, sans faire confiance au serveur. Le viewer vérifie que la clé authentifiée correspond à l'ID demandé ; le host, qu'elle correspond au demandeur annoncé.
- **Relay** : deux jetons aléatoires de 256 bits par session, un par côté, valables 30 s. Le relay apparie les deux flux et recopie des octets opaques.

## Connexion directe (M3)

Détails et alternatives dans [ADR 0003](adr/0003-p2p.md).

- **Un seul endpoint QUIC par pair** pour le rendezvous, le direct et le relay : l'adresse publique que le serveur observe à l'enregistrement est la correspondance NAT qui servira au hole punching.
- **Candidats** : le pair annonce ses adresses LAN (`RegisterPeer.local_addrs`, énumérées par l'OS : `getifaddrs`, `GetAdaptersAddresses`) ; le serveur les transmet, précédées de l'adresse observée, dans le `RelayGrant` de l'autre pair (au plus 8).
- **Rôles fixes** : le viewer est client QUIC, le host serveur. Le host émet lui aussi des tentatives vers les candidats du viewer pour ouvrir sa propre correspondance NAT. Hors d'une session qu'il vient d'accepter, le host refuse toute connexion entrante.
- **Choix du chemin par le viewer** : il envoie `DirectJoin` sur la connexion directe s'il l'obtient dans les 3 s, sinon il parle sur le relay. Le host suit. TLS n'est pas vérifié sur le direct (certificat éphémère) : Noise authentifie les pairs comme à travers le relay.
- **Vie privée** : `relay_only` à l'enregistrement (`--relay-only`) : le serveur ne communique jamais les adresses de ce pair, et la session passe par le relay.
- **Quotas** : les limites du serveur public ne portent que sur le relay. Si le relay est plein ou le quota de l'IP atteint, la session est quand même proposée en direct seul (`relay_unavailable`), et l'erreur n'est remontée que si le direct échoue.
- **Limites connues** : NAT symétriques (port différent par destination) → relay. Un NAT qui crée un état conntrack pour un paquet entrant non sollicité au lieu de le jeter peut décaler le port ; les box usuelles jettent ce trafic. `tools/nat-lab.sh` rejoue ces cas en CI.

## Presse-papier et fichiers (M3)

Crate `creamote-transfer`, dans le canal Noise, avec les numéros 20 à 39 de `SessionMessage`. Branchée dans `creamote-session` (`Sharing`, `host::serve_with`, `viewer::start_with`) : chaque côté choisit ce qu'il offre, le host n'accorde `clipboard` et `file_transfer` que s'il les offre et que le ticket ou l'utilisateur présent les autorise (« vue seule » les retire), et ignore les messages d'une fonction non accordée.

- **Presse-papier** : texte, HTML et image (PNG), 16 Mio par format, découpés en morceaux de 48 Kio. Accès natif via `arboard` (Win32, NSPasteboard, sélections X11, data-control Wayland) ; détection des copies par `GetClipboardSequenceNumber` sous Windows, par relecture toutes les 500 ms ailleurs. Le contenu présent à l'ouverture de la session n'est pas envoyé, et une copie reçue n'est jamais renvoyée.
- **Fichiers** : dans les deux sens, un fichier par proposition (`FileOffer`), dossiers décomposés en chemins relatifs. Acceptation automatique, à la demande ou refus. Fenêtre de 4 Mio contrôlée par accusés de réception, empreinte BLAKE3 vérifiée avant de renommer `*.creamote-part`. Chemins reçus validés pour toutes les plateformes (ni absolu, ni `..`, ni nom réservé Windows), aucun fichier existant écrasé, date de modification conservée.

## Débit adaptatif et multi-écrans (M3)

- **Débit** (`creamote-session::rate`) : le host date chaque image envoyée et son accusé ; la file d'attente réseau est estimée par l'écart entre ce délai et le plus faible délai récent. Au-delà de 80 ms le débit de l'encodeur baisse de 25 % (au plus une fois par seconde, plancher 300 kbit/s) ; après 3 s sans file et si l'encodeur produit, il remonte de 10 % jusqu'au débit initial. Un écran statique ne fait donc pas monter le débit, et une latence constante (liaison lointaine) n'est pas prise pour de la congestion. Chaque changement est annoncé par un nouveau `VideoConfig`.
- **Écrans** : le host relit la liste des écrans toutes les 2 s et envoie `DisplayList` quand elle change (écran branché, débranché, résolution). Si la capture de l'écran diffusé échoue, il repasse sur l'écran principal (au plus une tentative toutes les 5 s) et les entrées suivent. Le viewer choisit l'écran par `VideoConfig.display_id` (liste dans le client, `--display` dans la CLI).

## Wayland (M3)

Wayland n'autorise ni capture ni injection directes : le host passe par **xdg-desktop-portal** (D-Bus, `zbus`), qui délègue au compositeur (GNOME, KDE, wlroots selon le backend installé).

- **Une seule session `RemoteDesktop`** avec les sources `ScreenCast` : une seule boîte de dialogue pour les écrans et le clavier/souris, ouverte après le consentement Creamote. Le portail renvoie un **jeton de restauration** (`persist_mode` = jusqu'à révocation), gardé dans `$XDG_STATE_HOME/creamote/portal-restore-token` (0600) : les sessions suivantes, y compris sans surveillance, ne redemandent rien tant que l'utilisateur n'a pas révoqué l'accès.
- **Image** : un flux PipeWire par écran (`OpenPipeWireRemote` puis `libpipewire`), mémoire partagée BGRx/BGRA (RGBx/RGBA convertis), curseur incrusté si le compositeur le propose. L'identifiant d'écran est le nœud PipeWire.
- **Entrées** : `NotifyKeyboardKeycode` (codes evdev), `NotifyPointerMotionAbsolute` en coordonnées logiques du flux diffusé, `NotifyPointerButton`, `NotifyPointerAxisDiscrete`.
- **Durée de vie** : la session est partagée par la capture et l'injection et fermée 15 s après la dernière utilisation (l'indicateur de partage disparaît). Si l'utilisateur révoque le partage, la capture échoue, la session est marquée fermée et le repli sur l'écran principal en rouvre une.
- **Détection** : `XDG_SESSION_TYPE=wayland` ou `WAYLAND_DISPLAY` ; `CREAMOTE_LINUX_BACKEND=x11|portal` force le choix. Fonction `wayland` du host (par défaut), qui lie `libpipewire-0.3` ; le client n'en dépend pas.
- **Limites** : la liste des écrans est celle choisie dans la boîte (pas de branchement à chaud) ; le host doit tourner dans la session graphique de l'utilisateur (bus D-Bus de session) ; pas encore de DMA-BUF (zéro-copie).
- **Test** : `tools/wayland-lab.sh` (job CI) lance un bus D-Bus privé, PipeWire, WirePlumber et une source GStreamer ; le test sert lui-même un faux portail et vérifie les appels D-Bus, l'image reçue, les entrées, la fermeture et le jeton de restauration.

## Android (M5)

Détails et alternatives dans [ADR 0005](adr/0005-android.md).

- **Cœur partagé** : `creamote-mobile` (même réseau, même session, même chiffrement que le desktop), compilé par `cargo-ndk` et exposé à Kotlin par uniffi (`android/core`).
- **Host** : MediaProjection rend dans la surface d'entrée d'un encodeur MediaCodec ; l'app pousse les images H.264 au cœur, qui les traite comme une `EncodedSource` (contrôle de flux, débit adaptatif, images clés à la demande). Une seule session à la fois. Les entrées sont remises à l'app (usage HID + `KEYCODE_*`, pointeur normalisé) pour un AccessibilityService ou une API constructeur.
- **Viewer** : décodage MediaCodec dans l'app, accusé de chaque image.
- **Presse-papier** : texte, via `ClipboardManager` (lecture possible seulement au premier plan depuis Android 10).

## Serveur officiel et serveurs custom

Un seul binaire `creamote-server`. En mode `public` il applique une `ServerPolicy` (au relay seulement, une connexion directe ne coûtant rien au serveur) : **une session relay à la fois par adresse IP du demandeur**, **10 minutes maximum par session**, **5 Mbit/s par sens** et 200 sessions au total, valeurs réglables. Le serveur officiel n'offre pas la gestion de parc (comptes, entités, RBAC) : elle est réservée aux serveurs auto-hébergés. Client et host conservent une liste de serveurs, chacun épinglé par son empreinte.

Protection du serveur public (M6, `server/src/ratelimit.rs`) : par adresse IP (préfixe /64 en IPv6), au plus 32 connexions QUIC simultanées (refusées avant le handshake), 20 enregistrements et 30 demandes de session par minute (`STATUS_RATE_LIMITED`, `REASON_RATE_LIMITED`) ; la dernière limite empêche aussi de balayer les ID pour trouver les appareils en ligne. Le relay plafonne chaque sens d'une session par un seau à jetons (rafale de 250 ms) : les octets en trop restent dans les tampons QUIC, le contrôle de flux ralentit l'émetteur et le débit adaptatif du host réagit. Le plafond est annoncé dans `ServerPolicy.max_relay_bitrate_bps` ; le host règle son encodeur à 90 % de cette valeur quand la session passe par le relay. Métriques Prometheus sans donnée personnelle (`--metrics-listen`). Déploiement : [deploy/official](../deploy/official/README.md).

## Gestion de parc (M4)

Disponible sur les serveurs auto-hébergés (pas sur le serveur officiel). Données en SQLite par défaut ou PostgreSQL, API HTTP décrite dans [api.md](api.md).

Un rôle (ensemble de permissions) est attribué à un utilisateur ou un groupe de sécurité sur une portée : entité, parc (imbricable) ou machine, avec héritage vers le bas. Le serveur évalue les droits à la demande de connexion et émet un **ticket de session signé** ; le host, qui a épinglé la clé du serveur à l'enrôlement, n'applique que les permissions du ticket.

## Session desktop (M2)

- **Capture** (`creamote-capture`) : API natives seulement, image BGRA livrée quand l'écran change. Windows : DXGI Desktop Duplication ; macOS : ScreenCaptureKit ; Linux X11 : MIT-SHM avec repli `GetImage`, curseur via XFixes ; Wayland : voir ci-dessous.
- **Encodage** (`creamote-codec`) : H.264 Annex B sans images B. Windows : MFT Media Foundation matériels du constructeur (Quick Sync, NVENC, AMF), puis encodeur Microsoft ; macOS : VideoToolbox ; Linux et machines sans encodeur matériel : openh264. Un encodeur qui échoue en cours de session passe la main au suivant (image clé forcée).
- **Entrées** (`creamote-input`) : touches physiques (usages USB HID, comme `KeyboardEvent.code`), pointeur en coordonnées normalisées sur l'écran diffusé. Windows : `SendInput` en scancodes ; macOS : `CGEventPost` ; X11 : XTest. Tout ce qui est enfoncé est relâché en fin de session.
- **Session** (`creamote-session`) : `Hello` → consentement éventuel → `HelloAck` (permissions accordées, écrans) → `VideoConfig` → flux de `VideoChunk`. Le viewer acquitte chaque image décodée ; le host ne garde que 3 images en vol, ce qui borne la latence quand le réseau sature. Les entrées ne sont injectées que si `control` est accordé.
- **Consentement** : demandé à l'utilisateur présent (contrôle, vue seule, refus ; 30 s puis refus) pour un host non enrôlé ou un ticket sans `unattended`. La boîte affiche l'appareil et le compte vérifiés et le code de vérification. Windows : `MessageBox` ; macOS : AppleScript (`osascript`) ; Linux : zenity ou kdialog ; à défaut le terminal.
- **Client** : Tauri, décodage par WebCodecs dans la WebView, openh264 en repli.

Décisions : [ADR 0002](adr/0002-medias.md).

## Milestones

| Milestone | Contenu |
| --- | --- |
| M0 | Workspace, schémas protobuf, identité + Noise, CI 3 OS |
| M1 | Serveur rendezvous + relay, outil CLI de session chiffrée de test |
| M2 | Capture, H.264 et input sur Windows, macOS, Linux X11 ; client desktop Tauri minimal |
| M3 | Hole punching P2P, débit adaptatif, multi-écrans, presse-papier, fichiers, Wayland |
| M4 | Comptes, carnet d'adresses, entités, parcs, RBAC, groupes, tickets signés, audit, console web d'administration |
| M5 | App Android native (Kotlin + cœur Rust via JNI) : client, host via MediaProjection + AccessibilityService, et API constructeur (Samsung Knox, etc.) quand elles sont disponibles |
| M6 | Mode public du serveur officiel, installeurs signés, mise à jour auto, déploiement de masse |
