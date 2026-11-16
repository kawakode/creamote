# Architecture

Vue d'ensemble ; les décisions détaillées sont dans `docs/adr/`.

## Flux d'une session

1. **Enregistrement** : host et client ouvrent une connexion persistante vers le serveur de rendezvous choisi et s'annoncent avec leur identité (`RegisterPeer`).
2. **Signalisation** : le client demande à joindre un ID (`ConnectRequest`) ; le serveur transmet l'offre au host (`ConnectOffer`) et échange les adresses observées.
3. **P2P** : les deux pairs tentent une connexion QUIC directe (LAN puis hole punching UDP).
4. **Repli relay** : en cas d'échec, le serveur délivre un `RelayGrant` ; le relay recopie des octets opaques. Repli TCP/WebSocket 443 si l'UDP est bloqué.
5. **Handshake Noise XX** entre les deux pairs, à l'intérieur du transport, authentifié par les identités d'appareil (`creamote-crypto`). Les `SessionMessage` circulent ensuite chiffrés.

## Authentification du serveur et des pairs

- **Serveur** : certificat auto-signé conservé dans son dossier de données. Les pairs l'épinglent par son empreinte (BLAKE3 du certificat), communiquée avec l'adresse du serveur. Pas d'autorité de certification.
- **Enregistrement** : le pair signe avec sa clé d'identité l'exporteur TLS de la connexion QUIC (`RegisterPeer.proof`). La preuve est liée à cette connexion et ne peut pas être rejouée.
- **Session** : le host et le viewer vérifient l'identité de l'autre à l'issue du handshake Noise, sans faire confiance au serveur. Le viewer vérifie que la clé authentifiée correspond à l'ID demandé ; le host, qu'elle correspond au demandeur annoncé.
- **Relay** : deux jetons aléatoires de 256 bits par session, un par côté, valables 30 s. Le relay apparie les deux flux et recopie des octets opaques.

## Serveur officiel et serveurs custom

Un seul binaire `creamote-server`. En mode `public` il applique une `ServerPolicy` : **une session relay à la fois par adresse IP du demandeur**, **10 minutes maximum par session** et 200 sessions au total, valeurs réglables. Le serveur officiel n'offre pas la gestion de parc (comptes, entités, RBAC) : elle est réservée aux serveurs auto-hébergés. Le plafond de débit et la limitation de l'enregistrement d'IDs arrivent en M6. Client et host conservent une liste de serveurs, chacun épinglé par son empreinte.

## Gestion de parc (M4)

Disponible sur les serveurs auto-hébergés (pas sur le serveur officiel). Données en SQLite par défaut ou PostgreSQL, API HTTP décrite dans [api.md](api.md).

Un rôle (ensemble de permissions) est attribué à un utilisateur ou un groupe de sécurité sur une portée : entité, parc (imbricable) ou machine, avec héritage vers le bas. Le serveur évalue les droits à la demande de connexion et émet un **ticket de session signé** ; le host, qui a épinglé la clé du serveur à l'enrôlement, n'applique que les permissions du ticket.

## Session desktop (M2)

- **Capture** (`creamote-capture`) : API natives seulement, image BGRA livrée quand l'écran change. Windows : DXGI Desktop Duplication ; macOS : ScreenCaptureKit ; Linux X11 : MIT-SHM avec repli `GetImage`, curseur via XFixes. Wayland (portail + PipeWire) arrive en M3.
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
