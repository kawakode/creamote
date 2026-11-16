# Creamote

Suite de prise de contrôle à distance multiplateforme (Windows, macOS, Linux, Android), chiffrée de bout en bout et auto-hébergeable. Logiciel libre sous licence [AGPL-3.0](LICENSE).

| Composant | Rôle |
| --- | --- |
| **Client desktop** (`client/`, Tauri) | Windows, macOS, Linux : se connecter à une machine, ou laisser une machine se connecter à soi (partage ponctuel). |
| **App Android** (`android/`, Kotlin) | Client et host Android, natifs, appuyés sur le cœur Rust via JNI. |
| **Host** (`host/`, Rust) | Service installé sur une machine destinée à être contrôlée sans surveillance. |
| **Serveur** (`server/`, Rust) | Rendezvous + relay auto-hébergeable, carnet d'adresses, entités, parcs de machines, RBAC et groupes de sécurité. |

Client et host choisissent leur serveur : un serveur auto-hébergé, ou le serveur officiel (une session relay à la fois par IP, 10 minutes maximum, sans gestion de parc). Dans tous les cas le relay ne voit que des octets chiffrés : l'image et les entrées sont chiffrées entre les deux appareils (Noise XX).

## État

Milestone **M1 : rendezvous et relay**. Voir [docs/architecture.md](docs/architecture.md) pour la feuille de route.

- `proto/` : schémas protobuf (rendezvous, relay, session).
- `crates/creamote-proto` : types générés et framing des messages.
- `crates/creamote-crypto` : identité d'appareil (Ed25519 + clé Noise X25519 liée), ID à 9 chiffres, empreinte, handshake Noise XX authentifié et canal chiffré.
- `crates/creamote-net` : QUIC avec certificat de serveur épinglé, client de rendezvous, connexion directe entre pairs (LAN, hole punching UDP) avec repli sur le relay, canal chiffré de bout en bout.
- `crates/creamote-transfer` : presse-papier partagé (API natives de chaque OS) et transfert de fichiers dans la session chiffrée.
- `server/` : rendezvous + relay, mode public avec limites (voir [deploy/](deploy/README.md)), et gestion de parc : comptes, entités, parcs, groupes de sécurité, RBAC et audit, via une [API HTTP](docs/api.md) et une console web d'administration intégrée, sur SQLite ou PostgreSQL ; enrôlement des machines et tickets de session signés.
- `crates/creamote-capture` : capture d'écran native (DXGI Desktop Duplication, ScreenCaptureKit, X11 MIT-SHM).
- `crates/creamote-codec` : encodage H.264 par les encodeurs matériels natifs (Media Foundation, VideoToolbox), openh264 en repli.
- `crates/creamote-input` : injection clavier/souris native (SendInput, CGEvent, XTest), touches physiques USB HID.
- `crates/creamote-session` : session de bout en bout (vidéo, entrées, consentement, contrôle de flux).
- `host/` : s'enregistre, demande le consentement de l'utilisateur présent et diffuse l'écran.
- `cli/` : `creamote-cli`, outil de test des connexions (réception et enregistrement du flux).

## Essai local

```sh
cargo run -p creamote-server -- --listen 127.0.0.1:21400
# noter l'empreinte affichée, puis dans un 2e terminal :
cargo run -p creamote-host -- --server 127.0.0.1:21400 --server-pin <empreinte>
# noter l'ID du host, puis dans un 3e terminal :
cargo run -p creamote-cli -- view "<ID>" --server 127.0.0.1:21400 --server-pin <empreinte> --record flux.h264
```

Le host affiche une demande de connexion (contrôle, vue seule ou refus) avec le code de vérification, identique des deux côtés. Une fois acceptée, l'écran du host est encodé en H.264 et est chiffré de bout en bout, en connexion directe quand c'est possible, via le relay sinon (`--relay-only` côté host ou client pour ne jamais révéler son adresse à l'autre pair) ; `ffplay flux.h264` relit l'enregistrement. Sous macOS, autorisez le host dans Réglages Système > Confidentialité et sécurité > Enregistrement de l'écran et Accessibilité.

Le presse-papier est partagé et le host accepte les fichiers dans `Téléchargements/Creamote` (`--no-clipboard`, `--no-files`, `--files-dir` pour changer cela) ; côté CLI, `--clipboard`, `--send <fichier ou dossier>` et `--files-dir <dossier>` pour recevoir.

`sudo tools/nat-lab.sh cone|symmetric|same-lan` (Linux) rejoue une session entre deux machines derrière des NAT simulés.

## Développement

Prérequis : Rust stable (voir `rust-toolchain.toml`). Aucun `protoc` n'est nécessaire, les schémas sont compilés en Rust pur.

```sh
cargo test --workspace
```
