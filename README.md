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
- `crates/creamote-net` : QUIC avec certificat de serveur épinglé, client de rendezvous, connexion au relay, canal chiffré de bout en bout.
- `server/` : rendezvous + relay, mode public avec limites (voir [deploy/](deploy/README.md)).
- `host/` : s'enregistre et accepte les sessions (écho chiffré en attendant la capture d'écran de M2).
- `cli/` : `creamote-cli`, outil de test des connexions.

## Essai local

```sh
cargo run -p creamote-server -- --listen 127.0.0.1:21400
# noter l'empreinte affichée, puis dans un 2e terminal :
cargo run -p creamote-host -- --server 127.0.0.1:21400 --server-pin <empreinte>
# noter l'ID du host, puis dans un 3e terminal :
cargo run -p creamote-cli -- connect "<ID>" --server 127.0.0.1:21400 --server-pin <empreinte>
```

Chaque ligne tapée dans le client traverse le relay chiffrée de bout en bout et revient en écho du host. Les deux côtés affichent le même code de vérification.

## Développement

Prérequis : Rust stable (voir `rust-toolchain.toml`). Aucun `protoc` n'est nécessaire, les schémas sont compilés en Rust pur.

```sh
cargo test --workspace
```
