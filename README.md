# Creamote

Suite de prise de contrôle à distance multiplateforme (Windows, macOS, Linux, Android), chiffrée de bout en bout et auto-hébergeable.

| Composant | Rôle |
| --- | --- |
| **Client** (`client/`, Flutter) | Se connecter à une machine, ou laisser une machine se connecter à soi (partage ponctuel). |
| **Host** (`host/`, Rust) | Service installé sur une machine destinée à être contrôlée sans surveillance. |
| **Serveur** (`server/`, Rust) | Rendezvous + relay auto-hébergeable, carnet d'adresses, entités, parcs de machines, RBAC et groupes de sécurité. |

Client et host choisissent leur serveur : un serveur auto-hébergé, ou le serveur officiel (nombre de connexions et durée des sessions relay limités). Dans tous les cas le relay ne voit que des octets chiffrés : l'image et les entrées sont chiffrées entre les deux appareils (Noise XX).

## État

Milestone **M0 : fondations**. Voir [docs/architecture.md](docs/architecture.md) pour la feuille de route.

- `proto/` : schémas protobuf (rendezvous, session).
- `crates/creamote-proto` : types générés et framing des messages.
- `crates/creamote-crypto` : identité d'appareil (Ed25519 + clé Noise X25519 liée), ID à 9 chiffres, empreinte, handshake Noise XX authentifié et canal chiffré.
- `host/` : crée ou recharge l'identité de l'appareil et affiche son ID.
- `server/` : squelette (rendezvous et relay en M1).

## Développement

Prérequis : Rust stable (voir `rust-toolchain.toml`). Aucun `protoc` n'est nécessaire, les schémas sont compilés en Rust pur.

```sh
cargo test --workspace
cargo run -p creamote-host -- --identity-file ./dev.identity
```
