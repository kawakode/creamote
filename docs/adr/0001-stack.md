# ADR 0001 : stack technique

- Statut : proposé (en attente de validation)
- Date : 2026-11-15

## Contexte

Creamote doit tourner sur Windows, macOS, Linux et Android, capturer et encoder l'écran avec une faible latence, injecter des entrées, traverser les NAT, et offrir un serveur auto-hébergeable. Client, host et serveur doivent parler exactement le même protocole.

## Décision proposée

- **Rust** pour toute la logique : protocole, crypto, réseau, capture, codec, input, host et serveur. Les crates partagées garantissent un protocole identique partout.
- **Flutter** pour l'interface client, via `flutter_rust_bridge`, sur les quatre OS.
- **QUIC** (quinn) pour le transport, **protobuf** (prost, compilé par protox sans `protoc`) pour les messages.
- **Noise XX** (`Noise_XX_25519_ChaChaPoly_BLAKE2s`, crate `snow`) pour le chiffrement de bout en bout, authentifié par une identité Ed25519 qui signe la clé statique Noise.
- **SQLite** par défaut côté serveur, **PostgreSQL** en option (sqlx).

## Alternatives

- Tauri pour le desktop + Kotlin natif pour Android : deux interfaces à maintenir.
- Serveur en Go : plus simple à écrire, mais protocole et crypto dupliqués.

## Points ouverts

- Licence du projet.
- Limites exactes du serveur officiel.
- Console web d'administration en plus de l'app.
