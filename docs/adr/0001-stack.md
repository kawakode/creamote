# ADR 0001 : stack technique

- Statut : accepté (validé par Sébastien le 2026-11-15)
- Date : 2026-11-15

## Contexte

Creamote doit tourner sur Windows, macOS, Linux et Android, capturer et encoder l'écran avec une faible latence, injecter des entrées, traverser les NAT, et offrir un serveur auto-hébergeable. Client, host et serveur doivent parler exactement le même protocole.

## Décision

- **Rust** pour toute la logique : protocole, crypto, réseau, capture, codec, input, host et serveur. Les crates partagées garantissent un protocole identique partout.
- **Tauri 2** pour le client desktop (Windows, macOS, Linux) : interface web (TypeScript) et commandes Rust appelant directement les crates du cœur.
- **Kotlin natif** pour l'app Android (client et host), avec le cœur Rust compilé en bibliothèque et appelé via JNI (uniffi). MediaProjection et AccessibilityService sont de toute façon des API Kotlin/Java.
- **QUIC** (quinn) pour le transport, **protobuf** (prost, compilé par protox sans `protoc`) pour les messages.
- **Noise XX** (`Noise_XX_25519_ChaChaPoly_BLAKE2s`, crate `snow`) pour le chiffrement de bout en bout, authentifié par une identité Ed25519 qui signe la clé statique Noise.
- **SQLite** par défaut côté serveur, **PostgreSQL** en option (sqlx).

## Alternatives

- Flutter sur les quatre OS : une seule interface, mais un runtime de plus et une couche FFI Dart. Écarté au profit d'une UI web desktop et d'une app Android native.
- Serveur en Go : plus simple à écrire, mais protocole et crypto dupliqués.

## Points ouverts

- Licence du projet.
- Limites exactes du serveur officiel.
- Console web d'administration en plus de l'app.
