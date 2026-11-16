# Déploiement du serveur

Le serveur écoute en **UDP** (QUIC) sur le port 21400 par défaut. Au premier démarrage il génère un certificat dans son dossier de données et affiche son **empreinte** : c'est elle que les hosts et clients utilisent pour authentifier le serveur (`--server-pin`). Conservez le dossier de données, sinon l'empreinte change.

## Docker

```sh
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml logs creamote-server
```

## Binaire

```sh
cargo build --release -p creamote-server
./target/release/creamote-server --data-dir /var/lib/creamote
```

Options utiles : `--relay-addr` (adresse publique annoncée pour le relay), `--public` (mode serveur officiel : une session relay à la fois par IP, 10 min par session, 200 sessions au total), `--max-relay-sessions`, `--max-relay-sessions-per-ip`, `--max-relay-seconds`.
