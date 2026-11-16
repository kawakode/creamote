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

## Gestion de parc

Hors mode public, le serveur active la gestion de parc : base SQLite dans le dossier de données (ou PostgreSQL via `--database-url` / `CREAMOTE_DATABASE_URL`), API HTTP et **console web d'administration** sur `127.0.0.1:21401` (console à la racine `/`, API sous `/api/v1`). Elles parlent HTTP en clair : exposez-les uniquement derrière un reverse proxy TLS, par exemple avec Caddy :

```
admin.example.org {
    reverse_proxy 127.0.0.1:21401
}
```

Passez `--relay-addr <hôte>:21400` pour que la console affiche la bonne commande d'enrôlement des machines, et `--trust-forwarded-for` quand l'API est derrière le reverse proxy (la limitation des tentatives de connexion par adresse IP utilise alors `X-Forwarded-For`). Activez la double authentification sur les comptes d'administration depuis « Mon compte » dans la console : application d'authentification (TOTP) ou clés de sécurité WebAuthn (YubiKey, Windows Hello, Touch ID…). Les clés exigent `--public-url https://admin.example.org` : elles sont liées à ce domaine et ne fonctionnent que si la console est ouverte par cette adresse.

SSO d'entreprise (Keycloak, Entra ID, Google Workspace, Authentik…) : déclarez un client OIDC « confidentiel » avec l'URL de retour `https://admin.example.org/api/v1/auth/oidc/callback`, puis lancez le serveur avec `--public-url https://admin.example.org --oidc-issuer <URL de l'émetteur> --oidc-client-id <id> --oidc-name "Nom affiché"` et le secret dans `CREAMOTE_OIDC_CLIENT_SECRET`. Les comptes doivent exister dans Creamote avec la même adresse e-mail (voir [docs/api.md](../docs/api.md)).

Créer le premier super-administrateur (le mot de passe est lu sur l'entrée standard) :

```sh
creamote-server --data-dir /var/lib/creamote user-add --email admin@example.org --name Admin --superadmin
# Docker :
docker compose -f deploy/docker-compose.yml run --rm -T creamote-server user-add --email admin@example.org --name Admin --superadmin
```

Connectez-vous ensuite à la console avec ce compte. Voir [docs/api.md](../docs/api.md) pour l'API.

Options utiles : `--relay-addr` (adresse publique annoncée pour le relay), `--metrics-listen 127.0.0.1:21402` (métriques Prometheus sur `/metrics`), `--max-relay-sessions`, `--max-relay-sessions-per-ip`, `--max-relay-seconds`, `--max-relay-kbps` (limites du relay, illimitées par défaut sur un serveur auto-hébergé).

Serveur public (`--public`, sans gestion de parc, avec limites par IP) : voir [official/README.md](official/README.md).

## Host installé comme service

Sur les machines à contrôler sans surveillance, installez le host comme service (droits administrateur) :

```sh
creamote-host service install     # Windows : service CreamoteHost ; macOS : agent launchd ; Linux : service utilisateur systemd
creamote-host service uninstall
```

Il lit sa configuration dans `/etc/creamote/host.conf` (Linux), `/Library/Application Support/Creamote/host.conf` (macOS) ou `%ProgramData%\Creamote\host.conf` (Windows) :

```text
server = relay.example.org:21400
server_pin = <empreinte du serveur>
# Jeton d'enrôlement : le host rejoint le parc à son premier démarrage.
enroll_token = <jeton créé dans la console>
# Facultatif :
# name = Poste accueil       (par défaut : nom de la machine)
# relay_only = false
# clipboard = true
# file_transfer = true
```

Le service se reconnecte seul si le serveur redémarre. Fonctionnement et limites par système : [ADR 0004](../docs/adr/0004-host-service.md).
