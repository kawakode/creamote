# Serveur officiel

Le serveur officiel est le même binaire `creamote-server`, lancé en **mode public** (`--public`) : rendezvous et relay ouverts à tous, **sans gestion de parc** (ni comptes, ni API, ni console). Le relay ne voit que des octets chiffrés de bout en bout.

## Limites du mode public

Toutes réglables ; `0` désactive une limite.

| Limite | Défaut | Option |
| --- | --- | --- |
| Sessions relay simultanées, au total | 200 | `--max-relay-sessions` |
| Sessions relay simultanées par IP du demandeur | 1 | `--max-relay-sessions-per-ip` |
| Durée d'une session relay | 10 min | `--max-relay-seconds` |
| Débit d'une session relay, par sens | 5 Mbit/s | `--max-relay-kbps` |
| Connexions QUIC simultanées par IP | 32 | `--max-connections-per-ip` |
| Enregistrements d'appareils par IP et par minute | 20 | `--registrations-per-minute` |
| Demandes de session par IP et par minute | 30 | `--connect-requests-per-minute` |

- Les limites par IP comptent une adresse IPv6 par **préfixe /64**, le bloc attribué à un abonné.
- Elles ne portent que sur le **relay** et la signalisation : une session qui aboutit en connexion directe ne coûte rien au serveur et n'est ni limitée en durée ni en débit. Si le relay est plein ou le quota de l'IP atteint, la session est quand même tentée en direct.
- Le plafond de débit est annoncé aux pairs à l'enregistrement : le host règle son encodeur à 90 % du plafond quand la session passe par le relay, et le débit adaptatif fait le reste. Le relay retient les octets en trop sans en perdre (contrôle de flux QUIC).
- La limite de demandes de session empêche aussi de balayer les ID à 9 chiffres pour découvrir les appareils en ligne.

## Prérequis

- Un serveur Linux avec une IP publique fixe (IPv4, et IPv6 si possible) et un **nom DNS** (`relay.example.org`).
- Port **21400/udp** ouvert en entrée. Rien d'autre n'est exposé.
- Bande passante : chaque session relay consomme jusqu'à 2 × 5 Mbit/s ; 200 sessions pleines = 2 Gbit/s. En pratique la plupart des sessions passent en direct et une session de bureau consomme bien moins. Le CPU est faible (recopie d'octets) : 2 vCPU et 1 Go de RAM suffisent pour commencer.
- Tampons UDP : copiez [`99-creamote.conf`](99-creamote.conf) dans `/etc/sysctl.d/` puis `sysctl --system`.

## Installation

### Docker

```sh
CREAMOTE_PUBLIC_HOST=relay.example.org docker compose -f deploy/official/docker-compose.yml up -d
docker compose -f deploy/official/docker-compose.yml logs creamote-public | grep Empreinte
```

Le conteneur utilise le **réseau de l'hôte** : avec la traduction d'adresses de Docker, le serveur verrait l'adresse de la passerelle au lieu de celle des pairs, ce qui fausserait les limites par IP et empêcherait la connexion directe.

### systemd

```sh
cargo build --release --locked -p creamote-server
sudo install -m 0755 target/release/creamote-server /usr/local/bin/
sudo useradd --system --home-dir /var/lib/creamote --shell /usr/sbin/nologin creamote
sudo install -m 0644 deploy/official/creamote-server.service /etc/systemd/system/
# Remplacer relay.example.org dans l'unité, puis :
sudo systemctl daemon-reload && sudo systemctl enable --now creamote-server
journalctl -u creamote-server | grep Empreinte
```

L'unité est durcie (système de fichiers en lecture seule hors `/var/lib/creamote`, aucun privilège, appels système filtrés). `SIGTERM` arrête le serveur proprement.

## Publier l'adresse et l'empreinte

Les clients et les hosts authentifient le serveur par l'**empreinte** de son certificat (pas d'autorité de certification). Publiez le couple `relay.example.org:21400` + empreinte sur le site du projet : les utilisateurs le saisissent une fois dans le client ou le host.

**Sauvegardez le dossier de données** (`/var/lib/creamote` ou le volume `creamote-public-data`) : il contient le certificat. S'il est perdu, l'empreinte change et tous les appareils refusent le serveur jusqu'à leur mise à jour.

## Supervision

`--metrics-listen 127.0.0.1:21402` expose `/metrics` au format Prometheus : connexions, enregistrements, demandes de session, refus par cause, sessions relay ouvertes et en cours, octets recopiés, nombre de pairs en ligne. Aucune donnée personnelle (ni ID, ni adresse). Exemple de collecte :

```yaml
scrape_configs:
  - job_name: creamote
    static_configs:
      - targets: ["127.0.0.1:21402"]
```

[`prometheus-alerts.yml`](prometheus-alerts.yml) propose des alertes : serveur injoignable, relay plein, afflux d'enregistrements refusés, débit proche de la capacité.

Les journaux (`RUST_LOG=info`) contiennent les ID et adresses IP des pairs à l'enregistrement : réglez leur durée de conservation selon votre politique de confidentialité (`RUST_LOG=warn` les supprime).

## Mise à jour

Remplacez le binaire (ou `docker compose pull`/`build`) et redémarrez : les pairs se réenregistrent automatiquement en quelques secondes, les sessions relay en cours sont coupées. Le dossier de données, donc l'empreinte, est conservé.
