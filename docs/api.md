# API de gestion de parc

Base : `http://127.0.0.1:21401/api/v1` (à exposer derrière un reverse proxy TLS). Corps et réponses en JSON. Erreurs : `{ "error": "<code>", "message": "<texte>" }` avec les statuts 400, 401, 403, 404 et 409.

La **console web d'administration** est servie par le même port, à la racine
(`http://127.0.0.1:21401/`). C'est une application monopage sans dépendance,
embarquée dans le binaire (`server/console/`), qui n'utilise que cette API.
Elle est servie avec une politique de sécurité du contenu stricte (aucune
ressource extérieure, pas de script en ligne, pas d'intégration en iframe) et
garde le jeton d'API dans `sessionStorage` (effacé à la fermeture de
l'onglet).

## Authentification

| Méthode | Chemin | Rôle |
| --- | --- | --- |
| POST | `/auth/login` | `{ email, password }` → `{ token, expires_at }` (jeton valable 12 h) |
| POST | `/auth/logout` | révoque le jeton courant |
| GET | `/me` | profil et entités, avec les permissions au niveau entité |
| GET | `/server-info` | `{ server_pin, server_address, version }` : de quoi enrôler un host |

Les requêtes suivantes portent `Authorization: Bearer <token>`. Les mots de passe sont hachés en Argon2id (12 caractères minimum) ; les jetons sont stockés hachés et révocables.

## Super-administrateur

| Méthode | Chemin | Rôle |
| --- | --- | --- |
| GET, POST | `/users` | lister, créer `{ email, display_name, password, superadmin? }` |
| POST | `/entities` | créer `{ name, owner_email? }` ; le propriétaire reçoit le rôle `owner` |
| DELETE | `/entities/{eid}` | supprimer une entité |

Le premier super-administrateur se crée en ligne de commande : `creamote-server user-add --superadmin`.

## Entités

Une entité dont l'utilisateur n'est pas membre répond 404. La permission requise est indiquée pour chaque écriture ; la lecture demande d'être membre.

| Méthode | Chemin | Permission |
| --- | --- | --- |
| GET | `/entities`, `/entities/{eid}` | membre |
| GET | `/entities/{eid}/my-permissions?fleet_id=` ou `?device=` | membre |
| GET, POST | `/entities/{eid}/members` (`{ email }`) | `manage_access` |
| DELETE | `/entities/{eid}/members/{uid}` | `manage_access` |
| GET, POST | `/entities/{eid}/fleets` (`{ name, parent_id? }`) | `manage_devices` sur le parent |
| PATCH | `/entities/{eid}/fleets/{fid}` (`{ name?, parent_id? }`) | `manage_devices` sur le parc et la destination |
| DELETE | `/entities/{eid}/fleets/{fid}` (sans sous-parc ni machine) | `manage_devices` |
| GET, POST | `/entities/{eid}/groups` (`{ name }`) | `manage_access` |
| DELETE | `/entities/{eid}/groups/{gid}` | `manage_access` |
| GET, POST | `/entities/{eid}/groups/{gid}/members` (`{ user_id }`) | `manage_access` |
| DELETE | `/entities/{eid}/groups/{gid}/members/{uid}` | `manage_access` |
| GET, POST | `/entities/{eid}/roles` (`{ name, permissions: [...] }`) | `manage_access` |
| DELETE | `/entities/{eid}/roles/{rid}` (non attribué) | `manage_access` |
| GET, POST | `/entities/{eid}/bindings` | `manage_access` |
| DELETE | `/entities/{eid}/bindings/{bid}` | `manage_access` |
| GET | `/entities/{eid}/audit?limit=` | `view_audit` |
| GET, POST | `/entities/{eid}/enrollment-tokens` (`{ fleet_id, uses?: 1, ttl_hours?: 24 }`) | `manage_devices` sur le parc |
| DELETE | `/entities/{eid}/enrollment-tokens/{tid}` | `manage_devices` sur le parc |
| GET | `/entities/{eid}/devices`, `/entities/{eid}/devices/{did}` | au moins une permission sur la machine |
| PATCH | `/entities/{eid}/devices/{did}` (`{ name?, fleet_id? }`) | `manage_devices` sur la machine et le parc de destination |
| DELETE | `/entities/{eid}/devices/{did}` | `manage_devices` sur la machine |

Une attribution : `{ "role_id": "technician", "subject": { "kind": "group", "id": "…" }, "scope": { "kind": "fleet", "id": "…" } }`. Sujet `user` ou `group`, portée `entity`, `fleet` ou `device`. Une attribution sur un parc vaut pour ses sous-parcs et leurs machines.

Garde-fou : une opération qui laisserait l'entité sans personne disposant de `manage_access` au niveau entité est refusée (409).

## Permissions et rôles intégrés

`view_screen`, `control`, `clipboard`, `file_transfer`, `unattended` (connexion sans consentement), `manage_devices`, `manage_access`, `view_audit`.

| Rôle | Permissions |
| --- | --- |
| `owner` | toutes |
| `fleet-admin` | view_screen, control, clipboard, file_transfer, unattended, manage_devices |
| `technician` | view_screen, control, clipboard, file_transfer |
| `observer` | view_screen |

## Machines et tickets de session

**Enrôlement.** Un administrateur crée un jeton d'enrôlement (`cre_…`, montré
une seule fois) pour un parc. Sur la machine :

```sh
creamote-host --server relay.example.org:21400 --server-pin <empreinte> \
  --enroll cre_… --name "PC-Compta-01"
```

Le host prouve son identité au rendezvous, envoie le jeton, et reçoit en
retour la clé publique avec laquelle le serveur signe les tickets. Il
l'épingle dans `creamote-host.enrollment` (avec le serveur et son empreinte) :
les démarrages suivants n'ont plus besoin d'option.

**Tickets.** Pour se connecter à une machine enrôlée, le client demande un
ticket :

| Méthode | Chemin | Permission |
| --- | --- | --- |
| POST | `/tickets` (`{ device_id: "012 345 678", viewer_key: "<clé Ed25519 hex>" }`) → `{ ticket, permissions, expires_at }` | `view_screen` sur la machine |

Le ticket (protobuf `creamote.ticket.v1.SignedTicket`, en hexadécimal) est
signé par la clé de tickets du serveur (`ticket-signing.key` dans le dossier de
données) et lie : le host, la clé de l'appareil qui se connecte, l'utilisateur,
ses permissions effectives sur la machine, et une validité de 2 minutes. Le
client le joint à sa demande de connexion ; le host enrôlé le vérifie et
vérifie que la clé authentifiée par Noise est bien celle du ticket. Un ticket
volé est donc inutilisable depuis un autre appareil.

En attendant le consentement de l'utilisateur présent (M2), un host enrôlé
n'accepte que les tickets accordant `view_screen` **et** `unattended`. Un host
non enrôlé reste en mode développement et accepte toute demande.

Avec la CLI :

```sh
export CREAMOTE_API_TOKEN=$(echo "$MOT_DE_PASSE" | creamote-cli login --api-url https://creamote.example.org --email moi@example.org)
creamote-cli connect "012 345 678" --server relay.example.org:21400 --server-pin <empreinte> \
  --api-url https://creamote.example.org
```
