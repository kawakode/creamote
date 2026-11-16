# API de gestion de parc

Base : `http://127.0.0.1:21401/api/v1` (à exposer derrière un reverse proxy TLS). Corps et réponses en JSON. Erreurs : `{ "error": "<code>", "message": "<texte>" }` avec les statuts 400, 401, 403, 404 et 409.

## Authentification

| Méthode | Chemin | Rôle |
| --- | --- | --- |
| POST | `/auth/login` | `{ email, password }` → `{ token, expires_at }` (jeton valable 12 h) |
| POST | `/auth/logout` | révoque le jeton courant |
| GET | `/me` | profil et entités, avec les permissions au niveau entité |

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
| GET | `/entities/{eid}/my-permissions?fleet_id=` | membre |
| GET, POST | `/entities/{eid}/members` (`{ email }`) | `manage_access` |
| DELETE | `/entities/{eid}/members/{uid}` | `manage_access` |
| GET, POST | `/entities/{eid}/fleets` (`{ name, parent_id? }`) | `manage_devices` sur le parent |
| PATCH | `/entities/{eid}/fleets/{fid}` (`{ name?, parent_id? }`) | `manage_devices` sur le parc et la destination |
| DELETE | `/entities/{eid}/fleets/{fid}` (sans sous-parc) | `manage_devices` |
| GET, POST | `/entities/{eid}/groups` (`{ name }`) | `manage_access` |
| DELETE | `/entities/{eid}/groups/{gid}` | `manage_access` |
| GET, POST | `/entities/{eid}/groups/{gid}/members` (`{ user_id }`) | `manage_access` |
| DELETE | `/entities/{eid}/groups/{gid}/members/{uid}` | `manage_access` |
| GET, POST | `/entities/{eid}/roles` (`{ name, permissions: [...] }`) | `manage_access` |
| DELETE | `/entities/{eid}/roles/{rid}` (non attribué) | `manage_access` |
| GET, POST | `/entities/{eid}/bindings` | `manage_access` |
| DELETE | `/entities/{eid}/bindings/{bid}` | `manage_access` |
| GET | `/entities/{eid}/audit?limit=` | `view_audit` |

Une attribution : `{ "role_id": "technician", "subject": { "kind": "group", "id": "…" }, "scope": { "kind": "fleet", "id": "…" } }`. Sujet `user` ou `group`, portée `entity` ou `fleet` (la portée `device` arrive avec l'enrôlement des hosts). Une attribution sur un parc vaut pour ses sous-parcs.

Garde-fou : une opération qui laisserait l'entité sans personne disposant de `manage_access` au niveau entité est refusée (409).

## Permissions et rôles intégrés

`view_screen`, `control`, `clipboard`, `file_transfer`, `unattended` (connexion sans consentement), `manage_devices`, `manage_access`, `view_audit`.

| Rôle | Permissions |
| --- | --- |
| `owner` | toutes |
| `fleet-admin` | view_screen, control, clipboard, file_transfer, unattended, manage_devices |
| `technician` | view_screen, control, clipboard, file_transfer |
| `observer` | view_screen |
