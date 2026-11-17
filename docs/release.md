# Publier une version

1. Mettre la même version dans `Cargo.toml` (`[workspace.package]`) et `client/src-tauri/tauri.conf.json`, puis fusionner dans `main`.
2. Poser l'étiquette : `git tag v0.2.0 && git push origin v0.2.0`.
3. Le workflow [Release](../.github/workflows/release.yml) construit les paquets, les signe si les secrets sont configurés, publie l'image du serveur sur `ghcr.io/kawakode/creamote/creamote-server` et crée une **release en brouillon** avec `SHA256SUMS`.
4. Vérifier le brouillon, puis le publier.

Lancé à la main (Actions > Release > Run workflow), le workflow construit tout sans rien publier : les paquets sont dans les artefacts du run.

## Paquets produits

| Système | Host (sans surveillance) | Client | Serveur |
| --- | --- | --- | --- |
| Windows x64 | `creamote-host-<v>-x64.msi` (service `CreamoteHost`) | MSI et installeur NSIS | — |
| macOS universel | `creamote-host-<v>-macos.pkg` (agent launchd) | `.dmg` | — |
| Linux x86_64 | `.deb`, `.rpm` (service utilisateur systemd) | `.deb`, `.rpm`, AppImage | archive, image Docker |

La CLI de test (`creamote-cli`) est fournie en archive pour chaque système.

## Secrets de signature

Chaque signature est facultative : sans ses secrets, l'étape est sautée et les paquets ne sont pas signés (Windows SmartScreen et macOS Gatekeeper avertiront l'utilisateur). Les secrets se déclarent dans Settings > Secrets and variables > Actions du dépôt.

### Windows : Azure Trusted Signing

Les certificats de signature de code ne sont plus délivrés en fichier PFX (clé obligatoirement sur un module matériel depuis 2023) ; le workflow utilise donc [Azure Trusted Signing](https://learn.microsoft.com/azure/trusted-signing/), qui signe sans clé locale (compte Azure, validation d'identité de l'éditeur).

| Secret | Contenu |
| --- | --- |
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | Application Entra ID ayant le rôle « Trusted Signing Certificate Profile Signer » |
| `AZURE_TRUSTED_SIGNING_ENDPOINT` | ex. `https://weu.codesigning.azure.net/` |
| `AZURE_TRUSTED_SIGNING_ACCOUNT` | nom du compte Trusted Signing |
| `AZURE_TRUSTED_SIGNING_PROFILE` | nom du profil de certificat |

Les exécutables (host, CLI, client) sont signés avant d'être empaquetés, puis les installeurs eux-mêmes.

### macOS : Developer ID et notarisation

Nécessite un compte Apple Developer Program.

| Secret | Contenu |
| --- | --- |
| `APPLE_CERTIFICATE` | export `.p12` en base64 contenant **Developer ID Application** et **Developer ID Installer** |
| `APPLE_CERTIFICATE_PASSWORD` | mot de passe du `.p12` |
| `APPLE_SIGNING_IDENTITY` | ex. `Developer ID Application: Nom (TEAMID)` |
| `APPLE_INSTALLER_IDENTITY` | ex. `Developer ID Installer: Nom (TEAMID)` |
| `APPLE_ID`, `APPLE_PASSWORD` | identifiant Apple et mot de passe d'application (appleid.apple.com) |
| `APPLE_TEAM_ID` | identifiant d'équipe |

Le host est signé avec le runtime renforcé et l'identifiant `org.creamote.host` (à utiliser dans les profils PPPC MDM), puis le `.pkg` est signé, notarisé et agrafé. Le client est signé et notarisé par Tauri.

### Linux

Pas de signature de paquet pour l'instant : `SHA256SUMS` accompagne la release. Un dépôt APT/RPM signé pourra venir ensuite.

## Mise à jour automatique

Le host et le client se mettent à jour seuls quand la release est construite avec une **clé de mise à jour** (format minisign, celui du greffon updater de Tauri). Sans elle, aucune mise à jour automatique n'est proposée.

Créer la clé une fois, hors du dépôt :

```sh
cargo install tauri-cli --version "^2" --locked
cargo tauri signer generate -w creamote-update.key   # demande un mot de passe
```

| Où | Nom | Contenu |
| --- | --- | --- |
| Variable du dépôt (Settings > Secrets and variables > Actions > Variables) | `UPDATE_PUBKEY` | contenu de `creamote-update.key.pub` |
| Secret | `UPDATE_PRIVATE_KEY` | contenu de `creamote-update.key` |
| Secret | `UPDATE_PRIVATE_KEY_PASSWORD` | son mot de passe |

Conservez la clé privée hors ligne : la perdre empêche de publier des mises à jour aux installations existantes, la divulguer permettrait d'en publier de fausses. Les deux (variable et secrets) vont ensemble : une clé publique sans clé privée fait échouer la construction du client.

La release publie alors :

- `host-latest.json` et sa signature `host-latest.json.sig` : version, URL et SHA-256 de chaque paquet du host. Le host vérifie la signature du manifeste avec la clé intégrée, n'accepte qu'une version **strictement plus récente**, vérifie l'empreinte du paquet et lance l'installeur du système (`msiexec`, `installer`, `dpkg`, `rpm`). La vérification tourne toutes les 6 heures avec les droits d'administration : dans le service sous Windows, par le démon launchd `org.creamote.host.update` sous macOS et le timer systemd `creamote-host-update.timer` sous Linux. Après la mise à jour, le host de chaque session redémarre dès qu'aucune session n'est en cours.
- `client-latest.json` : manifeste du greffon updater de Tauri. Le client vérifie au démarrage et propose l'installation.

Côté machines, `auto_update = false` dans `host.conf` désactive la mise à jour du host, et `update_url` désigne un miroir interne (par exemple pour valider une version avant de la diffuser au parc). `creamote-host update --check` indique si une version est disponible.
