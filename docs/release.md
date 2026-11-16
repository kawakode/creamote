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
