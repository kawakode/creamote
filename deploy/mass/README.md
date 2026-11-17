# Déploiement de masse du host

Le host s'installe avec le paquet de chaque système ([docs/release.md](../../docs/release.md)) puis lit `host.conf`. Avec un **jeton d'enrôlement à usages multiples** créé dans la console (onglet Machines : nombre de machines et validité), chaque machine rejoint le parc à son premier démarrage, sous son nom réseau. La console affiche les commandes ci-dessous, prêtes à copier, à la création du jeton.

Le jeton n'est utile qu'une fois par machine : une fois enrôlé, le host garde son enrôlement (fichier `enrollment`) et ignore le jeton. Limitez le nombre d'usages et la validité au déploiement prévu, et révoquez-le ensuite.

## Windows : MSI

```bat
msiexec /i creamote-host-0.2.0-x64.msi /qn SERVER=relay.example.org:21400 SERVER_PIN=<empreinte> ENROLL_TOKEN=<jeton>
```

Propriétés facultatives : `HOST_NAME` (sinon le nom de la machine), `RELAY_ONLY=true`, `AUTO_UPDATE=false`. Elles écrivent `%ProgramData%\Creamote\host.conf` (réservé à SYSTEM et aux administrateurs) avant le démarrage du service ; `ENROLL_TOKEN` n'apparaît pas dans le journal d'installation.

- **Intune** : application Win32 (ou « line-of-business » MSI) avec la ligne de commande ci-dessus ; détection par le code produit du MSI.
- **GPO** : l'installation logicielle par GPO ne passe pas de propriétés ; utilisez un script de démarrage d'ordinateur avec la commande `msiexec` (MSI sur un partage lisible par les comptes ordinateurs), ou une transformation `.mst` créée avec Orca.
- **SCCM / PDQ / autres** : même commande.

## macOS : pkg et MDM

1. Déployer `creamote-host-<version>-macos.pkg` (Jamf, Kandji, Intune…).
2. Puis un script exécuté en root :
   ```sh
   "/Library/Application Support/Creamote/creamote-host" configure \
     --server relay.example.org:21400 --server-pin <empreinte> --enroll-token <jeton>
   ```
3. Installer le profil [creamote-host-pppc.mobileconfig](creamote-host-pppc.mobileconfig) (remplacer `TEAMID`) : il accorde l'**Accessibilité**. L'**enregistrement de l'écran** ne peut pas être accordé par MDM (règle d'Apple) : le profil permet à l'utilisateur, même standard, de l'autoriser à la première demande.

## Linux : deb, rpm et Ansible

```sh
sudo apt install ./creamote-host_0.2.0_amd64.deb      # ou : sudo dnf install ./creamote-host-0.2.0-1.x86_64.rpm
sudo creamote-host configure --server relay.example.org:21400 --server-pin <empreinte> --enroll-token <jeton>
```

Le host démarre à la prochaine ouverture de session graphique. Playbook d'exemple : [ansible-creamote-host.yml](ansible-creamote-host.yml).

Sous Linux, `/etc/creamote/host.conf` doit rester lisible par les utilisateurs (le host tourne dans leur session), jeton compris : c'est une raison de plus pour des jetons à durée courte. Sous macOS et Linux l'identité est propre à chaque utilisateur (voir [ADR 0004](../../docs/adr/0004-host-service.md)) : chaque compte qui ouvre une session consomme un usage du jeton.

## Mises à jour

Les hosts installés se mettent à jour seuls (versions signées, toutes les 6 heures). Pour valider une version avant de la diffuser, publiez le manifeste sur un miroir interne et pointez le parc dessus : `configure --update-url https://miroir.example.org/host-latest.json`, ou `AUTO_UPDATE=false` pour gérer les versions vous-même.
