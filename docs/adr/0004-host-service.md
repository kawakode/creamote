# ADR 0004 : host installé comme service

- Statut : proposé (M6b)
- Date : 2026-11-16

## Contexte

Pour l'accès sans surveillance, le host doit démarrer avec la machine et survivre aux coupures réseau, sans terminal ni utilisateur pour le lancer. Mais la capture d'écran et l'injection d'entrées n'ont lieu que dans la session graphique : un service système classique (session 0 sous Windows, daemon sous macOS et Linux) ne voit pas l'écran.

## Décision

- **Windows** : un service `CreamoteHost` (compte SYSTEM, démarrage automatique, relance en cas d'échec) lance `creamote-host --service` **dans la session affichée sur la console** (`WTSGetActiveConsoleSessionId`). Il duplique son propre jeton SYSTEM, le rattache à cette session (`SetTokenInformation(TokenSessionId)`) et lance le processus sur `winsta0\default` (`CreateProcessAsUserW`). Le host garde ainsi les droits de SYSTEM : il capture et pilote le bureau de n'importe quel utilisateur, et l'identité de la machine reste dans `%ProgramData%\Creamote`, réservé à SYSTEM et aux administrateurs. Le service vérifie la session toutes les 2 s et relance le host quand elle change ou qu'il s'arrête. Journal : `%ProgramData%\Creamote\host.log`.
- **macOS** : un agent `launchd` dans `/Library/LaunchAgents` (`LimitLoadToSessionType = Aqua`, `KeepAlive`), lancé dans chaque session graphique. Seul un processus de la session obtient les autorisations « Enregistrement de l'écran » et « Accessibilité » (accordées par l'utilisateur, ou par un profil PPPC en MDM).
- **Linux** : un service utilisateur systemd lié à `graphical-session.target`, activé pour tous (`systemctl --global enable`). Il hérite de `DISPLAY`/`WAYLAND_DISPLAY` et du bus D-Bus de session, nécessaires au portail Wayland.
- **Configuration** : un fichier système `clé = valeur` (`/etc/creamote/host.conf`, `/Library/Application Support/Creamote/host.conf`, `%ProgramData%\Creamote\host.conf`) écrit par l'installeur ou l'outil de déploiement : serveur, empreinte, jeton d'enrôlement, nom, options. La ligne de commande a priorité. Un jeton présent dans la configuration enrôle le host à son premier démarrage ; il est ensuite ignoré.
- **Mode service** (`--service`) : configuration système, données dans le dossier de la plateforme, reconnexion au serveur avec attente croissante (2 s à 60 s).

## Conséquences

- Sous macOS et Linux l'identité est **par utilisateur** (`~/Library/Application Support/Creamote`, `$XDG_STATE_HOME/creamote`) : une machine partagée par plusieurs comptes apparaît comme plusieurs appareils, chacun enrôlé avec le même jeton (jetons à usages multiples). Une identité unique par machine demanderait un démon privilégié et un agent par session reliés par IPC ; à reconsidérer si le besoin apparaît.
- Pas d'accès **avant l'ouverture de session** sous macOS et Linux. Sous Windows, l'écran de connexion et les invites UAC sont sur le bureau sécurisé (`Winlogon`), que le host ne capture pas encore (bascule de bureau à ajouter).
- Sous Windows, les fichiers reçus vont dans `C:\Users\Public\Downloads\Creamote` (le host tourne sous SYSTEM, pas sous l'utilisateur).

## Alternatives écartées

- **Tâche planifiée « à l'ouverture de session »** sous Windows : pas de relance sur changement d'utilisateur, ni d'accès hors session ouverte.
- **Démarrage automatique XDG** (`/etc/xdg/autostart`) sous Linux : universel mais sans relance en cas d'arrêt ; systemd utilisateur est présent sur les distributions visées.
