# Architecture

Vue d'ensemble ; les décisions détaillées sont dans `docs/adr/`.

## Flux d'une session

1. **Enregistrement** : host et client ouvrent une connexion persistante vers le serveur de rendezvous choisi et s'annoncent avec leur identité (`RegisterPeer`).
2. **Signalisation** : le client demande à joindre un ID (`ConnectRequest`) ; le serveur transmet l'offre au host (`ConnectOffer`) et échange les adresses observées.
3. **P2P** : les deux pairs tentent une connexion QUIC directe (LAN puis hole punching UDP).
4. **Repli relay** : en cas d'échec, le serveur délivre un `RelayGrant` ; le relay recopie des octets opaques. Repli TCP/WebSocket 443 si l'UDP est bloqué.
5. **Handshake Noise XX** entre les deux pairs, à l'intérieur du transport, authentifié par les identités d'appareil (`creamote-crypto`). Les `SessionMessage` circulent ensuite chiffrés.

## Serveur officiel et serveurs custom

Un seul binaire `creamote-server`. En mode `public` il applique une `ServerPolicy` : sessions relay simultanées plafonnées, durée maximale par session relay, débit plafonné, limitation de l'enregistrement d'IDs. Client et host conservent une liste de serveurs, chacun épinglé par sa clé publique.

## Gestion de parc (M4)

Un rôle (ensemble de permissions) est attribué à un utilisateur ou un groupe de sécurité sur une portée : entité, parc (imbricable) ou machine, avec héritage vers le bas. Le serveur évalue les droits à la demande de connexion et émet un **ticket de session signé** ; le host, qui a épinglé la clé du serveur à l'enrôlement, n'applique que les permissions du ticket.

## Milestones

| Milestone | Contenu |
| --- | --- |
| M0 | Workspace, schémas protobuf, identité + Noise, CI 3 OS |
| M1 | Serveur rendezvous + relay, outil CLI de session chiffrée de test |
| M2 | Capture, H.264 et input sur Windows, macOS, Linux X11 ; client desktop Tauri minimal |
| M3 | Hole punching P2P, débit adaptatif, multi-écrans, presse-papier, fichiers, Wayland |
| M4 | Comptes, carnet d'adresses, entités, parcs, RBAC, groupes, tickets signés, audit, console web |
| M5 | App Android native (Kotlin + cœur Rust via JNI) : client, host via MediaProjection + AccessibilityService |
| M6 | Mode public du serveur officiel, installeurs signés, mise à jour auto, déploiement de masse |
