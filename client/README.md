# Client desktop Creamote (Tauri)

Client minimal (M2) pour Windows, macOS et Linux : Tauri 2, interface en JavaScript sans framework (`ui/`) et commandes Rust (`src-tauri/`) qui appellent directement les crates du cœur (`creamote-net`, `creamote-session`, `creamote-codec`).

`src-tauri` est un workspace cargo distinct, exclu du workspace racine : la pile WebView (webkit2gtk sous Linux) n'est ainsi requise que pour construire le client.

## Fonctionnement

- Connexion par ID d'appareil, via le serveur de rendezvous/relais (adresse + empreinte), ou avec un ticket demandé à l'API pour un appareil géré.
- Le flux H.264 (Annex B) arrive par un `Channel` binaire. Il est décodé par **WebCodecs** quand la WebView le permet (WebView2, WKWebView), sinon en Rust par openh264 puis envoyé en RGBA (WebKitGTK).
- Clavier : `KeyboardEvent.code` → usage HID (`ui/keymap.js`, vérifié contre la table Rust de `creamote-input`). Souris : coordonnées normalisées, boutons et molette en crans.
- Le code de vérification à 6 chiffres est affiché dans la barre : il doit correspondre à celui de l'hôte.
- **Presse-papier partagé** (si le host l'accorde) : texte, HTML et images, dans les deux sens. Case « Synchroniser le presse-papier » à la connexion (mémorisée) et bouton de la barre pour le suspendre ou le reprendre pendant la session ; suspendu, rien n'est lu ni écrit.
- **Fichiers** (si le host l'accorde) : glisser-déposer de fichiers ou de dossiers sur la fenêtre, ou boutons « Envoyer des fichiers… » / « Dossier… » (boîte de dialogue native). Les fichiers proposés par le poste distant sont à accepter ou refuser un par un ; ils arrivent dans `Téléchargements/Creamote` (jamais d'écrasement, empreinte BLAKE3 vérifiée). Le panneau « Transferts » montre la progression et permet d'annuler.
- Les chemins envoyés ne viennent jamais de la WebView : seuls le dépôt sur la fenêtre et la boîte de dialogue, gérés en Rust, choisissent les fichiers. Les plugins `dialog` et `opener` n'ont aucune permission côté JavaScript.

## Construire et lancer

Prérequis Linux : `libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev`.

```sh
cd client/src-tauri
cargo run --release
```

Le paquet installable (`cargo tauri build`) viendra avec la distribution (M6).
