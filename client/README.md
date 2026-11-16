# Client desktop Creamote (Tauri)

Client minimal (M2) pour Windows, macOS et Linux : Tauri 2, interface en JavaScript sans framework (`ui/`) et commandes Rust (`src-tauri/`) qui appellent directement les crates du cœur (`creamote-net`, `creamote-session`, `creamote-codec`).

`src-tauri` est un workspace cargo distinct, exclu du workspace racine : la pile WebView (webkit2gtk sous Linux) n'est ainsi requise que pour construire le client.

## Fonctionnement

- Connexion par ID d'appareil, via le serveur de rendezvous/relais (adresse + empreinte), ou avec un ticket demandé à l'API pour un appareil géré.
- Le flux H.264 (Annex B) arrive par un `Channel` binaire. Il est décodé par **WebCodecs** quand la WebView le permet (WebView2, WKWebView), sinon en Rust par openh264 puis envoyé en RGBA (WebKitGTK).
- Clavier : `KeyboardEvent.code` → usage HID (`ui/keymap.js`, vérifié contre la table Rust de `creamote-input`). Souris : coordonnées normalisées, boutons et molette en crans.
- Le code de vérification à 6 chiffres est affiché dans la barre : il doit correspondre à celui de l'hôte.

## Construire et lancer

Prérequis Linux : `libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev`.

```sh
cd client/src-tauri
cargo run --release
```

Le paquet installable (`cargo tauri build`) viendra avec la distribution (M6).
