# ADR 0002 : capture, encodage et entrées par les API natives

- Statut : accepté (consigne de Sébastien du 2026-11-16 : utiliser les API constructeur et OS pour éviter les soucis)
- Date : 2026-11-16

## Contexte

La qualité perçue d'un outil de contrôle à distance dépend de la latence et de la charge CPU de la chaîne capture → encodage → réseau → décodage. Les bibliothèques multiplateformes génériques (FFmpeg, GStreamer, `scrap`) ajoutent des dépendances système lourdes et masquent les cas particuliers de chaque OS (bureau sécurisé, autorisations macOS, perte de duplication DXGI).

## Décision

- **Capture** : DXGI Desktop Duplication (Windows 8+), ScreenCaptureKit (macOS 12.3+), X11 MIT-SHM + XFixes. Liaisons directes (`windows`, `objc2-*`, `x11rb`), sans bibliothèque intermédiaire.
- **Encodage H.264** : encodeurs matériels via l'API de l'OS, qui expose ceux des constructeurs : Media Foundation (MFT Intel Quick Sync, NVIDIA NVENC, AMD AMF, puis encodeur Microsoft) et VideoToolbox. **openh264** (Cisco, BSD-2, compilé depuis les sources) sert de repli : machines virtuelles, Linux en attendant VA-API/NVENC (M3), échec d'un encodeur en cours de session.
- **Entrées** : `SendInput` en scancodes, `CGEventPost`, XTest ; touches physiques (usages HID) pour ne pas dépendre de la disposition clavier du viewer.
- **Décodage côté client** : WebCodecs dans la WebView de Tauri (décodeur matériel du système), openh264 en Rust si WebCodecs est absent.
- Images transmises en mémoire système (BGRA → NV12/I420) en M2 ; le zéro-copie GPU (texture D3D11 ou `IOSurface` directement vers l'encodeur) viendra avec le débit adaptatif.

## Conséquences

- Code `unsafe` limité aux modules de liaison (`dxgi.rs`, `sck.rs`, `x11.rs`, `mf.rs`, `vt.rs`, `win.rs`, `mac.rs`), autorisé module par module.
- Chaque OS a des autorisations propres : Enregistrement de l'écran et Accessibilité sous macOS ; bureau sécurisé (UAC, écran de connexion) inaccessible sans service Windows (M6).
- H.264 est soumis à des brevets : les encodeurs de l'OS sont couverts par leur éditeur ; pour openh264 compilé depuis les sources, la licence de brevets de Cisco ne s'applique qu'à ses binaires. À trancher avant la distribution (M6) : téléchargement du binaire Cisco au premier lancement, ou AV1/VP9 en logiciel.
