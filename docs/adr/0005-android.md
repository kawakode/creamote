# ADR 0005 : app Android

- Statut : proposé (M5a)
- Date : 2026-11-16

## Contexte

L'app Android (Kotlin, décidé en ADR 0001) doit être client (voir et piloter un autre appareil) et host (partager l'écran du téléphone ou de la tablette), avec le même protocole, le même chiffrement et la même gestion de parc que le desktop. Les API de capture, d'encodage et d'injection d'Android sont en Java ; le protocole est en Rust.

## Décision

- **Cœur Rust partagé** : crate `creamote-mobile`, compilée en `libcreamote_mobile.so` par `cargo-ndk` (arm64-v8a, armeabi-v7a, x86_64 ; Android 8.0, API 26, minimum). Elle réutilise `creamote-net` (rendezvous, P2P, relay, Noise), `creamote-session` (consentement, tickets, contrôle de flux, débit adaptatif) et `creamote-transfer`.
- **uniffi** pour l'interface Kotlin : liaisons générées depuis la bibliothèque compilée (mode « library », `uniffi.toml`), pas de JNI écrit à la main ni de `unsafe` dans le dépôt. Les rappels de l'app (`HostDelegate`, `ViewerListener`, `ClipboardProvider`, `LogSink`) sont des interfaces Kotlin. Les liaisons passent par JNA (AAR).
- **API bloquante + runtime interne** : `connect` et `startHost` bloquent (appelées hors du thread principal) ; le runtime tokio vit dans la bibliothèque. Les rappels vidéo partent d'un thread dédié, jamais d'un worker tokio.
- **Host : l'app capture et encode**. MediaProjection rend dans la surface d'entrée d'un encodeur MediaCodec (H.264 matériel du constructeur, zéro copie) ; l'app pousse les images encodées (`HostService.pushFrame`). Côté Rust, `creamote-session` accepte une `EncodedSource` à la place du couple capture + encodeur : même contrôle de flux (3 images en vol), même débit adaptatif (`setBitrate` → `MediaCodec.setParameters`), images clés à la demande. Si l'envoi prend du retard, la file est vidée jusqu'à la prochaine image clé, demandée à l'encodeur (une image P ne peut pas être sautée).
- **Viewer : l'app décode** avec MediaCodec dans une `SurfaceView` et acquitte chaque image.
- **Entrées** : le host remet à l'app des touches physiques (usage HID + `KEYCODE_*` équivalent) et un pointeur normalisé. L'app les injecte par un AccessibilityService (gestes `dispatchGesture`, actions globales, saisie) ou par une API constructeur quand elle est disponible (Samsung Knox, M5d).
- **Une session à la fois** sur le host Android (une seule projection d'écran) ; une demande pendant une session est refusée.
- **Tests sans appareil** : `android/jvm-tests` compile les liaisons Kotlin pour la JVM de la machine, charge le cœur compilé pour l'hôte et joue une session complète host ↔ viewer contre un vrai `creamote-server`. L'AAR Android est construit en CI.

## Alternatives

- Capture en `ImageReader` et encodage en Rust (openh264 ou `AMediaCodec` via le NDK) : une copie de chaque image (plusieurs Mo) à travers JNI, et un encodeur logiciel lent sur mobile. Écarté.
- JNI écrit à la main (`jni-rs`) : pas de dépendance JNA, mais du code `unsafe` et des signatures à maintenir des deux côtés. À reconsidérer si JNA pèse sur la taille ou les performances.
- App Flutter ou Tauri mobile : écarté en ADR 0001 (accès natif à MediaProjection, AccessibilityService et API constructeur).
