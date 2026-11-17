# App Android Creamote (Kotlin)

App Android native (client et host). Choix d'architecture : [ADR 0005](../docs/adr/0005-android.md).

| Module | Contenu |
| --- | --- |
| `core` | AAR du cœur Rust (`crates/creamote-mobile`) : `libcreamote_mobile.so` compilée par `cargo-ndk` et liaisons Kotlin générées par uniffi (paquet `org.creamote.core`) |
| `app` | App (paquet `org.creamote.android`) : visionneuse, partage de l'écran, consentement, Samsung Knox |
| `jvm-tests` | Projet Gradle séparé : liaisons testées sur la JVM de la machine, sans SDK Android, contre un vrai `creamote-server` |

## Construire

Prérequis : Rust (stable), les cibles Android, `cargo-ndk`, le SDK Android et le NDK (`ANDROID_NDK_HOME`), JDK 17.

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo install cargo-ndk --locked
cd android
./gradlew :core:assembleRelease                    # AAR, trois ABI
./gradlew :core:assembleDebug -Pcreamote.abis=x86_64 -Pcreamote.cargoProfile=debug   # émulateur, plus rapide
./gradlew -p jvm-tests test                        # liaisons sur la JVM (Linux)
```

Les tâches `cargoNdk` et `uniffiBindings` du module `core` sont lancées avant chaque build ; les sorties vont dans `core/build/rust` et `core/build/generated/uniffi`.

## API du cœur

- `Identity.loadOrCreate(path)` : identité de l'appareil (fichier privé de l'app).
- `connect(identity, ConnectRequest, ViewerListener, ClipboardProvider?)` → `ViewerSession` : vidéo H.264 remise à `onFrame` (à décoder par MediaCodec puis acquitter par `ack`), entrées par `key` (usage HID ; `hidFromAndroidKeycode` pour un clavier matériel) et `pointer` (coordonnées normalisées).
- `startHost(identity, HostConfig, HostDelegate, ClipboardProvider?)` → `HostService` : l'app fournit l'écran, le consentement, le flux encodé (`startStream`, puis `pushFrame`) et l'injection (`key` avec le `KEYCODE_*` équivalent, `pointer`). Enrôlement dans un parc par `HostConfig.enrollToken`. Reconnexion automatique au serveur.
- `initLogging(LogSink, filtre)` : journal Rust vers logcat.

Toutes les fonctions qui touchent au réseau sont bloquantes : appelez-les depuis `Dispatchers.IO`.

## App

- **Visionneuse** (`ViewerActivity`) : décodage MediaCodec dans une `SurfaceView` au format de l'écran distant. Toucher = clic, appui long = clic droit, glisser = bouton enfoncé, deux doigts = molette ; souris et clavier matériels transmis tels quels ; clavier logiciel converti en touches d'un clavier QWERTY US (le protocole transmet des touches physiques). Barre : Échap, Tab, Ctrl/Alt/Win (une touche), Ctrl+Alt+Suppr, écran suivant.
- **Partage** (`host/HostService`) : service de premier plan qui reste enregistré auprès du serveur (enrôlement par jeton possible). À chaque demande, `ConsentActivity` montre l'appareil, le compte et le code de vérification, puis demande l'autorisation système de capture (une par session, imposée par Android). MediaProjection rend dans la surface d'un encodeur MediaCodec ; la rotation change la taille sans recréer la projection.
- **Contrôle** : par le service d'accessibilité de Creamote (gestes rejoués au relâchement, retour/accueil, saisie via l'éditeur d'accessibilité sur Android 13+, sinon texte ajouté au champ actif), ou par **Samsung Knox** (`RemoteInjection`, événements tactiles en direct et touches système) quand la licence Knox est activée (l'app doit être administrateur de l'appareil). Le SDK Knox est appelé par réflexion : rien n'est embarqué.
- **Limites** : une session à la fois ; sans Knox ni accessibilité, affichage seul ; pas encore testé sur appareil réel.
