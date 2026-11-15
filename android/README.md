# App Android Creamote (Kotlin)

App Android native (client et host). Le cœur Rust est compilé en bibliothèque pour Android (`cargo-ndk`) et exposé à Kotlin via uniffi/JNI. La capture passe par MediaProjection et l'injection d'entrées par un AccessibilityService. Prévue au milestone M5.
