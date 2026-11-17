# JNA et les liaisons uniffi sont appelées par réflexion depuis le code natif.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class org.creamote.core.** { *; }
-dontwarn java.awt.**
