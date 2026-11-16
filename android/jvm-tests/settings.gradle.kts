// Tests des liaisons Kotlin sur la JVM de la machine de développement, sans
// SDK Android : le cœur Rust est compilé pour l'hôte et chargé par JNA.
pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

rootProject.name = "creamote-jvm-tests"
