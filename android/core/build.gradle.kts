// Cœur Rust (crates/creamote-mobile) : bibliothèques natives compilées par
// cargo-ndk et liaisons Kotlin générées par uniffi, empaquetées en AAR.

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

val repoRoot = rootDir.parentFile
val abis = (findProperty("creamote.abis") as String).split(',').map { it.trim() }.filter { it.isNotEmpty() }
val cargoProfile = findProperty("creamote.cargoProfile") as String
val jniDir = layout.buildDirectory.dir("rust/jniLibs")
val bindingsDir = layout.buildDirectory.dir("generated/uniffi")

android {
    namespace = "org.creamote.core"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
    }

    sourceSets["main"].jniLibs.srcDir(jniDir)
    sourceSets["main"].java.srcDir(bindingsDir)

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    // Liaisons uniffi : JNA (variante AAR, avec ses bibliothèques natives).
    api("net.java.dev.jna:jna:5.17.0@aar")
}

// cargo ndk -t <abi>… -o build/rust/jniLibs build -p creamote-mobile
val cargoNdk by tasks.registering(Exec::class) {
    group = "rust"
    description = "Compile libcreamote_mobile.so pour chaque ABI Android"
    workingDir = repoRoot
    val args = mutableListOf("cargo", "ndk", "--platform", "26")
    abis.forEach { args += listOf("-t", it) }
    args += listOf("-o", jniDir.get().asFile.absolutePath, "build", "-p", "creamote-mobile", "--locked")
    if (cargoProfile == "release") args += "--release"
    commandLine(args)
    inputs.dir(repoRoot.resolve("crates"))
    inputs.file(repoRoot.resolve("Cargo.lock"))
    outputs.dir(jniDir)
}

// Liaisons Kotlin lues dans la bibliothèque compilée (mode « library »).
val uniffiBindings by tasks.registering(Exec::class) {
    group = "rust"
    description = "Génère les liaisons Kotlin du cœur Rust"
    dependsOn(cargoNdk)
    workingDir = repoRoot
    val lib = jniDir.get().file("${abis.first()}/libcreamote_mobile.so").asFile
    commandLine(
        "cargo", "run", "--locked", "-q", "-p", "creamote-mobile", "--features", "bindgen",
        "--bin", "uniffi-bindgen", "--", "generate", "--library", lib.absolutePath,
        "--language", "kotlin", "--no-format", "--out-dir", bindingsDir.get().asFile.absolutePath,
    )
    inputs.dir(jniDir)
    outputs.dir(bindingsDir)
    doFirst { delete(bindingsDir) }
}

tasks.named("preBuild") { dependsOn(uniffiBindings) }
