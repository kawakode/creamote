plugins {
    kotlin("jvm") version "2.2.0"
}

val repoRoot = rootDir.parentFile.parentFile
val targetDir = repoRoot.resolve("target/debug")
val bindingsDir = layout.buildDirectory.dir("generated/uniffi")

sourceSets["test"].kotlin.srcDir(bindingsDir)

dependencies {
    testImplementation("net.java.dev.jna:jna:5.17.0")
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.12.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

// Cœur Rust et serveur compilés pour l'hôte.
val cargoBuild by tasks.registering(Exec::class) {
    group = "rust"
    workingDir = repoRoot
    commandLine("cargo", "build", "--locked", "-p", "creamote-mobile", "-p", "creamote-server")
}

val uniffiBindings by tasks.registering(Exec::class) {
    group = "rust"
    dependsOn(cargoBuild)
    workingDir = repoRoot
    commandLine(
        "cargo", "run", "--locked", "-q", "-p", "creamote-mobile", "--features", "bindgen",
        "--bin", "uniffi-bindgen", "--", "generate", "--library",
        targetDir.resolve("libcreamote_mobile.so").absolutePath,
        "--language", "kotlin", "--no-format", "--out-dir", bindingsDir.get().asFile.absolutePath,
    )
    inputs.file(targetDir.resolve("libcreamote_mobile.so"))
    outputs.dir(bindingsDir)
    doFirst { delete(bindingsDir) }
}

tasks.named("compileTestKotlin") { dependsOn(uniffiBindings) }

tasks.test {
    useJUnitPlatform()
    systemProperty("jna.library.path", targetDir.absolutePath)
    systemProperty("creamote.server", targetDir.resolve("creamote-server").absolutePath)
    testLogging {
        events("passed", "failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        showStandardStreams = true
    }
}
