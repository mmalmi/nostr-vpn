plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

import org.gradle.api.tasks.Exec
import org.gradle.api.GradleException

val repoRoot = layout.projectDirectory.dir("../..")
val rustOutputDir = layout.projectDirectory.dir("src/main/jniLibs")
val releaseStoreFile = providers.environmentVariable("ANDROID_KEYSTORE_PATH")
val releaseStorePassword = providers.environmentVariable("ANDROID_KEYSTORE_PASSWORD")
val releaseKeyAlias = providers.environmentVariable("ANDROID_KEY_ALIAS")
val releaseKeyPassword = providers.environmentVariable("ANDROID_KEY_PASSWORD")
val hasReleaseSigning =
    releaseStoreFile.isPresent &&
        releaseStorePassword.isPresent &&
        releaseKeyAlias.isPresent &&
        releaseKeyPassword.isPresent
val debugUsesReleaseSigning =
    providers.environmentVariable("NVPN_ANDROID_DEBUG_RELEASE_SIGNING")
        .orNull
        ?.lowercase() in setOf("1", "true", "yes", "on")
val buildGitSha = providers.environmentVariable("NVPN_BUILD_GIT_SHA").orElse("").get()
val buildTimestampUtc = providers.environmentVariable("NVPN_BUILD_TIMESTAMP_UTC").orElse("").get()
val androidPackageName =
    providers.environmentVariable("NVPN_ANDROID_PACKAGE").orElse("fi.siriusbusiness.nvpn").get()
val androidLegacyFixtureWithoutNativeLibs =
    providers.environmentVariable("NVPN_ANDROID_LEGACY_FIXTURE_WITHOUT_NATIVE_LIBS")
        .orNull
        ?.lowercase() in setOf("1", "true", "yes", "on")

if (androidLegacyFixtureWithoutNativeLibs && androidPackageName == "fi.siriusbusiness.nvpn") {
    throw GradleException("Native-free Android fixtures cannot use the canonical package")
}

fun buildConfigString(value: String): String =
    "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

android {
    namespace = "org.nostrvpn.app"
    compileSdk = 36

    defaultConfig {
        applicationId = androidPackageName
        minSdk = 26
        targetSdk = 36
        versionCode = 4010900
        versionName = "4.1.9"
        buildConfigField("String", "NVPN_BUILD_GIT_SHA", buildConfigString(buildGitSha))
        buildConfigField("String", "NVPN_BUILD_TIMESTAMP_UTC", buildConfigString(buildTimestampUtc))

        ndk {
            abiFilters += "arm64-v8a"
        }
    }

    val updateManifestUrl =
        providers.environmentVariable("NVPN_UPDATE_MANIFEST_URL").orNull?.takeIf { it.isNotBlank() } ?: ""
    val updatePollSeconds =
        providers.environmentVariable("NVPN_UPDATE_POLL_SECONDS").orNull?.toLongOrNull() ?: 0L

    val releaseSigningConfig =
        if (hasReleaseSigning) {
            signingConfigs.create("release") {
                storeFile = file(releaseStoreFile.get())
                storePassword = releaseStorePassword.get()
                keyAlias = releaseKeyAlias.get()
                keyPassword = releaseKeyPassword.get()
            }
        } else {
            null
        }
    if (debugUsesReleaseSigning && releaseSigningConfig == null) {
        throw GradleException(
            "NVPN_ANDROID_DEBUG_RELEASE_SIGNING requires the Android release keystore variables",
        )
    }

    buildTypes {
        debug {
            if (debugUsesReleaseSigning) {
                signingConfig = releaseSigningConfig
            }
            buildConfigField("String", "UPDATE_MANIFEST_URL", "\"${updateManifestUrl}\"")
            buildConfigField("long", "UPDATE_POLL_SECONDS", "${updatePollSeconds}L")
            buildConfigField("boolean", "SELF_UPDATE_ENABLED", "false")
        }
        release {
            isMinifyEnabled = false
            if (releaseSigningConfig != null) {
                signingConfig = releaseSigningConfig
            }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            buildConfigField("String", "UPDATE_MANIFEST_URL", "\"${updateManifestUrl}\"")
            buildConfigField("long", "UPDATE_POLL_SECONDS", "${updatePollSeconds}L")
            buildConfigField("boolean", "SELF_UPDATE_ENABLED", "true")
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        jniLibs {
            if (androidLegacyFixtureWithoutNativeLibs) {
                excludes += "**/*.so"
            } else {
                keepDebugSymbols += setOf(
                    "**/libbarhopper_v3.so",
                    "**/libboringtun-*.so",
                    "**/libandroidx.graphics.path.so",
                    "**/libimage_processing_util_jni.so",
                    "**/libnostr_vpn_app_core.so",
                    "**/libsurface_util_jni.so",
                )
            }
        }
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

kotlin {
    jvmToolchain(17)
}

tasks.register<Exec>("buildRustArm64") {
    workingDir = repoRoot.asFile
    doFirst {
        delete(rustOutputDir.dir("arm64-v8a"))
    }
    val cargoExecutable = providers.gradleProperty("nvpnCargoExecutable")
        .getOrElse("cargo")
    val cargoNdkExecutable = providers.gradleProperty(
        "nvpnCargoNdkExecutable"
    ).orNull
    val cargoNdkCommand = if (cargoNdkExecutable == null) {
        listOf(cargoExecutable, "ndk")
    } else {
        environment("CARGO", cargoExecutable)
        // cargo-ndk consumes the subcommand token that Cargo normally inserts.
        listOf(cargoNdkExecutable, "ndk")
    }
    commandLine(
        *(cargoNdkCommand + listOf(
                "--target",
                "arm64-v8a",
                "--platform",
                "26",
                "--output-dir",
                rustOutputDir.asFile.absolutePath,
                "build",
                "--quiet",
            ) + listOf(
                "--package",
                "nostr-vpn-app-core",
                "--release",
            )).toTypedArray()
    )
}

tasks.matching { task ->
    task.name in listOf("mergeDebugNativeLibs", "mergeReleaseNativeLibs")
}.configureEach {
    dependsOn("buildRustArm64")
}

dependencies {
    implementation("androidx.activity:activity-compose:1.11.0")
    implementation("androidx.camera:camera-camera2:1.4.2")
    implementation("androidx.camera:camera-lifecycle:1.4.2")
    implementation("androidx.camera:camera-view:1.4.2")
    implementation("androidx.compose.foundation:foundation:1.9.2")
    implementation("androidx.compose.material3:material3:1.4.0")
    implementation("androidx.compose.ui:ui:1.9.2")
    implementation("androidx.compose.ui:ui-tooling-preview:1.9.2")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.9.4")
    implementation("com.google.mlkit:barcode-scanning:17.3.0")
    debugImplementation("androidx.compose.ui:ui-tooling:1.9.2")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}
