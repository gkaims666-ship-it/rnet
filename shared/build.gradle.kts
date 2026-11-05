plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.android.library)
}

kotlin {
    androidTarget {
        compilations.all {
            kotlinOptions {
                jvmTarget = "17"
            }
        }
    }

    // Register XCFramework so assembleRnetSharedReleaseXCFramework task exists for CI
    val xcf = org.jetbrains.kotlin.gradle.plugin.mpp.apple.XCFramework("RnetShared")

    listOf(
        iosX64(),
        iosArm64(),
        iosSimulatorArm64()
    ).forEach { iosTarget ->
        iosTarget.binaries.framework {
            baseName = "RnetShared"
            isStatic = true
            xcf.add(this)
        }
    }

    sourceSets {
        commonMain.dependencies {
            implementation(libs.kotlinx.coroutines.core)
        }
        androidMain.dependencies {
            // Android-specific: Bouncy Castle, Android APIs
            implementation(libs.bcprov)
        }
        // iosMain has no additional deps — uses Apple CryptoKit via Swift interop
    }
}

android {
    namespace = "com.rnet.shared"
    compileSdk = 36
    defaultConfig {
        minSdk = 29
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
