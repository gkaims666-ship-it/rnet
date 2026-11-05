plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace   = "com.rnet.app"
    compileSdk  = 36

    defaultConfig {
        applicationId   = "com.rnet.app"
        minSdk          = 29
        targetSdk       = 36
        versionCode     = 1
        versionName     = "1.0.0"

        // Universal APK — includes all three ABI splits
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        // Release signing: injected via CI environment variables (see android-build.yml)
        create("release") {
            storeFile     = file(System.getenv("KEYSTORE_PATH") ?: "keystore/debug.jks")
            storePassword = System.getenv("KEYSTORE_PASSWORD") ?: "android"
            keyAlias      = System.getenv("KEY_ALIAS")          ?: "androiddebugkey"
            keyPassword   = System.getenv("KEY_PASSWORD")       ?: "android"
        }
    }

    buildTypes {
        debug {
            isDebuggable         = true
            applicationIdSuffix  = ".debug"
        }
        release {
            isMinifyEnabled      = true
            isShrinkResources    = true
            signingConfig        = signingConfigs.getByName("release")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    // Universal APK output (single APK containing all ABIs)
    splits {
        abi {
            isEnable         = false   // Disabled: we produce one universal APK
            isUniversalApk   = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.14"
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            // BC ships duplicate BC-related signature files; exclude them
            excludes += "META-INF/BCKEY.DSA"
            excludes += "META-INF/BCKEY.SF"
        }
    }
}

dependencies {
    // Compose BOM
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.activity.compose)

    // Jetpack
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)

    // Coroutines
    implementation(libs.kotlinx.coroutines.android)

    // Bouncy Castle — ML-KEM (Kyber) PQC + HKDF
    implementation(libs.bouncycastle.bcprov)
    implementation(libs.bouncycastle.bcpkix)

    // Psiphon tunnel-core — decentralized resilient transport fallback (GPL v3)
    // Source: https://github.com/Psiphon-Labs/psiphon-tunnel-core
    // Used only when user enables "Route via Resilient Core" and no private relay is set.
    implementation(libs.psiphon.tunnel)

    // Test
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.ui.test.junit4)
    debugImplementation(libs.androidx.ui.tooling)
    debugImplementation(libs.androidx.ui.test.manifest)
}
