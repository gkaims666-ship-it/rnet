pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // Psiphon tunnel-core Android AAR (GPL v3)
        // https://github.com/Psiphon-Labs/psiphon-tunnel-core-Android-library
        maven { url = uri("https://raw.github.com/Psiphon-Labs/psiphon-tunnel-core-Android-library/master") }
    }
}
rootProject.name = "rnet"
include(":app")
include(":shared")
