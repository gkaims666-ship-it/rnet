package com.rnet.app

import android.app.Application
import androidx.appcompat.app.AppCompatDelegate
import com.rnet.app.diag.CrashHandler
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

class RnetApplication : Application() {
    override fun onCreate() {
        super.onCreate()

        // Capture uncaught exceptions to a local, sanitized crash log before
        // anything else can crash. No automatic upload — the user shares logs
        // from the dashboard when they choose to.
        val versionName = runCatching {
            packageManager.getPackageInfo(packageName, 0).versionName
        }.getOrNull() ?: "unknown"
        CrashHandler.install(this, versionName)

        // Force dark theme globally — the app was designed for dark mode.
        AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES)

        // Register Bouncy Castle for ML-KEM / Kyber lookups.
        // Insert AFTER AndroidOpenSSL (position 1 conflicts with Android's SSL stack
        // on API 29+ and causes a crash). We append at the end so Android's own
        // providers stay undisturbed; BC is only used for PQC operations.
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }
}
