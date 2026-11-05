package com.rnet.app

import android.app.Application
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

class RnetApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        // Register Bouncy Castle for ML-KEM / Kyber lookups.
        // Insert AFTER AndroidOpenSSL (position 1 conflicts with Android's SSL stack
        // on API 29+ and causes a crash). We append at the end so Android's own
        // providers stay undisturbed; BC is only used for PQC operations.
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }
}
