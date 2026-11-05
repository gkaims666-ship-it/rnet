package com.rnet.app

import android.app.Application
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

class RnetApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        // Register Bouncy Castle as the first security provider so ML-KEM / Kyber
        // lookups resolve before the default Android providers.
        Security.removeProvider("BC")  // Remove any old BC installation
        Security.insertProviderAt(BouncyCastleProvider(), 1)
    }
}
