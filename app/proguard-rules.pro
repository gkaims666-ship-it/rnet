# ── RNET ProGuard rules ──

# Bouncy Castle PQC — keep all provider registration and algorithm classes
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# Android TelephonyManager public API (reflection not used, but keep for completeness)
-keep class android.telephony.** { *; }

# Kotlin coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-keepclassmembernames class kotlinx.coroutines.** {
    volatile <fields>;
}

# Keep RNET data classes used in StateFlow (names may be used in serialization)
-keep class com.rnet.app.transport.CellSnapshot { *; }
-keep class com.rnet.app.gateway.HotspotGateway$StationMetrics { *; }
-keep class com.rnet.app.ui.UiState { *; }
