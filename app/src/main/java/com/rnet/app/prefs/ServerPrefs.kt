package com.rnet.app.prefs

import android.content.Context

/**
 * ServerPrefs — persists the user-configured relay endpoint.
 *
 * The user enters their own RNET relay host/port on the onboarding screen.
 * Nothing is sent to the network until a valid configuration is saved here.
 */
object ServerPrefs {

    private const val PREF_FILE  = "rnet_server_prefs"
    private const val KEY_HOST   = "relay_host"
    private const val KEY_PORT   = "relay_port"
    private const val DEFAULT_PORT = 7777

    /** Returns true when the user has saved a relay endpoint. */
    fun isConfigured(ctx: Context): Boolean =
        getHost(ctx).isNotBlank()

    fun getHost(ctx: Context): String =
        ctx.getSharedPreferences(PREF_FILE, Context.MODE_PRIVATE)
           .getString(KEY_HOST, "") ?: ""

    fun getPort(ctx: Context): Int =
        ctx.getSharedPreferences(PREF_FILE, Context.MODE_PRIVATE)
           .getInt(KEY_PORT, DEFAULT_PORT)

    fun save(ctx: Context, host: String, port: Int) {
        ctx.getSharedPreferences(PREF_FILE, Context.MODE_PRIVATE).edit()
            .putString(KEY_HOST, host.trim())
            .putInt(KEY_PORT, port)
            .apply()
    }

    fun clear(ctx: Context) {
        ctx.getSharedPreferences(PREF_FILE, Context.MODE_PRIVATE).edit().clear().apply()
    }

    // ── Resilient Core preference ──────────────────────────────────────────────

    private const val KEY_RESILIENT_CORE = "use_resilient_core"

    /**
     * Returns true when Psiphon resilient routing is enabled.
     * Default: true — Psiphon is ON out-of-the-box for zero-config emergency use.
     * The user may disable it from the Dashboard toggle.
     */
    fun useResilientCore(ctx: Context): Boolean =
        ctx.getSharedPreferences(PREF_FILE, Context.MODE_PRIVATE)
           .getBoolean(KEY_RESILIENT_CORE, true)

    fun setUseResilientCore(ctx: Context, enabled: Boolean) {
        ctx.getSharedPreferences(PREF_FILE, Context.MODE_PRIVATE).edit()
            .putBoolean(KEY_RESILIENT_CORE, enabled)
            .apply()
    }
}
