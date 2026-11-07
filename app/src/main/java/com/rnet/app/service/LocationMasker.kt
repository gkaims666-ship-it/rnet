package com.rnet.app.service

import android.content.Context
import android.location.Location
import android.location.LocationManager
import android.os.Build
import android.os.SystemClock
import android.util.Log

/**
 * LocationMasker — provides fake GPS coordinates matching the Psiphon exit region.
 *
 * When the VPN routes through an exit node in e.g. the Netherlands, apps that use
 * GPS can still see your real location. This sets the GPS mock location to the
 * capital city of the chosen Psiphon region, so GPS also shows the exit country.
 *
 * Requirements:
 *   1. App must declare ACCESS_MOCK_LOCATION in the manifest.
 *   2. User must enable "Allow mock locations" in Developer Options (Settings →
 *      Developer Options → Select mock location app → pick RNET).
 *      On Android 6+, this is done through "Select mock location app".
 *
 * Usage:
 *   LocationMasker.start(context, "NL")   // set GPS to Amsterdam
 *   LocationMasker.stop(context)          // remove mock provider
 */
object LocationMasker {

    private const val TAG = "LocationMasker"
    private const val PROVIDER = LocationManager.GPS_PROVIDER

    // Region code → (latitude, longitude, city name)
    // Covers all countries in RnetForegroundService.FREE_REGIONS + extras
    private val REGION_COORDS = mapOf(
        "IS" to Triple(64.1355, -21.8954, "Reykjavik"),    // Iceland — #1 internet freedom
        "EE" to Triple(59.4370,  24.7536, "Tallinn"),      // Estonia
        "NO" to Triple(59.9139,  10.7522, "Oslo"),         // Norway
        "SE" to Triple(59.3293,  18.0686, "Stockholm"),    // Sweden
        "FI" to Triple(60.1699,  24.9384, "Helsinki"),     // Finland
        "CH" to Triple(47.3769,   8.5417, "Zurich"),       // Switzerland
        "DE" to Triple(52.5200,  13.4050, "Berlin"),       // Germany
        "NL" to Triple(52.3676,   4.9041, "Amsterdam"),    // Netherlands
        "AT" to Triple(48.2082,  16.3738, "Vienna"),       // Austria
        "CZ" to Triple(50.0755,  14.4378, "Prague"),       // Czech Republic
        "CA" to Triple(43.6532, -79.3832, "Toronto"),      // Canada
        "US" to Triple(40.7128, -74.0060, "New York"),     // United States
        "GB" to Triple(51.5074,  -0.1278, "London"),       // United Kingdom
        "JP" to Triple(35.6762, 139.6503, "Tokyo"),        // Japan
        "AU" to Triple(-33.8688, 151.2093,"Sydney"),       // Australia
        // extras kept for completeness
        "FR" to Triple(48.8566,   2.3522, "Paris"),
        "RO" to Triple(44.4268,  26.1025, "Bucharest"),
        "SG" to Triple( 1.3521, 103.8198, "Singapore"),
        ""   to Triple(64.1355, -21.8954, "Reykjavik")     // default = Iceland
    )

    @Volatile private var active = false

    /**
     * Start providing mock GPS locations for the given Psiphon region code.
     * Returns the city name that GPS is now spoofed to, or null if mock
     * locations are not enabled in Developer Options.
     */
    fun start(context: Context, region: String): String? {
        val lm = context.getSystemService(Context.LOCATION_SERVICE) as LocationManager
        val (lat, lon, city) = REGION_COORDS[region] ?: REGION_COORDS[""]!!

        return try {
            // Add mock provider — will throw SecurityException if not enabled
            try { lm.removeTestProvider(PROVIDER) } catch (_: Exception) {}
            @Suppress("DEPRECATION")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                lm.addTestProvider(
                    PROVIDER,
                    false, false, false, false, false, true, true,
                    android.location.provider.ProviderProperties.POWER_USAGE_LOW,
                    android.location.provider.ProviderProperties.ACCURACY_FINE
                )
            } else {
                lm.addTestProvider(
                    PROVIDER,
                    false, false, false, false, false, true, true,
                    android.location.Criteria.POWER_LOW,
                    android.location.Criteria.ACCURACY_FINE
                )
            }
            lm.setTestProviderEnabled(PROVIDER, true)
            active = true

            // Push an initial location immediately so apps get it right away
            pushLocation(lm, lat, lon)

            Log.i(TAG, "GPS mocked → $city ($lat, $lon)")
            city
        } catch (e: SecurityException) {
            Log.w(TAG, "Mock location not permitted — enable in Developer Options: ${e.message}")
            null
        } catch (e: Exception) {
            Log.w(TAG, "LocationMasker start failed: ${e.message}")
            null
        }
    }

    /** Push a single mock location update. Call periodically to keep apps happy. */
    fun push(context: Context, region: String) {
        if (!active) return
        val lm = context.getSystemService(Context.LOCATION_SERVICE) as LocationManager
        val (lat, lon, _) = REGION_COORDS[region] ?: REGION_COORDS[""]!!
        try { pushLocation(lm, lat, lon) } catch (_: Exception) {}
    }

    /** Stop mocking and remove the test provider. */
    fun stop(context: Context) {
        active = false
        val lm = context.getSystemService(Context.LOCATION_SERVICE) as LocationManager
        try {
            lm.setTestProviderEnabled(PROVIDER, false)
            lm.removeTestProvider(PROVIDER)
            Log.i(TAG, "GPS mock removed")
        } catch (_: Exception) {}
    }

    private fun pushLocation(lm: LocationManager, lat: Double, lon: Double) {
        val loc = Location(PROVIDER).apply {
            latitude  = lat
            longitude = lon
            altitude  = 10.0
            accuracy  = 1.0f
            time      = System.currentTimeMillis()
            elapsedRealtimeNanos = SystemClock.elapsedRealtimeNanos()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                verticalAccuracyMeters = 1.0f
            }
        }
        lm.setTestProviderLocation(PROVIDER, loc)
    }
}
