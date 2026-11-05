package com.rnet.app.ui

import android.Manifest
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.rnet.app.R
import com.rnet.app.service.RnetVpnService

class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    // Runtime permissions launcher
    private val permissionsLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { /* permissions result — app continues regardless */ }

    // VPN permission launcher — Android requires explicit user approval before VpnService starts
    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            // User approved VPN — start the service
            startVpnService()
        }
    }

    // Consent activity launcher (hotspot gateway)
    private val consentLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            viewModel.onConsentGranted()
            viewModel.toggleGateway(true)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Request only runtime (dangerous) permissions on first launch.
        // INTERNET and ACCESS_NETWORK_STATE are install-time (normal) permissions —
        // passing them to RequestMultiplePermissions throws SecurityException on Android 6+.
        val permissions = buildList {
            add(Manifest.permission.ACCESS_FINE_LOCATION)
            add(Manifest.permission.READ_PHONE_STATE)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                add(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
        permissionsLauncher.launch(permissions.toTypedArray())

        setContent {
            MaterialTheme(colorScheme = rnetDarkColorScheme()) {
                val uiState by viewModel.ui.collectAsState()
                RnetDashboard(
                    uiState    = uiState,
                    onEngineToggle  = { wantOn ->
                        if (wantOn) requestVpnAndStart()
                        else stopVpnService()
                        viewModel.toggleEngine(wantOn)
                    },
                    onResilientCoreToggle = { viewModel.setUseResilientCore(it) },
                    onGatewayToggle = { wantOn ->
                        if (wantOn) {
                            if (uiState.gatewayConsentGranted) {
                                viewModel.toggleGateway(true)
                            } else {
                                consentLauncher.launch(
                                    Intent(this, ConsentActivity::class.java)
                                )
                            }
                        } else {
                            viewModel.toggleGateway(false)
                        }
                    }
                )
            }
        }
    }

    /** Request VPN permission if needed, then start the VPN service. */
    private fun requestVpnAndStart() {
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            // Need user approval — show the system VPN dialog
            vpnPermissionLauncher.launch(vpnIntent)
        } else {
            // Already approved — start immediately
            startVpnService()
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, RnetVpnService::class.java).apply {
            action = RnetVpnService.ACTION_START
        }
        startForegroundService(intent)
    }

    private fun stopVpnService() {
        val intent = Intent(this, RnetVpnService::class.java).apply {
            action = RnetVpnService.ACTION_STOP
        }
        startService(intent)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RnetDashboard(
    uiState: UiState,
    onEngineToggle: (Boolean) -> Unit,
    onGatewayToggle: (Boolean) -> Unit,
    onResilientCoreToggle: (Boolean) -> Unit = {}
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.app_name)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer
                )
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // ---- Main engine toggle ----
            EngineToggleCard(uiState.engineActive, onEngineToggle)

            // ---- Resilient Core opt-in (Psiphon decentralized routing) ----
            ResilientCoreCard(uiState.useResilientCore, onResilientCoreToggle)

            // ---- Telemetry widget ----
            TelemetryCard(uiState)

            // ---- Hotspot gateway (requires consent) ----
            GatewayCard(uiState, onGatewayToggle)
        }
    }
}

@Composable
private fun EngineToggleCard(active: Boolean, onToggle: (Boolean) -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .padding(20.dp)
                .fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = stringResource(R.string.engine_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = if (active) stringResource(R.string.engine_status_active)
                           else        stringResource(R.string.engine_status_inactive),
                    style = MaterialTheme.typography.bodySmall,
                    color = if (active) MaterialTheme.colorScheme.primary
                            else        MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Switch(checked = active, onCheckedChange = onToggle)
        }
    }
}

@Composable
private fun ResilientCoreCard(enabled: Boolean, onToggle: (Boolean) -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(20.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = stringResource(R.string.resilient_core_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Switch(checked = enabled, onCheckedChange = onToggle)
            }
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = stringResource(R.string.resilient_core_disclosure),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun TelemetryCard(state: UiState) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = stringResource(R.string.telemetry_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
            HorizontalDivider()
            MetricRow(label = stringResource(R.string.metric_snr),
                      value = "%.0f%%".format(state.snr))
            MetricRow(label = stringResource(R.string.metric_pdr),
                      value = "%.1f%%".format(state.packetDeliveryRate * 100f))
            MetricRow(label = stringResource(R.string.metric_technology),
                      value = if (state.bandMhz > 0) "${state.technology} ${state.bandMhz} MHz"
                              else state.technology)
            MetricRow(label = stringResource(R.string.metric_stations),
                      value = state.activeStations.toString())
            MetricRow(label = stringResource(R.string.metric_bytes_in),
                      value = formatBytes(state.totalBytesIn))
            MetricRow(label = stringResource(R.string.metric_bytes_out),
                      value = formatBytes(state.totalBytesOut))
        }
    }
}

@Composable
private fun GatewayCard(state: UiState, onToggle: (Boolean) -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(20.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = stringResource(R.string.gateway_title),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = stringResource(R.string.gateway_subtitle),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Switch(checked = state.gatewayActive, onCheckedChange = onToggle)
            }
            if (!state.gatewayConsentGranted) {
                Spacer(Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.gateway_consent_required),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.tertiary
                )
            }
        }
    }
}

@Composable
private fun MetricRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(text = label,  style = MaterialTheme.typography.bodyMedium,
             color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(text = value,  style = MaterialTheme.typography.bodyMedium,
             fontWeight = FontWeight.Medium)
    }
}

private fun formatBytes(bytes: Long): String = when {
    bytes >= 1_000_000_000L -> "%.1f GB".format(bytes / 1_000_000_000f)
    bytes >= 1_000_000L     -> "%.1f MB".format(bytes / 1_000_000f)
    bytes >= 1_000L         -> "%.1f KB".format(bytes / 1_000f)
    else                    -> "$bytes B"
}

/** Dark color scheme used throughout the app. */
@Composable
fun rnetDarkColorScheme(): ColorScheme = darkColorScheme(
    primary            = Color(0xFF82B4FF),   // bright blue accent
    onPrimary          = Color(0xFF003062),
    primaryContainer   = Color(0xFF1A3A5C),   // dark blue card header
    onPrimaryContainer = Color(0xFFD6E4FF),
    secondary          = Color(0xFF9FC8FF),
    onSecondary        = Color(0xFF003258),
    secondaryContainer = Color(0xFF1C3A5A),
    onSecondaryContainer = Color(0xFFD0E4FF),
    tertiary           = Color(0xFF78DCCA),   // teal for notices
    onTertiary         = Color(0xFF003731),
    background         = Color(0xFF0E1317),   // near-black background
    onBackground       = Color(0xFFE2E8F0),
    surface            = Color(0xFF161C22),   // card background
    onSurface          = Color(0xFFE2E8F0),
    surfaceVariant     = Color(0xFF1E2730),
    onSurfaceVariant   = Color(0xFF90A4B4),   // muted label text
    error              = Color(0xFFFFB4AB),
    onError            = Color(0xFF690005),
    outline            = Color(0xFF2D3A47)
)
