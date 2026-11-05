package com.rnet.app.ui

import android.Manifest
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import com.rnet.app.prefs.ServerPrefs
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.rnet.app.R

class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    // Runtime permissions launcher
    private val permissionsLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { results ->
        val allGranted = results.values.all { it }
        if (!allGranted) {
            // Show rationale — handled in UI
        }
    }

    // Consent activity launcher
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

        // Setup screen bypassed: app boots directly to Dashboard on first launch.
        // Zero-configuration emergency-launch mode — no relay setup required.

        // Request minimum required permissions on first launch
        val permissions = buildList {
            add(Manifest.permission.INTERNET)
            add(Manifest.permission.ACCESS_NETWORK_STATE)
            add(Manifest.permission.ACCESS_FINE_LOCATION)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                add(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
        permissionsLauncher.launch(permissions.toTypedArray())

        setContent {
            MaterialTheme {
                val uiState by viewModel.ui.collectAsState()
                RnetDashboard(
                    uiState    = uiState,
                    onEngineToggle  = { viewModel.toggleEngine(it) },
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
                    text = "Route via Resilient Core",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Switch(checked = enabled, onCheckedChange = onToggle)
            }
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = "When enabled, your traffic is routed through the Psiphon " +
                       "decentralized network (psiphon.ca) — an open-source, non-profit " +
                       "censorship-circumvention service. " +
                       "Psiphon can see that you are connected, but not the content of " +
                       "your traffic, which is end-to-end encrypted by RNET. " +
                       "Applies on next engine start.",
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
            Divider()
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
