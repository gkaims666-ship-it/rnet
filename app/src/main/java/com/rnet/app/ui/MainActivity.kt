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
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Hub
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.SignalCellularAlt
import androidx.compose.material.icons.filled.WifiTethering
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.rnet.app.R

class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    // Runtime permissions launcher
    private val permissionsLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { /* permissions result — app continues regardless */ }

    // VPN permission launcher — Android requires explicit user approval before VpnService starts.
    // After approval, we start RnetForegroundService (which starts Psiphon, then starts
    // RnetVpnService once the SOCKS5 port is ready). This avoids a double-Psiphon crash.
    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            // VPN permission granted — now start the foreground engine service
            viewModel.toggleEngine(true)
        } else {
            // User denied — revert the optimistic switch state to OFF
            viewModel.setEngineActive(false)
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
                        if (wantOn) {
                            // Optimistically show ON; revert in launcher if denied
                            viewModel.setEngineActive(true)
                            requestVpnPermission()
                        } else {
                            viewModel.toggleEngine(false)
                        }
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
                    },
                    onFaqClick = {
                        startActivity(Intent(this, FaqActivity::class.java))
                    }
                )
            }
        }
    }

    /**
     * Request VPN permission if needed. If permission is already granted,
     * starts the engine immediately. If not, shows the system VPN dialog;
     * the engine starts in [vpnPermissionLauncher] callback after approval.
     */
    private fun requestVpnPermission() {
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            // Need user approval — show the system VPN dialog
            vpnPermissionLauncher.launch(vpnIntent)
        } else {
            // Already approved — start engine directly
            viewModel.toggleEngine(true)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RnetDashboard(
    uiState: UiState,
    onEngineToggle: (Boolean) -> Unit,
    onGatewayToggle: (Boolean) -> Unit,
    onResilientCoreToggle: (Boolean) -> Unit = {},
    onFaqClick: () -> Unit = {}
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = stringResource(R.string.app_name),
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 2.sp
                    )
                },
                actions = {
                    IconButton(onClick = onFaqClick) {
                        Icon(
                            imageVector = Icons.Filled.Info,
                            contentDescription = stringResource(R.string.faq_button),
                            tint = MaterialTheme.colorScheme.primary
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                    titleContentColor = MaterialTheme.colorScheme.onBackground
                )
            )
        },
        containerColor = MaterialTheme.colorScheme.background
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // ---- Main engine toggle ----
            EngineToggleCard(uiState.engineActive, onEngineToggle)

            // ---- Resilient Core opt-in (Psiphon decentralized routing) ----
            ResilientCoreCard(uiState.useResilientCore, onResilientCoreToggle)

            // ---- Telemetry widget ----
            TelemetryCard(uiState)

            // ---- Hotspot gateway (requires consent) ----
            GatewayCard(uiState, onGatewayToggle)

            Spacer(Modifier.height(8.dp))
        }
    }
}

@Composable
private fun CardIconBadge(icon: ImageVector, tint: Color, bgColor: Color) {
    Box(
        modifier = Modifier
            .size(40.dp)
            .clip(MaterialTheme.shapes.small)
            .background(bgColor),
        contentAlignment = Alignment.Center
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = tint,
            modifier = Modifier.size(22.dp)
        )
    }
}

@Composable
private fun CardHeader(
    icon: ImageVector,
    title: String,
    iconTint: Color = MaterialTheme.colorScheme.primary,
    iconBg: Color = MaterialTheme.colorScheme.primaryContainer
) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        CardIconBadge(icon = icon, tint = iconTint, bgColor = iconBg)
        Spacer(Modifier.width(12.dp))
        Text(
            text = title,
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.onSurface
        )
    }
}

@Composable
private fun EngineToggleCard(active: Boolean, onToggle: (Boolean) -> Unit) {
    val cardColor by animateColorAsState(
        targetValue = if (active) Color(0xFF1A0A2E) else MaterialTheme.colorScheme.surface,
        animationSpec = tween(durationMillis = 400),
        label = "engineCard"
    )
    val borderColor by animateColorAsState(
        targetValue = if (active) MaterialTheme.colorScheme.primary.copy(alpha = 0.5f)
                      else Color.Transparent,
        animationSpec = tween(durationMillis = 400),
        label = "engineBorder"
    )
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(
                width = 1.dp,
                color = borderColor,
                shape = MaterialTheme.shapes.medium
            ),
        colors = CardDefaults.cardColors(containerColor = cardColor),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Row(
            modifier = Modifier
                .padding(16.dp)
                .fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                CardHeader(
                    icon = Icons.Filled.Security,
                    title = stringResource(R.string.engine_title),
                    iconTint = if (active) MaterialTheme.colorScheme.primary
                               else MaterialTheme.colorScheme.onSurfaceVariant,
                    iconBg = if (active) MaterialTheme.colorScheme.primaryContainer
                             else MaterialTheme.colorScheme.surfaceVariant
                )
                Spacer(Modifier.height(6.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (active) {
                        Box(
                            modifier = Modifier
                                .size(8.dp)
                                .clip(MaterialTheme.shapes.extraSmall)
                                .background(Color(0xFF4CAF50))
                        )
                        Spacer(Modifier.width(6.dp))
                    }
                    Text(
                        text = if (active) stringResource(R.string.engine_status_active)
                               else stringResource(R.string.engine_status_inactive),
                        style = MaterialTheme.typography.bodySmall,
                        color = if (active) Color(0xFF81C784)
                                else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            Switch(checked = active, onCheckedChange = onToggle)
        }
    }
}

@Composable
private fun ResilientCoreCard(enabled: Boolean, onToggle: (Boolean) -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    CardHeader(
                        icon = Icons.Filled.Hub,
                        title = stringResource(R.string.resilient_core_title),
                        iconTint = if (enabled) Color(0xFFCE93D8)
                                   else MaterialTheme.colorScheme.onSurfaceVariant,
                        iconBg = if (enabled) Color(0xFF2D0845)
                                 else MaterialTheme.colorScheme.surfaceVariant
                    )
                }
                Switch(checked = enabled, onCheckedChange = onToggle)
            }
            Spacer(modifier = Modifier.height(10.dp))
            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.5f))
            Spacer(modifier = Modifier.height(10.dp))
            Text(
                text = stringResource(R.string.resilient_core_disclosure),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                lineHeight = 18.sp
            )
        }
    }
}

@Composable
private fun TelemetryCard(state: UiState) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            CardHeader(
                icon = Icons.Filled.SignalCellularAlt,
                title = stringResource(R.string.telemetry_title),
                iconTint = Color(0xFFB39DDB),
                iconBg = Color(0xFF1E0D35)
            )
            Spacer(Modifier.height(12.dp))
            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f))
            Spacer(Modifier.height(12.dp))
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                MetricRow(
                    label = stringResource(R.string.metric_snr),
                    value = "%.0f%%".format(state.snr),
                    valueColor = signalColor(state.snr / 100f)
                )
                MetricRow(
                    label = stringResource(R.string.metric_pdr),
                    value = "%.1f%%".format(state.packetDeliveryRate * 100f),
                    valueColor = signalColor(state.packetDeliveryRate)
                )
                MetricRow(
                    label = stringResource(R.string.metric_technology),
                    value = if (state.bandMhz > 0) "${state.technology} ${state.bandMhz} MHz"
                            else state.technology
                )
                MetricRow(
                    label = stringResource(R.string.metric_stations),
                    value = state.activeStations.toString()
                )
                MetricRow(
                    label = stringResource(R.string.metric_bytes_in),
                    value = formatBytes(state.totalBytesIn)
                )
                MetricRow(
                    label = stringResource(R.string.metric_bytes_out),
                    value = formatBytes(state.totalBytesOut)
                )
            }
        }
    }
}

private fun signalColor(ratio: Float): Color = when {
    ratio >= 0.7f -> Color(0xFF81C784)   // green — good
    ratio >= 0.4f -> Color(0xFFFFB74D)   // amber — mediocre
    else          -> Color(0xFFEF9A9A)   // red — poor
}

@Composable
private fun GatewayCard(state: UiState, onToggle: (Boolean) -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    CardHeader(
                        icon = Icons.Filled.WifiTethering,
                        title = stringResource(R.string.gateway_title),
                        iconTint = if (state.gatewayActive) Color(0xFFCE93D8)
                                   else MaterialTheme.colorScheme.onSurfaceVariant,
                        iconBg = if (state.gatewayActive) Color(0xFF2D0845)
                                 else MaterialTheme.colorScheme.surfaceVariant
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        text = stringResource(R.string.gateway_subtitle),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Switch(checked = state.gatewayActive, onCheckedChange = onToggle)
            }
            if (!state.gatewayConsentGranted) {
                Spacer(Modifier.height(10.dp))
                HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f))
                Spacer(Modifier.height(10.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Filled.Info,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.tertiary,
                        modifier = Modifier.size(14.dp)
                    )
                    Spacer(Modifier.width(6.dp))
                    Text(
                        text = stringResource(R.string.gateway_consent_required),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.tertiary
                    )
                }
            }
        }
    }
}

@Composable
private fun MetricRow(
    label: String,
    value: String,
    valueColor: Color = MaterialTheme.colorScheme.onSurface
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.SemiBold,
            color = valueColor
        )
    }
}

private fun formatBytes(bytes: Long): String = when {
    bytes >= 1_000_000_000L -> "%.1f GB".format(bytes / 1_000_000_000f)
    bytes >= 1_000_000L     -> "%.1f MB".format(bytes / 1_000_000f)
    bytes >= 1_000L         -> "%.1f KB".format(bytes / 1_000f)
    else                    -> "$bytes B"
}

/** Dark color scheme used throughout the app — black and purple. */
@Composable
fun rnetDarkColorScheme(): ColorScheme = darkColorScheme(
    primary              = Color(0xFFCE93D8),   // soft lavender-purple
    onPrimary            = Color(0xFF1A0028),
    primaryContainer     = Color(0xFF2D0845),   // very dark purple container
    onPrimaryContainer   = Color(0xFFEDD5F7),
    secondary            = Color(0xFFB39DDB),   // muted violet accent
    onSecondary          = Color(0xFF1A0040),
    secondaryContainer   = Color(0xFF1E0D35),
    onSecondaryContainer = Color(0xFFD8C8F0),
    tertiary             = Color(0xFFF48FB1),   // soft pink accent for notices
    onTertiary           = Color(0xFF2A0018),
    tertiaryContainer    = Color(0xFF1E0010),
    onTertiaryContainer  = Color(0xFFFFC8DB),
    background           = Color(0xFF07040C),   // near-black with slight purple tint
    onBackground         = Color(0xFFE8DFF0),
    surface              = Color(0xFF0F0A18),   // card background — dark purple-black
    onSurface            = Color(0xFFE8DFF0),
    surfaceVariant       = Color(0xFF180F25),   // slightly lighter surface
    onSurfaceVariant     = Color(0xFF9E8FB0),   // muted label — soft purple-grey
    error                = Color(0xFFEF9A9A),
    onError              = Color(0xFF4E0000),
    errorContainer       = Color(0xFF2A0A0A),
    onErrorContainer     = Color(0xFFFFCDD2),
    outline              = Color(0xFF2E2040),   // subtle purple separator
    outlineVariant       = Color(0xFF211530)
)
