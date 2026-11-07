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
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Hub
import androidx.compose.material.icons.filled.Info
import androidx.compose.foundation.BorderStroke
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.SignalCellularAlt
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.WifiTethering
import androidx.compose.ui.draw.alpha
import com.rnet.app.service.ConnectionPhase
import com.rnet.app.service.RnetForegroundService
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
                    onRegionChange = { viewModel.setExitRegion(it) },
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
    onRegionChange: (String) -> Unit = {},
    onFaqClick: () -> Unit = {}
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(28.dp)
                                .clip(MaterialTheme.shapes.small)
                                .background(MaterialTheme.colorScheme.primaryContainer),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Shield,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(16.dp)
                            )
                        }
                        Spacer(Modifier.width(10.dp))
                        Text(
                            text = stringResource(R.string.app_name),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 1.5.sp,
                            color = MaterialTheme.colorScheme.onBackground
                        )
                    }
                },
                actions = {
                    IconButton(onClick = onFaqClick) {
                        Icon(
                            imageVector = Icons.Filled.Info,
                            contentDescription = stringResource(R.string.faq_button),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
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
                .padding(horizontal = 16.dp, vertical = 4.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Spacer(Modifier.height(4.dp))
            EngineHeroCard(uiState, onEngineToggle)

            if (uiState.engineActive) {
                ConnectionStatusCard(uiState)
            }

            RegionPickerCard(
                selectedRegion  = uiState.exitRegion,
                onSelect        = onRegionChange,
                engineActive    = uiState.engineActive,
                connectionPhase = uiState.connectionPhase,
                proxyLabel      = uiState.proxyLabel
            )

            ResilientCoreCard(uiState.useResilientCore, onResilientCoreToggle)

            TelemetryCard(uiState)

            GatewayCard(uiState, onGatewayToggle)

            Spacer(Modifier.height(16.dp))
        }
    }
}

// ── Hero engine card ─────────────────────────────────────────────────────────

@Composable
private fun EngineHeroCard(state: UiState, onToggle: (Boolean) -> Unit) {
    val active = state.engineActive

    val bgColor by animateColorAsState(
        targetValue = if (active) Color(0xFF130826) else MaterialTheme.colorScheme.surface,
        animationSpec = tween(500), label = "heroBg"
    )
    val borderAlpha by animateColorAsState(
        targetValue = if (active) MaterialTheme.colorScheme.primary.copy(alpha = 0.6f)
                      else MaterialTheme.colorScheme.outline.copy(alpha = 0.3f),
        animationSpec = tween(500), label = "heroBorder"
    )

    val infiniteTransition = rememberInfiniteTransition(label = "heroPulse")
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 0.9f, targetValue = 1.1f,
        animationSpec = infiniteRepeatable(
            animation = tween(1200, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ), label = "heroScale"
    )
    val isTransitioning = active && state.connectionPhase != ConnectionPhase.ACTIVE

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, borderAlpha, MaterialTheme.shapes.large),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = bgColor),
        elevation = CardDefaults.cardElevation(defaultElevation = if (active) 6.dp else 2.dp)
    ) {
        Row(
            modifier = Modifier
                .padding(horizontal = 20.dp, vertical = 20.dp)
                .fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Left side: status indicator + text
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                // Animated status orb
                Box(
                    modifier = Modifier
                        .size(if (active && isTransitioning) (44 * pulseScale).dp else 44.dp)
                        .clip(MaterialTheme.shapes.medium)
                        .background(
                            if (active) MaterialTheme.colorScheme.primaryContainer
                            else MaterialTheme.colorScheme.surfaceVariant
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Filled.Security,
                        contentDescription = null,
                        tint = if (active) MaterialTheme.colorScheme.primary
                               else MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(24.dp)
                    )
                }
                Spacer(Modifier.width(14.dp))
                Column {
                    Text(
                        text = stringResource(R.string.engine_title),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Spacer(Modifier.height(3.dp))
                    StatusPill(state)
                }
            }
            // Right side: toggle switch
            Switch(
                checked = active,
                onCheckedChange = onToggle,
                colors = SwitchDefaults.colors(
                    checkedThumbColor   = MaterialTheme.colorScheme.onPrimary,
                    checkedTrackColor   = MaterialTheme.colorScheme.primary,
                    uncheckedThumbColor = MaterialTheme.colorScheme.onSurfaceVariant,
                    uncheckedTrackColor = MaterialTheme.colorScheme.surfaceVariant
                )
            )
        }
    }
}

@Composable
private fun StatusPill(state: UiState) {
    val active = state.engineActive
    val infiniteTransition = rememberInfiniteTransition(label = "pillPulse")
    val dotAlpha by infiniteTransition.animateFloat(
        initialValue = 1f, targetValue = 0.25f,
        animationSpec = infiniteRepeatable(
            animation = tween(700, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ), label = "dotAlpha"
    )
    val isAnimating = active && state.connectionPhase != ConnectionPhase.ACTIVE

    val dotColor = when {
        !active -> MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f)
        state.connectionPhase == ConnectionPhase.ACTIVE -> Color(0xFF4CAF50)
        else -> Color(0xFFFFB74D)
    }
    val label = when {
        !active -> stringResource(R.string.engine_status_inactive)
        state.connectionPhase == ConnectionPhase.ACTIVE -> stringResource(R.string.engine_status_active)
        state.connectionPhase == ConnectionPhase.FINDING_PROXY -> stringResource(R.string.vpn_status_starting_tunnel)
        else -> stringResource(R.string.vpn_status_connecting)
    }

    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            modifier = Modifier
                .size(7.dp)
                .clip(MaterialTheme.shapes.extraSmall)
                .background(dotColor)
                .then(if (isAnimating) Modifier.alpha(dotAlpha) else Modifier)
        )
        Spacer(Modifier.width(5.dp))
        Text(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = if (active) Color(0xFF81C784) else MaterialTheme.colorScheme.onSurfaceVariant,
            letterSpacing = 0.sp
        )
    }
}

// ── Connection status card ───────────────────────────────────────────────────

@Composable
private fun ConnectionStatusCard(state: UiState) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = Color(0xFF0D0718)),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(modifier = Modifier.padding(18.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(MaterialTheme.shapes.small)
                        .background(Color(0xFF1A0A2E)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(Icons.Filled.Shield, null,
                        tint = Color(0xFF9C64D6), modifier = Modifier.size(20.dp))
                }
                Spacer(Modifier.width(12.dp))
                Text("Connection",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface)
            }

            Spacer(Modifier.height(14.dp))
            HorizontalDivider(color = Color(0xFF2E2040))
            Spacer(Modifier.height(14.dp))

            // Traffic row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly
            ) {
                TrafficStat(label = "↓ IN",  value = formatBytes(state.totalBytesIn),  color = Color(0xFF80DEEA))
                VerticalDivider(modifier = Modifier.height(32.dp), color = Color(0xFF2E2040))
                TrafficStat(label = "↑ OUT", value = formatBytes(state.totalBytesOut), color = Color(0xFFCE93D8))
                VerticalDivider(modifier = Modifier.height(32.dp), color = Color(0xFF2E2040))
                TrafficStat(label = "Sessions", value = state.activeSessionCount.toString(), color = Color(0xFFB39DDB))
            }

            Spacer(Modifier.height(14.dp))
            HorizontalDivider(color = Color(0xFF2E2040))
            Spacer(Modifier.height(12.dp))

            Column(verticalArrangement = Arrangement.spacedBy(9.dp)) {
                MetricRow("Tunnel", state.proxyLabel,
                    valueColor = when {
                        state.proxyLabel.startsWith("Smart") -> Color(0xFF81C784)
                        state.proxyLabel == "Direct" -> Color(0xFFFFB74D)
                        else -> Color(0xFFB39DDB)
                    })
                if (state.exitRegion.isNotEmpty()) {
                    MetricRow("Location", "${regionFlag(state.exitRegion)}  ${state.exitRegion}",
                        valueColor = Color(0xFF80DEEA))
                }
                MetricRow("DNS", "DoH · Cloudflare", valueColor = Color(0xFF81C784))
                if (state.routeCacheSize > 0 || state.pooledSockets > 0) {
                    MetricRow("Route cache", "${state.routeCacheSize} dest · ${state.pooledSockets} warm",
                        valueColor = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}

@Composable
private fun TrafficStat(label: String, value: String, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value,
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Bold,
            color = color)
        Spacer(Modifier.height(2.dp))
        Text(label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

// ── Region metadata ──────────────────────────────────────────────────────────
private data class RegionInfo(val code: String, val city: String, val note: String)
private val ALL_REGIONS = listOf(
    RegionInfo("IS", "Reykjavik",  "No censorship — #1 internet freedom"),
    RegionInfo("EE", "Tallinn",    "Digital-first, no filtering"),
    RegionInfo("NO", "Oslo",       "No content blocking"),
    RegionInfo("SE", "Stockholm",  "No content blocking"),
    RegionInfo("FI", "Helsinki",   "No content blocking"),
    RegionInfo("CH", "Zurich",     "Strong legal protections"),
    RegionInfo("DE", "Berlin",     "No state filtering"),
    RegionInfo("NL", "Amsterdam",  "No state filtering"),
    RegionInfo("AT", "Vienna",     "No state filtering"),
    RegionInfo("CZ", "Prague",     "No state filtering"),
    RegionInfo("CA", "Toronto",    "No blocking"),
    RegionInfo("US", "New York",   "No ISP-level filtering"),
    RegionInfo("GB", "London",     "Minor court-ordered blocks only"),
    RegionInfo("JP", "Tokyo",      "Open internet"),
    RegionInfo("AU", "Sydney",     "Mostly open")
)

@Composable
private fun RegionPickerCard(
    selectedRegion: String,
    onSelect: (String) -> Unit,
    engineActive: Boolean = false,
    connectionPhase: ConnectionPhase = ConnectionPhase.IDLE,
    proxyLabel: String = ""
) {
    var expanded by remember { mutableStateOf(false) }
    val current = ALL_REGIONS.find { it.code == selectedRegion } ?: ALL_REGIONS[0]
    val isSwitching = engineActive && proxyLabel.startsWith("Switching")

    val infiniteTransition = rememberInfiniteTransition(label = "switchPulse")
    val switchAlpha by infiniteTransition.animateFloat(
        initialValue = 1f, targetValue = 0.3f,
        animationSpec = infiniteRepeatable(
            animation = tween(600, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ), label = "switchAlpha"
    )

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(modifier = Modifier.padding(18.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier.size(36.dp)
                            .clip(MaterialTheme.shapes.small)
                            .background(Color(0xFF0A1A1E)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(Icons.Filled.Language, null,
                            tint = Color(0xFF80DEEA), modifier = Modifier.size(20.dp))
                    }
                    Spacer(Modifier.width(12.dp))
                    Text("Exit Country",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurface)
                }
                if (engineActive) {
                    if (isSwitching) {
                        Text("● Switching…",
                            style = MaterialTheme.typography.labelSmall,
                            color = Color(0xFFFFB74D).copy(alpha = switchAlpha),
                            fontWeight = FontWeight.Medium)
                    } else if (connectionPhase == ConnectionPhase.ACTIVE) {
                        Text("● Live",
                            style = MaterialTheme.typography.labelSmall,
                            color = Color(0xFF4CAF50),
                            fontWeight = FontWeight.Medium)
                    }
                }
            }
            Spacer(Modifier.height(12.dp))
            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f))
            Spacer(Modifier.height(12.dp))

            OutlinedButton(
                onClick = { expanded = true },
                modifier = Modifier.fillMaxWidth(),
                shape = MaterialTheme.shapes.medium,
                colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFF80DEEA)),
                border = BorderStroke(1.dp, Color(0xFF80DEEA).copy(alpha = 0.4f))
            ) {
                Text(
                    text = "${regionFlag(current.code)}  ${current.code}  —  ${current.city}",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                    modifier = Modifier.weight(1f)
                )
                Icon(Icons.Filled.ExpandMore, null, tint = Color(0xFF80DEEA),
                    modifier = Modifier.size(18.dp))
            }

            DropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false },
                modifier = Modifier.fillMaxWidth(0.92f).background(Color(0xFF130924))
            ) {
                ALL_REGIONS.forEach { region ->
                    val isSelected = region.code == selectedRegion
                    DropdownMenuItem(
                        text = {
                            Column {
                                Text(
                                    text = "${regionFlag(region.code)}  ${region.code}  —  ${region.city}",
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = if (isSelected) Color(0xFF80DEEA) else MaterialTheme.colorScheme.onSurface,
                                    fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal
                                )
                                Text(text = region.note,
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.65f))
                            }
                        },
                        onClick = { onSelect(region.code); expanded = false },
                        leadingIcon = if (isSelected) ({
                            Icon(Icons.Filled.Check, null,
                                tint = Color(0xFF80DEEA), modifier = Modifier.size(16.dp))
                        }) else null
                    )
                }
            }

            if (engineActive) {
                Spacer(Modifier.height(8.dp))
                Text(
                    text = if (isSwitching) "● Reconnecting new exit node…"
                           else "Changes apply instantly — no disconnect",
                    style = MaterialTheme.typography.labelSmall,
                    color = if (isSwitching) Color(0xFFFFB74D).copy(alpha = 0.8f)
                            else MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                )
            }
        }
    }
}

// ── Resilient Core card ───────────────────────────────────────────────────────

@Composable
private fun ResilientCoreCard(enabled: Boolean, onToggle: (Boolean) -> Unit) {
    val bgColor by animateColorAsState(
        targetValue = if (enabled) Color(0xFF130826) else MaterialTheme.colorScheme.surface,
        animationSpec = tween(400), label = "rcBg"
    )
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = bgColor),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(modifier = Modifier.padding(18.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                    Box(
                        modifier = Modifier.size(36.dp)
                            .clip(MaterialTheme.shapes.small)
                            .background(if (enabled) Color(0xFF2D0845) else MaterialTheme.colorScheme.surfaceVariant),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(Icons.Filled.Hub, null,
                            tint = if (enabled) Color(0xFFCE93D8) else MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(20.dp))
                    }
                    Spacer(Modifier.width(12.dp))
                    Text(stringResource(R.string.resilient_core_title),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurface)
                }
                Switch(
                    checked = enabled, onCheckedChange = onToggle,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = MaterialTheme.colorScheme.onPrimary,
                        checkedTrackColor = Color(0xFFCE93D8)
                    )
                )
            }
            Spacer(Modifier.height(10.dp))
            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f))
            Spacer(Modifier.height(10.dp))
            Text(
                text = stringResource(R.string.resilient_core_disclosure),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                lineHeight = 18.sp
            )
        }
    }
}

// ── Telemetry card ───────────────────────────────────────────────────────────

@Composable
private fun TelemetryCard(state: UiState) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(modifier = Modifier.padding(18.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier.size(36.dp)
                        .clip(MaterialTheme.shapes.small)
                        .background(Color(0xFF1E0D35)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(Icons.Filled.SignalCellularAlt, null,
                        tint = Color(0xFFB39DDB), modifier = Modifier.size(20.dp))
                }
                Spacer(Modifier.width(12.dp))
                Text(stringResource(R.string.telemetry_title),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurface)
            }
            Spacer(Modifier.height(14.dp))
            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f))
            Spacer(Modifier.height(12.dp))
            Column(verticalArrangement = Arrangement.spacedBy(9.dp)) {
                MetricRowBar(
                    label = stringResource(R.string.metric_snr),
                    value = "%.0f%%".format(state.snr),
                    fraction = state.snr / 100f
                )
                MetricRowBar(
                    label = stringResource(R.string.metric_pdr),
                    value = "%.1f%%".format(state.packetDeliveryRate * 100f),
                    fraction = state.packetDeliveryRate
                )
                MetricRow(
                    label = stringResource(R.string.metric_technology),
                    value = if (state.bandMhz > 0) "${state.technology} · ${state.bandMhz} MHz"
                            else state.technology
                )
                MetricRow(
                    label = stringResource(R.string.metric_stations),
                    value = state.activeStations.toString()
                )
            }
        }
    }
}

@Composable
private fun MetricRowBar(label: String, value: String, fraction: Float) {
    Column {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(label,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value,
                style = MaterialTheme.typography.bodySmall,
                fontWeight = FontWeight.SemiBold,
                color = signalColor(fraction))
        }
        Spacer(Modifier.height(4.dp))
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(4.dp)
                .clip(MaterialTheme.shapes.extraSmall)
                .background(MaterialTheme.colorScheme.surfaceVariant)
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth(fraction.coerceIn(0f, 1f))
                    .fillMaxHeight()
                    .background(signalColor(fraction))
            )
        }
    }
}

// ── Gateway card ─────────────────────────────────────────────────────────────

@Composable
private fun GatewayCard(state: UiState, onToggle: (Boolean) -> Unit) {
    val bgColor by animateColorAsState(
        targetValue = if (state.gatewayActive) Color(0xFF130826) else MaterialTheme.colorScheme.surface,
        animationSpec = tween(400), label = "gwBg"
    )
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = bgColor),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(modifier = Modifier.padding(18.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                    Box(
                        modifier = Modifier.size(36.dp)
                            .clip(MaterialTheme.shapes.small)
                            .background(
                                if (state.gatewayActive) Color(0xFF2D0845)
                                else MaterialTheme.colorScheme.surfaceVariant
                            ),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(Icons.Filled.WifiTethering, null,
                            tint = if (state.gatewayActive) Color(0xFFCE93D8)
                                   else MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(20.dp))
                    }
                    Spacer(Modifier.width(12.dp))
                    Column {
                        Text(stringResource(R.string.gateway_title),
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.onSurface)
                        Text(stringResource(R.string.gateway_subtitle),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                Switch(
                    checked = state.gatewayActive, onCheckedChange = onToggle,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = MaterialTheme.colorScheme.onPrimary,
                        checkedTrackColor = Color(0xFFCE93D8)
                    )
                )
            }
            if (!state.gatewayConsentGranted) {
                Spacer(Modifier.height(10.dp))
                HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f))
                Spacer(Modifier.height(10.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Filled.Info, null,
                        tint = MaterialTheme.colorScheme.tertiary, modifier = Modifier.size(13.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(stringResource(R.string.gateway_consent_required),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.tertiary)
                }
            }
        }
    }
}

// ── Shared helpers ────────────────────────────────────────────────────────────

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
        Text(label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.SemiBold,
            color = valueColor)
    }
}

private fun signalColor(ratio: Float): Color = when {
    ratio >= 0.7f -> Color(0xFF81C784)
    ratio >= 0.4f -> Color(0xFFFFB74D)
    else          -> Color(0xFFEF9A9A)
}

private fun formatBytes(bytes: Long): String = when {
    bytes >= 1_000_000_000L -> "%.1f GB".format(bytes / 1_000_000_000f)
    bytes >= 1_000_000L     -> "%.1f MB".format(bytes / 1_000_000f)
    bytes >= 1_000L         -> "%.1f KB".format(bytes / 1_000f)
    else                    -> "$bytes B"
}

private fun regionFlag(code: String): String {
    if (code.length != 2) return "🌍"
    val base = 0x1F1E6 - 'A'.code
    return String(Character.toChars(base + code[0].uppercaseChar().code)) +
           String(Character.toChars(base + code[1].uppercaseChar().code))
}

@Composable
fun rnetDarkColorScheme(): ColorScheme = darkColorScheme(
    primary              = Color(0xFFB983E8),   // vivid lavender
    onPrimary            = Color(0xFF16002A),
    primaryContainer     = Color(0xFF311050),   // rich purple container
    onPrimaryContainer   = Color(0xFFEDD5F7),
    secondary            = Color(0xFF9B82D4),   // soft violet
    onSecondary          = Color(0xFF16003C),
    secondaryContainer   = Color(0xFF1E0D35),
    onSecondaryContainer = Color(0xFFD8C8F0),
    tertiary             = Color(0xFFF48FB1),
    onTertiary           = Color(0xFF2A0018),
    tertiaryContainer    = Color(0xFF1E0010),
    onTertiaryContainer  = Color(0xFFFFC8DB),
    background           = Color(0xFF060309),   // near-black, slight purple
    onBackground         = Color(0xFFEDE6F5),
    surface              = Color(0xFF0E0917),   // card dark-purple
    onSurface            = Color(0xFFEDE6F5),
    surfaceVariant       = Color(0xFF1A1226),
    onSurfaceVariant     = Color(0xFF9B8DB4),
    error                = Color(0xFFEF9A9A),
    onError              = Color(0xFF4E0000),
    errorContainer       = Color(0xFF2A0A0A),
    onErrorContainer     = Color(0xFFFFCDD2),
    outline              = Color(0xFF2A1D3D),
    outlineVariant       = Color(0xFF1E1430)
)
