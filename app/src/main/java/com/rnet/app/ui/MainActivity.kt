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
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.*
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.*
import androidx.compose.ui.res.stringResource
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.rnet.app.R
import com.rnet.app.service.ConnectionPhase

class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    private val permissionsLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { /* permissions result — app continues regardless */ }

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            viewModel.toggleEngine(true)
        } else {
            viewModel.setEngineActive(false)
        }
    }

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
                    uiState         = uiState,
                    onEngineToggle  = { wantOn ->
                        if (wantOn) {
                            viewModel.setEngineActive(true)
                            requestVpnPermission()
                        } else {
                            viewModel.toggleEngine(false)
                        }
                    },
                    onResilientCoreToggle = { viewModel.setUseResilientCore(it) },
                    onRegionChange  = { viewModel.setExitRegion(it) },
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
                    onFaqClick = { startActivity(Intent(this, FaqActivity::class.java)) }
                )
            }
        }
    }

    private fun requestVpnPermission() {
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            vpnPermissionLauncher.launch(vpnIntent)
        } else {
            viewModel.toggleEngine(true)
        }
    }
}

// ── Color palette ─────────────────────────────────────────────────────────────
private val Purple900 = Color(0xFF0D0618)
private val Purple800 = Color(0xFF160826)
private val Purple700 = Color(0xFF1E0D35)
private val Purple500 = Color(0xFF4A1980)
private val PurpleGlow = Color(0xFFB983E8)
private val PurpleLight = Color(0xFFDDB8F5)
private val CyanAccent  = Color(0xFF80DEEA)
private val GreenActive = Color(0xFF69F0AE)
private val AmberWarn   = Color(0xFFFFD54F)
private val RedError    = Color(0xFFFF6B6B)
private val SurfaceCard = Color(0xFF120B22)
private val SurfaceCardAlt = Color(0xFF0F091C)
private val OutlineWeak = Color(0xFF2A1D3D)
private val TextPrimary = Color(0xFFEDE6F5)
private val TextSecondary = Color(0xFF9B8DB4)

@Composable
fun rnetDarkColorScheme(): ColorScheme = darkColorScheme(
    primary              = PurpleGlow,
    onPrimary            = Color(0xFF16002A),
    primaryContainer     = Purple700,
    onPrimaryContainer   = PurpleLight,
    secondary            = Color(0xFF9B82D4),
    onSecondary          = Color(0xFF16003C),
    secondaryContainer   = Color(0xFF1E0D35),
    onSecondaryContainer = Color(0xFFD8C8F0),
    tertiary             = CyanAccent,
    onTertiary           = Color(0xFF002A2E),
    tertiaryContainer    = Color(0xFF003740),
    onTertiaryContainer  = Color(0xFFA8EDFD),
    background           = Purple900,
    onBackground         = TextPrimary,
    surface              = SurfaceCard,
    onSurface            = TextPrimary,
    surfaceVariant       = Color(0xFF1A1226),
    onSurfaceVariant     = TextSecondary,
    error                = RedError,
    onError              = Color(0xFF4E0000),
    errorContainer       = Color(0xFF2A0A0A),
    onErrorContainer     = Color(0xFFFFCDD2),
    outline              = OutlineWeak,
    outlineVariant       = Color(0xFF1E1430)
)

// ── Root scaffold ─────────────────────────────────────────────────────────────
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
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    0f to Purple900,
                    0.4f to Color(0xFF0E0820),
                    1f to Purple900
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
        ) {
            // Top bar
            RnetTopBar(onFaqClick)

            Spacer(Modifier.height(4.dp))

            // Hero engine section
            EngineHeroSection(uiState, onEngineToggle)

            Column(
                modifier = Modifier.padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                AnimatedVisibility(
                    visible = uiState.engineActive,
                    enter = fadeIn(tween(400)) + expandVertically(tween(400)),
                    exit  = fadeOut(tween(300)) + shrinkVertically(tween(300))
                ) {
                    ConnectionStatusCard(uiState)
                }

                RegionPickerCard(
                    selectedRegion  = uiState.exitRegion,
                    onSelect        = onRegionChange,
                    engineActive    = uiState.engineActive,
                    connectionPhase = uiState.connectionPhase,
                    proxyLabel      = uiState.proxyLabel
                )

                AnimatedVisibility(
                    visible = true,
                    enter = fadeIn(tween(500, delayMillis = 100)),
                    exit  = fadeOut(tween(300))
                ) {
                    ResilientCoreCard(uiState.useResilientCore, onResilientCoreToggle)
                }

                TelemetryCard(uiState)

                GatewayCard(uiState, onGatewayToggle)

                Spacer(Modifier.height(24.dp))
            }
        }
    }
}

@Composable
private fun RnetTopBar(onFaqClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp, vertical = 16.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            // Logo circle
            Box(
                modifier = Modifier
                    .size(34.dp)
                    .clip(CircleShape)
                    .background(
                        Brush.radialGradient(
                            listOf(Purple500, Purple700)
                        )
                    )
                    .border(1.dp, PurpleGlow.copy(alpha = 0.5f), CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Icon(Icons.Filled.Shield, null, tint = PurpleLight,
                    modifier = Modifier.size(18.dp))
            }
            Spacer(Modifier.width(10.dp))
            Column {
                Text(
                    text = stringResource(R.string.app_name),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 2.sp,
                    color = TextPrimary
                )
                Text(
                    text = "Secure Transport",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextSecondary,
                    letterSpacing = 0.5.sp
                )
            }
        }
        IconButton(onClick = onFaqClick) {
            Icon(Icons.Filled.Info, null, tint = TextSecondary)
        }
    }
}

// ── Engine hero ───────────────────────────────────────────────────────────────
@Composable
private fun EngineHeroSection(state: UiState, onToggle: (Boolean) -> Unit) {
    val active = state.engineActive
    val isConnecting = active && state.connectionPhase != ConnectionPhase.ACTIVE

    // Glow animation
    val infiniteTransition = rememberInfiniteTransition(label = "heroGlow")
    val glowAlpha by infiniteTransition.animateFloat(
        initialValue = 0.3f, targetValue = 0.9f,
        animationSpec = infiniteRepeatable(
            animation = tween(1500, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ), label = "glow"
    )
    val ringScale by infiniteTransition.animateFloat(
        initialValue = 1f, targetValue = 1.12f,
        animationSpec = infiniteRepeatable(
            animation = tween(1200, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ), label = "ring"
    )

    val ringColor by animateColorAsState(
        targetValue = when {
            !active -> TextSecondary.copy(alpha = 0.3f)
            isConnecting -> AmberWarn.copy(alpha = glowAlpha)
            else -> GreenActive.copy(alpha = 0.7f)
        },
        animationSpec = tween(600), label = "ringColor"
    )
    val coreColor by animateColorAsState(
        targetValue = if (active) PurpleGlow else TextSecondary.copy(alpha = 0.5f),
        animationSpec = tween(400), label = "coreColor"
    )

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp)
            .padding(bottom = 8.dp),
        contentAlignment = Alignment.Center
    ) {
        // Glow halo behind button
        if (active) {
            Box(
                modifier = Modifier
                    .size((160 * (if (isConnecting) ringScale else 1f)).dp)
                    .clip(CircleShape)
                    .background(
                        Brush.radialGradient(
                            listOf(
                                (if (isConnecting) AmberWarn else GreenActive).copy(alpha = 0.12f * glowAlpha),
                                Color.Transparent
                            )
                        )
                    )
            )
        }

        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.padding(vertical = 16.dp)
        ) {
            // Ring + button
            Box(contentAlignment = Alignment.Center) {
                // Outer decorative ring
                Canvas(modifier = Modifier.size(130.dp)) {
                    val strokeWidth = 2.dp.toPx()
                    val radius = size.minDimension / 2f - strokeWidth
                    drawCircle(
                        color = ringColor,
                        radius = radius,
                        style = androidx.compose.ui.graphics.drawscope.Stroke(strokeWidth)
                    )
                }
                // Inner ring (dashed effect using thin solid arc)
                Canvas(modifier = Modifier.size(110.dp)) {
                    val strokeWidth = 1.dp.toPx()
                    val radius = size.minDimension / 2f - strokeWidth
                    drawCircle(
                        color = ringColor.copy(alpha = ringColor.alpha * 0.4f),
                        radius = radius,
                        style = androidx.compose.ui.graphics.drawscope.Stroke(strokeWidth)
                    )
                }
                // Main power button
                Box(
                    modifier = Modifier
                        .size(88.dp)
                        .clip(CircleShape)
                        .background(
                            Brush.radialGradient(
                                if (active) listOf(Purple500, Purple800)
                                else listOf(Color(0xFF1A1230), Color(0xFF0E0920))
                            )
                        )
                        .border(
                            width = 2.dp,
                            brush = Brush.linearGradient(
                                listOf(coreColor, coreColor.copy(alpha = 0.3f))
                            ),
                            shape = CircleShape
                        )
                        .clickable { onToggle(!active) },
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Filled.PowerSettingsNew,
                        contentDescription = if (active) "Stop" else "Start",
                        tint = coreColor,
                        modifier = Modifier.size(36.dp)
                    )
                }
            }

            Spacer(Modifier.height(16.dp))

            // Status label
            val statusText = when {
                !active -> stringResource(R.string.engine_status_inactive)
                isConnecting -> when (state.connectionPhase) {
                    ConnectionPhase.FINDING_PROXY -> stringResource(R.string.vpn_status_starting_tunnel)
                    else -> stringResource(R.string.vpn_status_connecting)
                }
                else -> stringResource(R.string.engine_status_active)
            }

            Text(
                text = statusText,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = when {
                    !active -> TextSecondary
                    isConnecting -> AmberWarn
                    else -> GreenActive
                },
                letterSpacing = 0.5.sp
            )

            Spacer(Modifier.height(4.dp))

            Text(
                text = stringResource(R.string.engine_title),
                style = MaterialTheme.typography.labelMedium,
                color = TextSecondary,
                letterSpacing = 1.sp
            )

            if (active && !isConnecting && state.exitRegion.isNotEmpty()) {
                Spacer(Modifier.height(10.dp))
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.Center,
                    modifier = Modifier
                        .clip(MaterialTheme.shapes.small)
                        .background(
                            Brush.horizontalGradient(
                                listOf(Purple700.copy(alpha = 0.8f), Color(0xFF0A1A1E).copy(alpha = 0.8f))
                            )
                        )
                        .border(1.dp, CyanAccent.copy(alpha = 0.2f), MaterialTheme.shapes.small)
                        .padding(horizontal = 14.dp, vertical = 6.dp)
                ) {
                    Text(regionFlag(state.exitRegion), fontSize = 15.sp)
                    Spacer(Modifier.width(7.dp))
                    Text(
                        text = state.exitRegion,
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold,
                        color = CyanAccent,
                        letterSpacing = 1.sp
                    )
                    Spacer(Modifier.width(10.dp))
                    // Animated uptime counter
                    UptimeCounter()
                }
            }
        }
    }
}

// ── Connection status ────────────────────────────────────────────────────────
@Composable
private fun ConnectionStatusCard(state: UiState) {
    GlassCard {
        Column(modifier = Modifier.padding(18.dp)) {
            CardHeader(icon = Icons.Filled.Shield, title = "Connection",
                iconTint = PurpleGlow, iconBg = Purple700)
            Spacer(Modifier.height(14.dp))
            CardDivider()
            Spacer(Modifier.height(14.dp))

            // Traffic stats row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly
            ) {
                TrafficBubble(label = "↓ IN",    value = formatBytes(state.totalBytesIn),   color = CyanAccent)
                VerticalDivider(modifier = Modifier.height(40.dp), color = OutlineWeak)
                TrafficBubble(label = "↑ OUT",   value = formatBytes(state.totalBytesOut),  color = PurpleGlow)
                VerticalDivider(modifier = Modifier.height(40.dp), color = OutlineWeak)
                TrafficBubble(label = "Sessions", value = "${state.activeSessionCount}",    color = Color(0xFFB39DDB))
            }

            Spacer(Modifier.height(14.dp))
            CardDivider()
            Spacer(Modifier.height(12.dp))

            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                MetricRow("Tunnel",   state.proxyLabel,
                    valueColor = when {
                        state.proxyLabel.startsWith("Smart") -> GreenActive
                        state.proxyLabel == "Direct" -> AmberWarn
                        else -> TextSecondary
                    })
                if (state.exitRegion.isNotEmpty()) {
                    MetricRow("Exit",
                        "${regionFlag(state.exitRegion)}  ${state.exitRegion}",
                        valueColor = CyanAccent)
                }
                MetricRow("DNS", "DoH · Cloudflare", valueColor = GreenActive)
                if (state.routeCacheSize > 0 || state.pooledSockets > 0) {
                    MetricRow("Pool",
                        "${state.routeCacheSize} routes · ${state.pooledSockets} warm",
                        valueColor = TextSecondary)
                }
            }
        }
    }
}

@Composable
private fun TrafficBubble(label: String, value: String, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value,
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.ExtraBold,
            color = color,
            fontSize = 15.sp)
        Spacer(Modifier.height(3.dp))
        Text(label,
            style = MaterialTheme.typography.labelSmall,
            color = TextSecondary,
            letterSpacing = 0.5.sp)
    }
}

// ── Region picker ──────────────────────────────────────────────────────────
private data class RegionInfo(val code: String, val city: String, val note: String)
private val ALL_REGIONS = listOf(
    RegionInfo("IS", "Reykjavik",  "#1 internet freedom"),
    RegionInfo("EE", "Tallinn",    "Digital-first, no filtering"),
    RegionInfo("NO", "Oslo",       "No content blocking"),
    RegionInfo("SE", "Stockholm",  "No content blocking"),
    RegionInfo("FI", "Helsinki",   "No content blocking"),
    RegionInfo("CH", "Zurich",     "Strong privacy laws"),
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
    engineActive: Boolean,
    connectionPhase: ConnectionPhase,
    proxyLabel: String
) {
    var expanded by remember { mutableStateOf(false) }
    val current = ALL_REGIONS.find { it.code == selectedRegion } ?: ALL_REGIONS[0]
    val isSwitching = engineActive && proxyLabel.startsWith("Switching")

    val infiniteTransition = rememberInfiniteTransition(label = "switchPulse")
    val switchAlpha by infiniteTransition.animateFloat(
        initialValue = 1f, targetValue = 0.3f,
        animationSpec = infiniteRepeatable(tween(600), RepeatMode.Reverse),
        label = "switchAlpha"
    )

    GlassCard {
        Column(modifier = Modifier.padding(18.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                CardHeader(icon = Icons.Filled.Language, title = "Exit Country",
                    iconTint = CyanAccent, iconBg = Color(0xFF0A1A1E))
                if (engineActive) {
                    if (isSwitching) {
                        Text("● Switching…",
                            style = MaterialTheme.typography.labelSmall,
                            color = AmberWarn.copy(alpha = switchAlpha),
                            fontWeight = FontWeight.SemiBold)
                    } else if (connectionPhase == ConnectionPhase.ACTIVE) {
                        LivePill()
                    }
                }
            }

            Spacer(Modifier.height(12.dp))
            CardDivider()
            Spacer(Modifier.height(12.dp))

            OutlinedButton(
                onClick = { expanded = true },
                modifier = Modifier.fillMaxWidth(),
                shape = MaterialTheme.shapes.medium,
                colors = ButtonDefaults.outlinedButtonColors(contentColor = CyanAccent),
                border = BorderStroke(1.dp, CyanAccent.copy(alpha = 0.35f))
            ) {
                Text(
                    text = "${regionFlag(current.code)}  ${current.code}  —  ${current.city}",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.weight(1f)
                )
                Icon(Icons.Filled.ExpandMore, null, tint = CyanAccent.copy(alpha = 0.7f),
                    modifier = Modifier.size(18.dp))
            }

            DropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false },
                modifier = Modifier
                    .fillMaxWidth(0.92f)
                    .background(Color(0xFF130924))
            ) {
                ALL_REGIONS.forEach { region ->
                    val isSelected = region.code == selectedRegion
                    DropdownMenuItem(
                        text = {
                            Column {
                                Text(
                                    "${regionFlag(region.code)}  ${region.code}  —  ${region.city}",
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = if (isSelected) CyanAccent else TextPrimary,
                                    fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal
                                )
                                Text(region.note,
                                    style = MaterialTheme.typography.labelSmall,
                                    color = TextSecondary.copy(alpha = 0.6f))
                            }
                        },
                        onClick = { onSelect(region.code); expanded = false },
                        leadingIcon = if (isSelected) ({
                            Icon(Icons.Filled.Check, null,
                                tint = CyanAccent, modifier = Modifier.size(16.dp))
                        }) else null
                    )
                }
            }

            Spacer(Modifier.height(6.dp))
            Text(
                text = if (isSwitching) "● Reconnecting new exit node…"
                       else if (engineActive) "Changes apply instantly · no disconnect"
                       else "Will apply on next connect",
                style = MaterialTheme.typography.labelSmall,
                color = if (isSwitching) AmberWarn.copy(alpha = 0.8f)
                        else TextSecondary.copy(alpha = 0.5f)
            )
        }
    }
}

// ── Resilient Core ────────────────────────────────────────────────────────────
@Composable
private fun ResilientCoreCard(enabled: Boolean, onToggle: (Boolean) -> Unit) {
    val bgAlpha by animateColorAsState(
        targetValue = if (enabled) Purple700.copy(alpha = 0.5f) else Color.Transparent,
        animationSpec = tween(400), label = "rcBg"
    )
    GlassCard(extraBorderAlpha = if (enabled) 0.6f else 0.3f) {
        Column(modifier = Modifier.padding(18.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                CardHeader(icon = Icons.Filled.Hub, title = stringResource(R.string.resilient_core_title),
                    iconTint = if (enabled) PurpleGlow else TextSecondary,
                    iconBg = if (enabled) Purple700 else Color(0xFF1A1226))
                Switch(
                    checked = enabled, onCheckedChange = onToggle,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor   = TextPrimary,
                        checkedTrackColor   = PurpleGlow,
                        uncheckedThumbColor = TextSecondary,
                        uncheckedTrackColor = Color(0xFF1A1226)
                    )
                )
            }
            Spacer(Modifier.height(10.dp))
            CardDivider()
            Spacer(Modifier.height(10.dp))
            Text(
                stringResource(R.string.resilient_core_disclosure),
                style = MaterialTheme.typography.bodySmall,
                color = TextSecondary,
                lineHeight = 19.sp
            )
        }
    }
}

// ── Telemetry ─────────────────────────────────────────────────────────────────
@Composable
private fun TelemetryCard(state: UiState) {
    GlassCard {
        Column(modifier = Modifier.padding(18.dp)) {
            CardHeader(icon = Icons.Filled.SignalCellularAlt, title = stringResource(R.string.telemetry_title),
                iconTint = Color(0xFFB39DDB), iconBg = Color(0xFF1E0D35))
            Spacer(Modifier.height(14.dp))
            CardDivider()
            Spacer(Modifier.height(12.dp))
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                SignalBar(label = stringResource(R.string.metric_snr),
                    value = "%.0f%%".format(state.snr),
                    fraction = state.snr / 100f)
                SignalBar(label = stringResource(R.string.metric_pdr),
                    value = "%.1f%%".format(state.packetDeliveryRate * 100f),
                    fraction = state.packetDeliveryRate)
                MetricRow(stringResource(R.string.metric_technology),
                    if (state.bandMhz > 0) "${state.technology} · ${state.bandMhz} MHz"
                    else state.technology)
                MetricRow(stringResource(R.string.metric_stations), "${state.activeStations}")
            }
        }
    }
}

@Composable
private fun SignalBar(label: String, value: String, fraction: Float) {
    Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
        Row(modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween) {
            Text(label, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
            Text(value, style = MaterialTheme.typography.bodySmall,
                fontWeight = FontWeight.Bold, color = signalColor(fraction))
        }
        // Track
        Box(
            modifier = Modifier.fillMaxWidth().height(5.dp)
                .clip(CircleShape)
                .background(Color(0xFF1A1226))
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth(fraction.coerceIn(0f, 1f))
                    .fillMaxHeight()
                    .clip(CircleShape)
                    .background(
                        Brush.horizontalGradient(
                            listOf(signalColor(fraction).copy(alpha = 0.6f), signalColor(fraction))
                        )
                    )
            )
        }
    }
}

// ── Gateway ───────────────────────────────────────────────────────────────────
@Composable
private fun GatewayCard(state: UiState, onToggle: (Boolean) -> Unit) {
    GlassCard(extraBorderAlpha = if (state.gatewayActive) 0.6f else 0.3f) {
        Column(modifier = Modifier.padding(18.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                CardHeader(
                    icon = Icons.Filled.WifiTethering,
                    title = stringResource(R.string.gateway_title),
                    subtitle = stringResource(R.string.gateway_subtitle),
                    iconTint = if (state.gatewayActive) PurpleGlow else TextSecondary,
                    iconBg = if (state.gatewayActive) Purple700 else Color(0xFF1A1226)
                )
                Switch(
                    checked = state.gatewayActive, onCheckedChange = onToggle,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor   = TextPrimary,
                        checkedTrackColor   = PurpleGlow,
                        uncheckedThumbColor = TextSecondary,
                        uncheckedTrackColor = Color(0xFF1A1226)
                    )
                )
            }
            if (!state.gatewayConsentGranted) {
                Spacer(Modifier.height(10.dp))
                CardDivider()
                Spacer(Modifier.height(10.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Filled.Info, null,
                        tint = CyanAccent, modifier = Modifier.size(13.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(stringResource(R.string.gateway_consent_required),
                        style = MaterialTheme.typography.bodySmall,
                        color = CyanAccent)
                }
            }
        }
    }
}

// ── Shared layout components ──────────────────────────────────────────────────

@Composable
private fun GlassCard(
    extraBorderAlpha: Float = 0.3f,
    content: @Composable () -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(MaterialTheme.shapes.large)
            .background(
                Brush.linearGradient(
                    listOf(SurfaceCard, SurfaceCardAlt),
                    start = Offset(0f, 0f),
                    end = Offset(0f, 300f)
                )
            )
            .border(
                1.dp,
                Brush.linearGradient(
                    listOf(
                        PurpleGlow.copy(alpha = extraBorderAlpha),
                        OutlineWeak.copy(alpha = 0.3f),
                        Color.Transparent
                    )
                ),
                MaterialTheme.shapes.large
            )
    ) {
        content()
    }
}

@Composable
private fun CardHeader(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    subtitle: String? = null,
    iconTint: Color,
    iconBg: Color
) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            modifier = Modifier
                .size(38.dp)
                .clip(MaterialTheme.shapes.small)
                .background(iconBg)
                .border(1.dp, iconTint.copy(alpha = 0.3f), MaterialTheme.shapes.small),
            contentAlignment = Alignment.Center
        ) {
            Icon(icon, null, tint = iconTint, modifier = Modifier.size(20.dp))
        }
        Spacer(Modifier.width(12.dp))
        Column {
            Text(title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = TextPrimary)
            if (subtitle != null) {
                Text(subtitle,
                    style = MaterialTheme.typography.labelSmall,
                    color = TextSecondary)
            }
        }
    }
}

@Composable
private fun CardDivider() {
    HorizontalDivider(color = OutlineWeak.copy(alpha = 0.5f), thickness = 0.5.dp)
}

@Composable
private fun LivePill() {
    val infinite = rememberInfiniteTransition(label = "livePulse")
    val alpha by infinite.animateFloat(
        initialValue = 1f, targetValue = 0.4f,
        animationSpec = infiniteRepeatable(tween(700), RepeatMode.Reverse),
        label = "liveAlpha"
    )
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .clip(CircleShape)
            .background(GreenActive.copy(alpha = 0.12f))
            .padding(horizontal = 8.dp, vertical = 3.dp)
    ) {
        Box(
            modifier = Modifier.size(5.dp).clip(CircleShape)
                .background(GreenActive.copy(alpha = alpha))
        )
        Spacer(Modifier.width(5.dp))
        Text("LIVE",
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Bold,
            color = GreenActive,
            letterSpacing = 1.sp)
    }
}

@Composable
private fun MetricRow(
    label: String,
    value: String,
    valueColor: Color = TextPrimary
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
        Text(value,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.SemiBold,
            color = valueColor)
    }
}

// ── Uptime counter ────────────────────────────────────────────────────────────

@Composable
private fun UptimeCounter() {
    var seconds by remember { mutableStateOf(0) }
    LaunchedEffect(Unit) {
        while (true) {
            kotlinx.coroutines.delay(1000L)
            seconds++
        }
    }
    val h = seconds / 3600
    val m = (seconds % 3600) / 60
    val s = seconds % 60
    val text = if (h > 0) "%d:%02d:%02d".format(h, m, s)
               else       "%02d:%02d".format(m, s)
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            modifier = Modifier.size(5.dp).clip(CircleShape)
                .background(GreenActive)
        )
        Spacer(Modifier.width(5.dp))
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.SemiBold,
            color = GreenActive.copy(alpha = 0.85f),
            fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace
        )
    }
}

// ── Pure helpers ──────────────────────────────────────────────────────────────

private fun signalColor(ratio: Float): Color = when {
    ratio >= 0.7f -> GreenActive
    ratio >= 0.4f -> AmberWarn
    else          -> RedError
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
