package com.rnet.app.ui

import android.net.wifi.p2p.WifiP2pDevice
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.rnet.app.R

/**
 * MeshConsentDialog — prominent opt-in confirmation shown before RNET routes
 * any traffic through or accepts any traffic from a discovered mesh peer.
 *
 * This dialog is shown in two scenarios:
 *   1. Local user wants to route their own traffic THROUGH a peer gateway.
 *   2. Local user wants this device to ACT AS a gateway for mesh peers.
 *
 * Both are distinct actions with separate consent strings. Neither action
 * begins until the user taps the affirmative button.
 *
 * Usage in Compose:
 *   if (showMeshConsent) {
 *       MeshConsentDialog(
 *           peer = discoveredDevice,
 *           mode = MeshConsentMode.USE_AS_GATEWAY,
 *           onAccept  = { viewModel.confirmMeshGateway(it) },
 *           onDecline = { showMeshConsent = false }
 *       )
 *   }
 */

enum class MeshConsentMode {
    /** This device will route its traffic through the peer. */
    ROUTE_THROUGH_PEER,
    /** This device will act as a gateway for the peer cluster. */
    ACT_AS_GATEWAY
}

@Composable
fun MeshConsentDialog(
    peer: WifiP2pDevice?,
    mode: MeshConsentMode,
    onAccept:  (WifiP2pDevice?) -> Unit,
    onDecline: () -> Unit
) {
    val peerName = peer?.deviceName ?: stringResource(R.string.mesh_unknown_peer)

    AlertDialog(
        onDismissRequest = onDecline,
        title = {
            Text(
                text = when (mode) {
                    MeshConsentMode.ROUTE_THROUGH_PEER -> stringResource(R.string.mesh_consent_route_title)
                    MeshConsentMode.ACT_AS_GATEWAY     -> stringResource(R.string.mesh_consent_gateway_title)
                },
                fontWeight = FontWeight.Bold
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    text = when (mode) {
                        MeshConsentMode.ROUTE_THROUGH_PEER ->
                            stringResource(R.string.mesh_consent_route_body, peerName)
                        MeshConsentMode.ACT_AS_GATEWAY ->
                            stringResource(R.string.mesh_consent_gateway_body)
                    },
                    style = MaterialTheme.typography.bodyMedium
                )
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.secondaryContainer
                    )
                ) {
                    Text(
                        text = stringResource(R.string.mesh_consent_note),
                        modifier = Modifier.padding(12.dp),
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        },
        confirmButton = {
            Button(onClick = { onAccept(peer) }) {
                Text(stringResource(R.string.mesh_consent_accept))
            }
        },
        dismissButton = {
            OutlinedButton(onClick = onDecline) {
                Text(stringResource(R.string.mesh_consent_decline))
            }
        }
    )
}
