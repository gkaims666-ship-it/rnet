package com.rnet.app.ui

import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.rnet.app.prefs.ServerPrefs

/**
 * ServerSetupActivity — first-run onboarding screen.
 *
 * Shown when no relay endpoint has been saved yet. The user enters:
 *   • Host — domain name or IP of their self-hosted RNET relay
 *   • Port — UDP port the relay listens on (default 7777)
 *
 * The app will not start the transport engine until valid configuration is saved.
 * See deploy/ in the repository root for a one-command relay server deployment.
 */
class ServerSetupActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                ServerSetupScreen(
                    onSave = { host, port ->
                        ServerPrefs.save(this, host, port)
                        startActivity(Intent(this, MainActivity::class.java))
                        finish()
                    }
                )
            }
        }
    }

    companion object {
        fun shouldShow(ctx: Context): Boolean = !ServerPrefs.isConfigured(ctx)
    }
}

@Composable
private fun ServerSetupScreen(onSave: (host: String, port: Int) -> Unit) {
    var host by remember { mutableStateOf("") }
    var portText by remember { mutableStateOf("7777") }
    var hostError by remember { mutableStateOf(false) }
    var portError by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "RNET Setup",
            style = MaterialTheme.typography.headlineMedium
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = "Enter your RNET relay server address.\n" +
                   "Deploy your own relay in one command — see deploy/ in the repository.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Spacer(modifier = Modifier.height(32.dp))

        OutlinedTextField(
            value = host,
            onValueChange = { host = it; hostError = false },
            label = { Text("Relay host (domain or IP)") },
            placeholder = { Text("relay.example.com") },
            isError = hostError,
            supportingText = if (hostError) ({ Text("Enter a valid hostname or IP") }) else null,
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri)
        )

        Spacer(modifier = Modifier.height(16.dp))

        OutlinedTextField(
            value = portText,
            onValueChange = { portText = it; portError = false },
            label = { Text("UDP port") },
            placeholder = { Text("7777") },
            isError = portError,
            supportingText = if (portError) ({ Text("Port must be 1–65535") }) else null,
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
        )

        Spacer(modifier = Modifier.height(32.dp))

        Button(
            onClick = {
                val trimHost = host.trim()
                val port = portText.trim().toIntOrNull()
                hostError = trimHost.isBlank()
                portError = port == null || port !in 1..65535
                if (!hostError && !portError) {
                    onSave(trimHost, port!!)
                }
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Save and continue")
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "No relay yet? Run docker compose up in the deploy/ directory\n" +
                   "on any Linux VPS to start your relay server.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
