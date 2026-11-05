package com.rnet.app.ui

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.rnet.app.R

/**
 * ConsentActivity — mandatory full-screen disclosure shown on first gateway activation.
 *
 * The user must scroll to the bottom and tap "I Understand — Enable Gateway" to
 * proceed. Tapping "Cancel" returns RESULT_CANCELED without enabling the gateway.
 *
 * This activity is REQUIRED before HotspotGateway.start() is called.
 * MainActivity enforces the gate by checking the saved consent preference.
 */
class ConsentActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                ConsentScreen(
                    onAccept = {
                        getSharedPreferences("rnet_prefs", MODE_PRIVATE)
                            .edit()
                            .putBoolean("gateway_consent_v1", true)
                            .apply()
                        setResult(RESULT_OK)
                        finish()
                    },
                    onDecline = {
                        setResult(RESULT_CANCELED)
                        finish()
                    }
                )
            }
        }
    }
}

@Composable
private fun ConsentScreen(onAccept: () -> Unit, onDecline: () -> Unit) {
    val scrollState = rememberScrollState()

    Scaffold { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .verticalScroll(scrollState)
                .padding(horizontal = 24.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(
                text = stringResource(R.string.consent_title),
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold
            )
            HorizontalDivider()

            Text(
                text = stringResource(R.string.consent_body_1),
                style = MaterialTheme.typography.bodyLarge
            )
            Text(
                text = stringResource(R.string.consent_body_2),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = stringResource(R.string.consent_body_3),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer
                )
            ) {
                Text(
                    text = stringResource(R.string.consent_highlight),
                    modifier = Modifier.padding(16.dp),
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            Button(
                onClick = onAccept,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(stringResource(R.string.consent_accept))
            }
            OutlinedButton(
                onClick = onDecline,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(stringResource(R.string.consent_decline))
            }
        }
    }
}
