package io.sshproxy.app

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

sealed class Screen {
    data object Main : Screen()
    data object AddProfile : Screen()
    data class EditProfile(val id: String) : Screen()
    data object Settings : Screen()
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    profiles: List<SshProfile>,
    selectedProfileId: String?,
    isProxyRunning: Boolean,
    vpnMode: Boolean,
    onSelectProfile: (String) -> Unit,
    onStartProxy: () -> Unit,
    onStopProxy: () -> Unit,
    onAddProfile: () -> Unit,
    onEditProfile: (String) -> Unit,
    onDeleteProfile: (String) -> Unit,
    onSettings: () -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("SSH Proxy") },
                actions = {
                    IconButton(onClick = onSettings, enabled = !isProxyRunning) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings")
                    }
                },
            )
        },
        floatingActionButton = {
            if (!isProxyRunning) {
                FloatingActionButton(onClick = onAddProfile) {
                    Icon(Icons.Default.Add, contentDescription = "Add profile")
                }
            }
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            if (profiles.isEmpty()) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(32.dp),
                    verticalArrangement = Arrangement.Center,
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Text(
                        "No SSH profiles",
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        "Tap + to add one",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            } else {
                LazyColumn(
                    modifier = Modifier
                        .weight(1f)
                        .padding(horizontal = 16.dp),
                ) {
                    items(profiles, key = { it.id }) { profile ->
                        val isSelected = profile.id == selectedProfileId
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 4.dp)
                                .clickable(enabled = !isProxyRunning) {
                                    onEditProfile(profile.id)
                                },
                            colors = CardDefaults.cardColors(
                                containerColor = if (isSelected)
                                    MaterialTheme.colorScheme.primaryContainer
                                else
                                    MaterialTheme.colorScheme.surface,
                            ),
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(8.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                RadioButton(
                                    selected = isSelected,
                                    onClick = { onSelectProfile(profile.id) },
                                    enabled = !isProxyRunning,
                                )
                                Column(
                                    modifier = Modifier.weight(1f),
                                ) {
                                    Text(
                                        profile.name,
                                        style = MaterialTheme.typography.titleSmall,
                                    )
                                    Text(
                                        "${profile.host}:${profile.port}",
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                }
                                if (!isProxyRunning) {
                                    IconButton(onClick = { onDeleteProfile(profile.id) }) {
                                        Icon(
                                            Icons.Default.Delete,
                                            contentDescription = "Delete",
                                            tint = MaterialTheme.colorScheme.error,
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Button(
                    onClick = onStartProxy,
                    enabled = !isProxyRunning && selectedProfileId != null,
                    modifier = Modifier.weight(1f),
                ) {
                    Text(if (vpnMode) "Start VPN" else "Start SOCKS5")
                }
                OutlinedButton(
                    onClick = onStopProxy,
                    enabled = isProxyRunning,
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Stop")
                }
            }
        }
    }
}
