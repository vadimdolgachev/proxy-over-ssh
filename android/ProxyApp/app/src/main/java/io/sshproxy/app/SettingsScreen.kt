package io.sshproxy.app

import androidx.activity.compose.BackHandler
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp

data class AppInfo(
    val name: String,
    val packageName: String,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    settings: AppSettings,
    onSaveSettings: (AppSettings) -> Unit,
    onBack: () -> Unit,
) {
    var vpnMode by rememberSaveable { mutableStateOf(settings.vpnMode) }
    var dnsAddress by rememberSaveable { mutableStateOf(settings.dnsAddress) }
    var socksPort by rememberSaveable { mutableStateOf(settings.socksPort.toString()) }
    var vpnAppMode by rememberSaveable { mutableStateOf(settings.vpnAppMode) }
    var excludedPackages by rememberSaveable { mutableStateOf(settings.excludedPackages) }
    var includedPackages by rememberSaveable { mutableStateOf(settings.includedPackages) }
    var searchQuery by rememberSaveable { mutableStateOf("") }

    val context = LocalContext.current
    val ownPackage = context.packageName
    val installedApps = rememberSaveable {
        val pm = context.packageManager
        pm.getInstalledApplications(0)
            .filter { it.packageName != ownPackage }
            .mapNotNull { appInfo ->
                val label = appInfo.loadLabel(pm).toString()
                if (label == appInfo.packageName) return@mapNotNull null
                AppInfo(name = label, packageName = appInfo.packageName)
            }
            .sortedBy { it.name.lowercase() }
    }

    val filteredApps = if (searchQuery.isBlank()) installedApps
    else installedApps.filter {
        it.name.contains(searchQuery, ignoreCase = true) ||
                it.packageName.contains(searchQuery, ignoreCase = true)
    }

    val selectedPackages = if (vpnAppMode == VpnAppMode.ALL_APPS) excludedPackages else includedPackages

    BackHandler(enabled = true) {
        onBack()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = {
                        val port = socksPort.toIntOrNull() ?: 10803
                        onSaveSettings(
                            AppSettings(
                                dnsAddress = dnsAddress,
                                socksPort = port,
                                vpnMode = vpnMode,
                                vpnAppMode = vpnAppMode,
                                excludedPackages = excludedPackages,
                                includedPackages = includedPackages,
                            )
                        )
                    }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState()),
        ) {
            // VPN Mode
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("VPN Mode", style = MaterialTheme.typography.bodyLarge)
                Switch(
                    checked = vpnMode,
                    onCheckedChange = { vpnMode = it },
                )
            }

            Text(
                if (vpnMode) "Route all device traffic through proxy" else "SOCKS5 proxy only (manual configuration)",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp),
            )

            Spacer(modifier = Modifier.height(16.dp))

            // DNS Address
            OutlinedTextField(
                value = dnsAddress,
                onValueChange = { dnsAddress = it },
                label = { Text("DNS Server") },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                singleLine = true,
            )

            Spacer(modifier = Modifier.height(12.dp))

            // SOCKS5 Port
            OutlinedTextField(
                value = socksPort,
                onValueChange = { socksPort = it },
                label = { Text("SOCKS5 Port") },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                singleLine = true,
            )

            if (vpnMode) {
                Spacer(modifier = Modifier.height(24.dp))

                // Per-app VPN routing
                Text(
                    "VPN App Routing",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(horizontal = 16.dp),
                )

                Spacer(modifier = Modifier.height(8.dp))

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(
                        selected = vpnAppMode == VpnAppMode.ALL_APPS,
                        onClick = { vpnAppMode = VpnAppMode.ALL_APPS },
                    )
                    Text("All apps", modifier = Modifier.weight(1f))
                }

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(
                        selected = vpnAppMode == VpnAppMode.SELECTED_APPS,
                        onClick = { vpnAppMode = VpnAppMode.SELECTED_APPS },
                    )
                    Text("Only selected apps", modifier = Modifier.weight(1f))
                }

                Text(
                    if (vpnAppMode == VpnAppMode.ALL_APPS) "Exclude checked apps from VPN"
                    else "Only checked apps will use VPN",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                )

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = { searchQuery = it },
                    label = { Text("Search apps") },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp),
                    singleLine = true,
                )

                Spacer(modifier = Modifier.height(8.dp))

                LazyColumn(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(400.dp)
                        .padding(horizontal = 16.dp),
                ) {
                    items(filteredApps, key = { it.packageName }) { app ->
                        val checked = app.packageName in selectedPackages
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 2.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Checkbox(
                                checked = checked,
                                onCheckedChange = { isChecked ->
                                    val packages = selectedPackages.toMutableSet()
                                    if (isChecked) packages.add(app.packageName)
                                    else packages.remove(app.packageName)
                                    if (vpnAppMode == VpnAppMode.ALL_APPS) {
                                        excludedPackages = packages
                                    } else {
                                        includedPackages = packages
                                    }
                                },
                            )
                            Column(modifier = Modifier.weight(1f)) {
                                Text(app.name, style = MaterialTheme.typography.bodyMedium)
                                Text(
                                    app.packageName,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}
