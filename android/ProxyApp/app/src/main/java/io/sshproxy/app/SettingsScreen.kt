package io.sshproxy.app

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.ExperimentalFoundationApi
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
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun SettingsScreen(
    settings: AppSettings,
    onSaveSettings: (AppSettings) -> Unit,
    onClose: () -> Unit,
) {
    var vpnMode by rememberSaveable { mutableStateOf(settings.vpnMode) }
    var dnsAddress by rememberSaveable { mutableStateOf(settings.dnsAddress) }
    var socksPort by rememberSaveable { mutableStateOf(settings.socksPort.toString()) }
    var vpnAppMode by rememberSaveable { mutableStateOf(settings.vpnAppMode) }
    var excludedPackages by rememberSaveable { mutableStateOf(settings.excludedPackages) }
    var includedPackages by rememberSaveable { mutableStateOf(settings.includedPackages) }
    var byeDpiEnabled by rememberSaveable { mutableStateOf(settings.byeDpiEnabled) }
    var byeDpiArgs by rememberSaveable { mutableStateOf(settings.byeDpiArgs) }
    var searchQuery by rememberSaveable { mutableStateOf("") }

    val context = LocalContext.current
    val proxyVersion = remember { ProxyNative.getVersion() }
    val ownPackage = context.packageName
    // remember, not rememberSaveable: the list is rebuilt from the package manager and is not
    // parcelable, so it must not end up in the saved instance state.
    val installedApps = remember {
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
    val orderedApps = remember(filteredApps, selectedPackages) {
        AppListOrdering.prioritize(filteredApps, selectedPackages)
    }

    val parsedPort = socksPort.trim().toIntOrNull()
    val isPortValid = parsedPort != null && parsedPort in 1..65535
    val hasSelectedApps = !vpnMode || vpnAppMode != VpnAppMode.SELECTED_APPS || includedPackages.isNotEmpty()
    val isDnsValid = dnsAddress.isNotBlank()
    val canSave = isPortValid && isDnsValid && hasSelectedApps

    // The values the user is currently editing. parsedPort is -1 while the port is invalid, so such
    // a state never compares equal to the stored settings.
    val editedSettings = AppSettings(
        dnsAddress = dnsAddress.trim(),
        socksPort = parsedPort ?: -1,
        vpnMode = vpnMode,
        vpnAppMode = vpnAppMode,
        excludedPackages = excludedPackages,
        includedPackages = includedPackages,
        byeDpiEnabled = byeDpiEnabled,
        byeDpiArgs = byeDpiArgs,
    )
    val hasChanges = editedSettings != settings

    val applySettings = {
        if (canSave && hasChanges) {
            onSaveSettings(editedSettings)
        } else {
            onClose()
        }
    }

    // The toolbar arrow and the system back button behave the same way: valid values are applied,
    // invalid ones are discarded instead of blocking the exit.
    BackHandler(enabled = true) {
        applySettings()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = { applySettings() }, enabled = canSave) {
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
                if (vpnMode) "Route all device traffic through proxy"
                else "SOCKS5 and HTTP CONNECT (manual configuration)",
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
                supportingText = { if (!isDnsValid) Text("DNS server is required") },
                isError = !isDnsValid,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                singleLine = true,
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Shared proxy port
            OutlinedTextField(
                value = socksPort,
                onValueChange = { socksPort = it },
                label = { Text("Proxy Port") },
                supportingText = { if (!isPortValid) Text("Enter a port from 1 to 65535") },
                isError = !isPortValid,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                singleLine = true,
            )

            Spacer(modifier = Modifier.height(16.dp))
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("ByeDPI", style = MaterialTheme.typography.bodyLarge)
                Switch(checked = byeDpiEnabled, onCheckedChange = { byeDpiEnabled = it })
            }
            Text(
                "Route the SSH connection through ByeDPI",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp),
            )
            if (byeDpiEnabled) {
                OutlinedTextField(
                    value = byeDpiArgs,
                    onValueChange = { byeDpiArgs = it },
                    label = { Text("ByeDPI arguments") },
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                    minLines = 2,
                )
            }

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

                if (!hasSelectedApps) {
                    Text(
                        "Select at least one installed app before saving",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.padding(horizontal = 16.dp),
                    )
                }

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
                    items(orderedApps, key = { it.packageName }) { app ->
                        val checked = app.packageName in selectedPackages
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .animateItem()
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
                            AppIcon(
                                packageName = app.packageName,
                                modifier = Modifier.padding(end = 12.dp),
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

            Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                Text("About", style = MaterialTheme.typography.titleMedium)
                Spacer(modifier = Modifier.height(8.dp))
                Text("Android app: ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})",
                    style = MaterialTheme.typography.bodyMedium)
                Text("proxy_over_ssh: $proxyVersion", style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}
