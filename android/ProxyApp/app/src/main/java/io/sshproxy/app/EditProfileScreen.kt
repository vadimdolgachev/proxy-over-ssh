package io.sshproxy.app

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EditProfileScreen(
    profile: SshProfile?,
    onSave: (SshProfile) -> Unit,
    onBack: () -> Unit,
) {
    val existingId = profile?.id ?: java.util.UUID.randomUUID().toString()

    var name by rememberSaveable { mutableStateOf(profile?.name ?: "") }
    var host by rememberSaveable { mutableStateOf(profile?.host ?: "") }
    var port by rememberSaveable { mutableStateOf((profile?.port ?: 22).toString()) }
    var username by rememberSaveable { mutableStateOf(profile?.username ?: "") }
    var privateKey by rememberSaveable { mutableStateOf(profile?.privateKeyBase64 ?: "") }

    val context = LocalContext.current

    val fileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        val content = context.contentResolver.openInputStream(uri)?.bufferedReader()?.readText()
            ?: return@rememberLauncherForActivityResult
        privateKey = SshProfile.normalizeKey(content)
    }

    val normalizedKey = SshProfile.normalizeKey(privateKey)
    val canSave = name.isNotBlank() && host.isNotBlank() && username.isNotBlank() && normalizedKey.isNotBlank()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (profile == null) "Add Profile" else "Edit Profile") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
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
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text("Profile Name") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )

            OutlinedTextField(
                value = host,
                onValueChange = { host = it },
                label = { Text("SSH Host") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )

            OutlinedTextField(
                value = port,
                onValueChange = { port = it },
                label = { Text("SSH Port") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )

            OutlinedTextField(
                value = username,
                onValueChange = { username = it },
                label = { Text("Username") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text("Private Key", style = MaterialTheme.typography.titleSmall)

            OutlinedTextField(
                value = privateKey,
                onValueChange = { privateKey = it },
                label = { Text("Private key") },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(120.dp),
                maxLines = 8,
            )

            OutlinedButton(
                onClick = {
                    fileLauncher.launch(arrayOf("*/*"))
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Import from file")
            }

            Spacer(modifier = Modifier.height(8.dp))

            Button(
                onClick = {
                    val parsedPort = port.toIntOrNull() ?: 22
                    onSave(
                        SshProfile(
                            id = existingId,
                            name = name,
                            host = host,
                            port = parsedPort,
                            username = username,
                            privateKeyBase64 = normalizedKey,
                        )
                    )
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = canSave,
            ) {
                Text("Save")
            }
        }
    }
}
