package io.sshproxy.app

import android.Manifest
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.ContextCompat
import io.sshproxy.app.ui.theme.ProxyAppTheme

class MainActivity : ComponentActivity() {

    private lateinit var profileStore: ProfileStore
    private lateinit var settingsStore: SettingsStore
    private var currentScreen by mutableStateOf<Screen>(Screen.Main)
    private var profiles by mutableStateOf<List<SshProfile>>(emptyList())
    private var selectedProfileId by mutableStateOf<String?>(null)
    private var proxyStatus by mutableStateOf(ProxyStatus())
    private var profileStorageError by mutableStateOf<String?>(null)
    private var appSettings by mutableStateOf(AppSettings())

    private var proxyService: ProxyService? = null
    private val statusListener = ProxyService.StatusListener { proxyStatus = it }

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            proxyService = (service as ProxyService.LocalBinder).getService()
            proxyService!!.addStatusListener(statusListener)
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            proxyService = null
            proxyStatus = ProxyStatus()
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { /* result ignored */ }

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startProxyInternal()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        profileStore = ProfileStore(this)
        settingsStore = SettingsStore(this)
        appSettings = settingsStore.getSettings()
        reloadProfiles()

        val runningId = profileStore.getRunningProfileId()
        selectedProfileId = runningId?.takeIf { id -> profiles.any { it.id == id } }

        setContent {
            ProxyAppTheme {
                when (val screen = currentScreen) {
                    is Screen.Main -> MainScreen(
                        profiles = profiles,
                        selectedProfileId = selectedProfileId,
                        proxyStatus = proxyStatus,
                        errorMessage = profileStorageError ?: proxyStatus.error,
                        vpnMode = appSettings.vpnMode,
                        onSelectProfile = { id ->
                            selectedProfileId = id
                        },
                        onStartProxy = { startProxy() },
                        onStopProxy = { stopProxy() },
                        onAddProfile = {
                            profileStorageError = null
                            currentScreen = Screen.AddProfile
                        },
                        onEditProfile = { id -> currentScreen = Screen.EditProfile(id) },
                        onDeleteProfile = { id ->
                            withProfileStorage {
                                profileStore.deleteProfile(id)
                                if (selectedProfileId == id) {
                                    selectedProfileId = null
                                }
                                reloadProfilesOrThrow()
                            }
                        },
                        onSettings = { currentScreen = Screen.Settings },
                    )

                    is Screen.AddProfile -> EditProfileScreen(
                        profile = null,
                        errorMessage = profileStorageError,
                        onSave = { profile ->
                            withProfileStorage {
                                profileStore.saveProfile(profile)
                                reloadProfilesOrThrow()
                                selectedProfileId = profile.id
                                currentScreen = Screen.Main
                            }
                        },
                        onBack = { currentScreen = Screen.Main },
                    )

                    is Screen.EditProfile -> {
                        val profile = profiles.firstOrNull { it.id == screen.id }
                        EditProfileScreen(
                            profile = profile,
                            errorMessage = profileStorageError,
                            onSave = { updated ->
                                withProfileStorage {
                                    profileStore.saveProfile(updated)
                                    reloadProfilesOrThrow()
                                    currentScreen = Screen.Main
                                }
                            },
                            onBack = { currentScreen = Screen.Main },
                        )
                    }

                    is Screen.Settings -> SettingsScreen(
                        settings = appSettings,
                        onSaveSettings = { newSettings ->
                            settingsStore.save(newSettings)
                            appSettings = newSettings
                            currentScreen = Screen.Main
                        },
                        onBack = {
                            currentScreen = Screen.Main
                        },
                    )
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        val intent = Intent(this, ProxyService::class.java)
        bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
    }

    override fun onStop() {
        proxyService?.removeStatusListener(statusListener)
        super.onStop()
        unbindService(serviceConnection)
    }

    private fun reloadProfiles() {
        withProfileStorage { reloadProfilesOrThrow() }
    }

    private fun reloadProfilesOrThrow() {
        profiles = profileStore.getProfiles()
        profileStorageError = null
    }

    private inline fun withProfileStorage(action: () -> Unit) {
        try {
            action()
        } catch (e: ProfileStorageException) {
            Log.e(TAG, "SSH profile storage operation failed", e)
            profiles = emptyList()
            selectedProfileId = null
            profileStorageError = e.message ?: "Unable to access SSH profiles"
        }
    }

    private fun startProxy() {
        if (appSettings.vpnMode) {
            val vpnIntent = VpnService.prepare(this)
            if (vpnIntent != null) {
                vpnPermissionLauncher.launch(vpnIntent)
                return
            }
        }
        startProxyInternal()
    }

    private fun startProxyInternal() {
        val id = selectedProfileId ?: return
        val profile = profiles.firstOrNull { it.id == id } ?: return
        if (!SshProfile.isValidHostKeySha256(profile.hostKeySha256)) return
        val intent = Intent(this, ProxyService::class.java).apply {
            action = ProxyService.ACTION_START
            putExtra(ProxyService.EXTRA_PROFILE_ID, profile.id)
        }
        startForegroundService(intent)
        proxyStatus = ProxyStatus(ProxyState.STARTING)
    }

    private fun stopProxy() {
        val intent = Intent(this, ProxyService::class.java).apply {
            action = ProxyService.ACTION_STOP
        }
        startService(intent)
        proxyStatus = ProxyStatus(ProxyState.STOPPING)
    }

    private companion object {
        const val TAG = "MainActivity"
    }
}
