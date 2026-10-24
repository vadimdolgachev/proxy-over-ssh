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
    private var pendingAutoStartName: String? = null
    private var pendingVpnProfileId: String? = null

    private var proxyService: ProxyService? = null
    private val statusListener = ProxyService.StatusListener { proxyStatus = it }

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            proxyService = (service as ProxyService.LocalBinder).getService()
            proxyService!!.addStatusListener(statusListener)
            processPendingAutoStart()
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
        val profileId = pendingVpnProfileId
        pendingVpnProfileId = null
        if (profileId == null) return@registerForActivityResult
        if (result.resultCode == RESULT_OK) {
            startProxyInternal(profileId)
        } else {
            reportStartError("VPN permission was not granted; profile was not started")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        // Explicit automation starts should not be blocked by the optional notification prompt.
        if (savedInstanceState == null && !intent.hasExtra(EXTRA_PROFILE_NAME)
            && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
        ) {
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
        pendingAutoStartName = savedInstanceState?.getString(STATE_AUTO_START_NAME)
        pendingVpnProfileId = savedInstanceState?.getString(STATE_VPN_PROFILE_ID)

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
                        onClose = {
                            currentScreen = Screen.Main
                        },
                    )
                }
            }
        }
        acceptAutoStartIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        acceptAutoStartIntent(intent)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putString(STATE_AUTO_START_NAME, pendingAutoStartName)
        outState.putString(STATE_VPN_PROFILE_ID, pendingVpnProfileId)
        super.onSaveInstanceState(outState)
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
        proxyService = null
    }

    private fun acceptAutoStartIntent(intent: Intent) {
        if (!intent.hasExtra(EXTRA_PROFILE_NAME)) return
        pendingAutoStartName = intent.getStringExtra(EXTRA_PROFILE_NAME) ?: ""
        // Consume the request so activity recreation does not start the profile again.
        intent.removeExtra(EXTRA_PROFILE_NAME)
        currentScreen = Screen.Main
        processPendingAutoStart()
    }

    private fun processPendingAutoStart() {
        // Wait for the existing service's real status before deciding whether to start it.
        if (proxyService == null) return
        val name = pendingAutoStartName ?: return
        pendingAutoStartName = null
        try {
            reloadProfilesOrThrow()
            val profile = ProfileSelection.requireByName(profiles, name)
            Log.i(TAG, "Auto-start requested for profile '${profile.name}'")
            requestProfileStart(profile)
        } catch (e: Exception) {
            reportStartError(e.message ?: "Unable to select SSH profile")
        }
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
        val profile = profiles.firstOrNull { it.id == selectedProfileId } ?: return
        requestProfileStart(profile)
    }

    private fun requestProfileStart(profile: SshProfile) {
        try {
            if (proxyStatus.isActive) {
                require(proxyService?.currentProfileId == profile.id) {
                    "Another SSH profile is active; stop it before starting '${profile.name}'"
                }
                profileStorageError = null
                selectedProfileId = profile.id
                Log.i(TAG, "Profile '${profile.name}' is already active")
                return
            }
            pendingVpnProfileId?.let { pendingId ->
                require(pendingId == profile.id) { "VPN permission is pending for another SSH profile" }
                return
            }
            require(SshProfile.isValidHostKeySha256(profile.hostKeySha256)) { "Invalid SSH host-key fingerprint" }
            appSettings = settingsStore.getSettings()
            profileStorageError = null
            selectedProfileId = profile.id
            if (appSettings.vpnMode) {
                val vpnIntent = VpnService.prepare(this)
                if (vpnIntent != null) {
                    pendingVpnProfileId = profile.id
                    vpnPermissionLauncher.launch(vpnIntent)
                    return
                }
            }
            startProxyInternal(profile.id)
        } catch (e: Exception) {
            if (pendingVpnProfileId == profile.id) pendingVpnProfileId = null
            reportStartError(e.message ?: "Unable to start SSH profile")
        }
    }

    private fun startProxyInternal(profileId: String) {
        try {
            val profile = requireNotNull(profiles.firstOrNull { it.id == profileId }) { "SSH profile no longer exists" }
            require(SshProfile.isValidHostKeySha256(profile.hostKeySha256)) { "Invalid SSH host-key fingerprint" }
            selectedProfileId = profile.id
            val intent = Intent(this, ProxyService::class.java).apply {
                action = ProxyService.ACTION_START
                putExtra(ProxyService.EXTRA_PROFILE_ID, profile.id)
            }
            startForegroundService(intent)
            proxyStatus = ProxyStatus(ProxyState.STARTING)
            Log.i(TAG, "Starting SSH profile '${profile.name}'")
        } catch (e: Exception) {
            reportStartError(e.message ?: "Unable to start SSH profile")
        }
    }

    private fun reportStartError(message: String) {
        profileStorageError = message
        Log.e(TAG, "Profile start failed: $message")
    }

    private fun stopProxy() {
        val intent = Intent(this, ProxyService::class.java).apply {
            action = ProxyService.ACTION_STOP
        }
        startService(intent)
        proxyStatus = ProxyStatus(ProxyState.STOPPING)
    }

    companion object {
        const val EXTRA_PROFILE_NAME = "profile_name"
        private const val TAG = "MainActivity"
        private const val STATE_AUTO_START_NAME = "auto_start_name"
        private const val STATE_VPN_PROFILE_ID = "vpn_profile_id"
    }
}
