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
    private var isProxyRunning by mutableStateOf(false)
    private var appSettings by mutableStateOf(AppSettings())

    private var proxyService: ProxyService? = null

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            proxyService = (service as ProxyService.LocalBinder).getService()
            isProxyRunning = proxyService!!.isProxyRunning
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            proxyService = null
            isProxyRunning = false
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
        selectedProfileId = runningId

        setContent {
            ProxyAppTheme {
                when (val screen = currentScreen) {
                    is Screen.Main -> MainScreen(
                        profiles = profiles,
                        selectedProfileId = selectedProfileId,
                        isProxyRunning = isProxyRunning,
                        vpnMode = appSettings.vpnMode,
                        onSelectProfile = { id ->
                            selectedProfileId = id
                        },
                        onStartProxy = { startProxy() },
                        onStopProxy = { stopProxy() },
                        onAddProfile = { currentScreen = Screen.AddProfile },
                        onEditProfile = { id -> currentScreen = Screen.EditProfile(id) },
                        onDeleteProfile = { id ->
                            profileStore.deleteProfile(id)
                            if (selectedProfileId == id) {
                                selectedProfileId = null
                            }
                            reloadProfiles()
                        },
                        onSettings = { currentScreen = Screen.Settings },
                    )

                    is Screen.AddProfile -> EditProfileScreen(
                        profile = null,
                        onSave = { profile ->
                            profileStore.saveProfile(profile)
                            reloadProfiles()
                            selectedProfileId = profile.id
                            currentScreen = Screen.Main
                        },
                        onBack = { currentScreen = Screen.Main },
                    )

                    is Screen.EditProfile -> {
                        val profile = profileStore.getProfile(screen.id)
                        EditProfileScreen(
                            profile = profile,
                            onSave = { updated ->
                                profileStore.saveProfile(updated)
                                reloadProfiles()
                                currentScreen = Screen.Main
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
        super.onStop()
        unbindService(serviceConnection)
    }

    private fun reloadProfiles() {
        profiles = profileStore.getProfiles()
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
        val profile = profileStore.getProfile(id) ?: return
        val settings = settingsStore.getSettings()

        val intent = Intent(this, ProxyService::class.java).apply {
            action = ProxyService.ACTION_START
            putExtra(ProxyService.EXTRA_HOST, profile.host)
            putExtra(ProxyService.EXTRA_PORT, profile.port)
            putExtra(ProxyService.EXTRA_USERNAME, profile.username)
            putExtra(ProxyService.EXTRA_KEY, profile.privateKeyBase64)
            putExtra(ProxyService.EXTRA_LISTEN_PORT, settings.socksPort)
            putExtra(ProxyService.EXTRA_VPN_MODE, settings.vpnMode)
            putExtra(ProxyService.EXTRA_DNS_ADDRESS, settings.dnsAddress)
            putExtra(ProxyService.EXTRA_VPN_APP_MODE, settings.vpnAppMode.name)
            putStringArrayListExtra(ProxyService.EXTRA_EXCLUDED_PACKAGES, ArrayList(settings.excludedPackages))
            putStringArrayListExtra(ProxyService.EXTRA_INCLUDED_PACKAGES, ArrayList(settings.includedPackages))
        }
        startForegroundService(intent)
        isProxyRunning = true
        profileStore.setRunningProfileId(id)
    }

    private fun stopProxy() {
        val intent = Intent(this, ProxyService::class.java).apply {
            action = ProxyService.ACTION_STOP
        }
        startService(intent)
        isProxyRunning = false
        profileStore.setRunningProfileId(null)
    }
}
