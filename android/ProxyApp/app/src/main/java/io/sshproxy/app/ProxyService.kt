package io.sshproxy.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import java.net.InetAddress

class ProxyService : VpnService(), ProxyListener {
    fun interface StatusListener {
        fun onStatusChanged(status: ProxyStatus)
    }

    inner class LocalBinder : android.os.Binder() {
        fun getService(): ProxyService = this@ProxyService
    }

    private data class PendingStart(
        val generation: Long,
        val profileId: String,
        val profile: SshProfile,
        val settings: AppSettings,
    )

    private val binder = LocalBinder()
    private val mainHandler = Handler(Looper.getMainLooper())
    private val statusListeners = mutableSetOf<StatusListener>()
    private val proxyNative by lazy { ProxyNative(this) }
    private val profileStore by lazy { ProfileStore(this) }
    private val settingsStore by lazy { SettingsStore(this) }

    private var status = ProxyStatus()
    private var generation = 0L
    private var pendingStart: PendingStart? = null
    private var vpnInterface: ParcelFileDescriptor? = null
    private var cleanupInProgress = false

    val currentStatus: ProxyStatus
        get() = status

    val isProxyRunning: Boolean
        get() = status.state == ProxyState.RUNNING

    companion object {
        const val CHANNEL_ID = "proxy_channel"
        const val NOTIFICATION_ID = 1

        const val ACTION_START = "io.sshproxy.app.START"
        const val ACTION_STOP = "io.sshproxy.app.STOP"
        const val EXTRA_PROFILE_ID = "profile_id"

        private const val TAG = "ProxyService"
    }

    fun addStatusListener(listener: StatusListener) {
        statusListeners.add(listener)
        listener.onStatusChanged(status)
    }

    fun removeStatusListener(listener: StatusListener) {
        statusListeners.remove(listener)
    }

    override fun onBind(intent: Intent?): IBinder? {
        return if (intent?.action == SERVICE_INTERFACE) super.onBind(intent) else binder
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> stopProxy()
            ACTION_START -> startProxy(intent)
        }
        return START_NOT_STICKY
    }

    private fun startProxy(intent: Intent) {
        if (status.isActive) return

        val runGeneration = ++generation
        updateStatus(ProxyStatus(ProxyState.STARTING))
        createNotificationChannel()
        startForegroundCompat(buildNotification("Starting SSH proxy…"))

        try {
            val profileId = requireNotNull(intent.getStringExtra(EXTRA_PROFILE_ID)) { "Missing SSH profile" }
            val profile = requireNotNull(profileStore.getProfile(profileId)) { "SSH profile no longer exists" }
            val settings = settingsStore.getSettings()
            validateConfiguration(profile, settings)

            pendingStart = PendingStart(runGeneration, profileId, profile, settings)
            proxyNative.start(
                profile.host,
                profile.port,
                profile.username,
                profile.privateKeyBase64,
                profile.hostKeySha256,
                settings.socksPort,
            )
        } catch (e: Exception) {
            failRun(runGeneration, e.message ?: "Unable to start proxy")
        }
    }

    private fun validateConfiguration(profile: SshProfile, settings: AppSettings) {
        require(profile.host.isNotBlank()) { "SSH host is required" }
        require(profile.username.isNotBlank()) { "SSH username is required" }
        require(profile.privateKeyBase64.isNotBlank()) { "SSH private key is required" }
        require(SshProfile.isValidHostKeySha256(profile.hostKeySha256)) { "Invalid SSH host-key fingerprint" }
        ProxyValidation.requireValidPort(profile.port, "SSH port")
        ProxyValidation.requireValidPort(settings.socksPort, "Proxy port")
        if (settings.vpnMode) {
            InetAddress.getByName(settings.dnsAddress)
            if (settings.vpnAppMode == VpnAppMode.SELECTED_APPS) {
                ProxyValidation.requireSelectedApplications(settings.includedPackages)
            }
        }
    }

    override fun onStarted() {
        postForCurrentRun { run ->
            try {
                if (run.settings.vpnMode) {
                    val tun = establishVpn(run.settings)
                    vpnInterface = tun
                    proxyNative.startTunnel(tun.fd, run.settings.socksPort)
                }
                profileStore.setRunningProfileId(run.profileId)
                updateStatus(ProxyStatus(ProxyState.RUNNING))
                notifyForeground(
                    if (run.settings.vpnMode) "VPN proxy running"
                    else "SOCKS5 / HTTP proxy running on port ${run.settings.socksPort}"
                )
            } catch (e: Exception) {
                failRun(run.generation, e.message ?: "Unable to establish VPN")
            }
        }
    }

    override fun onFinished() {
        postForCurrentRun { run ->
            if (status.state != ProxyState.STOPPING) {
                failRun(run.generation, "Native proxy stopped unexpectedly")
            }
        }
    }

    override fun onError(code: Long, msg: String) {
        postForCurrentRun { run -> failRun(run.generation, "Proxy error $code: $msg") }
    }

    override fun onTunnelFinished(code: Long) {
        postForCurrentRun { run ->
            if (status.state != ProxyState.STOPPING) {
                failRun(run.generation, "VPN tunnel stopped unexpectedly (code $code)")
            }
        }
    }

    private fun postForCurrentRun(block: (PendingStart) -> Unit) {
        val callbackGeneration = pendingStart?.generation ?: return
        mainHandler.post {
            val run = pendingStart
            if (run != null && run.generation == callbackGeneration && generation == callbackGeneration) {
                block(run)
            }
        }
    }

    private fun establishVpn(settings: AppSettings): ParcelFileDescriptor {
        val builder = Builder()
            .addAddress("10.0.0.2", 24)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            .addDnsServer(InetAddress.getByName(settings.dnsAddress))
            .setSession("SSH Proxy")
            .setMtu(1500)

        if (settings.vpnAppMode == VpnAppMode.SELECTED_APPS) {
            var allowedApplications = 0
            for (pkg in settings.includedPackages.filter { it.isNotBlank() }.distinct()) {
                try {
                    builder.addAllowedApplication(pkg)
                    allowedApplications++
                } catch (e: PackageManager.NameNotFoundException) {
                    Log.w(TAG, "Selected VPN application is not installed: $pkg", e)
                }
            }
            check(allowedApplications > 0) { "None of the selected VPN applications are installed" }
        } else {
            for (pkg in settings.excludedPackages.filter { it.isNotBlank() }.distinct()) {
                try {
                    builder.addDisallowedApplication(pkg)
                } catch (e: PackageManager.NameNotFoundException) {
                    Log.w(TAG, "Excluded VPN application is not installed: $pkg", e)
                }
            }
            builder.addDisallowedApplication(packageName)
        }

        return checkNotNull(builder.establish()) { "Android refused to establish the VPN interface" }
    }

    private fun failRun(runGeneration: Long, message: String) {
        if (generation != runGeneration) return
        Log.e(TAG, message)
        stopProxy(message)
    }

    private fun stopProxy(error: String? = null, stopService: Boolean = true) {
        if (cleanupInProgress) return
        cleanupInProgress = true
        generation++
        updateStatus(ProxyStatus(if (error == null) ProxyState.STOPPING else ProxyState.ERROR, error))
        pendingStart = null

        try {
            vpnInterface?.let {
                proxyNative.stopTunnel()
                it.close()
            }
            vpnInterface = null
            proxyNative.stop()
            proxyNative.destroy()
        } catch (e: Exception) {
            Log.e(TAG, "Proxy shutdown failed", e)
        } finally {
            runCatching { profileStore.setRunningProfileId(null) }
                .onFailure { Log.e(TAG, "Unable to clear the running profile", it) }
            stopForeground(STOP_FOREGROUND_REMOVE)
            if (error == null) updateStatus(ProxyStatus(ProxyState.STOPPED))
            cleanupInProgress = false
            if (stopService) stopSelf()
        }
    }

    override fun onDestroy() {
        stopProxy(stopService = false)
        super.onDestroy()
    }

    override fun onRevoke() {
        mainHandler.post { stopProxy("VPN permission was revoked") }
    }

    private fun updateStatus(newStatus: ProxyStatus) {
        status = newStatus
        statusListeners.toList().forEach { it.onStatusChanged(newStatus) }
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(CHANNEL_ID, "Proxy Service", NotificationManager.IMPORTANCE_LOW)
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun startForegroundCompat(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun notifyForeground(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun buildNotification(text: String): Notification {
        val contentIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, ProxyService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopAction = Notification.Action.Builder(null, "Stop", stopIntent).build()

        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("SSH Proxy")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setOngoing(true)
            .setContentIntent(contentIntent)
            .addAction(stopAction)
            .build()
    }
}
