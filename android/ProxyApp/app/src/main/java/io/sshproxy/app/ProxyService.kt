package io.sshproxy.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor

class ProxyService : VpnService() {

    private val binder = LocalBinder()

    inner class LocalBinder : android.os.Binder() {
        fun getService(): ProxyService = this@ProxyService
    }

    var isProxyRunning = false
        private set

    companion object {
        const val CHANNEL_ID = "proxy_channel"
        const val NOTIFICATION_ID = 1

        const val ACTION_START = "io.sshproxy.app.START"
        const val ACTION_STOP = "io.sshproxy.app.STOP"

        const val EXTRA_HOST = "ssh_host"
        const val EXTRA_PORT = "ssh_port"
        const val EXTRA_USERNAME = "ssh_username"
        const val EXTRA_KEY = "ssh_key"
        const val EXTRA_LISTEN_PORT = "listen_port"
        const val EXTRA_VPN_MODE = "vpn_mode"
        const val EXTRA_DNS_ADDRESS = "dns_address"
        const val EXTRA_VPN_APP_MODE = "vpn_app_mode"
        const val EXTRA_EXCLUDED_PACKAGES = "excluded_packages"
        const val EXTRA_INCLUDED_PACKAGES = "included_packages"
    }

    private val proxyNative = ProxyNative()
    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopProxy()
                return START_NOT_STICKY
            }

            ACTION_START -> {
                createNotificationChannel()
                val listenPort = intent.getIntExtra(EXTRA_LISTEN_PORT, 10803)
                val vpnMode = intent.getBooleanExtra(EXTRA_VPN_MODE, false)
                val notification = buildNotification(
                    if (vpnMode) "VPN proxy running" else "SOCKS5 proxy running on port $listenPort"
                )
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    startForeground(
                        NOTIFICATION_ID,
                        notification,
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                    )
                }

                proxyNative.start(
                    intent.getStringExtra(EXTRA_HOST) ?: return START_NOT_STICKY,
                    intent.getIntExtra(EXTRA_PORT, 22),
                    intent.getStringExtra(EXTRA_USERNAME) ?: return START_NOT_STICKY,
                    intent.getStringExtra(EXTRA_KEY),
                    listenPort
                )

                if (vpnMode) {
                    val dnsAddress = intent.getStringExtra(EXTRA_DNS_ADDRESS) ?: "1.1.1.1"
                    val vpnAppMode =
                        intent.getStringExtra(EXTRA_VPN_APP_MODE) ?: VpnAppMode.ALL_APPS.name
                    val excludedPkgs =
                        intent.getStringArrayListExtra(EXTRA_EXCLUDED_PACKAGES) ?: emptyList()
                    val includedPkgs =
                        intent.getStringArrayListExtra(EXTRA_INCLUDED_PACKAGES) ?: emptyList()

                    val tunFd =
                        establishVpn(dnsAddress, vpnAppMode, excludedPkgs, includedPkgs)
                    if (tunFd != null) {
                        proxyNative.startTunnel(tunFd, listenPort)
                    }
                }

                isProxyRunning = true
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopProxy()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopProxy()
        super.onRevoke()
    }

    private fun establishVpn(
        dnsAddress: String,
        vpnAppMode: String,
        excludedPackages: List<String>,
        includedPackages: List<String>,
    ): Int? {
        try {
            val builder = Builder()
                .addAddress("10.0.0.2", 24)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .addDnsServer(dnsAddress)
                .setSession("SSH Proxy")
                .setMtu(1500)

            if (vpnAppMode == VpnAppMode.SELECTED_APPS.name) {
                for (pkg in includedPackages) {
                    try {
                        builder.addAllowedApplication(pkg)
                    } catch (_: Exception) {
                    }
                }
            } else {
                for (pkg in excludedPackages) {
                    try {
                        builder.addDisallowedApplication(pkg)
                    } catch (_: Exception) {
                    }
                }
                try {
                    builder.addDisallowedApplication(packageName)
                } catch (_: Exception) {
                }
            }

            vpnInterface = builder.establish() ?: return null
            return vpnInterface!!.fd
        } catch (_: Exception) {
            return null
        }
    }

    private fun stopProxy() {
        isProxyRunning = false
        if (vpnInterface != null) {
            proxyNative.stopTunnel()
            vpnInterface?.close()
            vpnInterface = null
        }
        proxyNative.stop()
        proxyNative.destroy()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Proxy Service",
            NotificationManager.IMPORTANCE_LOW
        )
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(text: String): Notification {
        val contentIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val stopIntent = PendingIntent.getService(
            this, 1,
            Intent(this, ProxyService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val stopAction = Notification.Action.Builder(
            null, "Stop", stopIntent
        ).build()

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
