package io.sshproxy.app

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
@SdkSuppress(minSdkVersion = 31)
class ByeDpiServiceFailureInstrumentedTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private var bound = false
    private var adoptedPermissions = false
    private var service: ProxyService? = null
    private var port = 0
    private val connected = CountDownLatch(1)
    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            service = (binder as ProxyService.LocalBinder).getService()
            connected.countDown()
        }
        override fun onServiceDisconnected(name: ComponentName?) { service = null }
    }

    @Before
    fun setUp() {
        // Never replace real profiles or disturb the user's existing VPN.
        assumeTrue(context.packageName == "io.sshproxy.app.autostarttest")
        instrumentation.uiAutomation.adoptShellPermissionIdentity(
            "android.permission.START_FOREGROUND_SERVICES_FROM_BACKGROUND",
        )
        adoptedPermissions = true
        context.getSharedPreferences("ssh_profiles", Context.MODE_PRIVATE).edit().clear().commit()
        context.getSharedPreferences("app_settings", Context.MODE_PRIVATE).edit().clear().commit()
        port = ServerSocket(0).use { it.localPort }
        SettingsStore(context).save(AppSettings(vpnMode = false, socksPort = port,
            byeDpiEnabled = true, byeDpiArgs = "--split 2"))
        ProfileStore(context).saveProfile(SshProfile(id = "fixture", name = "Failure fixture",
            host = "127.0.0.1", username = "fixture", privateKeyBase64 = "unused-fixture-key",
            hostKeySha256 = "SHA256:" + "A".repeat(43)))
        instrumentation.runOnMainSync {
            bound = context.bindService(Intent(context, ProxyService::class.java), connection, Context.BIND_AUTO_CREATE)
        }
        assertTrue(bound && connected.await(5, TimeUnit.SECONDS))
    }

    @After
    fun tearDown() {
        if (bound) {
            instrumentation.runOnMainSync {
                service?.onStartCommand(Intent(context, ProxyService::class.java).setAction(ProxyService.ACTION_STOP), 0, 1)
                context.unbindService(connection)
            }
        }
        if (adoptedPermissions) instrumentation.uiAutomation.dropShellPermissionIdentity()
    }

    private fun status(): ProxyStatus {
        var result = ProxyStatus()
        instrumentation.runOnMainSync { result = requireNotNull(service).currentStatus }
        return result
    }

    private fun waitFor(state: ProxyState) {
        val deadline = SystemClock.elapsedRealtime() + 5000
        while (status().state != state && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(10)
        assertEquals(status().error, state, status().state)
    }

    private fun start() {
        instrumentation.runOnMainSync {
            context.startForegroundService(Intent(context, ProxyService::class.java).apply {
                action = ProxyService.ACTION_START
                putExtra(ProxyService.EXTRA_PROFILE_ID, "fixture")
            })
        }
    }

    @Test
    fun failureClosesConnectionsIgnoresLateCallbacksAndAllowsRestart() {
        start()
        waitFor(ProxyState.RUNNING)
        Socket("127.0.0.1", port).use { client ->
            client.soTimeout = 5000
            client.getOutputStream().write(byteArrayOf(5, 1, 0))
            assertEquals(5, client.getInputStream().read())
            assertEquals(0, client.getInputStream().read())
            // Native callbacks arrive on worker threads and are posted to the service's main handler.
            instrumentation.runOnMainSync {
                requireNotNull(service).onError(24, "Embedded ByeDPI stopped unexpectedly")
                requireNotNull(service).onStarted()
                requireNotNull(service).onFinished()
            }
            waitFor(ProxyState.ERROR)
            assertTrue(status().error.orEmpty().contains("Embedded ByeDPI"))
            instrumentation.runOnMainSync { assertNull(service?.currentProfileId) }
            try {
                assertEquals(-1, client.getInputStream().read())
            } catch (_: SocketException) {
                // A reset also proves that cleanup closed the native connection.
            }
        }
        start()
        waitFor(ProxyState.RUNNING)
        instrumentation.runOnMainSync {
            service?.onStartCommand(Intent(context, ProxyService::class.java).setAction(ProxyService.ACTION_STOP), 0, 2)
        }
        waitFor(ProxyState.STOPPED)
        assertNull(status().error)
    }

    @Test
    fun nativeStartupFailureDestroysByeDpiAndAllowsRetry() {
        ServerSocket(port).use {
            start()
            waitFor(ProxyState.ERROR)
        }
        start()
        waitFor(ProxyState.RUNNING)
    }
}
