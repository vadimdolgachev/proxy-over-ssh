package io.sshproxy.app

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
@SdkSuppress(minSdkVersion = 31)
class ProfileAutoStartInstrumentedTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private var bound = false
    private var service: ProxyService? = null
    private lateinit var profiles: ProfileStore
    private var proxyPort = 0
    private val connected = CountDownLatch(1)
    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            service = (binder as ProxyService.LocalBinder).getService()
            connected.countDown()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            service = null
        }
    }

    private fun profile(id: String, name: String) = SshProfile(
        id = id,
        name = name,
        host = "127.0.0.1",
        username = "fixture",
        privateKeyBase64 = "fixture-key-not-used-for-a-network-connection",
        hostKeySha256 = "SHA256:" + "A".repeat(43),
    )

    @Before
    fun setUp() {
        // These tests seed app-private storage and start a listener: never run them on real user data.
        assumeTrue(
            "Use -PprofileTestApplicationId=io.sshproxy.app.autostarttest",
            context.packageName == "io.sshproxy.app.autostarttest",
        )
        context.getSharedPreferences("ssh_profiles", Context.MODE_PRIVATE).edit().clear().commit()
        context.getSharedPreferences("app_settings", Context.MODE_PRIVATE).edit().clear().commit()
        proxyPort = ServerSocket(0).use { it.localPort }
        SettingsStore(context).save(AppSettings(vpnMode = false, socksPort = proxyPort))
        profiles = ProfileStore(context)
        profiles.saveProfile(profile("other", "Other"))
        profiles.saveProfile(profile("target", "Profile name"))
        profiles.setRunningProfileId("other") // A previous selection must not override the requested name.
        instrumentation.runOnMainSync {
            bound = context.bindService(Intent(context, ProxyService::class.java), connection, Context.BIND_AUTO_CREATE)
        }
        assertTrue(bound && connected.await(5, TimeUnit.SECONDS))
    }

    @After
    fun tearDown() {
        if (!bound) return
        stopProxy()
        resumedActivity()?.let { activity -> instrumentation.runOnMainSync { activity.finish() } }
        instrumentation.runOnMainSync { context.unbindService(connection) }
        bound = false
    }

    private fun waitUntil(condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + 5000
        while (SystemClock.elapsedRealtime() < deadline) {
            if (condition()) return
            SystemClock.sleep(25)
        }
        assertTrue("Timed out waiting for profile launch", condition())
    }

    private fun state(): Pair<ProxyState?, String?> {
        var result: Pair<ProxyState?, String?> = null to null
        instrumentation.runOnMainSync { result = service?.currentStatus?.state to service?.currentProfileId }
        return result
    }

    private fun resumedActivity(): MainActivity? {
        var result: MainActivity? = null
        instrumentation.runOnMainSync {
            result = ActivityLifecycleMonitorRegistry.getInstance().getActivitiesInStage(Stage.RESUMED)
                .filterIsInstance<MainActivity>().singleOrNull()
        }
        return result
    }

    private fun onActivity(action: (MainActivity) -> Unit) {
        val activity = requireNotNull(resumedActivity())
        instrumentation.runOnMainSync { action(activity) }
    }

    private fun shellStart(name: String, cold: Boolean) {
        // Exercise the same shell entry point as ADB, including names containing spaces.
        val flags = if (cold) "0x10008000" else "0x30000000"
        val quotedName = "'" + name.replace("'", "'\\''") + "'"
        val command = "am start -W -f $flags -n ${context.packageName}/${MainActivity::class.java.name}" +
            " --es ${MainActivity.EXTRA_PROFILE_NAME} $quotedName\n"
        val streams = instrumentation.uiAutomation.executeShellCommandRw("sh")
        ParcelFileDescriptor.AutoCloseOutputStream(streams[1]).use {
            it.write(command.toByteArray(Charsets.UTF_8))
        }
        val output = ParcelFileDescriptor.AutoCloseInputStream(streams[0]).bufferedReader().use { it.readText() }
        assertFalse(output, output.contains("Error:"))
        waitUntil { resumedActivity() != null }
        instrumentation.waitForIdleSync()
    }

    private fun launch(name: String) = shellStart(name, cold = true)

    private fun sendNewIntent(name: String) = shellStart(name, cold = false)

    private fun waitForError(text: String) {
        waitUntil {
            instrumentation.uiAutomation.rootInActiveWindow
                ?.findAccessibilityNodeInfosByText(text)?.isNotEmpty() == true
        }
        assertEquals(ProxyState.STOPPED to null, state())
    }

    private fun stopProxy() {
        if (state().first in listOf(ProxyState.STARTING, ProxyState.RUNNING)) {
            instrumentation.runOnMainSync {
                context.startService(Intent(context, ProxyService::class.java).setAction(ProxyService.ACTION_STOP))
            }
            waitUntil { state().first == ProxyState.STOPPED }
        }
    }

    @Test
    fun coldLaunchSelectsNamedProfileAndConsumesRequest() {
        launch("Profile name")
        waitUntil { state() == (ProxyState.RUNNING to "target") }
        assertEquals("target", profiles.getRunningProfileId())
        onActivity { assertFalse(it.intent.hasExtra(MainActivity.EXTRA_PROFILE_NAME)) }
        stopProxy()
        val oldActivity = resumedActivity()
        onActivity { it.recreate() }
        waitUntil { resumedActivity()?.let { it !== oldActivity } == true }
        instrumentation.waitForIdleSync()
        onActivity { assertFalse(it.intent.hasExtra(MainActivity.EXTRA_PROFILE_NAME)) }
        assertEquals(ProxyState.STOPPED to null, state())
    }

    @Test
    fun warmLaunchAndRepeatedRequestKeepExistingConnection() {
        launch("Missing profile")
        waitForError("was not found")
        sendNewIntent("Profile name")
        waitUntil { state() == (ProxyState.RUNNING to "target") }
        Socket("127.0.0.1", proxyPort).use { client ->
            client.soTimeout = 5000
            sendNewIntent("Profile name")
            onActivity { assertFalse(it.intent.hasExtra(MainActivity.EXTRA_PROFILE_NAME)) }
            client.getOutputStream().write(byteArrayOf(5, 1, 0))
            assertEquals(5, client.getInputStream().read())
            assertEquals(0, client.getInputStream().read())
            assertEquals(ProxyState.RUNNING to "target", state())
        }
    }

    @Test
    fun missingAndDuplicateNamesDoNotStartPreviousSelection() {
        launch("Missing profile")
        waitForError("was not found")
        onActivity { it.finish() }
        profiles.saveProfile(profile("duplicate", "Profile name"))
        launch("Profile name")
        waitForError("Multiple SSH profiles")
    }

    @Test
    fun differentActiveProfileIsNotReplaced() {
        launch("Profile name")
        waitUntil { state() == (ProxyState.RUNNING to "target") }
        sendNewIntent("Other")
        waitUntil {
            instrumentation.uiAutomation.rootInActiveWindow
                ?.findAccessibilityNodeInfosByText("Another SSH profile is active")?.isNotEmpty() == true
        }
        assertEquals(ProxyState.RUNNING to "target", state())
    }
}
