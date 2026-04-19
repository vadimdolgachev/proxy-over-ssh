package io.sshproxy.app

import android.util.Log
import androidx.annotation.Keep

@Keep
interface ProxyListener {
    fun onStarted()
    fun onFinished()
    fun onError(code: Long, msg: String)
}

class ProxyNative: ProxyListener {
    private var handle = 0L

    private external fun nativeCreate(): Long
    private external fun nativeStart(
        handle: Long, sshHost: String, sshPort: Int,
        sshUsername: String, privateKeyData: String?, listenPort: Int
    )
    private external fun nativeStop(handle: Long)
    private external fun nativeDestroy(handle: Long)
    private external fun nativeStartTunnel(handle: Long, tunFd: Int, socksPort: Int)
    private external fun nativeStopTunnel(handle: Long)
    external fun registerListener(listener: ProxyListener)
    external fun unregisterListener()

    fun start(
        sshHost: String, sshPort: Int,
        sshUsername: String, privateKeyData: String?, listenPort: Int
    ) {
        if (handle == 0L) {
            handle = nativeCreate()
        }
        registerListener(this)
        nativeStart(handle, sshHost, sshPort, sshUsername, privateKeyData, listenPort)
    }

    fun startTunnel(tunFd: Int, socksPort: Int) {
        if (handle != 0L) {
            nativeStartTunnel(handle, tunFd, socksPort)
        }
    }

    fun stopTunnel() {
        if (handle != 0L) {
            nativeStopTunnel(handle)
        }
    }

    fun stop() {
        if (handle != 0L) {
            nativeStop(handle)
        }
    }

    fun destroy() {
        unregisterListener()
        if (handle != 0L) {
            nativeDestroy(handle)
            handle = 0L
        }
    }

    override fun onStarted() {
        Log.d(TAG, "onStarted: ")
    }

    override fun onFinished() {
        Log.d(TAG, "onFinished: ")
    }

    override fun onError(code: Long, msg: String) {
        Log.d(TAG, "onError: $msg, $code")
    }

    companion object {
        init {
            System.loadLibrary("proxyapp")
        }
        const val TAG = "ProxyNative"
    }
}
