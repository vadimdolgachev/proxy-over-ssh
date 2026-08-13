package io.sshproxy.app

import androidx.annotation.Keep

@Keep
interface ProxyListener {
    fun onStarted()
    fun onFinished()
    fun onError(code: Long, msg: String)
    fun onTunnelFinished(code: Long)
}

class ProxyNative(private val listener: ProxyListener) {
    private var handle = 0L

    private external fun nativeCreate(): Long
    private external fun nativeRegisterListener(handle: Long, listener: ProxyListener)
    private external fun nativeStart(
        handle: Long,
        sshHost: String,
        sshPort: Int,
        sshUsername: String,
        privateKeyData: String?,
        hostKeySha256: String,
        listenPort: Int,
    )
    private external fun nativeStop(handle: Long)
    private external fun nativeDestroy(handle: Long)
    private external fun nativeStartTunnel(handle: Long, tunFd: Int, socksPort: Int)
    private external fun nativeStopTunnel(handle: Long)

    fun start(
        sshHost: String,
        sshPort: Int,
        sshUsername: String,
        privateKeyData: String?,
        hostKeySha256: String,
        listenPort: Int,
    ) {
        if (handle == 0L) {
            handle = nativeCreate()
            check(handle != 0L) { "Failed to create native proxy context" }
            nativeRegisterListener(handle, listener)
        }
        nativeStart(handle, sshHost, sshPort, sshUsername, privateKeyData, hostKeySha256, listenPort)
    }

    fun startTunnel(tunFd: Int, socksPort: Int) {
        check(handle != 0L) { "Native proxy context is not initialized" }
        nativeStartTunnel(handle, tunFd, socksPort)
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
        val currentHandle = handle
        if (currentHandle == 0L) {
            return
        }
        handle = 0L
        nativeDestroy(currentHandle)
    }

    companion object {
        init {
            System.loadLibrary("proxyapp")
        }
    }
}
