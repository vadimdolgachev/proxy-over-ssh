package io.sshproxy.app

class ProxyNative {
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

    fun start(
        sshHost: String, sshPort: Int,
        sshUsername: String, privateKeyData: String?, listenPort: Int
    ) {
        if (handle == 0L) {
            handle = nativeCreate()
        }
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
        if (handle != 0L) {
            nativeDestroy(handle)
            handle = 0L
        }
    }

    companion object {
        init {
            System.loadLibrary("proxyapp")
        }
    }
}
