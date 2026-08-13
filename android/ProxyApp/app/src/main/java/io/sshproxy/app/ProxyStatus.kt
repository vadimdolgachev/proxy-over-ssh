package io.sshproxy.app

enum class ProxyState {
    STOPPED,
    STARTING,
    RUNNING,
    STOPPING,
    ERROR,
}

data class ProxyStatus(
    val state: ProxyState = ProxyState.STOPPED,
    val error: String? = null,
) {
    val isActive: Boolean
        get() = state == ProxyState.STARTING || state == ProxyState.RUNNING || state == ProxyState.STOPPING
}

object ProxyValidation {
    fun requireValidPort(port: Int, name: String): Int {
        require(port in 1..65535) { "$name must be between 1 and 65535" }
        return port
    }

    fun requireSelectedApplications(packages: Collection<String>) {
        require(packages.any { it.isNotBlank() }) {
            "Select at least one application before starting selected-app VPN mode"
        }
    }
}
