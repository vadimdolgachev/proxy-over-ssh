package io.sshproxy.app

import android.content.Context
import org.json.JSONArray

data class AppSettings(
    val dnsAddress: String = "1.1.1.1",
    val socksPort: Int = 1080,
    val vpnMode: Boolean = true,
    val vpnAppMode: VpnAppMode = VpnAppMode.ALL_APPS,
    val excludedPackages: Set<String> = emptySet(),
    val includedPackages: Set<String> = emptySet(),
)

enum class VpnAppMode {
    ALL_APPS,
    SELECTED_APPS,
}

class SettingsStore(context: Context) {

    private val prefs = context.getSharedPreferences("app_settings", Context.MODE_PRIVATE)

    fun getSettings(): AppSettings {
        return AppSettings(
            dnsAddress = prefs.getString(KEY_DNS_ADDRESS, "1.1.1.1") ?: "1.1.1.1",
            socksPort = prefs.getInt(KEY_SOCKS_PORT, 1080),
            vpnMode = prefs.getBoolean(KEY_VPN_MODE, true),
            vpnAppMode = if (prefs.getString(KEY_VPN_APP_MODE, VpnAppMode.ALL_APPS.name) == VpnAppMode.SELECTED_APPS.name)
                VpnAppMode.SELECTED_APPS else VpnAppMode.ALL_APPS,
            excludedPackages = loadStringSet(KEY_EXCLUDED_PACKAGES),
            includedPackages = loadStringSet(KEY_INCLUDED_PACKAGES),
        )
    }

    fun save(settings: AppSettings) {
        prefs.edit().apply {
            putString(KEY_DNS_ADDRESS, settings.dnsAddress)
            putInt(KEY_SOCKS_PORT, settings.socksPort)
            putBoolean(KEY_VPN_MODE, settings.vpnMode)
            putString(KEY_VPN_APP_MODE, settings.vpnAppMode.name)
            putString(KEY_EXCLUDED_PACKAGES, setToJson(settings.excludedPackages))
            putString(KEY_INCLUDED_PACKAGES, setToJson(settings.includedPackages))
            apply()
        }
    }

    private fun loadStringSet(key: String): Set<String> {
        val json = prefs.getString(key, null) ?: return emptySet()
        val arr = JSONArray(json)
        return (0 until arr.length()).mapTo(mutableSetOf()) { arr.getString(it) }
    }

    private fun setToJson(set: Set<String>): String {
        val arr = JSONArray()
        set.forEach { arr.put(it) }
        return arr.toString()
    }

    companion object {
        private const val KEY_DNS_ADDRESS = "dns_address"
        private const val KEY_SOCKS_PORT = "socks_port"
        private const val KEY_VPN_MODE = "vpn_mode"
        private const val KEY_VPN_APP_MODE = "vpn_app_mode"
        private const val KEY_EXCLUDED_PACKAGES = "excluded_pkgs"
        private const val KEY_INCLUDED_PACKAGES = "included_pkgs"
    }
}
