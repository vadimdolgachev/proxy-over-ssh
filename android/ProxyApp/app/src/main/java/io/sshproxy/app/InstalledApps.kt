package io.sshproxy.app

/**
 * An installed application shown in the per-app VPN routing list.
 *
 * Deliberately free of Android dependencies so it can be used from plain JVM unit tests.
 */
data class AppInfo(
    val name: String,
    val packageName: String,
)

/**
 * Orders the application list so that the currently checked applications come first.
 *
 * Checked applications keep a higher priority in the list regardless of the routing mode:
 * in "All apps" mode they are the ones excluded from the VPN, in "Only selected apps" mode
 * they are the ones routed through it. Applications inside each group stay sorted by name.
 */
object AppListOrdering {
    fun prioritize(apps: List<AppInfo>, selectedPackages: Set<String>): List<AppInfo> =
        apps.sortedWith(
            compareByDescending<AppInfo> { it.packageName in selectedPackages }
                .thenBy { it.name.lowercase() }
        )
}
