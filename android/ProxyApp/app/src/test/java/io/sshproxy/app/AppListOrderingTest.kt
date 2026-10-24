package io.sshproxy.app

import org.junit.Assert.assertEquals
import org.junit.Test

class AppListOrderingTest {
    private val apps = listOf(
        AppInfo("Alpha", "com.alpha"),
        AppInfo("Bravo", "com.bravo"),
        AppInfo("Charlie", "com.charlie"),
        AppInfo("Delta", "com.delta"),
    )

    @Test
    fun selectedApplicationsAreOrderedBeforeUnselectedOnes() {
        val ordered = AppListOrdering.prioritize(apps, setOf("com.charlie"))
        assertEquals(
            listOf("com.charlie", "com.alpha", "com.bravo", "com.delta"),
            ordered.map { it.packageName },
        )
    }

    @Test
    fun selectedApplicationsStayAlphabeticalAmongThemselves() {
        val ordered = AppListOrdering.prioritize(apps, setOf("com.delta", "com.bravo"))
        assertEquals(
            listOf("com.bravo", "com.delta", "com.alpha", "com.charlie"),
            ordered.map { it.packageName },
        )
    }

    @Test
    fun emptySelectionKeepsAlphabeticalOrder() {
        val ordered = AppListOrdering.prioritize(apps, emptySet())
        assertEquals(
            listOf("com.alpha", "com.bravo", "com.charlie", "com.delta"),
            ordered.map { it.packageName },
        )
    }

    @Test
    fun unknownPackagesAreIgnored() {
        val ordered = AppListOrdering.prioritize(apps, setOf("com.missing"))
        assertEquals(
            listOf("com.alpha", "com.bravo", "com.charlie", "com.delta"),
            ordered.map { it.packageName },
        )
    }

    @Test
    fun orderingIsCaseInsensitive() {
        val mixedCase = listOf(
            AppInfo("zebra", "com.zebra"),
            AppInfo("Apple", "com.apple"),
        )
        val ordered = AppListOrdering.prioritize(mixedCase, emptySet())
        assertEquals(listOf("com.apple", "com.zebra"), ordered.map { it.packageName })
    }
}
