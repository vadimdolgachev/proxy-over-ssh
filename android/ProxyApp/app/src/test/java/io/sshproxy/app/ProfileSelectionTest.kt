package io.sshproxy.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ProfileSelectionTest {
    private fun profile(id: String, name: String) = SshProfile(
        id = id,
        name = name,
        host = "127.0.0.1",
        username = "fixture",
        privateKeyBase64 = "fixture-key",
    )

    @Test
    fun selectsRequestedNameInsteadOfFirstProfile() {
        val first = profile("first", "Other")
        val target = profile("target", "Profile name")
        assertEquals(target, ProfileSelection.requireByName(listOf(first, target), "Profile name"))
    }

    @Test
    fun rejectsMissingAndBlankNames() {
        val profiles = listOf(profile("first", "Profile name"))
        for (name in listOf("", "  ", "Missing", "profile name")) {
            assertThrows(IllegalArgumentException::class.java) { ProfileSelection.requireByName(profiles, name) }
        }
    }

    @Test
    fun rejectsAmbiguousNames() {
        val profiles = listOf(profile("first", "Profile name"), profile("second", "Profile name"))
        assertThrows(IllegalArgumentException::class.java) {
            ProfileSelection.requireByName(profiles, "Profile name")
        }
    }

    @Test
    fun matchesUnicodeAndSpacesExactly() {
        val target = profile("target", "Тестовый SSH профиль")
        assertEquals(target, ProfileSelection.requireByName(listOf(target), target.name))
    }
}
