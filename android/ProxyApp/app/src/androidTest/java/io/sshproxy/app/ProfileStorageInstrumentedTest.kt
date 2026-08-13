package io.sshproxy.app

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ProfileStorageInstrumentedTest {
    private val preferenceName = "ssh_profiles_instrumentation_test"
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val preferences by lazy {
        context.getSharedPreferences(preferenceName, android.content.Context.MODE_PRIVATE)
    }

    @Before
    fun clearPreferences() {
        preferences.edit().clear().commit()
    }

    @Test
    fun cipherRoundTripsAndRejectsTampering() {
        val cipher = AndroidKeystoreProfileCipher()
        val plaintext = "private-${System.nanoTime()}"
        val encrypted = cipher.encrypt(plaintext)

        assertNotEquals(plaintext, encrypted)
        assertEquals(plaintext, cipher.decrypt(encrypted))

        val replacement = if (encrypted.last() == 'A') 'B' else 'A'
        val tampered = encrypted.dropLast(1) + replacement
        try {
            cipher.decrypt(tampered)
            throw AssertionError("Tampered profile ciphertext was accepted")
        } catch (_: ProfileStorageException) {
            // Expected: AES-GCM authentication must reject modified ciphertext.
        }
    }

    @Test
    fun legacyProfilesAreMigratedWithoutLeavingPlaintext() {
        val profile = SshProfile(
            id = "migration-test",
            name = "Migration",
            host = "example.test",
            port = 22,
            username = "root",
            privateKeyBase64 = "secret-key-material",
            hostKeySha256 = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        preferences.edit().putString("profiles_json", JSONArray().put(profile.toJson()).toString()).commit()

        val loaded = ProfileStore(context, preferenceName = preferenceName).getProfiles()

        assertEquals(listOf(profile), loaded)
        assertFalse(preferences.contains("profiles_json"))
        val encrypted = preferences.getString("profiles_encrypted_v1", null)
        assertNotNull(encrypted)
        assertTrue(encrypted?.contains(profile.privateKeyBase64) == false)
    }
}
