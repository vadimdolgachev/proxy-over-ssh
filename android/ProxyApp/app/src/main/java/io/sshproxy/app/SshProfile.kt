package io.sshproxy.app

import android.content.Context
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

data class SshProfile(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val host: String,
    val port: Int = 22,
    val username: String,
    val privateKeyBase64: String,
    val hostKeySha256: String = "",
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("id", id)
            put("name", name)
            put("host", host)
            put("port", port)
            put("username", username)
            put("privateKeyBase64", privateKeyBase64)
            put("hostKeySha256", hostKeySha256)
        }
    }

    companion object {
        fun fromJson(json: JSONObject): SshProfile {
            return SshProfile(
                id = json.getString("id"),
                name = json.getString("name"),
                host = json.getString("host"),
                port = json.getInt("port"),
                username = json.getString("username"),
                privateKeyBase64 = json.getString("privateKeyBase64"),
                hostKeySha256 = json.optString("hostKeySha256"),
            )
        }

        fun normalizeKey(key: String): String {
            var text = key.replace("\\n", "\n")

            // If no PEM headers visible, try base64 decode (e.g. output of: cat key | base64 -w 0)
            if (!text.contains("-----BEGIN")) {
                try {
                    val decoded = String(Base64.decode(text.replace("\n", ""), Base64.DEFAULT))
                    if (decoded.contains("-----BEGIN")) {
                        text = decoded
                    }
                } catch (_: IllegalArgumentException) {
                }
            }

            return text.trim()
        }

        fun isValidHostKeySha256(fingerprint: String): Boolean {
            val digest = fingerprint.trim().removePrefix("SHA256:").removeSuffix("=")
            return digest.length == 43 && digest.all { it.isLetterOrDigit() || it == '+' || it == '/' }
        }
    }
}

class ProfileStore internal constructor(
    context: Context,
    private val cipher: ProfileCipher = AndroidKeystoreProfileCipher(),
    preferenceName: String = PREFERENCE_NAME,
) {

    private val prefs = context.getSharedPreferences(preferenceName, Context.MODE_PRIVATE)

    fun getProfiles(): List<SshProfile> {
        val encrypted = prefs.getString(KEY_PROFILES_ENCRYPTED, null)
        if (encrypted != null) {
            return parseProfiles(cipher.decrypt(encrypted))
        }

        val legacyJson = prefs.getString(KEY_PROFILES_LEGACY, null) ?: return emptyList()
        val profiles = parseProfiles(legacyJson)
        writeProfiles(profiles)
        return profiles
    }

    private fun parseProfiles(json: String): List<SshProfile> {
        try {
            val array = JSONArray(json)
            return (0 until array.length()).map { i ->
                SshProfile.fromJson(array.getJSONObject(i))
            }
        } catch (e: Exception) {
            throw ProfileStorageException("Unable to read SSH profiles; the saved data was preserved", e)
        }
    }

    fun getProfile(id: String): SshProfile? {
        return getProfiles().find { it.id == id }
    }

    fun saveProfile(profile: SshProfile) {
        val profiles = getProfiles().toMutableList()
        val index = profiles.indexOfFirst { it.id == profile.id }
        if (index >= 0) {
            profiles[index] = profile
        } else {
            profiles.add(profile)
        }
        writeProfiles(profiles)
    }

    fun deleteProfile(id: String) {
        val profiles = getProfiles().filter { it.id != id }
        writeProfiles(profiles)
    }

    private fun writeProfiles(profiles: List<SshProfile>) {
        val array = JSONArray()
        profiles.forEach { array.put(it.toJson()) }
        val encrypted = cipher.encrypt(array.toString())
        if (!prefs.edit()
                .putString(KEY_PROFILES_ENCRYPTED, encrypted)
                .remove(KEY_PROFILES_LEGACY)
                .commit()
        ) {
            throw ProfileStorageException("Unable to save encrypted SSH profiles")
        }
    }

    fun getRunningProfileId(): String? = prefs.getString(KEY_RUNNING_PROFILE, null)

    fun setRunningProfileId(id: String?) {
        prefs.edit().apply {
            if (id != null) putString(KEY_RUNNING_PROFILE, id) else remove(KEY_RUNNING_PROFILE)
        }.apply()
    }

    companion object {
        private const val PREFERENCE_NAME = "ssh_profiles"
        private const val KEY_PROFILES_LEGACY = "profiles_json"
        private const val KEY_PROFILES_ENCRYPTED = "profiles_encrypted_v1"
        private const val KEY_RUNNING_PROFILE = "running_profile_id"
    }
}
