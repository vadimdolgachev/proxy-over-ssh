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
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("id", id)
            put("name", name)
            put("host", host)
            put("port", port)
            put("username", username)
            put("privateKeyBase64", privateKeyBase64)
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
    }
}

class ProfileStore(context: Context) {

    private val prefs = context.getSharedPreferences("ssh_profiles", Context.MODE_PRIVATE)

    fun getProfiles(): List<SshProfile> {
        val json = prefs.getString(KEY_PROFILES, null) ?: return emptyList()
        val array = JSONArray(json)
        return (0 until array.length()).map { i ->
            SshProfile.fromJson(array.getJSONObject(i))
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
        prefs.edit().putString(KEY_PROFILES, array.toString()).apply()
    }

    fun getRunningProfileId(): String? = prefs.getString(KEY_RUNNING_PROFILE, null)

    fun setRunningProfileId(id: String?) {
        prefs.edit().apply {
            if (id != null) putString(KEY_RUNNING_PROFILE, id) else remove(KEY_RUNNING_PROFILE)
        }.apply()
    }

    companion object {
        private const val KEY_PROFILES = "profiles_json"
        private const val KEY_RUNNING_PROFILE = "running_profile_id"
    }
}
