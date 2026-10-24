package io.sshproxy.app

internal object ProfileSelection {
    fun requireByName(profiles: List<SshProfile>, name: String): SshProfile {
        require(name.isNotBlank()) { "profile_name must not be blank" }
        val matches = profiles.filter { it.name == name }
        require(matches.isNotEmpty()) { "SSH profile '$name' was not found" }
        require(matches.size == 1) { "Multiple SSH profiles are named '$name'; choose a unique name" }
        return matches.single()
    }
}
