package io.sshproxy.app

object ByeDpiPresets {

    data class Preset(val name: String, val args: String)

    // No -S (TCP MD5 Signature) presets here: some Android kernels do not support it and
    // ByeDPI fails the connection instead of falling back (desync.c set_md5sig path).
    val ALL: List<Preset> = listOf(
        Preset("Default", DEFAULT_BYEDPI_ARGS),
        Preset("Fake only", "-f -1 -t 8"),
        Preset("Disorder + torst + TLS record", "-d 1 -A torst -r 1+s"),
        Preset("OOB only", "--oob 1"),
        Preset("Fake + TLS record", "-f -1 -r 3+s"),
    )

    fun matchArgs(args: String): Preset? = ALL.find { it.args == args.trim() }

    /**
     * Appends the ByeDPI debug level as `-x <level>` to the argument string. ByeDPI keeps the
     * last parsed value, so the appended flag overrides any `-x` typed inside the arguments.
     * Levels verified against third_party/byedpi: 1 enables connection/strategy logs, 2 also
     * enables verbose logging (main.c help text, error.h).
     */
    fun effectiveByeDpiArgs(args: String, debugLevel: Int): String {
        val base = args.trim()
        val level = debugLevel.coerceIn(0, 2)
        if (level == 0) {
            return base
        }
        return if (base.isEmpty()) "-x $level" else "$base -x $level"
    }
}
