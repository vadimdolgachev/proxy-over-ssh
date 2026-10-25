package io.sshproxy.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ByeDpiPresetsTest {

    @Test
    fun defaultArgsMatchTheDefaultPreset() {
        assertEquals("Default", ByeDpiPresets.matchArgs(DEFAULT_BYEDPI_ARGS)?.name)
    }

    @Test
    fun presetArgsAreMatchedAfterTrimming() {
        val preset = ByeDpiPresets.ALL.first()
        assertEquals(preset.name, ByeDpiPresets.matchArgs("  ${preset.args}  ")?.name)
    }

    @Test
    fun everyPresetMatchesItself() {
        ByeDpiPresets.ALL.forEach { preset ->
            assertEquals(preset.name, ByeDpiPresets.matchArgs(preset.args)?.name)
        }
    }

    @Test
    fun customArgsDoNotMatchAnyPreset() {
        assertNull(ByeDpiPresets.matchArgs("-f -1 -t 9 -S"))
        assertNull(ByeDpiPresets.matchArgs(""))
    }

    @Test
    fun presetsHaveUniqueNonEmptyNamesAndArgs() {
        assertTrue(ByeDpiPresets.ALL.isNotEmpty())
        assertEquals(ByeDpiPresets.ALL.size, ByeDpiPresets.ALL.map { it.name }.toSet().size)
        assertEquals(ByeDpiPresets.ALL.size, ByeDpiPresets.ALL.map { it.args }.toSet().size)
        assertTrue(ByeDpiPresets.ALL.all { it.name.isNotBlank() && it.args.isNotBlank() })
    }

    @Test
    fun debugLevelZeroLeavesArgsUnchanged() {
        assertEquals(DEFAULT_BYEDPI_ARGS, ByeDpiPresets.effectiveByeDpiArgs(DEFAULT_BYEDPI_ARGS, 0))
        assertEquals("-x 1", ByeDpiPresets.effectiveByeDpiArgs("-x 1", 0))
        assertEquals("-f -1", ByeDpiPresets.effectiveByeDpiArgs(" -f -1 ", 0))
    }

    @Test
    fun debugLevelAppendsXAtTheEnd() {
        assertEquals("$DEFAULT_BYEDPI_ARGS -x 1",
            ByeDpiPresets.effectiveByeDpiArgs(DEFAULT_BYEDPI_ARGS, 1))
        assertEquals("-f -1 -x 2", ByeDpiPresets.effectiveByeDpiArgs(" -f -1 ", 2))
    }

    @Test
    fun debugLevelHandlesEmptyArgs() {
        assertEquals("-x 2", ByeDpiPresets.effectiveByeDpiArgs("  ", 2))
    }
}
