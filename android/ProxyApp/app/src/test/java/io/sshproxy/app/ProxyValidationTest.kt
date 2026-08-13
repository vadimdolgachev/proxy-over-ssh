package io.sshproxy.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProxyValidationTest {
    @Test
    fun validBoundaryPortsAreAccepted() {
        assertEquals(1, ProxyValidation.requireValidPort(1, "Port"))
        assertEquals(65535, ProxyValidation.requireValidPort(65535, "Port"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun zeroPortIsRejected() {
        ProxyValidation.requireValidPort(0, "Port")
    }

    @Test(expected = IllegalArgumentException::class)
    fun emptySelectedApplicationListIsRejected() {
        ProxyValidation.requireSelectedApplications(setOf("", "  "))
    }

    @Test
    fun onlyTransitionalAndRunningStatesAreActive() {
        assertFalse(ProxyStatus(ProxyState.STOPPED).isActive)
        assertTrue(ProxyStatus(ProxyState.STARTING).isActive)
        assertTrue(ProxyStatus(ProxyState.RUNNING).isActive)
        assertTrue(ProxyStatus(ProxyState.STOPPING).isActive)
        assertFalse(ProxyStatus(ProxyState.ERROR).isActive)
    }
}
