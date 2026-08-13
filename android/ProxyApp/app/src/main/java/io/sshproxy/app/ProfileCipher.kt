package io.sshproxy.app

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class ProfileStorageException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

internal interface ProfileCipher {
    fun encrypt(plaintext: String): String
    fun decrypt(payload: String): String
}

internal class AndroidKeystoreProfileCipher : ProfileCipher {
    override fun encrypt(plaintext: String): String {
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
            cipher.updateAAD(AAD)
            val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
            val iv = cipher.iv
            check(iv.size == IV_SIZE_BYTES) { "Android Keystore returned an invalid GCM IV" }
            return listOf(
                FORMAT_VERSION,
                Base64.getEncoder().encodeToString(iv),
                Base64.getEncoder().encodeToString(ciphertext),
            ).joinToString(":")
        } catch (e: Exception) {
            throw ProfileStorageException("Unable to encrypt SSH profiles", e)
        }
    }

    override fun decrypt(payload: String): String {
        try {
            val fields = payload.split(':', limit = 3)
            require(fields.size == 3 && fields[0] == FORMAT_VERSION) { "Unsupported profile format" }
            val iv = Base64.getDecoder().decode(fields[1])
            require(iv.size == IV_SIZE_BYTES) { "Invalid profile encryption IV" }
            val ciphertext = Base64.getDecoder().decode(fields[2])
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, getExistingKey(), GCMParameterSpec(TAG_SIZE_BITS, iv))
            cipher.updateAAD(AAD)
            return cipher.doFinal(ciphertext).toString(Charsets.UTF_8)
        } catch (e: ProfileStorageException) {
            throw e
        } catch (e: Exception) {
            throw ProfileStorageException("Unable to decrypt SSH profiles; the saved data was preserved", e)
        }
    }

    private fun getExistingKey(): SecretKey {
        val keyStore = loadKeyStore()
        return keyStore.getKey(KEY_ALIAS, null) as? SecretKey
            ?: throw ProfileStorageException("SSH profile encryption key is unavailable")
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = loadKeyStore()
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }

    private fun loadKeyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "ssh_proxy_profiles_aes_v1"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val FORMAT_VERSION = "v1"
        const val IV_SIZE_BYTES = 12
        const val TAG_SIZE_BITS = 128
        val AAD = "io.sshproxy.app:ssh_profiles:v1".toByteArray(Charsets.UTF_8)
    }
}
