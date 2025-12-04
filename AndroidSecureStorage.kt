package ir.iconkadeh.library.storage

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.russhwolf.settings.Settings
import ir.iconkadeh.admin.base.SecureStorage
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class AndroidSecureStorage(
    private val settings: Settings
) : SecureStorage {

    private val keyAlias = "AndroidSecureKeyAlias_v1"
    private val provider = "AndroidKeyStore"
    private val transformation = "AES/GCM/NoPadding"

    private fun getSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(provider)
        keyStore.load(null)
        keyStore.getEntry(keyAlias, null)?.let {
            return (it as KeyStore.SecretKeyEntry).secretKey
        }
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, provider)
        val spec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    private fun encrypt(data: String): String {
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey())
        val iv = cipher.iv
        val encryptedBytes = cipher.doFinal(data.toByteArray(Charsets.UTF_8))
        val ivString = Base64.encodeToString(iv, Base64.NO_WRAP)
        val dataString = Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)
        return "$ivString:$dataString"
    }

    private fun decrypt(data: String): String {
        val parts = data.split(":")
        if (parts.size != 2) throw IllegalArgumentException("Invalid encrypted data format")
        val iv = Base64.decode(parts[0], Base64.NO_WRAP)
        val encryptedBytes = Base64.decode(parts[1], Base64.NO_WRAP)
        val cipher = Cipher.getInstance(transformation)
        val spec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(), spec)
        return String(cipher.doFinal(encryptedBytes), Charsets.UTF_8)
    }

    override fun putString(key: String, value: String) {
        try {
            settings.putString(key, encrypt(value))
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    override fun getString(key: String, defaultValue: String?): String? {
        val encrypted = settings.getStringOrNull(key) ?: return defaultValue
        return try {
            decrypt(encrypted)
        } catch (e: Exception) {
            e.printStackTrace()
            defaultValue
        }
    }

    override fun putInt(key: String, value: Int) {
        putString(key, value.toString())
    }

    override fun getInt(key: String, defaultValue: Int): Int {
        return getString(key)?.toIntOrNull() ?: defaultValue
    }

    override fun putBoolean(key: String, value: Boolean) {
        putString(key, value.toString())
    }

    override fun getBoolean(key: String, defaultValue: Boolean): Boolean {
        return getString(key)?.toBooleanStrictOrNull() ?: defaultValue
    }

    override fun remove(key: String) {
        settings.remove(key)
    }

    override fun clear() {
        settings.clear()
    }
}
