package ir.iconkadeh.library.storage

import com.russhwolf.settings.KeychainSettings
import com.russhwolf.settings.Settings

class IosSecureStorage : SecureStorage {
    
    private val settings: Settings = KeychainSettings(service = "ir.iconkadeh.app.secure")

    override fun putString(key: String, value: String) {
        settings.putString(key, value)
    }

    override fun getString(key: String, defaultValue: String?): String? {
        return settings.getStringOrNull(key) ?: defaultValue
    }

    override fun putInt(key: String, value: Int) {
        settings.putInt(key, value)
    }

    override fun getInt(key: String, defaultValue: Int): Int {
        return settings.getInt(key, defaultValue)
    }

    override fun putBoolean(key: String, value: Boolean) {
        settings.putBoolean(key, value)
    }

    override fun getBoolean(key: String, defaultValue: Boolean): Boolean {
        return settings.getBoolean(key, defaultValue)
    }

    override fun remove(key: String) {
        settings.remove(key)
    }

    override fun clear() {
        settings.clear()
    }
}