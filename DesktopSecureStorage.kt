package ir.iconkadeh.library.storage

import com.russhwolf.settings.Settings
import ir.iconkadeh.admin.base.SecureStorage
import java.io.File
import java.net.NetworkInterface
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class DesktopSecureStorage(
    private val settings: Settings
) : SecureStorage {

    // Define the key file location in a hidden user directory
    private val keyFile = File(System.getProperty("user.home"), ".iconkadeh_secure_store/master_key.dat")
    private val algorithm = "AES"
    private val transformation = "AES/GCM/NoPadding"
    private val tagLength = 128
    private val ivLength = 12

    // Cache the secret key in memory to avoid reading file on every operation
    private var cachedSecretKey: SecretKey? = null

    init {
        // Ensure the directory exists with restricted permissions
        prepareKeyDirectory()
    }

    /**
     * Prepares the directory and sets strict file permissions for Linux/macOS.
     */
    private fun prepareKeyDirectory() {
        val parent = keyFile.parentFile
        if (!parent.exists()) {
            parent.mkdirs()
        }
        
        // Apply strict permissions if the OS supports POSIX (Linux/macOS)
        // This ensures other users on the system cannot read the key file
        try {
            val path = parent.toPath()
            if (path.fileSystem.supportedFileAttributeViews().contains("posix")) {
                val permissions = HashSet<PosixFilePermission>()
                permissions.add(PosixFilePermission.OWNER_READ)
                permissions.add(PosixFilePermission.OWNER_WRITE)
                permissions.add(PosixFilePermission.OWNER_EXECUTE)
                Files.setPosixFilePermissions(path, permissions)
                
                if (keyFile.exists()) {
                    val filePerms = HashSet<PosixFilePermission>()
                    filePerms.add(PosixFilePermission.OWNER_READ)
                    filePerms.add(PosixFilePermission.OWNER_WRITE)
                    Files.setPosixFilePermissions(keyFile.toPath(), filePerms)
                }
            }
        } catch (ignored: Exception) {
            // Permission setting might fail on some file systems, proceed safely
        }
    }

    /**
     * Generates a unique key based on the machine hardware and user info.
     * This ensures the key file cannot be simply copied and used on another machine.
     */
    private fun getMachineBoundKey(): SecretKey {
        val sb = StringBuilder()
        sb.append(System.getProperty("user.name", "unknown_user"))
        sb.append(System.getProperty("os.name", "unknown_os"))
        sb.append(System.getProperty("os.arch", "unknown_arch"))

        try {
            // Try to get Hardware Address (MAC) for stronger binding
            val networks = NetworkInterface.getNetworkInterfaces()
            while (networks.hasMoreElements()) {
                val network = networks.nextElement()
                val mac = network.hardwareAddress
                if (mac != null) {
                    for (b in mac) {
                        sb.append(String.format("%02X", b))
                    }
                    // We just need one stable interface
                    if (sb.length > 100) break 
                }
            }
        } catch (ignored: Exception) {
            // Fallback to system properties only if network check fails
        }

        val sha = MessageDigest.getInstance("SHA-256")
        val keyBytes = sha.digest(sb.toString().toByteArray(StandardCharsets.UTF_8))
        return SecretKeySpec(keyBytes, algorithm)
    }

    /**
     * Retrieves the Master Key.
     * If existing: Reads from file and decrypts it using the Machine Key.
     * If new: Generates random key, encrypts it with Machine Key, saves to file.
     */
    @Synchronized
    private fun getOrGenerateKey(): SecretKey {
        if (cachedSecretKey != null) return cachedSecretKey!!

        val machineKey = getMachineBoundKey()

        if (keyFile.exists()) {
            try {
                val fileContent = keyFile.readText(StandardCharsets.UTF_8)
                val parts = fileContent.split(":")
                if (parts.size == 2) {
                    val iv = Base64.getDecoder().decode(parts[0])
                    val encryptedKey = Base64.getDecoder().decode(parts[1])

                    val cipher = Cipher.getInstance(transformation)
                    val spec = GCMParameterSpec(tagLength, iv)
                    cipher.init(Cipher.DECRYPT_MODE, machineKey, spec)
                    
                    val originalKeyBytes = cipher.doFinal(encryptedKey)
                    cachedSecretKey = SecretKeySpec(originalKeyBytes, algorithm)
                    return cachedSecretKey!!
                }
            } catch (e: Exception) {
                // If decryption fails (e.g. machine changed), we might need to reset
                System.err.println("Failed to load secure key. creating new one. Data loss implies.")
            }
        }

        // Generate new random master key
        val newKeyBytes = ByteArray(32) // 256-bit key
        SecureRandom().nextBytes(newKeyBytes)
        val masterKey = SecretKeySpec(newKeyBytes, algorithm)

        // Encrypt this master key using the Machine Key
        val cipher = Cipher.getInstance(transformation)
        val iv = ByteArray(ivLength)
        SecureRandom().nextBytes(iv)
        val spec = GCMParameterSpec(tagLength, iv)
        cipher.init(Cipher.ENCRYPT_MODE, machineKey, spec)
        
        val encryptedMasterKey = cipher.doFinal(newKeyBytes)
        val ivString = Base64.getEncoder().encodeToString(iv)
        val keyString = Base64.getEncoder().encodeToString(encryptedMasterKey)

        keyFile.writeText("$ivString:$keyString", StandardCharsets.UTF_8)
        
        // Re-apply permissions just in case
        prepareKeyDirectory()

        cachedSecretKey = masterKey
        return masterKey
    }

    private fun encrypt(data: String): String {
        val cipher = Cipher.getInstance(transformation)
        val iv = ByteArray(ivLength)
        SecureRandom().nextBytes(iv)
        val spec = GCMParameterSpec(tagLength, iv)
        
        cipher.init(Cipher.ENCRYPT_MODE, getOrGenerateKey(), spec)
        val encrypted = cipher.doFinal(data.toByteArray(StandardCharsets.UTF_8))
        
        val ivString = Base64.getEncoder().encodeToString(iv)
        val dataString = Base64.getEncoder().encodeToString(encrypted)
        return "$ivString:$dataString"
    }

    private fun decrypt(data: String): String {
        val parts = data.split(":")
        if (parts.size != 2) throw IllegalArgumentException("Invalid encrypted data format")
        
        val iv = Base64.getDecoder().decode(parts[0])
        val content = Base64.getDecoder().decode(parts[1])
        
        val spec = GCMParameterSpec(tagLength, iv)
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.DECRYPT_MODE, getOrGenerateKey(), spec)
        
        return String(cipher.doFinal(content), StandardCharsets.UTF_8)
    }

    // --- Interface Implementation ---

    override fun putString(key: String, value: String) {
        try {
            settings.putString(key, encrypt(value))
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    override fun getString(key: String, defaultValue: String?): String? {
        val data = settings.getStringOrNull(key) ?: return defaultValue
        return try {
            decrypt(data)
        } catch (e: Exception) {
            // Normally happens if key changed or data corruption
            e.printStackTrace()
            defaultValue
        }
    }

    override fun putInt(key: String, value: Int) {
        putString(key, value.toString())
    }

    override fun getInt(key: String, defaultValue: Int): Int {
        val str = getString(key, null) ?: return defaultValue
        return str.toIntOrNull() ?: defaultValue
    }

    override fun putBoolean(key: String, value: Boolean) {
        putString(key, value.toString())
    }

    override fun getBoolean(key: String, defaultValue: Boolean): Boolean {
        val str = getString(key, null) ?: return defaultValue
        return str.toBooleanStrictOrNull() ?: defaultValue
    }
    
    // Add other missing primitive types to ensure full support
    fun putLong(key: String, value: Long) {
        putString(key, value.toString())
    }
    
    fun getLong(key: String, defaultValue: Long): Long {
         val str = getString(key, null) ?: return defaultValue
        return str.toLongOrNull() ?: defaultValue
    }
    
    fun putFloat(key: String, value: Float) {
        putString(key, value.toString())
    }
    
    fun getFloat(key: String, defaultValue: Float): Float {
        val str = getString(key, null) ?: return defaultValue
        return str.toFloatOrNull() ?: defaultValue
    }

    override fun remove(key: String) {
        settings.remove(key)
    }

    override fun clear() {
        settings.clear()
        // Optional: Also delete the key file if you want a complete wipe, 
        // but typically 'clear' only clears data, not keys.
    }
}