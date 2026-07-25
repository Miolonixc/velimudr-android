package com.hermes.velimudr

import android.app.Activity
import android.content.Intent
import android.content.SharedPreferences
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.Bundle
import android.widget.*
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.hermes.velimudr.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.RequestBody.Companion.asRequestBody
import okhttp3.MultipartBody
import com.wireguard.android.backend.Backend
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import java.io.BufferedReader
import java.io.ByteArrayOutputStream
import java.io.StringReader
import java.io.File
import java.lang.Exception
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class WgTunnel(private val tunnelName: String) : Tunnel {
    override fun getName(): String = tunnelName
    override fun onStateChange(newState: Tunnel.State) {}
}

// OkHttpClient that trusts self-signed certs (homelab VPN *.srv.local)
fun trustAllClient(): OkHttpClient {
    val trustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }
    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, arrayOf(trustManager), SecureRandom())
    return OkHttpClient.Builder()
        .sslSocketFactory(sslContext.socketFactory, trustManager)
        .hostnameVerifier { _, _ -> true }
        .build()
}

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val client = trustAllClient()
    private var backend: Backend? = null
    private var tunnel: Tunnel? = null
    private var wgConnected: Boolean = false
    private lateinit var prefs: SharedPreferences
    private var styleIdx = 0

    private val PREFS_NAME = "velimudr"
    private val KEY_CONF = "wg_conf"

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            doConnectWg()
        } else {
            Toast.makeText(this, "Разрешение VPN не предоставлено", Toast.LENGTH_SHORT).show()
            setHubBusy(false)
        }
    }

    private val LLM_CHAT = "https://llm.srv.local/chat"
    private val LLM_TRANSCRIBE = "https://llm.srv.local/transcribe"
    private val LLM_VISION = "https://llm.srv.local/vision"
    private val sessionId = "android-" + System.currentTimeMillis()

    private val STYLES = arrayOf(
        "обычный", "пацанский", "чиловый", "пиджак", "флирт", "ментор", "киберпанк"
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        styleIdx = prefs.getInt("style_idx", 0)

        // Hub button: tap -> load conf (if none) then connect VPN
        binding.btnHub.setOnClickListener { onHubTap() }
        // Style toggle: cycle through styles
        binding.btnStyle.setOnClickListener { cycleStyle() }
        binding.btnSend.setOnClickListener { sendMessage() }
        binding.btnMic.setOnClickListener { pickAudio() }
        binding.btnPhoto.setOnClickListener { pickPhoto() }

        if (prefs.contains(KEY_CONF)) {
            binding.tvStatus.text = "Конфиг сохранён. Нажми кружок для VPN"
        }
        showStyle()
    }

    private fun cycleStyle() {
        styleIdx = (styleIdx + 1) % STYLES.size
        prefs.edit().putInt("style_idx", styleIdx).apply()
        showStyle()
    }

    private fun showStyle() {
        binding.tvStatus.text = "Стиль: ${STYLES[styleIdx]}"
    }

    // --- Hub button logic ---
    private fun onHubTap() {
        if (wgConnected) {
            disconnectWg()
            return
        }
        val saved = prefs.getString(KEY_CONF, null)
        if (saved.isNullOrEmpty()) {
            pickConf()
        } else {
            prepareAndConnect()
        }
    }

    private fun prepareAndConnect() {
        setHubBusy(true)
        val prepareIntent = GoBackend.VpnService.prepare(this)
        if (prepareIntent != null) {
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            doConnectWg()
        }
    }

    // --- WireGuard config loader with validation + persistence ---
    private val confPicker = registerForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
        uri ?: return@registerForActivityResult
        try {
            val text = contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() } ?: ""
            val validation = validateWgConf(text)
            if (!validation.first) {
                Toast.makeText(this, "Конфиг невалиден: ${validation.second}", Toast.LENGTH_LONG).show()
                return@registerForActivityResult
            }
            prefs.edit().putString(KEY_CONF, text).apply()
            Toast.makeText(this, "Конфиг сохранён", Toast.LENGTH_SHORT).show()
            prepareAndConnect()
        } catch (e: Exception) {
            Toast.makeText(this, "Ошибка чтения: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun pickConf() {
        confPicker.launch("*/*")
    }

    private fun validateWgConf(text: String): Pair<Boolean, String> {
        if (!text.contains("[Interface]")) return false to "нет секции [Interface]"
        if (!text.contains("PrivateKey")) return false to "нет PrivateKey"
        if (!text.contains("[Peer]")) return false to "нет секции [Peer]"
        if (!text.contains("PublicKey")) return false to "нет PublicKey у Peer"
        if (!text.contains("Endpoint")) return false to "нет Endpoint у Peer"
        if (!text.contains("AllowedIPs")) return false to "нет AllowedIPs"
        try {
            Config.parse(BufferedReader(StringReader(text)))
        } catch (e: Exception) {
            return false to "ошибка парсинга: ${e.message}"
        }
        return true to "OK"
    }

    private fun doConnectWg() {
        val conf = prefs.getString(KEY_CONF, null)
        if (conf == null) {
            setHubBusy(false)
            Toast.makeText(this, "Сначала загрузи .conf (кружок)", Toast.LENGTH_LONG).show()
            return
        }
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                backend = GoBackend(applicationContext)
                val config = Config.parse(BufferedReader(StringReader(conf)))
                tunnel = WgTunnel("velimudr-tunnel")
                backend!!.setState(tunnel!!, Tunnel.State.UP, config)
                wgConnected = true
                withContext(Dispatchers.Main) {
                    setHubBusy(false)
                    binding.dotConnected.visibility = android.view.View.VISIBLE
                    binding.tvStatus.text = "WG: подключен ✅"
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    setHubBusy(false)
                    Toast.makeText(this@MainActivity, "Ошибка WG: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun disconnectWg() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                tunnel?.let { backend?.setState(it, Tunnel.State.DOWN, null) }
                wgConnected = false
                withContext(Dispatchers.Main) {
                    binding.dotConnected.visibility = android.view.View.GONE
                    binding.tvStatus.text = "WG: отключен"
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity, "Ошибка отключения: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun setHubBusy(busy: Boolean) {
        binding.progressHub.visibility = if (busy) android.view.View.VISIBLE else android.view.View.GONE
        binding.btnHub.visibility = if (busy) android.view.View.GONE else android.view.View.VISIBLE
        if (busy) binding.tvStatus.text = "Подключение VPN..."
    }

    // --- Chat ---
    private fun sendMessage() {
        val text = binding.etMessage.text.toString().trim()
        if (text.isEmpty()) return
        binding.tvChat.append("Вы: $text\n")
        binding.etMessage.text.clear()
        val style = STYLES[styleIdx]
        val prompt = if (style == "обычный") text else "[Стиль общения: $style]\n\n$text"
        callLlm(prompt, "Velimudr")
    }

    private fun callLlm(prompt: String, who: String) {
        setBusy(true)
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val json = """{"session_id":"$sessionId","message":${quote(prompt)}}"""
                val body = json.toRequestBody("application/json".toMediaType())
                val req = Request.Builder().url(LLM_CHAT).post(body).build()
                val resp = client.newCall(req).execute()
                val raw = resp.body?.string() ?: ""
                val reply = raw.lines().filter { it.startsWith("data:") }
                    .joinToString("") { it.removePrefix("data:").trim() }.ifBlank { raw }
                withContext(Dispatchers.Main) {
                    binding.tvChat.append("$who: $reply\n\n")
                    setBusy(false)
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    binding.tvChat.append("Ошибка: ${e.message}\n\n")
                    setBusy(false)
                }
            }
        }
    }

    private fun setBusy(b: Boolean) {
        binding.progressBusy.visibility = if (b) android.view.View.VISIBLE else android.view.View.GONE
    }

    // --- Voice (STT) ---
    private val audioPicker = registerForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
        uri ?: return@registerForActivityResult
        setBusy(true)
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val input = contentResolver.openInputStream(uri) ?: return@launch
                val tmp = File.createTempFile("voice", ".ogg", cacheDir)
                tmp.outputStream().use { input.copyTo(it) }
                val reqBody = tmp.asRequestBody("audio/*".toMediaType())
                val req = Request.Builder().url(LLM_TRANSCRIBE)
                    .post(MultipartBody.Builder().setType(MultipartBody.FORM)
                        .addFormDataPart("file", "voice.ogg", reqBody).build()).build()
                val resp = client.newCall(req).execute()
                val text = resp.body?.string() ?: ""
                withContext(Dispatchers.Main) {
                    binding.etMessage.setText(text)
                    binding.tvChat.append("🎤: $text\n")
                    setBusy(false)
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    binding.tvChat.append("🎤 ошибка: ${e.message}\n\n")
                    setBusy(false)
                }
            }
        }
    }

    private fun pickAudio() {
        audioPicker.launch("audio/*")
    }

    // --- Photo (vision) ---
    private val photoPicker = registerForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
        uri ?: return@registerForActivityResult
        setBusy(true)
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val input = contentResolver.openInputStream(uri) ?: return@launch
                // downscale to <=1024px to stay well under upload limit
                val bytes = compressImage(input.readBytes())
                val reqBody = bytes.toRequestBody("image/jpeg".toMediaType())
                val req = Request.Builder().url(LLM_VISION)
                    .post(MultipartBody.Builder().setType(MultipartBody.FORM)
                        .addFormDataPart("file", "photo.jpg", reqBody).build()).build()
                val resp = client.newCall(req).execute()
                val desc = resp.body?.string() ?: ""
                withContext(Dispatchers.Main) {
                    binding.tvChat.append("🖼️: $desc\n\n")
                    setBusy(false)
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    binding.tvChat.append("🖼️ ошибка: ${e.message}\n\n")
                    setBusy(false)
                }
            }
        }
    }

    private fun compressImage(data: ByteArray): ByteArray {
        val bmp = BitmapFactory.decodeByteArray(data, 0, data.size) ?: return data
        val max = 1024
        val scale = minOf(1.0, max.toFloat() / maxOf(bmp.width, bmp.height))
        val w = (bmp.width * scale).toInt()
        val h = (bmp.height * scale).toInt()
        val out = Bitmap.createScaledBitmap(bmp, w, h, true)
        val stream = ByteArrayOutputStream()
        out.compress(Bitmap.CompressFormat.JPEG, 80, stream)
        return stream.toByteArray()
    }

    private fun pickPhoto() {
        photoPicker.launch("image/*")
    }

    private fun quote(s: String): String {
        val esc = s.replace("\\", "\\\\").replace("\"", "\\\"")
            .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
        return "\"$esc\""
    }

    override fun onDestroy() {
        super.onDestroy()
        try {
            val t = tunnel
            if (t != null) backend?.setState(t, Tunnel.State.DOWN, null)
        } catch (_: Exception) {}
    }
}
