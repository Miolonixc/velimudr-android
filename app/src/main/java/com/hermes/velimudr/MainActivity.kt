package com.hermes.velimudr

import android.app.Activity
import android.content.Intent
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
import java.io.StringReader
import java.io.File
import java.lang.Exception

class WgTunnel(private val tunnelName: String) : Tunnel {
    override fun getName(): String = tunnelName
    override fun onStateChange(newState: Tunnel.State) {}
}

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val client = OkHttpClient()
    private var backend: Backend? = null
    private var tunnel: Tunnel? = null
    private var wgConf: String? = null

    private val LLM_CHAT = "http://llm.srv.local/chat"
    private val LLM_TRANSCRIBE = "http://llm.srv.local/transcribe"
    private val LLM_TTS = "http://llm.srv.local/tts"
    private val LLM_VISION = "http://llm.srv.local/vision"
    private val sessionId = "android-" + System.currentTimeMillis()

    // Styles list (mirrors bot.py STYLES)
    private val STYLES = arrayOf(
        "обычный", "пацанский", "чиловый", "пиджак", "флирт", "ментор", "киберпанк"
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Style spinner
        val styleAdapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, STYLES)
        styleAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        binding.spinnerStyle.adapter = styleAdapter

        binding.btnConnect.setOnClickListener { connectWg() }
        binding.btnLoadConf.setOnClickListener { pickConf() }
        binding.btnSend.setOnClickListener { sendMessage() }
        binding.btnMic.setOnClickListener { pickAudio() }
        binding.btnPhoto.setOnClickListener { pickPhoto() }
    }

    // --- WireGuard config loader with validation ---
    private val confPicker = registerForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
        uri ?: return@registerForActivityResult
        try {
            val text = contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() } ?: ""
            val validation = validateWgConf(text)
            if (!validation.first) {
                Toast.makeText(this, "Конфиг невалиден: ${validation.second}", Toast.LENGTH_LONG).show()
                return@registerForActivityResult
            }
            wgConf = text
            binding.tvStatus.text = "WG: конфиг загружен ✅ (${validation.second})"
            Toast.makeText(this, "Конфиг загружен", Toast.LENGTH_SHORT).show()
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
        // Try parse via library
        try {
            Config.parse(BufferedReader(StringReader(text)))
        } catch (e: Exception) {
            return false to "ошибка парсинга: ${e.message}"
        }
        return true to "OK"
    }

    private fun connectWg() {
        val conf = wgConf
        if (conf == null) {
            Toast.makeText(this, "Сначала загрузи .conf (кнопка 📁)", Toast.LENGTH_LONG).show()
            return
        }
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                backend = GoBackend(applicationContext)
                val config = Config.parse(BufferedReader(StringReader(conf)))
                tunnel = WgTunnel("velimudr-tunnel")
                val prepareIntent = GoBackend.VpnService.prepare(this@MainActivity)
                if (prepareIntent != null) {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@MainActivity, "Подтверди VPN в системном диалоге", Toast.LENGTH_LONG).show()
                    }
                    // Note: proper flow needs startActivityForResult; simplified here
                    return@launch
                }
                backend!!.setState(tunnel!!, Tunnel.State.UP, config)
                withContext(Dispatchers.Main) {
                    binding.tvStatus.text = "WG: подключен ✅"
                    binding.btnConnect.isEnabled = false
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity, "Ошибка WG: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    // --- Chat ---
    private fun sendMessage() {
        val text = binding.etMessage.text.toString().trim()
        if (text.isEmpty()) return
        binding.tvChat.append("Вы: $text\n")
        binding.etMessage.text.clear()
        val style = STYLES[binding.spinnerStyle.selectedItemPosition]
        val prompt = if (style == "обычный") text else "[Стиль общения: $style]\n\n$text"
        callLlm(prompt, "Velimudr")
    }

    private fun callLlm(prompt: String, who: String) {
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
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) { binding.tvChat.append("Ошибка: ${e.message}\n\n") }
            }
        }
    }

    // --- Voice (STT + TTS) ---
    private val audioPicker = registerForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
        uri ?: return@registerForActivityResult
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
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) { Toast.makeText(this@MainActivity, "STT ошибка: ${e.message}", Toast.LENGTH_SHORT).show() }
            }
        }
    }

    private fun pickAudio() {
        audioPicker.launch("audio/*")
    }

    // --- Photo (vision) ---
    private val photoPicker = registerForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
        uri ?: return@registerForActivityResult
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val input = contentResolver.openInputStream(uri) ?: return@launch
                val tmp = File.createTempFile("photo", ".jpg", cacheDir)
                tmp.outputStream().use { input.copyTo(it) }
                val reqBody = tmp.asRequestBody("image/*".toMediaType())
                val req = Request.Builder().url(LLM_VISION)
                    .post(MultipartBody.Builder().setType(MultipartBody.FORM)
                        .addFormDataPart("file", "photo.jpg", reqBody).build()).build()
                val resp = client.newCall(req).execute()
                val desc = resp.body?.string() ?: ""
                withContext(Dispatchers.Main) {
                    binding.tvChat.append("🖼️: $desc\n\n")
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) { Toast.makeText(this@MainActivity, "Vision ошибка: ${e.message}", Toast.LENGTH_SHORT).show() }
            }
        }
    }

    private fun pickPhoto() {
        photoPicker.launch("image/*")
    }

    private fun quote(s: String): String {
        val esc = s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
        return "\"$esc\""
    }

    override fun onDestroy() {
        super.onDestroy()
        try { tunnel?.let { backend?.setState(it, Tunnel.State.DOWN, null) } } catch (_: Exception) {}
    }
}
