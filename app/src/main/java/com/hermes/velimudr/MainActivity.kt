package com.hermes.velimudr

import android.os.Bundle
import android.widget.Toast
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
import com.wireguard.android.backend.Backend
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import com.wireguard.config.InetEndpoint
import com.wireguard.config.InetNetwork
import com.wireguard.config.Peer
import com.wireguard.config.Interface
import java.lang.Exception

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val client = OkHttpClient()
    private var tunnel: Tunnel? = null
    private var backend: Backend? = null

    // LLM endpoint (inside WireGuard VPN)
    private val LLM_CHAT = "http://llm.srv.local/chat"
    private val sessionId = "android-" + System.currentTimeMillis()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnConnect.setOnClickListener { connectWg() }
        binding.btnSend.setOnClickListener { sendMessage() }
    }

    private fun connectWg() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                backend = GoBackend(applicationContext)
                // Config loaded from a string pasted by the user (assets/wg.conf.example as template)
                val confText = loadWgConfig()
                val config = Config.parse(confText)
                tunnel = backend!!.create("velimudr-tunnel", config, null)
                backend!!.setState(tunnel!!, Tunnel.State.UP)
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity, "WG подключён ✅", Toast.LENGTH_SHORT).show()
                    binding.btnConnect.isEnabled = false
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity, "Ошибка WG: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun loadWgConfig(): String {
        // Place your real config in assets/wg.conf (gitignored) or paste in settings.
        // This reads from raw string resource or assets; fallback to example.
        return try {
            assets.open("wg.conf").bufferedReader().use { it.readText() }
        } catch (e: Exception) {
            // Template placeholder — replace with real config before building
            throw IllegalStateException(
                "Добавь свой wg.conf в app/src/main/assets/wg.conf (не коммить приватный ключ!)"
            )
        }
    }

    private fun sendMessage() {
        val text = binding.etMessage.text.toString().trim()
        if (text.isEmpty()) return
        binding.tvChat.append("Вы: $text\n")
        binding.etMessage.text.clear()

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val json = """{"session_id":"$sessionId","message":${
                    org.json.JSONObject.quote(text)
                }}"""
                val body = json.toRequestBody("application/json".toMediaType())
                val req = Request.Builder().url(LLM_CHAT).post(body).build()
                val resp = client.newCall(req).execute()
                val raw = resp.body?.string() ?: ""
                // response is SSE-like stream "data: <token>"; join tokens
                val reply = raw.lines()
                    .filter { it.startsWith("data:") }
                    .joinToString("") { it.removePrefix("data:").trim() }
                    .ifBlank { raw }
                withContext(Dispatchers.Main) {
                    binding.tvChat.append("Velimudr: $reply\n\n")
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    binding.tvChat.append("Ошибка: ${e.message}\n\n")
                }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        try { tunnel?.let { backend?.setState(it, Tunnel.State.DOWN) } } catch (_: Exception) {}
    }
}
