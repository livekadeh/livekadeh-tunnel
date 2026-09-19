package com.example.livekadehtunnel

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

class MainActivity : ComponentActivity() {

    private var pendingServerAddr = ""
    private var pendingPort = 8443
    private var pendingKey = ""

    private val vpnRequest = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnService()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    TunnelScreen(
                        onConnect = { addr, port, key ->
                            pendingServerAddr = addr
                            pendingPort = port
                            pendingKey = key
                            val intent = VpnService.prepare(this)
                            if (intent != null) {
                                vpnRequest.launch(intent)
                            } else {
                                startVpnService()
                            }
                        },
                        onDisconnect = {
                            val intent = Intent(this, TunnelVpnService::class.java).apply {
                                action = TunnelVpnService.ACTION_DISCONNECT
                            }
                            startService(intent)
                        }
                    )
                }
            }
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, TunnelVpnService::class.java).apply {
            action = TunnelVpnService.ACTION_CONNECT
            putExtra("serverAddr", pendingServerAddr)
            putExtra("port", pendingPort)
            putExtra("key", pendingKey)
        }
        startService(intent)
    }
}

@Composable
fun TunnelScreen(
    onConnect: (String, Int, String) -> Unit,
    onDisconnect: () -> Unit
) {
    var serverIp by remember { mutableStateOf("162.217.249.229") }
    var portStr by remember { mutableStateOf("8443") }
    var key by remember { mutableStateOf("odd44ade196b2bf2110d54ec8c1fa9e3") }

    Column(modifier = Modifier.padding(16.dp)) {
        OutlinedTextField(
            value = serverIp,
            onValueChange = { serverIp = it },
            label = { Text("Server IP") },
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(modifier = Modifier.height(8.dp))
        OutlinedTextField(
            value = portStr,
            onValueChange = { portStr = it },
            label = { Text("Port") },
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(modifier = Modifier.height(8.dp))
        OutlinedTextField(
            value = key,
            onValueChange = { key = it },
            label = { Text("Secret Key") },
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(modifier = Modifier.height(16.dp))
        Row {
            Button(onClick = { onConnect(serverIp, portStr.toIntOrNull() ?: 8443, key) }) {
                Text("Connect")
            }
            Spacer(modifier = Modifier.width(16.dp))
            Button(onClick = onDisconnect) {
                Text("Disconnect")
            }
        }
    }
}
