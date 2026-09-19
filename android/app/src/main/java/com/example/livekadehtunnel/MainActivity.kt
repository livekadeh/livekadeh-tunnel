package com.example.livekadehtunnel

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay

class MainActivity : ComponentActivity() {

    private var pendingServerAddr = ""
    private var pendingPort = 8443
    private var pendingKey = ""
    private var pendingMode = 0

    private val vpnRequest = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnService()
        } else {
            Log.w("MainActivity", "VPN permission was not granted by user")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    primary = Color(0xFF00E5FF),
                    secondary = Color(0xFF7C4DFF),
                    background = Color(0xFF121212),
                    surface = Color(0xFF1E1E1E)
                )
            ) {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    TunnelScreen(
                        onConnect = { addr, port, key, mode ->
                            pendingServerAddr = addr
                            pendingPort = port
                            pendingKey = key
                            pendingMode = mode
                            try {
                                val intent = VpnService.prepare(this)
                                if (intent != null) {
                                    vpnRequest.launch(intent)
                                } else {
                                    startVpnService()
                                }
                            } catch (t: Throwable) {
                                Log.e("MainActivity", "VpnService.prepare failed", t)
                                startVpnService()
                            }
                        },
                        onDisconnect = {
                            try {
                                val intent = Intent(this, TunnelVpnService::class.java).apply {
                                    action = TunnelVpnService.ACTION_DISCONNECT
                                }
                                startService(intent)
                            } catch (t: Throwable) {
                                Log.e("MainActivity", "Failed to send disconnect intent", t)
                            }
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
            putExtra("mode", pendingMode)
        }
        try {
            startService(intent)
        } catch (t: Throwable) {
            Log.w("MainActivity", "startService failed, attempting startForegroundService", t)
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                try {
                    startForegroundService(intent)
                } catch (e: Throwable) {
                    Log.e("MainActivity", "startForegroundService also failed", e)
                }
            }
        }
    }
}

data class ConnectionMode(val name: String, val modeValue: Int)

val connectionModes = listOf(
    ConnectionMode("UDP Datagram (Fast & Low Latency)", 0),
    ConnectionMode("8 Lanes (Multi-TCP)", 8),
    ConnectionMode("4 Lanes (Multi-TCP)", 4),
    ConnectionMode("1 Lane (Single-TCP)", 1)
)

fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val kb = bytes / 1024.0
    if (kb < 1024) return String.format("%.1f KB", kb)
    val mb = kb / 1024.0
    if (mb < 1024) return String.format("%.2f MB", mb)
    val gb = mb / 1024.0
    return String.format("%.2f GB", gb)
}

fun formatSpeed(bytesPerSec: Long): String {
    if (bytesPerSec < 1024) return "$bytesPerSec B/s"
    val kb = bytesPerSec / 1024.0
    if (kb < 1024) return String.format("%.1f KB/s", kb)
    val mb = kb / 1024.0
    return String.format("%.2f MB/s", mb)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TunnelScreen(
    onConnect: (String, Int, String, Int) -> Unit,
    onDisconnect: () -> Unit
) {
    var serverIp by remember { mutableStateOf("2.59.170.232") }
    var portStr by remember { mutableStateOf("8443") }
    var key by remember { mutableStateOf("0ddd412de196b2bf2110d54ec8c1fa9e1155af78cb770721d9de03034a2e6852") }

    var selectedModeIndex by remember { mutableStateOf(0) }
    var dropdownExpanded by remember { mutableStateOf(false) }

    var isConnected by remember { mutableStateOf(false) }
    var txSpeed by remember { mutableStateOf(0L) }
    var rxSpeed by remember { mutableStateOf(0L) }
    var totalTx by remember { mutableStateOf(0L) }
    var totalRx by remember { mutableStateOf(0L) }
    var logText by remember { mutableStateOf("") }

    val scrollState = rememberScrollState()

    // Periodic statistics & log updater
    LaunchedEffect(Unit) {
        var lastTx = 0L
        var lastRx = 0L
        while (true) {
            try {
                val running = TunnelVpnService.isRunning
                isConnected = running

                val curTx = TunnelVpnService.getTxBytes()
                val curRx = TunnelVpnService.getRxBytes()

                if (running) {
                    txSpeed = (curTx - lastTx).coerceAtLeast(0L)
                    rxSpeed = (curRx - lastRx).coerceAtLeast(0L)
                } else {
                    txSpeed = 0L
                    rxSpeed = 0L
                }

                lastTx = curTx
                lastRx = curRx
                totalTx = curTx
                totalRx = curRx

                logText = TunnelVpnService.getNativeLogs()
            } catch (t: Throwable) {
                // Ignore stats polling error
            }

            delay(1000)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(scrollState)
    ) {
        // App Header
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(
                text = "Livekadeh Tunnel",
                fontSize = 24.sp,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
            )
            Spacer(modifier = Modifier.weight(1f))
            Badge(
                containerColor = if (isConnected) Color(0xFF00E676) else Color(0xFFFF5252)
            ) {
                Text(
                    text = if (isConnected) "CONNECTED" else "DISCONNECTED",
                    color = Color.Black,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(4.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Configuration Card
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                OutlinedTextField(
                    value = serverIp,
                    onValueChange = { serverIp = it },
                    label = { Text("Server Address (IP / Domain)") },
                    enabled = !isConnected,
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = portStr,
                    onValueChange = { portStr = it },
                    label = { Text("Port") },
                    enabled = !isConnected,
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = key,
                    onValueChange = { key = it },
                    label = { Text("Secret Key") },
                    enabled = !isConnected,
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(modifier = Modifier.height(12.dp))

                // Connection Mode Selector
                Text(
                    text = "Connection Type (Transport & Lanes):",
                    fontSize = 13.sp,
                    color = Color.Gray
                )
                Spacer(modifier = Modifier.height(4.dp))

                ExposedDropdownMenuBox(
                    expanded = dropdownExpanded && !isConnected,
                    onExpandedChange = { if (!isConnected) dropdownExpanded = !dropdownExpanded }
                ) {
                    OutlinedTextField(
                        value = connectionModes[selectedModeIndex].name,
                        onValueChange = {},
                        readOnly = true,
                        trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = dropdownExpanded) },
                        colors = ExposedDropdownMenuDefaults.outlinedTextFieldColors(),
                        enabled = !isConnected,
                        modifier = Modifier
                            .menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable, true)
                            .fillMaxWidth()
                    )
                    ExposedDropdownMenu(
                        expanded = dropdownExpanded && !isConnected,
                        onDismissRequest = { dropdownExpanded = false }
                    ) {
                        connectionModes.forEachIndexed { index, mode ->
                            DropdownMenuItem(
                                text = { Text(mode.name) },
                                onClick = {
                                    selectedModeIndex = index
                                    dropdownExpanded = false
                                }
                            )
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Connect / Disconnect Buttons
        if (!isConnected) {
            Button(
                onClick = {
                    val port = portStr.toIntOrNull() ?: 8443
                    val mode = connectionModes[selectedModeIndex].modeValue
                    onConnect(serverIp, port, key, mode)
                },
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp)
            ) {
                Text("Connect Tunnel", fontSize = 16.sp, fontWeight = FontWeight.Bold, color = Color.Black)
            }
        } else {
            Button(
                onClick = onDisconnect,
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFFF5252)),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp)
            ) {
                Text("Disconnect Tunnel", fontSize = 16.sp, fontWeight = FontWeight.Bold, color = Color.White)
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Traffic Speed & Data Counters Card
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "Traffic Statistics",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.primary
                )
                Spacer(modifier = Modifier.height(12.dp))

                Row(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Download Speed", fontSize = 12.sp, color = Color.Gray)
                        Text(
                            text = formatSpeed(rxSpeed),
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF00E676)
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text("Total Download: ${formatBytes(totalRx)}", fontSize = 12.sp, color = Color.LightGray)
                    }

                    Column(modifier = Modifier.weight(1f)) {
                        Text("Upload Speed", fontSize = 12.sp, color = Color.Gray)
                        Text(
                            text = formatSpeed(txSpeed),
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF2979FF)
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text("Total Upload: ${formatBytes(totalTx)}", fontSize = 12.sp, color = Color.LightGray)
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Live Log Terminal Viewer
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(
                text = "Live Logs",
                fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.primary
            )
            Spacer(modifier = Modifier.weight(1f))
            TextButton(onClick = { TunnelVpnService.clearNativeLogs() }) {
                Text("Clear", color = Color.Gray, fontSize = 12.sp)
            }
        }

        Spacer(modifier = Modifier.height(4.dp))

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(200.dp)
                .background(Color(0xFF0A0A0A), RoundedCornerShape(8.dp))
                .padding(8.dp)
        ) {
            val logLines = remember(logText) { logText.lines().filter { it.isNotBlank() } }
            val listState = rememberLazyListState()

            LaunchedEffect(logLines.size) {
                if (logLines.isNotEmpty()) {
                    listState.animateScrollToItem(logLines.size - 1)
                }
            }

            if (logLines.isEmpty()) {
                Text(
                    text = "No logs yet. Connect to see output...",
                    color = Color.DarkGray,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace
                )
            } else {
                LazyColumn(state = listState, modifier = Modifier.fillMaxSize()) {
                    items(logLines) { line ->
                        val color = when {
                            line.contains("[ERROR]") -> Color(0xFFFF5252)
                            line.contains("[WARN]") -> Color(0xFFFFD740)
                            line.contains("[INFO]") -> Color(0xFF00E5FF)
                            else -> Color(0xFFE0E0E0)
                        }
                        Text(
                            text = line,
                            color = color,
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))
    }
}
