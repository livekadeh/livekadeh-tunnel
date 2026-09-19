package com.example.livekadehtunnel

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

class TunnelTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        updateTileState()
    }

    override fun onClick() {
        super.onClick()
        if (TunnelVpnService.isRunning) {
            val intent = Intent(this, TunnelVpnService::class.java).apply {
                action = TunnelVpnService.ACTION_DISCONNECT
            }
            startService(intent)
            updateTileState(false)
        } else {
            val prepareIntent = VpnService.prepare(this)
            if (prepareIntent != null) {
                // VPN permission not granted yet, open MainActivity
                val mainIntent = Intent(this, MainActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    val pendingIntent = android.app.PendingIntent.getActivity(
                        this, 0, mainIntent,
                        android.app.PendingIntent.FLAG_IMMUTABLE or android.app.PendingIntent.FLAG_UPDATE_CURRENT
                    )
                    startActivityAndCollapse(pendingIntent)
                } else {
                    @Suppress("DEPRECATION")
                    startActivityAndCollapse(mainIntent)
                }
            } else {
                val prefs = getSharedPreferences("tunnel_prefs", Context.MODE_PRIVATE)
                val serverAddr = prefs.getString("server_addr", "2.59.170.232") ?: "2.59.170.232"
                val port = prefs.getInt("port", 8443)
                val key = prefs.getString("key", "0ddd412de196b2bf2110d54ec8c1fa9e1155af78cb770721d9de03034a2e6852") ?: ""
                val mode = prefs.getInt("mode", -1)
                val debug = prefs.getBoolean("debug", false)

                val intent = Intent(this, TunnelVpnService::class.java).apply {
                    action = TunnelVpnService.ACTION_CONNECT
                    putExtra("serverAddr", serverAddr)
                    putExtra("port", port)
                    putExtra("key", key)
                    putExtra("mode", mode)
                    putExtra("debug", debug)
                }
                try {
                    startService(intent)
                } catch (t: Throwable) {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        try {
                            startForegroundService(intent)
                        } catch (e: Throwable) {}
                    }
                }
                updateTileState(true)
            }
        }
    }

    private fun updateTileState(forcedState: Boolean? = null) {
        val active = forcedState ?: TunnelVpnService.isRunning
        val tile = qsTile ?: return
        tile.state = if (active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = "Livekadeh"
        tile.subtitle = if (active) "Connected" else "Disconnected"
        tile.updateTile()
    }
}
