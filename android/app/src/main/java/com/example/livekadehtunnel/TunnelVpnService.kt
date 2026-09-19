package com.example.livekadehtunnel

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log

class TunnelVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnThread: Thread? = null

    companion object {
        const val ACTION_CONNECT = "com.example.livekadehtunnel.CONNECT"
        const val ACTION_DISCONNECT = "com.example.livekadehtunnel.DISCONNECT"
        
        init {
            System.loadLibrary("livekadeh_native")
        }
    }

    private external fun startNativeTunnel(fd: Int, serverAddr: String, port: Int, key: String): Int
    private external fun stopNativeTunnel()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action == ACTION_DISCONNECT) {
            stopTunnel()
            return START_NOT_STICKY
        }

        val serverAddr = intent?.getStringExtra("serverAddr") ?: return START_NOT_STICKY
        val port = intent.getIntExtra("port", 8443)
        val key = intent.getStringExtra("key") ?: return START_NOT_STICKY

        startTunnel(serverAddr, port, key)
        return START_STICKY
    }

    private fun startTunnel(serverAddr: String, port: Int, key: String) {
        // Build VPN
        val builder = Builder()
        builder.setSession("Livekadeh Tunnel")
            .addAddress("10.8.0.2", 24)
            .addRoute("0.0.0.0", 0)
            .setMtu(1400)
            
        vpnInterface = builder.establish()

        val fd = vpnInterface?.fd ?: -1
        if (fd < 0) {
            Log.e("TunnelVPN", "Failed to establish VPN interface")
            stopSelf()
            return
        }

        vpnThread = Thread {
            Log.i("TunnelVPN", "Starting native tunnel on fd $fd")
            startNativeTunnel(fd, serverAddr, port, key)
            Log.i("TunnelVPN", "Native tunnel exited")
            stopSelf()
        }
        vpnThread?.start()
    }

    private fun stopTunnel() {
        stopNativeTunnel()
        vpnThread?.join()
        vpnInterface?.close()
        vpnInterface = null
        stopSelf()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }
}
