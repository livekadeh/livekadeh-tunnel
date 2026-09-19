package com.example.livekadehtunnel

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log

class TunnelVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnThread: Thread? = null

    companion object {
        const val ACTION_CONNECT = "com.example.livekadehtunnel.CONNECT"
        const val ACTION_DISCONNECT = "com.example.livekadehtunnel.DISCONNECT"
        const val CHANNEL_ID = "livekadeh_vpn_channel"
        const val NOTIF_ID = 1001

        @Volatile
        var isRunning: Boolean = false
            private set

        @Volatile
        var instance: TunnelVpnService? = null
            private set

        init {
            System.loadLibrary("livekadeh_native")
        }

        @JvmStatic
        external fun startNativeTunnel(serverAddr: String, port: Int, key: String, mode: Int): Int

        @JvmStatic
        external fun stopNativeTunnel()

        @JvmStatic
        external fun getTxBytes(): Long

        @JvmStatic
        external fun getRxBytes(): Long

        @JvmStatic
        external fun getNativeLogs(): String

        @JvmStatic
        external fun clearNativeLogs()

        @JvmStatic
        fun protectSocket(fd: Int): Boolean {
            val s = instance
            return if (s != null) {
                s.protect(fd)
            } else {
                false
            }
        }

        @JvmStatic
        fun establishVpnInterface(assignedIp: String): Int {
            val s = instance ?: return -1
            return s.createTunInterface(assignedIp)
        }
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action == ACTION_DISCONNECT) {
            stopTunnel()
            return START_NOT_STICKY
        }

        val serverAddr = intent?.getStringExtra("serverAddr") ?: return START_NOT_STICKY
        val port = intent.getIntExtra("port", 8443)
        val key = intent.getStringExtra("key") ?: return START_NOT_STICKY
        val mode = intent.getIntExtra("mode", 0)

        try {
            val notif = buildNotification("Livekadeh Tunnel ($serverAddr:$port)")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
            } else {
                startForeground(NOTIF_ID, notif)
            }
        } catch (t: Throwable) {
            Log.w("TunnelVPN", "Could not startForeground: ${t.message}")
        }

        startTunnel(serverAddr, port, key, mode)
        return START_STICKY
    }

    fun createTunInterface(assignedIp: String): Int {
        try {
            vpnInterface?.close()
        } catch (e: Throwable) {
            // Ignored
        }

        val builder = Builder()
        builder.setSession("Livekadeh Tunnel")
            .addAddress(assignedIp, 24)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .addDnsServer("8.8.8.8")
            .setMtu(1400)

        val vpn = builder.establish() ?: return -1
        vpnInterface = vpn
        return vpn.fd
    }

    private fun startTunnel(serverAddr: String, port: Int, key: String, mode: Int) {
        isRunning = true
        vpnThread = Thread {
            Log.i("TunnelVPN", "Starting native tunnel to $serverAddr:$port, mode=$mode")
            try {
                startNativeTunnel(serverAddr, port, key, mode)
            } catch (t: Throwable) {
                Log.e("TunnelVPN", "Native tunnel error", t)
            }
            Log.i("TunnelVPN", "Native tunnel finished")
            isRunning = false
            stopSelf()
        }
        vpnThread?.start()
    }

    private fun stopTunnel() {
        isRunning = false
        try {
            stopNativeTunnel()
        } catch (t: Throwable) {
            Log.w("TunnelVPN", "Error stopping native tunnel: ${t.message}")
        }
        try {
            vpnInterface?.close()
        } catch (e: Throwable) {
            Log.e("TunnelVPN", "Error closing vpnInterface", e)
        }
        vpnInterface = null
        try {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } catch (t: Throwable) {
            // Ignored
        }
        stopSelf()
    }

    override fun onDestroy() {
        stopTunnel()
        instance = null
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Livekadeh Tunnel Service",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        return builder
            .setContentTitle("Livekadeh Tunnel")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }
}
