package com.arista.client.core

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ProxyInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.arista.client.R
import com.arista.client.ui.MainActivity
import com.arista.client.utils.ConfigParser
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.*

@AndroidEntryPoint
class CoreVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false
    private var serviceJob: Job? = null
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    companion object {
        private const val CHANNEL_ID = "arista_vpn_channel"
        private const val NOTIFICATION_ID = 1001

        fun start(context: Context, configLink: String) {
            val intent = Intent(context, CoreVpnService::class.java).apply {
                putExtra("config_link", configLink)
                action = "START_VPN"
            }
            context.startService(intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, CoreVpnService::class.java).apply {
                action = "STOP_VPN"
            }
            context.startService(intent)
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            "START_VPN" -> {
                val configLink = intent.getStringExtra("config_link") ?: return START_NOT_STICKY
                startVpn(configLink)
            }
            "STOP_VPN" -> stopVpn()
            else -> stopVpn()
        }
        return START_STICKY
    }

    private fun startVpn(configLink: String) {
        if (isRunning) {
            stopVpn()
        }

        val builder = Builder()
        configureVpnBuilder(builder)

        try {
            vpnInterface = builder.establish()
            isRunning = true

            serviceJob = serviceScope.launch {
                startCore(configLink)
            }

            startForeground(NOTIFICATION_ID, createNotification())
        } catch (e: Exception) {
            stopVpn()
        }
    }

    private fun configureVpnBuilder(builder: Builder) {
        builder.setAddress("10.0.0.2", 24)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .addDnsServer("1.1.1.1")
            .setMtu(1500)
            .setSession("Arista VPN")

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
            builder.setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", 1080))
        }

        builder.addDisallowedApplication(packageName)
    }

    private suspend fun startCore(configLink: String) {
        val config = ConfigParser.parseConfigLink(configLink)
        if (config == null) {
            stopVpn()
            return
        }

        try {
            delay(1000)
        } catch (e: Exception) {
            stopVpn()
        }
    }

    private fun stopVpn() {
        isRunning = false
        serviceJob?.cancel()
        serviceJob = null

        try {
            vpnInterface?.close()
        } catch (e: Exception) {
        }
        vpnInterface = null

        stopForeground(true)
    }

    private fun createNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Arista VPN")
            .setContentText("🟢 متصل به سرور")
            .setSmallIcon(R.drawable.ic_vpn)
            .setContentIntent(pendingIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Arista VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "وضعیت اتصال VPN"
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVpn()
    }
}
