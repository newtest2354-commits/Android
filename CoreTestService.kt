package com.arista.client.core

import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import com.arista.client.data.models.Config
import com.arista.client.utils.ConfigParser
import com.arista.client.utils.PingUtil
import kotlinx.coroutines.*

class CoreTestService : Service() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var isRunning = false

    companion object {
        fun startTest(context: Context, configs: List<Config>) {
            val intent = Intent(context, CoreTestService::class.java).apply {
                putExtra("configs", configs.toTypedArray())
            }
            context.startService(intent)
        }

        fun stopTest(context: Context) {
            context.stopService(Intent(context, CoreTestService::class.java))
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val configs = intent?.getSerializableExtra("configs") as? Array<Config>
        if (configs != null && !isRunning) {
            isRunning = true
            serviceScope.launch {
                runTests(configs.toList())
                isRunning = false
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    private suspend fun runTests(configs: List<Config>) {
        withContext(Dispatchers.IO) {
            configs.forEach { config ->
                val ip = ConfigParser.extractIp(config.link)
                val port = ConfigParser.extractPort(config.link)
                val ping = PingUtil.tcpPing(ip, port, 2000)
                // ذخیره نتیجه در دیتابیس
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        isRunning = false
        serviceScope.cancel()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
