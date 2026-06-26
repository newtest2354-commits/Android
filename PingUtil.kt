package com.arista.client.utils

import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL

object PingUtil {

    fun tcpPing(ip: String, port: Int, timeout: Int = 2000): Long {
        return try {
            val startTime = System.currentTimeMillis()
            Socket().use { socket ->
                socket.connect(InetSocketAddress(ip, port), timeout)
            }
            System.currentTimeMillis() - startTime
        } catch (e: Exception) {
            -1L
        }
    }

    fun httpPing(timeout: Int = 3000): Long {
        return try {
            val startTime = System.currentTimeMillis()
            val url = URL("http://www.gstatic.com/generate_204")
            val connection = url.openConnection() as HttpURLConnection
            connection.connectTimeout = timeout
            connection.readTimeout = timeout
            connection.requestMethod = "HEAD"
            connection.connect()
            val responseCode = connection.responseCode
            connection.disconnect()

            if (responseCode == 204) {
                System.currentTimeMillis() - startTime
            } else {
                -1L
            }
        } catch (e: Exception) {
            -1L
        }
    }
}
