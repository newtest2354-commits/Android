package com.arista.client.utils

import android.util.Base64
import com.arista.client.data.models.Config
import org.json.JSONObject

object ConfigParser {

    fun parseConfigLink(link: String): Config? {
        return when {
            link.startsWith("vmess://") -> parseVmess(link)
            link.startsWith("vless://") -> parseVless(link)
            link.startsWith("trojan://") -> parseTrojan(link)
            link.startsWith("ss://") -> parseShadowsocks(link)
            link.startsWith("hysteria2://") || link.startsWith("hy2://") -> parseHysteria2(link)
            else -> null
        }
    }

    private fun parseVmess(link: String): Config? {
        try {
            val base64Part = link.substringAfter("vmess://")
            val decoded = String(Base64.decode(base64Part, Base64.DEFAULT))
            val json = JSONObject(decoded)

            return Config(
                link = link,
                protocol = "vmess",
                ip = json.optString("add"),
                port = json.optInt("port", 443),
                uuid = json.optString("id"),
                security = json.optString("scy", "auto"),
                network = json.optString("net", "tcp"),
                host = json.optString("host"),
                path = json.optString("path"),
                sni = json.optString("sni"),
                remark = json.optString("ps")
            )
        } catch (e: Exception) {
            return null
        }
    }

    private fun parseVless(link: String): Config? {
        try {
            val parts = link.substringAfter("vless://").split("?")
            val userInfo = parts[0].split("@")
            val uuid = userInfo[0]
            val serverPart = userInfo[1].split(":")
            val ip = serverPart[0]
            val port = serverPart[1].toIntOrNull() ?: 443

            val params = if (parts.size > 1) {
                parts[1].split("&").associate {
                    val pair = it.split("=")
                    pair[0] to pair.getOrNull(1) ?: ""
                }
            } else emptyMap()

            return Config(
                link = link,
                protocol = "vless",
                ip = ip,
                port = port,
                uuid = uuid,
                security = params["security"] ?: "none",
                network = params["type"] ?: "tcp",
                host = params["host"] ?: "",
                path = params["path"] ?: "",
                sni = params["sni"] ?: "",
                remark = "VLESS"
            )
        } catch (e: Exception) {
            return null
        }
    }

    private fun parseTrojan(link: String): Config? {
        try {
            val parts = link.substringAfter("trojan://").split("@")
            val password = parts[0]
            val serverPart = parts[1].split("?")
            val serverInfo = serverPart[0].split(":")
            val ip = serverInfo[0]
            val port = serverInfo[1].toIntOrNull() ?: 443

            val params = if (serverPart.size > 1) {
                serverPart[1].split("&").associate {
                    val pair = it.split("=")
                    pair[0] to pair.getOrNull(1) ?: ""
                }
            } else emptyMap()

            return Config(
                link = link,
                protocol = "trojan",
                ip = ip,
                port = port,
                password = password,
                security = "tls",
                network = params["type"] ?: "tcp",
                host = params["host"] ?: "",
                path = params["path"] ?: "",
                sni = params["sni"] ?: "",
                remark = "Trojan"
            )
        } catch (e: Exception) {
            return null
        }
    }

    private fun parseShadowsocks(link: String): Config? {
        try {
            var encoded = link.substringAfter("ss://")
            val parts = encoded.split("@")
            val methodAndPass = String(Base64.decode(parts[0], Base64.DEFAULT))
            val method = methodAndPass.split(":")[0]
            val password = methodAndPass.split(":")[1]
            val serverPart = parts[1].split(":")
            val ip = serverPart[0]
            val port = serverPart[1].split("#")[0].toIntOrNull() ?: 8388

            return Config(
                link = link,
                protocol = "shadowsocks",
                ip = ip,
                port = port,
                password = password,
                cipher = method,
                remark = "SS"
            )
        } catch (e: Exception) {
            return null
        }
    }

    private fun parseHysteria2(link: String): Config? {
        try {
            val url = if (link.startsWith("hy2://")) {
                link.replace("hy2://", "hysteria2://")
            } else link

            val parts = url.substringAfter("hysteria2://").split("@")
            val password = if (parts.size > 1) parts[0] else ""
            val serverPart = (if (parts.size > 1) parts[1] else parts[0]).split(":")
            val ip = serverPart[0]
            val port = serverPart[1].toIntOrNull() ?: 443

            return Config(
                link = link,
                protocol = "hysteria2",
                ip = ip,
                port = port,
                password = password,
                remark = "Hysteria2"
            )
        } catch (e: Exception) {
            return null
        }
    }

    fun extractIp(link: String): String {
        return parseConfigLink(link)?.ip ?: ""
    }

    fun extractPort(link: String): Int {
        return parseConfigLink(link)?.port ?: 443
    }
}
