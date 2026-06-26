package com.arista.client.data.models

import androidx.room.Entity
import androidx.room.PrimaryKey
import java.io.Serializable

@Entity(tableName = "configs")
data class Config(
    @PrimaryKey
    val link: String,
    val protocol: String = "vmess",
    val ip: String = "",
    val port: Int = 443,
    val uuid: String = "",
    val password: String = "",
    val cipher: String = "",
    val security: String = "auto",
    val network: String = "tcp",
    val host: String = "",
    val path: String = "",
    val sni: String = "",
    val remark: String = "",
    val country: String = "",
    val ping: Long = -1,
    val isActive: Boolean = false
) : Serializable
