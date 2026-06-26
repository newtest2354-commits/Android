package com.arista.client.network

import retrofit2.http.GET
import retrofit2.http.Url

interface ApiService {
    @GET
    suspend fun getConfigs(@Url url: String): String
}
