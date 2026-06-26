package com.arista.client

import android.app.Application
import dagger.hilt.android.HiltAndroidApp

@HiltAndroidApp
class AristaApplication : Application() {
    override fun onCreate() {
        super.onCreate()
    }
}
