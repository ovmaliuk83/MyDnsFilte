package com.example.dnsfilter

import android.content.Context
import java.util.concurrent.atomic.AtomicInteger

/** Счётчики в памяти. На диск пишутся редко, а не на каждый пакет. */
object FilterStats {
    private const val PREFS = "dns_prefs"
    private const val KEY_ADS = "ads_blocked_count"
    private const val KEY_DOT = "dot_blocked_count"

    val adsBlocked = AtomicInteger()
    val dotBlocked = AtomicInteger()

    @Volatile
    private var loaded = false

    @Synchronized
    fun init(context: Context) {
        if (loaded) return
        val p = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        adsBlocked.set(p.getInt(KEY_ADS, 0))
        dotBlocked.set(p.getInt(KEY_DOT, 0))
        loaded = true
    }

    fun save(context: Context) {
        if (!loaded) return
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putInt(KEY_ADS, adsBlocked.get())
            .putInt(KEY_DOT, dotBlocked.get())
            .apply()
    }
}
