package com.example.dnsfilter

/** Последние DNS-запросы только в памяти. Пока enabled = false, ничего не записывается. */
object QueryLog {
    private const val MAX = 200
    private val lock = Any()
    private val entries = LinkedHashMap<String, Boolean>() // домен -> заблокирован ли

    @Volatile
    var enabled = false

    fun record(domain: String, blocked: Boolean) {
        if (!enabled) return
        synchronized(lock) {
            entries.remove(domain)          // переносим в конец (самый свежий)
            entries[domain] = blocked
            if (entries.size > MAX) {
                val it = entries.entries.iterator()
                it.next()
                it.remove()
            }
        }
    }

    /** Свежие запросы сверху. */
    fun snapshot(): List<Pair<String, Boolean>> = synchronized(lock) {
        entries.entries.map { it.key to it.value }.reversed()
    }

    fun clear() = synchronized(lock) { entries.clear() }
}
