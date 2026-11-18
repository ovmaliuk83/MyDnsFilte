package com.example.dnsfilter

import android.content.Context
import android.content.SharedPreferences

/** Личные правила пользователя: свои блокировки и разрешённые домены. */
object RuleStore {
    private const val PREFS = "dns_prefs"
    private const val KEY_BLOCKED = "custom_blocked"
    private const val KEY_ALLOWED = "allowed_domains"

    private val DOMAIN_REGEX = Regex("^[a-z0-9_-]+(\\.[a-z0-9_-]+)+$")

    // Общие домены: их блокировка ломает почту, карты, поиск и т.п.
    private val PROTECTED = setOf(
        "yandex.ru", "yandex.by", "yandex.net", "ya.ru",
        "google.com", "googleapis.com", "gstatic.com", "youtube.com",
        "mail.ru", "vk.com", "apple.com", "microsoft.com"
    )

    private fun prefs(ctx: Context): SharedPreferences =
        ctx.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** Читает правила с диска в память (их использует сервис). */
    fun load(ctx: Context) {
        val p = prefs(ctx)
        val blocked = p.getStringSet(KEY_BLOCKED, emptySet()) ?: emptySet()
        val allowed = p.getStringSet(KEY_ALLOWED, emptySet()) ?: emptySet()
        LocalDnsVpnService.customBlocked.apply { clear(); addAll(blocked) }
        LocalDnsVpnService.allowedDomains.apply { clear(); addAll(allowed) }
    }

    /** Приводит ввод к домену: убирает http://, путь, порт, точку в конце. Null, если не похоже на домен. */
    fun normalize(input: String): String? {
        var s = input.trim().lowercase()
        s = s.substringAfter("://")
        s = s.substringBefore('/').substringBefore('?').substringBefore('#').substringBefore(':')
        s = s.trimEnd('.')
        return if (DOMAIN_REGEX.matches(s)) s else null
    }

    fun isProtected(domain: String) = domain in PROTECTED

    /** false, если домен защищён и блокировать его нельзя. */
    fun addBlocked(ctx: Context, domain: String): Boolean {
        if (isProtected(domain)) return false
        LocalDnsVpnService.customBlocked.add(domain)
        LocalDnsVpnService.allowedDomains.remove(domain)
        persist(ctx)
        return true
    }

    fun addAllowed(ctx: Context, domain: String) {
        LocalDnsVpnService.allowedDomains.add(domain)
        LocalDnsVpnService.customBlocked.remove(domain)
        persist(ctx)
    }

    fun remove(ctx: Context, domain: String) {
        LocalDnsVpnService.customBlocked.remove(domain)
        LocalDnsVpnService.allowedDomains.remove(domain)
        persist(ctx)
    }

    /** Пары (домен, true = блокировка / false = разрешён), по алфавиту. */
    fun entries(): List<Pair<String, Boolean>> {
        val blocked = LocalDnsVpnService.customBlocked.map { it to true }
        val allowed = LocalDnsVpnService.allowedDomains.map { it to false }
        return (blocked + allowed).sortedBy { it.first }
    }

    private fun persist(ctx: Context) {
        prefs(ctx).edit()
            .putStringSet(KEY_BLOCKED, HashSet(LocalDnsVpnService.customBlocked))
            .putStringSet(KEY_ALLOWED, HashSet(LocalDnsVpnService.allowedDomains))
            .apply()
    }
}
