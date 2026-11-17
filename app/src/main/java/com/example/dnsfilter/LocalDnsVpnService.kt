package com.example.dnsfilter

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import org.xbill.DNS.AAAARecord
import org.xbill.DNS.ARecord
import org.xbill.DNS.DClass
import org.xbill.DNS.Flags
import org.xbill.DNS.Message
import org.xbill.DNS.Rcode
import org.xbill.DNS.Section
import org.xbill.DNS.Type
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException

class LocalDnsVpnService : VpnService() {

    companion object {
        const val ACTION_STOP = "com.example.dnsfilter.STOP"

        private const val TAG = "DNS_FILTER"
        private const val CHANNEL_ID = "dns_filter"
        private const val NOTIFICATION_ID = 1
        private const val UPSTREAM_TIMEOUT_MS = 1500

        private val UPSTREAM_DNS = listOf("1.1.1.1", "77.88.8.8", "8.8.8.8")

        // Известные публичные DNS: заворачиваем их в туннель, чтобы резать DoT/DoH по IP
        private val INTERCEPTED_IPS = listOf("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9")

        private val EXTRA_BLOCKED = listOf(
            "an.yandex.ru", "mc.yandex.ru", "googleads.g.doubleclick.net",
            "googlesyndication.com", "ad.mail.ru"
        )

        // DoH-серверы по имени: чтобы браузеры не обходили фильтр
        private val DOH_DOMAINS = listOf(
            "dns.google", "mozilla.cloudflare-dns.com",
            "dns.adguard.com", "chrome.cloudflare-dns.com"
        )

        @Volatile
        var isRunning = false
            private set
    }

    @Volatile private var blocked: Set<String> = emptySet()
    @Volatile private var vpnInterface: ParcelFileDescriptor? = null
    private var workers: ExecutorService? = null
    private val writeLock = Any()

    // ───────────────────────── жизненный цикл ─────────────────────────

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }
        showForegroundNotification()
        if (!isRunning) startVpn()
        return START_STICKY
    }

    override fun onRevoke() {
        // Пользователь отключил VPN в системных настройках
        stopVpn()
        super.onRevoke()
    }

    override fun onDestroy() {
        releaseResources()
        super.onDestroy()
    }

    private fun showForegroundNotification() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "DNS-фильтр", NotificationManager.IMPORTANCE_LOW)
        )
        val flags = PendingIntent.FLAG_IMMUTABLE
        val openIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), flags
        )
        val stopIntent = PendingIntent.getService(
            this, 1,
            Intent(this, LocalDnsVpnService::class.java).setAction(ACTION_STOP), flags
        )
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("DNS-фильтр работает")
            .setContentText("Реклама и трекеры блокируются")
            .setContentIntent(openIntent)
            .addAction(0, "Выключить", stopIntent)
            .setOngoing(true)
            .build()

        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun startVpn() {
        isRunning = true
        FilterStats.init(this)
        workers = Executors.newFixedThreadPool(4)

        Thread({
            // Сначала грузим список, и только потом поднимаем туннель:
            // иначе первые запросы пройдут без фильтрации.
            if (blocked.isEmpty()) blocked = loadBlocklist()

            val iface = buildTunnel()
            if (iface == null || !isRunning) {
                Log.e(TAG, "Не удалось создать VPN-интерфейс")
                iface?.close()
                stopVpn()
                return@Thread
            }
            vpnInterface = iface
            runPacketLoop(iface)
        }, "dns-filter-loop").apply { isDaemon = true }.start()
    }

    private fun buildTunnel(): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("MyLocalDnsFilter")
            .addAddress("10.0.0.2", 32)
            .addDnsServer("10.0.0.1")
            .addRoute("10.0.0.1", 32)
            .setBlocking(true) // иначе read() возвращает 0 и цикл грузит CPU

        INTERCEPTED_IPS.forEach { builder.addRoute(it, 32) }

        val prefs = getSharedPreferences("dns_prefs", MODE_PRIVATE)
        val excluded = prefs.getStringSet("excluded_apps", emptySet()) ?: emptySet()
        for (pkg in excluded) {
            try {
                builder.addDisallowedApplication(pkg)
            } catch (e: PackageManager.NameNotFoundException) {
                Log.w(TAG, "Приложение $pkg не найдено")
            }
        }
        return builder.establish()
    }

    private fun stopVpn() {
        releaseResources()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun releaseResources() {
        isRunning = false
        workers?.shutdownNow()
        workers = null
        try {
            vpnInterface?.close()
        } catch (e: IOException) {
            Log.w(TAG, "Ошибка закрытия интерфейса: ${e.message}")
        }
        vpnInterface = null
        FilterStats.save(this)
    }

    // ───────────────────────── список блокировки ─────────────────────────

    private fun loadBlocklist(): Set<String> {
        val set = HashSet<String>(200_000)
        try {
            assets.open("hosts.txt").bufferedReader().useLines { lines ->
                for (raw in lines) {
                    val line = raw.substringBefore('#').trim()
                    if (line.isEmpty()) continue
                    // Формат: "domain" (после подготовки в CI) или "0.0.0.0 domain"
                    val domain = line.split(' ', '\t').last().lowercase()
                    if (domain.contains('.') && domain.any { it.isLetter() }) set.add(domain)
                }
            }
        } catch (e: IOException) {
            Log.e(TAG, "Не удалось прочитать hosts.txt: ${e.message}")
        }
        set.addAll(EXTRA_BLOCKED)
        set.addAll(DOH_DOMAINS)
        Log.d(TAG, "Загружено доменов: ${set.size}")
        return set
    }

    private fun isBlocked(domain: String): Boolean {
        val set = blocked
        var d = domain
        while (true) {
            if (d in set) return true
            val dot = d.indexOf('.')
            if (dot < 0 || dot == d.length - 1) return false
            d = d.substring(dot + 1) // ads.example.com → example.com
        }
    }

    // ───────────────────────── обработка пакетов ─────────────────────────

    private fun runPacketLoop(iface: ParcelFileDescriptor) {
        val input = FileInputStream(iface.fileDescriptor)
        val output = FileOutputStream(iface.fileDescriptor)
        val buffer = ByteArray(32767)

        while (isRunning) {
            val length = try {
                input.read(buffer)
            } catch (e: IOException) {
                if (isRunning) Log.w(TAG, "Ошибка чтения TUN: ${e.message}")
                break
            }
            if (length < 0) break
            if (length == 0) continue
            handlePacket(buffer.copyOf(length), output)
        }
        if (isRunning) stopVpn()
    }

    private fun handlePacket(packet: ByteArray, output: FileOutputStream) {
        if (packet.size < 28) return
        if (((packet[0].toInt() shr 4) and 0xF) != 4) return // только IPv4

        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < 20 || packet.size < ihl + 8) return

        when (packet[9].toInt() and 0xFF) {
            6 -> handleTcp(packet, ihl, output)
            17 -> handleUdp(packet, ihl, output)
        }
    }

    /** Любой TCP в нашем туннеле нежелателен (DoT, DoH по IP, TCP DNS): мгновенно рвём соединение. */
    private fun handleTcp(packet: ByteArray, ihl: Int, output: FileOutputStream) {
        if (packet.size < ihl + 20) return
        val flags = packet[ihl + 13].toInt() and 0xFF
        val isSyn = (flags and 0x02) != 0 && (flags and 0x10) == 0
        if (!isSyn) return

        if (u16(packet, ihl + 2) == 853) {
            FilterStats.dotBlocked.incrementAndGet()
            Log.d(TAG, "Заблокирован DoT")
        }
        writePacket(output, buildTcpReset(packet, ihl))
    }

    private fun handleUdp(packet: ByteArray, ihl: Int, output: FileOutputStream) {
        val destPort = u16(packet, ihl + 2)
        if (destPort == 853) { // DNS-over-QUIC: просто отбрасываем
            FilterStats.dotBlocked.incrementAndGet()
            return
        }
        if (destPort != 53) return

        val payloadLen = minOf(u16(packet, ihl + 4) - 8, packet.size - ihl - 8)
        if (payloadLen <= 0) return
        val dns = packet.copyOfRange(ihl + 8, ihl + 8 + payloadLen)

        try {
            // Каждый запрос в своём потоке: медленный апстрим не тормозит остальные
            workers?.execute { resolve(packet, ihl, dns, output) }
        } catch (e: RejectedExecutionException) {
            // сервис останавливается
        }
    }

    private fun resolve(requestPacket: ByteArray, ihl: Int, dns: ByteArray, output: FileOutputStream) {
        try {
            val query = Message(dns)
            val question = query.question ?: return
            val domain = question.name.toString(true).lowercase()

            val responseBytes = if (isBlocked(domain)) {
                FilterStats.adsBlocked.incrementAndGet()
                buildBlockedResponse(query)
            } else {
                forwardToUpstream(dns) ?: buildServFail(query)
            }
            writePacket(output, buildUdpResponse(requestPacket, ihl, responseBytes))
        } catch (e: Exception) {
            Log.w(TAG, "Ошибка обработки DNS-запроса: ${e.message}")
        }
    }

    private fun buildBlockedResponse(query: Message): ByteArray {
        val q = query.question
        val response = Message(query.header.id)
        response.header.setFlag(Flags.QR)
        response.header.setFlag(Flags.RA)
        if (query.header.getFlag(Flags.RD)) response.header.setFlag(Flags.RD)
        response.addRecord(q, Section.QUESTION)

        when (q.type) {
            Type.A -> response.addRecord(
                ARecord(q.name, DClass.IN, 300, InetAddress.getByAddress(ByteArray(4))),
                Section.ANSWER
            )
            Type.AAAA -> response.addRecord(
                AAAARecord(q.name, DClass.IN, 300, InetAddress.getByAddress(ByteArray(16))),
                Section.ANSWER
            )
        }
        return response.toWire()
    }

    private fun buildServFail(query: Message): ByteArray {
        val response = Message(query.header.id)
        response.header.setFlag(Flags.QR)
        response.header.setFlag(Flags.RA)
        response.header.rcode = Rcode.SERVFAIL
        query.question?.let { response.addRecord(it, Section.QUESTION) }
        return response.toWire()
    }

    private fun forwardToUpstream(dns: ByteArray): ByteArray? {
        for (server in UPSTREAM_DNS) {
            try {
                DatagramSocket().use { socket ->
                    protect(socket) // иначе запрос зациклится в нашем же VPN
                    socket.soTimeout = UPSTREAM_TIMEOUT_MS
                    socket.send(DatagramPacket(dns, dns.size, InetAddress.getByName(server), 53))

                    val buf = ByteArray(4096)
                    val reply = DatagramPacket(buf, buf.size)
                    socket.receive(reply)

                    // ID ответа должен совпадать с ID запроса
                    if (reply.length >= 2 && buf[0] == dns[0] && buf[1] == dns[1]) {
                        return buf.copyOf(reply.length)
                    }
                }
            } catch (e: IOException) {
                // пробуем следующий сервер
            }
        }
        return null
    }

    // ───────────────────────── сборка IP-пакетов ─────────────────────────

    private fun writePacket(output: FileOutputStream, data: ByteArray) {
        try {
            synchronized(writeLock) { output.write(data) }
        } catch (e: IOException) {
            if (isRunning) Log.w(TAG, "Ошибка записи в TUN: ${e.message}")
        }
    }

    private fun buildUdpResponse(req: ByteArray, ihl: Int, dns: ByteArray): ByteArray {
        val udpLen = 8 + dns.size
        val total = 20 + udpLen
        val out = ByteArray(total)
        val b = ByteBuffer.wrap(out)

        out[0] = 0x45
        out[8] = 64
        out[9] = 17
        b.putShort(2, total.toShort())
        System.arraycopy(req, 16, out, 12, 4) // src = бывший dst
        System.arraycopy(req, 12, out, 16, 4) // dst = бывший src
        b.putShort(10, checksum(out, 0, 20))

        System.arraycopy(req, ihl + 2, out, 20, 2) // порт источника = бывший порт назначения
        System.arraycopy(req, ihl, out, 22, 2)
        b.putShort(24, udpLen.toShort())
        // UDP-контрольная сумма для IPv4 может быть 0
        System.arraycopy(dns, 0, out, 28, dns.size)
        return out
    }

    private fun buildTcpReset(req: ByteArray, ihl: Int): ByteArray {
        val out = ByteArray(40)
        val b = ByteBuffer.wrap(out)

        out[0] = 0x45
        out[8] = 64
        out[9] = 6
        b.putShort(2, 40)
        System.arraycopy(req, 16, out, 12, 4)
        System.arraycopy(req, 12, out, 16, 4)
        b.putShort(10, checksum(out, 0, 20))

        System.arraycopy(req, ihl + 2, out, 20, 2)
        System.arraycopy(req, ihl, out, 22, 2)
        val clientSeq = ByteBuffer.wrap(req).getInt(ihl + 4)
        b.putInt(24, 0)               // seq
        b.putInt(28, clientSeq + 1)   // ack
        out[32] = (5 shl 4).toByte()  // длина заголовка 20 байт
        out[33] = 0x14                // RST + ACK

        // TCP-контрольная сумма с псевдозаголовком
        val pseudo = ByteArray(12 + 20)
        System.arraycopy(out, 12, pseudo, 0, 8)
        pseudo[9] = 6
        pseudo[11] = 20
        System.arraycopy(out, 20, pseudo, 12, 20)
        b.putShort(36, checksum(pseudo, 0, pseudo.size))
        return out
    }

    private fun u16(buf: ByteArray, offset: Int): Int =
        ((buf[offset].toInt() and 0xFF) shl 8) or (buf[offset + 1].toInt() and 0xFF)

    private fun checksum(buf: ByteArray, offset: Int, length: Int): Short {
        var sum = 0
        var i = offset
        val end = offset + length
        while (i < end) {
            val hi = buf[i].toInt() and 0xFF
            val lo = if (i + 1 < end) buf[i + 1].toInt() and 0xFF else 0
            sum += (hi shl 8) or lo
            i += 2
        }
        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv().toShort()
    }
}
