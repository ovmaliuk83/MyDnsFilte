package com.example.dnsfilter

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import org.xbill.DNS.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap

class LocalDnsVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false

    // Потокобезопасный набор для хранения базы доменов
    private val blockedDomains = ConcurrentHashMap.newKeySet<String>()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP") {
            stopVpn()
            return START_NOT_STICKY
        }

        if (!isRunning) {
            startVpn()
        }
        return START_STICKY
    }

    private fun loadBlocklistFromAssets() {
        try {
            assets.open("hosts.txt").bufferedReader().useLines { lines ->
                lines.forEach { rawLine ->
                    val line = rawLine.substringBefore("#").trim()
                    if (line.isNotEmpty()) {
                        val parts = line.split(Regex("\\s+"))
                        val domain = if (parts.size >= 2) parts[1] else parts[0]
                        if (domain != "localhost" && domain != "0.0.0.0" && domain.contains(".")) {
                            blockedDomains.add(domain.lowercase())
                        }
                    }
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }

        // Вывод в лог для проверки (adb logcat -s DNS_FILTER)
        android.util.Log.d("DNS_FILTER", "Загружено доменов: ${blockedDomains.size}")

        // Резервные домены (на случай, если файл hosts не загрузился)
        blockedDomains.add("an.yandex.ru")
        blockedDomains.add("mc.yandex.ru")
        blockedDomains.add("googleads.g.doubleclick.net")
        blockedDomains.add("googlesyndication.com")
        blockedDomains.add("ad.mail.ru")
        
        // Блокируем известные DoH-серверы (чтобы браузеры не обходили VPN)
        blockedDomains.add("dns.google")
        blockedDomains.add("mozilla.cloudflare-dns.com")
        blockedDomains.add("dns.adguard.com")
        blockedDomains.add("chrome.cloudflare-dns.com")
    }

    private fun startVpn() {
        // Настройки VPN. Используем только IPv4, чтобы весь трафик шел через нас.
        val builder = Builder()
            .setSession("MyLocalDnsFilter")
            .addAddress("10.0.0.2", 32)
            .addDnsServer("10.0.0.1")
            .addRoute("10.0.0.1", 32)
            
            // ПЕРЕХВАТЫВАЕМ ИЗВЕСТНЫЕ DNS-СЕРВЕРЫ:
            // Это заставит телефон отправлять запросы к ним через наш VPN,
            // где мы сможем заблокировать их попытки установить DoT (порт 853).
            .addRoute("8.8.8.8", 32)   // Google DNS
            .addRoute("8.8.4.4", 32)   // Google DNS alt
            .addRoute("1.1.1.1", 32)   // Cloudflare
            .addRoute("1.0.0.1", 32)   // Cloudflare alt
            .addRoute("9.9.9.9", 32)   // Quad9

        val prefs = getSharedPreferences("dns_prefs", MODE_PRIVATE)
        val excludedPackages = prefs.getStringSet("excluded_apps", emptySet()) ?: emptySet()

        for (packageName in excludedPackages) {
            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }

        vpnInterface = builder.establish()
        isRunning = true

        Thread {
            if (blockedDomains.isEmpty()) {
                loadBlocklistFromAssets()
            }
            runPacketLoop()
        }.start()
    }

    private fun runPacketLoop() {
        val descriptor = vpnInterface ?: return
        val inputStream = FileInputStream(descriptor.fileDescriptor)
        val outputStream = FileOutputStream(descriptor.fileDescriptor)
        val packet = ByteBuffer.allocate(32767)

        while (isRunning) {
            try {
                val length = inputStream.read(packet.array())
                if (length > 0) {
                    packet.limit(length)
                    handleIpPacket(packet, outputStream)
                    packet.clear()
                }
            } catch (e: Exception) {
                if (isRunning) e.printStackTrace()
                break
            }
        }
    }

    private fun handleIpPacket(packet: ByteBuffer, outputStream: FileOutputStream) {
        val version = (packet.get(0).toInt() shr 4) and 0xF
        if (version != 4) return // Обрабатываем только IPv4

        val ipHeaderLength = (packet.get(0).toInt() and 0x0F) * 4
        val protocol = packet.get(9).toInt() and 0xFF
        
        // Определяем IP назначения для логов
        val destIp = "${packet.get(16).toInt() and 0xFF}.${packet.get(17).toInt() and 0xFF}.${packet.get(18).toInt() and 0xFF}.${packet.get(19).toInt() and 0xFF}"

        // 1. БЛОКИРУЕМ PRIVATE DNS (DoT)
        // Если это TCP-пакет (protocol 6) и он идет на 853 порт — просто обрываем его.
        // Система не сможет установить защищенное соединение и переключится на обычный DNS.
        if (protocol == 6) {
            val destPort = packet.getShort(ipHeaderLength + 2).toInt() and 0xFFFF
            if (destPort == 853) {
                android.util.Log.d("DNS_FILTER", "Заблокирован Private DNS (DoT) на $destIp")
                return 
            }
            // Остальной TCP-трафик мы сейчас не обрабатываем (пропускаем)
            return 
        }

        // 2. ОБРАБАТЫВАЕМ ОБЫЧНЫЙ DNS (UDP)
        if (protocol != 17) return // Обрабатываем только UDP
        
        val destPort = packet.getShort(ipHeaderLength + 2).toInt() and 0xFFFF
        if (destPort != 53) return // Нас интересует только 53 порт (DNS)

        val udpHeaderLength = 8
        val totalHeaderLength = ipHeaderLength + udpHeaderLength

        val dnsData = ByteArray(packet.limit() - totalHeaderLength)
        packet.position(totalHeaderLength)
        packet.get(dnsData)

        try {
            val dnsMessage = Message(dnsData)
            val question = dnsMessage.question ?: return
            
            // ИСПРАВЛЕНИЕ: Убираем точку в конце домена!
            val domain = question.name.toString(true).lowercase().removeSuffix(".")

            val responseDnsBytes = if (isBlocked(domain)) {
                createBlockedResponse(dnsMessage)
            } else {
                forwardToRealDns(dnsData)
            } ?: return

            val responsePacket = buildResponsePacket(packet, ipHeaderLength, responseDnsBytes)
            outputStream.write(responsePacket)

        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun isBlocked(domain: String): Boolean {
        var current = domain
        while (true) {
            if (blockedDomains.contains(current)) return true
            if (!current.contains(".")) break
            current = current.substringAfter(".")
        }
        return false
    }

    private fun createBlockedResponse(request: Message): ByteArray {
        val response = Message(request.header.id)
        response.header.setFlag(Flags.QR.toInt())
        response.header.setFlag(Flags.RA.toInt())
        response.addRecord(request.question, Section.QUESTION)

        if (request.question.type == Type.A) {
            val answer = ARecord(
                request.question.name,
                DClass.IN,
                300,
                InetAddress.getByName("0.0.0.0")
            )
            response.addRecord(answer, Section.ANSWER)
        }
        return response.toWire()
    }

    private fun forwardToRealDns(dnsData: ByteArray): ByteArray? {
        // Резервные DNS: Cloudflare, Yandex, Google
        val servers = listOf("1.1.1.1", "77.88.8.8", "8.8.8.8")
        
        for (serverIp in servers) {
            val socket = DatagramSocket()
            protect(socket) // Защищаем сокет от зацикливания VPN
            socket.soTimeout = 2000 

            try {
                val serverAddress = InetAddress.getByName(serverIp)
                val outPacket = DatagramPacket(dnsData, dnsData.size, serverAddress, 53)
                socket.send(outPacket)

                val buffer = ByteArray(4096)
                val inPacket = DatagramPacket(buffer, buffer.size)
                socket.receive(inPacket)

                return inPacket.data.copyOf(inPacket.length)
            } catch (e: Exception) {
                // Если сервер не ответил, идем к следующему
            } finally {
                socket.close()
            }
        }
        return null
    }

    private fun buildResponsePacket(
        requestPacket: ByteBuffer,
        ipHeaderLen: Int,
        dnsPayload: ByteArray
    ): ByteArray {
        val totalLen = ipHeaderLen + 8 + dnsPayload.size
        val out = ByteBuffer.allocate(totalLen)

        val ipHeader = ByteArray(ipHeaderLen)
        requestPacket.position(0)
        requestPacket.get(ipHeader)
        out.put(ipHeader)

        out.putShort(2, totalLen.toShort())
        for (i in 0..3) {
            out.put(12 + i, ipHeader[16 + i])
            out.put(16 + i, ipHeader[12 + i])
        }
        out.putShort(10, 0)
        out.putShort(10, calculateChecksum(out.array(), 0, ipHeaderLen))

        val srcPort = requestPacket.getShort(ipHeaderLen)
        val dstPort = requestPacket.getShort(ipHeaderLen + 2)
        out.position(ipHeaderLen)
        out.putShort(dstPort)
        out.putShort(srcPort)
        out.putShort((8 + dnsPayload.size).toShort())
        out.putShort(0)

        out.put(dnsPayload)
        return out.array()
    }

    private fun calculateChecksum(buf: ByteArray, offset: Int, length: Int): Short {
        var sum = 0L
        var i = offset
        while (i < offset + length) {
            val word = ((buf[i].toInt() and 0xFF) shl 8) or (if (i + 1 < offset + length) (buf[i + 1].toInt() and 0xFF) else 0)
            sum += word
            i += 2
        }
        while ((sum shr 16) > 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return (sum.inv() and 0xFFFF).toShort()
    }

    private fun stopVpn() {
        isRunning = false
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        vpnInterface = null
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}
