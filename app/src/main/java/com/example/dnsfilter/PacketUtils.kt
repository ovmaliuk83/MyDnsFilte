package com.example.dnsfilter

import java.nio.ByteBuffer

/** Сборка IPv4-пакетов и контрольные суммы. */
object PacketUtils {

    fun u16(buf: ByteArray, offset: Int): Int =
        ((buf[offset].toInt() and 0xFF) shl 8) or (buf[offset + 1].toInt() and 0xFF)

    fun checksum(buf: ByteArray, offset: Int, length: Int): Short {
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

    /** Ответ на UDP-запрос: адреса и порты меняются местами. */
    fun buildUdpResponse(req: ByteArray, ihl: Int, dns: ByteArray): ByteArray {
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

    /** TCP RST в ответ на SYN: мгновенно обрывает соединение. */
    fun buildTcpReset(req: ByteArray, ihl: Int): ByteArray {
        val out = ByteArray(40)
        val b = ByteBuffer.wrap(out)

        out[0] = 0x45
        out[8] = 64
        out[9] = 6
        b.putShort(2, 40.toShort())
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
}
// КОНЕЦ ФАЙЛА
