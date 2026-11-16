// Замените в вашем коде только метод loadBlocklistFromAssets и forwardToRealDns:

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

        // Резервные домены (исправлена опечатка с :// )
        blockedDomains.add("an.yandex.ru")
        blockedDomains.add("mc.yandex.ru")
        blockedDomains.add("googleads.g.doubleclick.net")
        blockedDomains.add("googlesyndication.com")
        blockedDomains.add("ad.mail.ru")
    }

    // Улучшенный метод отправки DNS (если 8.8.8.8 заблокирован, пробуем 1.1.1.1 и Яндекс)
    private fun forwardToRealDns(dnsData: ByteArray): ByteArray? {
        val servers = listOf("1.1.1.1", "77.88.8.8", "8.8.8.8") // Резервные серверы
        
        for (serverIp in servers) {
            val socket = DatagramSocket()
            protect(socket)
            socket.soTimeout = 2000 // 2 секунды на ответ

            try {
                val serverAddress = InetAddress.getByName(serverIp)
                val outPacket = DatagramPacket(dnsData, dnsData.size, serverAddress, 53)
                socket.send(outPacket)

                val buffer = ByteArray(4096)
                val inPacket = DatagramPacket(buffer, buffer.size)
                socket.receive(inPacket)

                return inPacket.data.copyOf(inPacket.length)
            } catch (e: Exception) {
                // Если сервер не ответил, идем к следующему в списке
            } finally {
                socket.close()
            }
        }
        return null // Если все серверы недоступны
    }
