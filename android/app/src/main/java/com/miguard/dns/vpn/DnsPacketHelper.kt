package com.miguard.dns.vpn

import java.nio.ByteBuffer

/**
 * DnsPacketHelper — Bộ giải mã gói tin IPv4 + UDP + DNS và tạo phản hồi 0.0.0.0 (Sinkhole)
 */
object DnsPacketHelper {

    fun isUdpDnsPacket(packet: ByteArray, length: Int): Boolean {
        if (length < 28) return false
        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return false
        val protocol = packet[9].toInt() and 0xFF
        if (protocol != 17) return false // 17 = UDP
        val ipHeaderLen = (packet[0].toInt() and 0x0F) * 4
        if (length < ipHeaderLen + 8 + 12) return false
        val dstPort = ((packet[ipHeaderLen + 2].toInt() and 0xFF) shl 8) or
                (packet[ipHeaderLen + 3].toInt() and 0xFF)
        return dstPort == 53
    }

    fun extractDomainName(packet: ByteArray, length: Int): String? {
        if (!isUdpDnsPacket(packet, length)) return null
        val ipHeaderLen = (packet[0].toInt() and 0x0F) * 4
        val dnsStart = ipHeaderLen + 8
        var pos = dnsStart + 12 // Bỏ qua 12 bytes DNS Header
        val labels = mutableListOf<String>()

        while (pos < length) {
            val labelLen = packet[pos].toInt() and 0xFF
            if (labelLen == 0) break
            if ((labelLen and 0xC0) == 0xC0) break
            pos++
            if (pos + labelLen > length) return null
            labels.add(String(packet, pos, labelLen, Charsets.UTF_8))
            pos += labelLen
        }
        return if (labels.isEmpty()) null else labels.joinToString(".")
    }

    fun extractUdpPayload(packet: ByteArray, length: Int): ByteArray {
        val ipHeaderLen = (packet[0].toInt() and 0x0F) * 4
        val dnsOffset = ipHeaderLen + 8
        return packet.copyOfRange(dnsOffset, length)
    }

    /**
     * Tạo gói tin phản hồi DNS trả về 0.0.0.0 ngay lập tức cho các tên miền bị chặn
     */
    fun buildSinkholeResponse(requestPacket: ByteArray, requestLength: Int): ByteArray {
        val dnsQuery = extractUdpPayload(requestPacket, requestLength)
        val answerSection = byteArrayOf(
            0xC0.toByte(), 0x0C.toByte(), // Con trỏ tới QNAME tại offset 12
            0x00, 0x01,                   // TYPE A (IPv4)
            0x00, 0x01,                   // CLASS IN
            0x00, 0x00, 0x00, 0x3C,       // TTL = 60 giây
            0x00, 0x04,                   // RDLENGTH = 4 bytes
            0x00, 0x00, 0x00, 0x00        // RDATA = 0.0.0.0
        )

        val dnsResponse = ByteArray(dnsQuery.size + answerSection.size)
        System.arraycopy(dnsQuery, 0, dnsResponse, 0, dnsQuery.size)
        // Đặt cờ QR=1 (Response), RD=1, RA=1, RCODE=0 (No error)
        dnsResponse[2] = 0x81.toByte()
        dnsResponse[3] = 0x80.toByte()
        // Đặt ANCOUNT = 1
        dnsResponse[6] = 0x00
        dnsResponse[7] = 0x01
        System.arraycopy(answerSection, 0, dnsResponse, dnsQuery.size, answerSection.size)

        return wrapUdpResponse(requestPacket, dnsResponse, dnsResponse.size)
    }

    /**
     * Đóng gói payload DNS trả về vào gói tin IPv4 + UDP hoàn chỉnh để ghi vào giao diện TUN
     */
    fun wrapUdpResponse(
        originalRequest: ByteArray,
        dnsResponse: ByteArray,
        dnsLength: Int
    ): ByteArray {
        val ipHeaderLen = 20
        val udpHeaderLen = 8
        val totalLen = ipHeaderLen + udpHeaderLen + dnsLength
        val out = ByteBuffer.allocate(totalLen)

        val reqIpHeaderLen = (originalRequest[0].toInt() and 0x0F) * 4
        val srcIp = originalRequest.copyOfRange(12, 16)
        val dstIp = originalRequest.copyOfRange(16, 20)
        val srcPort = originalRequest.copyOfRange(reqIpHeaderLen, reqIpHeaderLen + 2)
        val dstPort = originalRequest.copyOfRange(reqIpHeaderLen + 2, reqIpHeaderLen + 4)

        // IPv4 Header (đảo chiều địa chỉ IP nguồn và đích)
        out.put(0x45.toByte())
        out.put(0x00.toByte())
        out.putShort(totalLen.toShort())
        out.putShort(0.toShort())
        out.putShort(0x4000.toShort())
        out.put(64.toByte())
        out.put(17.toByte()) // UDP
        out.putShort(0.toShort()) // Checksum tính sau
        out.put(dstIp)
        out.put(srcIp)

        // UDP Header (đảo chiều cổng nguồn và đích)
        out.put(dstPort)
        out.put(srcPort)
        out.putShort((udpHeaderLen + dnsLength).toShort())
        out.putShort(0.toShort()) // UDP checksum = 0 (tùy chọn trong IPv4)

        // DNS Payload
        out.put(dnsResponse, 0, dnsLength)

        val raw = out.array()
        val checksum = computeIpv4Checksum(raw, ipHeaderLen)
        raw[10] = ((checksum ushr 8) and 0xFF).toByte()
        raw[11] = (checksum and 0xFF).toByte()
        return raw
    }

    private fun computeIpv4Checksum(header: ByteArray, length: Int): Int {
        var sum = 0
        var i = 0
        while (i < length) {
            if (i != 10) {
                val word = ((header[i].toInt() and 0xFF) shl 8) or (header[i + 1].toInt() and 0xFF)
                sum += word
            }
            i += 2
        }
        while ((sum ushr 16) > 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv() and 0xFFFF
    }
}
