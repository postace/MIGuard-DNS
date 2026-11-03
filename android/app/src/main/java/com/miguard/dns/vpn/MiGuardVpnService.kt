package com.miguard.dns.vpn

import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import com.miguard.dns.data.PerAppMode
import com.miguard.dns.data.VpnRepository
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import kotlin.concurrent.thread

/**
 * MiGuardVpnService — Dịch vụ VPN cục bộ chặn telemetry Xiaomi/MIUI về 0.0.0.0
 * và chuyển tiếp các truy vấn hợp lệ ra DNS 1.1.1.1 hoặc 8.8.8.8.
 */
class MiGuardVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.miguard.dns.START_VPN"
        const val ACTION_STOP = "com.miguard.dns.STOP_VPN"
        const val VIRTUAL_TUN_IP = "10.111.222.1"
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    @Volatile private var isRunning = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpnTunnel()
            stopSelf()
            return START_NOT_STICKY
        }

        // Tự động dọn các bản ghi log cũ hơn thời hạn lưu trữ (mặc định 7 ngày)
        VpnRepository.purgeExpiredLogs()

        if (!isRunning) {
            isRunning = true
            VpnRepository.setVpnRunning(true)
            startDnsTunnel()
        }
        return START_STICKY
    }

    private fun startDnsTunnel() {
        val primaryDns = VpnRepository.primaryDns.value
        val secondaryDns = if (primaryDns == "1.1.1.1") "8.8.8.8" else "1.1.1.1"
        val selectedPkgs = VpnRepository.selectedPackages.value
        val mode = VpnRepository.perAppMode.value

        val builder = Builder()
            .setSession("MiGuard DNS")
            .setMtu(1500)
            .addAddress(VIRTUAL_TUN_IP, 24)
            .addDnsServer(primaryDns)
            .addDnsServer(secondaryDns)
            .addRoute(primaryDns, 32)
            .addRoute(secondaryDns, 32)

        selectedPkgs.forEach { pkg ->
            try {
                if (mode == PerAppMode.ALLOWLIST) {
                    builder.addAllowedApplication(pkg)
                } else {
                    builder.addDisallowedApplication(pkg)
                }
            } catch (_: PackageManager.NameNotFoundException) {
                // Bỏ qua nếu thiết bị không có package này
            }
        }

        vpnInterface = builder.establish() ?: run {
            stopVpnTunnel()
            return
        }

        thread(name = "MiGuard-DnsTunnel", isDaemon = true) {
            val fd = vpnInterface?.fileDescriptor ?: return@thread
            val input = FileInputStream(fd)
            val output = FileOutputStream(fd)
            val buffer = ByteArray(1500)

            while (isRunning) {
                try {
                    val length = input.read(buffer)
                    if (length > 0) {
                        val packetCopy = buffer.copyOf(length)
                        processPacket(packetCopy, length, output)
                    }
                } catch (_: Exception) {
                    if (!isRunning) break
                }
            }
        }
    }

    private fun processPacket(rawPacket: ByteArray, length: Int, tunOutput: FileOutputStream) {
        val domain = DnsPacketHelper.extractDomainName(rawPacket, length) ?: return
        val startTime = System.currentTimeMillis()

        if (VpnRepository.shouldBlockDomain(domain)) {
            val sinkholePacket = DnsPacketHelper.buildSinkholeResponse(rawPacket, length)
            synchronized(tunOutput) {
                tunOutput.write(sinkholePacket)
            }
            val elapsed = (System.currentTimeMillis() - startTime).coerceAtLeast(1L)
            VpnRepository.recordDnsLog(
                domain = domain,
                blocked = true,
                resolvedTarget = "0.0.0.0",
                latencyMs = elapsed
            )
        } else {
            val upstreamDns = VpnRepository.primaryDns.value
            thread(isDaemon = true) {
                try {
                    DatagramSocket().use { socket ->
                        protect(socket)
                        socket.soTimeout = 3000
                        val payload = DnsPacketHelper.extractUdpPayload(rawPacket, length)
                        val serverAddr = InetAddress.getByName(upstreamDns)
                        socket.send(DatagramPacket(payload, payload.size, serverAddr, 53))

                        val respBuf = ByteArray(1500)
                        val respPacket = DatagramPacket(respBuf, respBuf.size)
                        socket.receive(respPacket)

                        val wrapped = DnsPacketHelper.wrapUdpResponse(
                            originalRequest = rawPacket,
                            dnsResponse = respBuf,
                            dnsLength = respPacket.length
                        )
                        synchronized(tunOutput) {
                            tunOutput.write(wrapped)
                        }
                        val elapsed = (System.currentTimeMillis() - startTime).coerceAtLeast(1L)
                        VpnRepository.recordDnsLog(
                            domain = domain,
                            blocked = false,
                            resolvedTarget = upstreamDns,
                            latencyMs = elapsed
                        )
                    }
                } catch (_: Exception) {
                    // Timeout hoặc không có kết nối mạng
                }
            }
        }
    }

    private fun stopVpnTunnel() {
        isRunning = false
        VpnRepository.setVpnRunning(false)
        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }
        vpnInterface = null
    }

    override fun onDestroy() {
        stopVpnTunnel()
        super.onDestroy()
    }
}
