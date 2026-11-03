package com.miguard.dns.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import com.miguard.dns.MainActivity
import com.miguard.dns.R
import com.miguard.dns.data.PerAppMode
import com.miguard.dns.data.VpnRepository
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import kotlin.concurrent.thread

/**
 * MiGuardVpnService — Dịch vụ VPN Foreground chạy ngầm liên tục,
 * chặn telemetry Xiaomi/MIUI về 0.0.0.0 và chuyển tiếp các truy vấn hợp lệ ra DNS 1.1.1.1 hoặc 8.8.8.8.
 */
class MiGuardVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.miguard.dns.START_VPN"
        const val ACTION_STOP = "com.miguard.dns.STOP_VPN"
        const val VIRTUAL_TUN_IP = "10.111.222.1"
        private const val NOTIFICATION_CHANNEL_ID = "miguard_vpn_background_channel"
        private const val NOTIFICATION_ID = 1001
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    @Volatile private var isRunning = false

    override fun onCreate() {
        super.onCreate()
        VpnRepository.init(applicationContext)
        ensureNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        VpnRepository.init(applicationContext)

        if (intent?.action == ACTION_STOP) {
            stopVpnTunnel(persistState = true)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        // Đưa dịch vụ lên chế độ Foreground ngay lập tức để Android/MIUI cho phép chạy ngầm 24/7
        promoteToForeground()

        // Tự động dọn các bản ghi log cũ hơn thời hạn lưu trữ (mặc định 7 ngày)
        VpnRepository.purgeExpiredLogs()

        if (!isRunning) {
            isRunning = true
            VpnRepository.setVpnRunning(true, persistState = true)
            startDnsTunnel()
        }
        return START_STICKY
    }

    private fun ensureNotificationChannel() {
        val manager = getSystemService(NotificationManager::class.java) ?: return
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            "MiGuard DNS Background Protection",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Duy trì kết nối VPN lọc DNS chặn Telemetry chạy ngầm liên tục"
            setShowBadge(false)
        }
        manager.createNotificationChannel(channel)
    }

    private fun promoteToForeground() {
        ensureNotificationChannel()

        val openAppIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val openAppPendingIntent = PendingIntent.getActivity(
            this,
            0,
            openAppIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopVpnIntent = Intent(this, MiGuardVpnService::class.java).apply {
            action = ACTION_STOP
        }
        val stopVpnPendingIntent = PendingIntent.getService(
            this,
            1,
            stopVpnIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val primaryDns = VpnRepository.primaryDns.value
        val builder = Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle("MiGuard DNS đang chạy ngầm")
            .setContentText("Đang chặn Telemetry về 0.0.0.0 · DNS $primaryDns")
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setContentIntent(openAppPendingIntent)
            .addAction(
                Notification.Action.Builder(
                    null,
                    "Ngắt kết nối",
                    stopVpnPendingIntent
                ).build()
            )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            builder.setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE)
        }

        val notification = builder.build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        // Giữ dịch vụ tiếp tục chạy ngầm khi người dùng vuốt đóng ứng dụng khỏi Đa nhiệm (Recents)
        if (isRunning) {
            val restartIntent = Intent(applicationContext, MiGuardVpnService::class.java).apply {
                action = ACTION_START
            }
            applicationContext.startForegroundService(restartIntent)
        }
        super.onTaskRemoved(rootIntent)
    }

    override fun onRevoke() {
        stopVpnTunnel(persistState = true)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        super.onRevoke()
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

    private fun stopVpnTunnel(persistState: Boolean = false) {
        isRunning = false
        VpnRepository.setVpnRunning(false, persistState = persistState)
        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }
        vpnInterface = null
    }

    override fun onDestroy() {
        stopVpnTunnel(persistState = false)
        super.onDestroy()
    }
}
