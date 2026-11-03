package com.miguard.dns.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import com.miguard.dns.data.VpnRepository

/**
 * BootReceiver — Tự động khởi động lại dịch vụ VPN chạy ngầm khi bật nguồn thiết bị
 * hoặc sau khi cập nhật ứng dụng nếu trước đó người dùng đang bật bảo vệ.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action == Intent.ACTION_BOOT_COMPLETED || action == Intent.ACTION_MY_PACKAGE_REPLACED) {
            VpnRepository.init(context)
            val shouldStart = VpnRepository.isAutoStartOnBootEnabled(context) &&
                    VpnRepository.wasVpnEnabledBeforeStop(context)

            if (shouldStart && VpnService.prepare(context) == null) {
                val serviceIntent = Intent(context, MiGuardVpnService::class.java).apply {
                    this.action = MiGuardVpnService.ACTION_START
                }
                context.startForegroundService(serviceIntent)
            }
        }
    }
}
