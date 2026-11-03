package com.miguard.dns.data

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class PerAppMode {
    ALLOWLIST, // Chỉ lọc DNS cho các package được chọn (addAllowedApplication)
    BLOCKLIST  // Lọc toàn máy và loại trừ các package được chọn (addDisallowedApplication)
}

data class BlockRule(
    val domain: String,
    val enabled: Boolean = true,
    val isDefault: Boolean = false,
    val hitCount: Long = 0
)

data class DnsLogRecord(
    val id: Long,
    val timestampMs: Long,
    val domain: String,
    val blocked: Boolean,
    val resolvedTarget: String,
    val latencyMs: Long
)

object VpnRepository {
    const val DEFAULT_RETENTION_DAYS = 7L
    private const val DAY_MS = 24 * 60 * 60 * 1000L

    private val _vpnRunning = MutableStateFlow(false)
    val vpnRunning: StateFlow<Boolean> = _vpnRunning.asStateFlow()

    private val _primaryDns = MutableStateFlow("1.1.1.1")
    val primaryDns: StateFlow<String> = _primaryDns.asStateFlow()

    private val _retentionDays = MutableStateFlow(DEFAULT_RETENTION_DAYS)
    val retentionDays: StateFlow<Long> = _retentionDays.asStateFlow()

    private val _perAppMode = MutableStateFlow(PerAppMode.ALLOWLIST)
    val perAppMode: StateFlow<PerAppMode> = _perAppMode.asStateFlow()

    // 5 tên miền Xiaomi/MIUI chặn mặc định về 0.0.0.0
    private val _rules = MutableStateFlow(
        listOf(
            BlockRule("fraud-detection.engine.miui.com", enabled = true, isDefault = true),
            BlockRule("flash.sec.miui.com", enabled = true, isDefault = true),
            BlockRule("dm.wo.com.cn", enabled = true, isDefault = true),
            BlockRule("data.mistat.xiaomi.com", enabled = true, isDefault = true),
            BlockRule("tracking.miui.com", enabled = true, isDefault = true)
        )
    )
    val rules: StateFlow<List<BlockRule>> = _rules.asStateFlow()

    // Danh sách gợi ý tự động các domain telemetry Xiaomi/MIUI
    val miuiSuggestions = listOf(
        "data.mistat.intl.xiaomi.com",
        "tracking.intl.miui.com",
        "api.ad.xiaomi.com",
        "sdkconfig.ad.xiaomi.com",
        "ccc.sys.miui.com",
        "abtest.mistat.xiaomi.com",
        "metok.sys.miui.com",
        "sec-cdn.static.xiaomi.net"
    )

    private val _selectedPackages = MutableStateFlow(
        setOf(
            "com.miui.securitycenter",
            "com.miui.analytics",
            "com.miui.daemon",
            "com.miui.msa.global",
            "com.xiaomi.joyose",
            "com.xiaomi.finddevice",
            "com.miui.guardprovider"
        )
    )
    val selectedPackages: StateFlow<Set<String>> = _selectedPackages.asStateFlow()

    private val _logs = MutableStateFlow<List<DnsLogRecord>>(emptyList())
    val logs: StateFlow<List<DnsLogRecord>> = _logs.asStateFlow()

    fun setVpnRunning(running: Boolean) {
        _vpnRunning.value = running
    }

    fun setPrimaryDns(dns: String) {
        if (dns == "1.1.1.1" || dns == "8.8.8.8") {
            _primaryDns.value = dns
        }
    }

    fun setRetentionDays(days: Long) {
        _retentionDays.value = days
        purgeExpiredLogs()
    }

    fun setPerAppMode(mode: PerAppMode) {
        _perAppMode.value = mode
    }

    fun togglePackage(packageName: String) {
        val current = _selectedPackages.value.toMutableSet()
        if (current.contains(packageName)) {
            current.remove(packageName)
        } else {
            current.add(packageName)
        }
        _selectedPackages.value = current
    }

    fun addOrEnableRule(rawInput: String) {
        val clean = rawInput.trim().lowercase()
            .removePrefix("0.0.0.0")
            .removePrefix("127.0.0.1")
            .trim()
        if (clean.isEmpty()) return
        val current = _rules.value.toMutableList()
        val existingIdx = current.indexOfFirst { it.domain == clean }
        if (existingIdx >= 0) {
            current[existingIdx] = current[existingIdx].copy(enabled = true)
        } else {
            current.add(0, BlockRule(domain = clean, enabled = true, isDefault = false))
        }
        _rules.value = current
    }

    fun toggleRule(domain: String) {
        _rules.value = _rules.value.map {
            if (it.domain == domain) it.copy(enabled = !it.enabled) else it
        }
    }

    fun removeRule(domain: String) {
        _rules.value = _rules.value.filterNot { it.domain == domain }
    }

    fun shouldBlockDomain(domain: String): Boolean {
        val q = domain.lowercase()
        val matched = _rules.value.firstOrNull { rule ->
            rule.enabled && (q == rule.domain || q.endsWith(".${rule.domain}"))
        }
        if (matched != null) {
            _rules.value = _rules.value.map {
                if (it.domain == matched.domain) it.copy(hitCount = it.hitCount + 1) else it
            }
            return true
        }
        return false
    }

    fun recordDnsLog(domain: String, blocked: Boolean, resolvedTarget: String, latencyMs: Long) {
        val now = System.currentTimeMillis()
        val cutoff = now - (_retentionDays.value * DAY_MS)
        val entry = DnsLogRecord(
            id = now xor domain.hashCode().toLong(),
            timestampMs = now,
            domain = domain,
            blocked = blocked,
            resolvedTarget = resolvedTarget,
            latencyMs = latencyMs
        )
        _logs.value = (listOf(entry) + _logs.value.filter { it.timestampMs >= cutoff }).take(300)
    }

    /**
     * Xóa các bản ghi log kết nối cũ hơn thời gian cấu hình (Mặc định 7 ngày)
     */
    fun purgeExpiredLogs(customDays: Long = _retentionDays.value): Int {
        val cutoff = System.currentTimeMillis() - (customDays * DAY_MS)
        val before = _logs.value.size
        _logs.value = _logs.value.filter { it.timestampMs >= cutoff }
        return before - _logs.value.size
    }

    fun clearAllLogs() {
        _logs.value = emptyList()
    }
}
