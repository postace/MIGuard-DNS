package com.miguard.dns

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.miguard.dns.data.DnsLogRecord
import com.miguard.dns.data.PerAppMode
import com.miguard.dns.data.VpnRepository
import com.miguard.dns.vpn.MiGuardVpnService
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        VpnRepository.init(applicationContext)
        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    primary = Color(0xFF10B981),
                    onPrimary = Color.White,
                    background = Color(0xFF090D16),
                    surface = Color(0xFF111827)
                )
            ) {
                MiGuardAppScreen()
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun MiGuardAppScreen() {
    val context = LocalContext.current
    val haptic = LocalHapticFeedback.current
    val isRunning by VpnRepository.vpnRunning.collectAsState()
    val autoStartOnBoot by VpnRepository.autoStartOnBoot.collectAsState()
    val primaryDns by VpnRepository.primaryDns.collectAsState()
    val retentionDays by VpnRepository.retentionDays.collectAsState()
    val perAppMode by VpnRepository.perAppMode.collectAsState()
    val rules by VpnRepository.rules.collectAsState()
    val selectedPackages by VpnRepository.selectedPackages.collectAsState()
    val logs by VpnRepository.logs.collectAsState()

    var currentTab by remember { mutableStateOf(0) }
    var customDomainText by remember { mutableStateOf("") }
    var selectedLogItem by remember { mutableStateOf<DnsLogRecord?>(null) }

    val powerManager = remember { context.getSystemService(PowerManager::class.java) }
    var isIgnoringBatteryOpt by remember {
        mutableStateOf(powerManager?.isIgnoringBatteryOptimizations(context.packageName) ?: false)
    }

    val batteryOptLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) {
        isIgnoringBatteryOpt = powerManager?.isIgnoringBatteryOptimizations(context.packageName) ?: false
    }

    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { _ -> }

    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    fun requestUnrestrictedBackground() {
        isIgnoringBatteryOpt = powerManager?.isIgnoringBatteryOptimizations(context.packageName) ?: false
        if (!isIgnoringBatteryOpt) {
            try {
                val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                    data = Uri.parse("package:${context.packageName}")
                }
                batteryOptLauncher.launch(intent)
            } catch (_: Exception) {
                val fallback = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                batteryOptLauncher.launch(fallback)
            }
        }
    }

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val intent = Intent(context, MiGuardVpnService::class.java).apply {
                action = MiGuardVpnService.ACTION_START
            }
            context.startForegroundService(intent)
        }
    }

    fun toggleVpn() {
        if (isRunning) {
            val stopIntent = Intent(context, MiGuardVpnService::class.java).apply {
                action = MiGuardVpnService.ACTION_STOP
            }
            context.startService(stopIntent)
        } else {
            val prepareIntent = VpnService.prepare(context)
            if (prepareIntent != null) {
                vpnPermissionLauncher.launch(prepareIntent)
            } else {
                val startIntent = Intent(context, MiGuardVpnService::class.java).apply {
                    action = MiGuardVpnService.ACTION_START
                }
                context.startForegroundService(startIntent)
            }
        }
    }

    Scaffold(
        containerColor = Color(0xFF090D16),
        bottomBar = {
            NavigationBar(containerColor = Color(0xFF111827)) {
                listOf("Điều khiển", "Nhật ký", "Danh sách chặn", "Gói hệ thống").forEachIndexed { idx, title ->
                    NavigationBarItem(
                        selected = currentTab == idx,
                        onClick = { currentTab = idx },
                        icon = {},
                        label = { Text(title, fontSize = 12.sp) }
                    )
                }
            }
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            when (currentTab) {
                0 -> {
                    // Màn hình chính: Bật/Tắt VPN + Chọn DNS 1.1.1.1 / 8.8.8.8 + Thống kê
                    Surface(
                        shape = RoundedCornerShape(16.dp),
                        color = Color(0xFF111827),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Text(
                                text = if (isRunning) "Đang bảo vệ (TUN 10.111.222.1)" else "VPN đang tắt",
                                color = if (isRunning) Color(0xFF10B981) else Color.Gray,
                                fontSize = 13.sp,
                                fontFamily = FontFamily.Monospace
                            )
                            Text(
                                text = if (isRunning) "Đang chặn Telemetry Xiaomi/MIUI" else "Chạm để kích hoạt lọc DNS",
                                color = Color.White,
                                fontSize = 20.sp,
                                fontWeight = FontWeight.Bold
                            )
                            Button(
                                onClick = { toggleVpn() },
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = if (isRunning) Color(0xFFE11D48) else Color(0xFF10B981),
                                    contentColor = Color.White
                                ),
                                modifier = Modifier.fillMaxWidth().height(50.dp)
                            ) {
                                Text(
                                    text = if (isRunning) "Ngắt kết nối VPN" else "Bật bảo vệ DNS",
                                    color = Color.White,
                                    fontWeight = FontWeight.SemiBold
                                )
                            }
                        }
                    }

                    Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
                        listOf("1.1.1.1", "8.8.8.8").forEach { dns ->
                            OutlinedButton(
                                onClick = { VpnRepository.setPrimaryDns(dns) },
                                modifier = Modifier.weight(1f),
                                colors = ButtonDefaults.outlinedButtonColors(
                                    containerColor = if (primaryDns == dns) Color(0xFF10B981).copy(alpha = 0.15f) else Color.Transparent
                                )
                            ) {
                                Text("DNS $dns", color = Color.White, fontFamily = FontFamily.Monospace)
                            }
                        }
                    }

                    val totalBlocked = rules.sumOf { it.hitCount }
                    Text(
                        text = "Đã chặn về 0.0.0.0: $totalBlocked request · Chu kỳ xóa log: $retentionDays ngày",
                        color = Color.LightGray,
                        fontSize = 13.sp,
                        fontFamily = FontFamily.Monospace
                    )

                    // Thẻ cấu hình chạy ngầm 24/7 & Tắt giới hạn pin MIUI/Android
                    Surface(
                        shape = RoundedCornerShape(16.dp),
                        color = Color(0xFF111827),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Text(
                                text = "Chế độ chạy ngầm 24/7 (Foreground & MIUI)",
                                color = Color.White,
                                fontSize = 15.sp,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = if (isIgnoringBatteryOpt)
                                    "✓ Đã cấp quyền chạy ngầm không giới hạn pin (Unrestricted)"
                                else
                                    "⚠ Cần tắt giới ưu hóa pin để MIUI/HyperOS không tự đóng VPN khi khóa màn hình",
                                color = if (isIgnoringBatteryOpt) Color(0xFF10B981) else Color(0xFFF59E0B),
                                fontSize = 12.sp
                            )
                            if (!isIgnoringBatteryOpt) {
                                OutlinedButton(
                                    onClick = { requestUnrestrictedBackground() },
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Text("Cho phép chạy ngầm không giới hạn Pin", color = Color(0xFF10B981))
                                }
                            }
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = "Tự chạy ngầm khi khởi động máy",
                                        color = Color.White,
                                        fontSize = 13.sp
                                    )
                                    Text(
                                        text = "Tự động bật lại VPN sau khi khởi động lại thiết bị",
                                        color = Color.Gray,
                                        fontSize = 11.sp
                                    )
                                }
                                Switch(
                                    checked = autoStartOnBoot,
                                    onCheckedChange = { VpnRepository.setAutoStartOnBoot(it) }
                                )
                            }
                        }
                    }
                }

                1 -> {
                    // Màn hình Nhật ký thời gian thực & Tự xóa log (Mặc định 7 ngày)
                    Text("Tự động xóa log kết nối sau:", color = Color.White, fontWeight = FontWeight.SemiBold)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        listOf(1L, 3L, 7L, 14L, 30L).forEach { dayOption ->
                            FilterChip(
                                selected = retentionDays == dayOption,
                                onClick = { VpnRepository.setRetentionDays(dayOption) },
                                label = { Text(if (dayOption == 7L) "7 ngày (Mặc định)" else "$dayOption ngày") }
                            )
                        }
                    }

                    Text(
                        text = "Mẹo: Nhấn giữ (Long press) vào bất kỳ dòng nhật ký nào để thêm nhanh host vào danh sách chặn (0.0.0.0).",
                        color = Color.Gray,
                        fontSize = 11.sp
                    )

                    val sdf = remember { SimpleDateFormat("HH:mm:ss", Locale.getDefault()) }
                    LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        items(logs, key = { it.id }) { item ->
                            Surface(
                                shape = RoundedCornerShape(12.dp),
                                color = Color(0xFF111827),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .combinedClickable(
                                        onClick = {},
                                        onLongClick = {
                                            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                                            selectedLogItem = item
                                        }
                                    )
                            ) {
                                Row(
                                    modifier = Modifier.padding(12.dp).fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = item.domain,
                                            color = if (item.blocked) Color(0xFFF43F5E) else Color.White,
                                            fontFamily = FontFamily.Monospace,
                                            fontSize = 13.sp
                                        )
                                        Text(
                                            text = "${sdf.format(Date(item.timestampMs))} · ${item.latencyMs} ms",
                                            color = Color.Gray,
                                            fontSize = 11.sp,
                                            fontFamily = FontFamily.Monospace
                                        )
                                    }
                                    Text(
                                        text = if (item.blocked) "0.0.0.0" else item.resolvedTarget,
                                        color = if (item.blocked) Color(0xFFF43F5E) else Color(0xFF10B981),
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 12.sp
                                    )
                                }
                            }
                        }
                    }

                    selectedLogItem?.let { logEntry ->
                        val isAlreadyBlocked = rules.any {
                            it.enabled && (logEntry.domain.equals(it.domain, ignoreCase = true) ||
                                    logEntry.domain.lowercase().endsWith(".${it.domain.lowercase()}"))
                        }
                        AlertDialog(
                            onDismissRequest = { selectedLogItem = null },
                            containerColor = Color(0xFF111827),
                            title = {
                                Text(
                                    text = if (isAlreadyBlocked) "Tên miền đã trong danh sách chặn" else "Chặn tên miền này?",
                                    color = Color.White,
                                    fontSize = 16.sp,
                                    fontWeight = FontWeight.Bold
                                )
                            },
                            text = {
                                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Text(
                                        text = "0.0.0.0 ${logEntry.domain}",
                                        color = Color(0xFF10B981),
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = FontWeight.SemiBold,
                                        fontSize = 13.sp
                                    )
                                    Text(
                                        text = if (isAlreadyBlocked)
                                            "Host này hiện đang bị chặn về 0.0.0.0. Bạn có muốn bỏ chặn host này khỏi danh sách không?"
                                        else
                                            "Thêm host này vào danh sách chặn (Sinkhole 0.0.0.0) để ngăn các kết nối tiếp theo.",
                                        color = Color.LightGray,
                                        fontSize = 13.sp
                                    )
                                }
                            },
                            confirmButton = {
                                if (isAlreadyBlocked) {
                                    Button(
                                        onClick = {
                                            VpnRepository.toggleRule(logEntry.domain.lowercase())
                                            Toast.makeText(
                                                context,
                                                "Đã tắt chặn ${logEntry.domain}",
                                                Toast.LENGTH_SHORT
                                            ).show()
                                            selectedLogItem = null
                                        },
                                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFF59E0B))
                                    ) {
                                        Text("Bỏ chặn", color = Color.Black)
                                    }
                                } else {
                                    Button(
                                        onClick = {
                                            VpnRepository.addOrEnableRule(logEntry.domain)
                                            Toast.makeText(
                                                context,
                                                "Đã thêm ${logEntry.domain} vào danh sách chặn (0.0.0.0)",
                                                Toast.LENGTH_SHORT
                                            ).show()
                                            selectedLogItem = null
                                        },
                                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFE11D48))
                                    ) {
                                        Text("Thêm vào danh sách chặn", color = Color.White)
                                    }
                                }
                            },
                            dismissButton = {
                                TextButton(onClick = { selectedLogItem = null }) {
                                    Text("Hủy", color = Color.Gray)
                                }
                            }
                        )
                    }
                }

                2 -> {
                    // Màn hình Danh sách chặn & Gợi ý MIUI
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                        OutlinedTextField(
                            value = customDomainText,
                            onValueChange = { customDomainText = it },
                            placeholder = { Text("0.0.0.0 domain.com") },
                            modifier = Modifier.weight(1f),
                            singleLine = true
                        )
                        Button(
                            onClick = {
                                VpnRepository.addOrEnableRule(customDomainText)
                                customDomainText = ""
                            },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = Color(0xFF10B981),
                                contentColor = Color.White
                            )
                        ) {
                            Text("Thêm", color = Color.White, fontWeight = FontWeight.SemiBold)
                        }
                    }

                    LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        items(rules, key = { it.domain }) { rule ->
                            Surface(
                                shape = RoundedCornerShape(12.dp),
                                color = Color(0xFF111827),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Row(
                                    modifier = Modifier.padding(12.dp).fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = "0.0.0.0 ${rule.domain}",
                                            color = Color.White,
                                            fontFamily = FontFamily.Monospace,
                                            fontSize = 13.sp
                                        )
                                        Text(
                                            text = "Đã chặn ${rule.hitCount} lần",
                                            color = Color.Gray,
                                            fontSize = 11.sp
                                        )
                                    }
                                    Switch(
                                        checked = rule.enabled,
                                        onCheckedChange = { VpnRepository.toggleRule(rule.domain) }
                                    )
                                }
                            }
                        }
                    }
                }

                3 -> {
                    // Màn hình chọn Package hệ thống (Per-App VPN)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilterChip(
                            selected = perAppMode == PerAppMode.ALLOWLIST,
                            onClick = { VpnRepository.setPerAppMode(PerAppMode.ALLOWLIST) },
                            label = { Text("Chỉ lọc gói đã chọn") }
                        )
                        FilterChip(
                            selected = perAppMode == PerAppMode.BLOCKLIST,
                            onClick = { VpnRepository.setPerAppMode(PerAppMode.BLOCKLIST) },
                            label = { Text("Lọc toàn máy & loại trừ") }
                        )
                    }

                    val systemPackages = listOf(
                        "com.miui.securitycenter",
                        "com.miui.analytics",
                        "com.miui.daemon",
                        "com.miui.msa.global",
                        "com.xiaomi.joyose",
                        "com.xiaomi.finddevice",
                        "com.miui.guardprovider"
                    )

                    LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        items(systemPackages) { pkg ->
                            Surface(
                                shape = RoundedCornerShape(12.dp),
                                color = Color(0xFF111827),
                                modifier = Modifier.fillMaxWidth().clickable { VpnRepository.togglePackage(pkg) }
                            ) {
                                Row(
                                    modifier = Modifier.padding(12.dp).fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(pkg, color = Color.White, fontFamily = FontFamily.Monospace, fontSize = 13.sp)
                                    Checkbox(
                                        checked = selectedPackages.contains(pkg),
                                        onCheckedChange = { VpnRepository.togglePackage(pkg) }
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
