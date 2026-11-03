import {
  AppFilterMode,
  DnsUpstream,
  DomainRule,
  LogRetentionDays,
  SystemPackageItem,
} from '../data/vpnDefaults';

export function generateHostsFileContent(rules: DomainRule[]): string {
  const activeRules = rules.filter((r) => r.enabled);
  const header = [
    '# MiGuard DNS — Local Sinkhole Hosts Configuration',
    `# Active Blocked Domains: ${activeRules.length}`,
    '# Target Sinkhole Address: 0.0.0.0',
    '',
  ];
  const lines = activeRules.map((r) => `0.0.0.0 ${r.domain}`);
  return [...header, ...lines].join('\n');
}

export function generateKotlinVpnServiceCode(
  rules: DomainRule[],
  upstreamDns: DnsUpstream,
  secondaryDns: DnsUpstream,
  filterMode: AppFilterMode,
  packages: SystemPackageItem[],
  logRetentionDays: LogRetentionDays = 7
): string {
  const activeDomains = rules.filter((r) => r.enabled).map((r) => `        "${r.domain}"`);
  const selectedPackages = packages.filter((p) => p.selected).map((p) => `        "${p.packageName}"`);

  const perAppCodeBlock =
    filterMode === 'allowlist'
      ? `        // Chế độ: Chỉ lọc DNS cho các package hệ thống được chọn
        targetPackages.forEach { pkg ->
            try {
                builder.addAllowedApplication(pkg)
            } catch (e: PackageManager.NameNotFoundException) {
                // Bỏ qua nếu thiết bị không cài sẵn package này
            }
        }`
      : `        // Chế độ: Lọc toàn thiết bị và loại trừ các package được chọn
        targetPackages.forEach { pkg ->
            try {
                builder.addDisallowedApplication(pkg)
            } catch (e: PackageManager.NameNotFoundException) {
                // Bỏ qua nếu thiết bị không cài sẵn package này
            }
        }`;

  return `package com.miguard.dns.vpn

import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentLinkedDeque
import kotlin.concurrent.thread

/**
 * MiGuardVpnService — Dịch vụ Android VPN cục bộ nhẹ
 * Chặn các domain telemetry Xiaomi/MIUI về 0.0.0.0
 * Chuyển tiếp các truy vấn hợp lệ ra DNS ${upstreamDns} / ${secondaryDns}
 * Tự động xóa nhật ký kết nối quá ${logRetentionDays} ngày (mặc định 7 ngày)
 */
class MiGuardVpnService : VpnService() {

    data class ConnectionLog(val timestampMs: Long, val domain: String, val blocked: Boolean)

    private var vpnInterface: ParcelFileDescriptor? = null
    @Volatile private var isRunning = false
    private val connectionLogs = ConcurrentLinkedDeque<ConnectionLog>()

    companion object {
        const val PRIMARY_DNS = "${upstreamDns}"
        const val SECONDARY_DNS = "${secondaryDns}"
        const val VIRTUAL_TUN_IP = "10.111.222.1"
        const val LOG_RETENTION_DAYS = ${logRetentionDays}L
        const val LOG_RETENTION_MS = LOG_RETENTION_DAYS * 24 * 60 * 60 * 1000L
    }

    // Danh sách tên miền bị chặn về 0.0.0.0
    private val blockedDomains = hashSetOf(
${activeDomains.join(',\n')}
    )

    // Danh sách package hệ thống áp dụng bộ lọc Per-App VPN
    private val targetPackages = listOf(
${selectedPackages.join(',\n')}
    )

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        purgeExpiredLogs()
        if (!isRunning) {
            isRunning = true
            startDnsTunnel()
        }
        return START_STICKY
    }

    /**
     * Tự động xóa các bản ghi log kết nối cũ hơn thời gian lưu trữ (${logRetentionDays} ngày)
     */
    fun purgeExpiredLogs(retentionMs: Long = LOG_RETENTION_MS) {
        val cutoffTime = System.currentTimeMillis() - retentionMs
        val iterator = connectionLogs.iterator()
        while (iterator.hasNext()) {
            if (iterator.next().timestampMs < cutoffTime) {
                iterator.remove()
            }
        }
    }

    private fun startDnsTunnel() {
        val builder = Builder()
            .setSession("MiGuard DNS Filter")
            .setMtu(1500)
            .addAddress(VIRTUAL_TUN_IP, 24)
            .addDnsServer(PRIMARY_DNS)
            .addDnsServer(SECONDARY_DNS)
            // Chỉ định tuyến lưu lượng tới máy chủ DNS qua TUN để tiết kiệm pin tối đa
            .addRoute(PRIMARY_DNS, 32)
            .addRoute(SECONDARY_DNS, 32)

${perAppCodeBlock}

        vpnInterface = builder.establish() ?: return

        thread(name = "MiGuard-DnsLoop", isDaemon = true) {
            val fd = vpnInterface?.fileDescriptor ?: return@thread
            val input = FileInputStream(fd)
            val output = FileOutputStream(fd)
            val packet = ByteArray(1500)

            while (isRunning) {
                val length = input.read(packet)
                if (length > 0) {
                    handleIpPacket(packet, length, output)
                }
            }
        }
    }

    private fun handleIpPacket(rawPacket: ByteArray, length: Int, tunOutput: FileOutputStream) {
        val qName = DnsPacketHelper.extractDomainName(rawPacket, length) ?: return
        val normalizedDomain = qName.lowercase()

        if (shouldBlock(normalizedDomain)) {
            // Trả về ngay bản ghi A = 0.0.0.0 (Sinkhole) không cần ra mạng
            val sinkholeResponse = DnsPacketHelper.buildSinkholeResponse(rawPacket, length)
            tunOutput.write(sinkholeResponse)
            connectionLogs.addFirst(ConnectionLog(System.currentTimeMillis(), normalizedDomain, true))
        } else {
            // Chuyển tiếp ra DNS ${upstreamDns} qua socket được bảo vệ (protect)
            forwardToUpstreamDns(rawPacket, length, tunOutput)
            connectionLogs.addFirst(ConnectionLog(System.currentTimeMillis(), normalizedDomain, false))
        }
        purgeExpiredLogs()
    }

    private fun shouldBlock(domain: String): Boolean {
        if (blockedDomains.contains(domain)) return true
        return blockedDomains.any { blocked -> domain.endsWith(".\$blocked") }
    }

    private fun forwardToUpstreamDns(rawPacket: ByteArray, length: Int, tunOutput: FileOutputStream) {
        DatagramSocket().use { socket ->
            protect(socket) // Tránh vòng lặp qua chính VPN
            socket.soTimeout = 3000
            val dnsPayload = DnsPacketHelper.extractUdpPayload(rawPacket, length)
            val upstreamAddr = InetAddress.getByName(PRIMARY_DNS)
            socket.send(DatagramPacket(dnsPayload, dnsPayload.size, upstreamAddr, 53))

            val respBuf = ByteArray(1500)
            val respPacket = DatagramPacket(respBuf, respBuf.size)
            socket.receive(respPacket)

            val wrappedIpPacket = DnsPacketHelper.wrapUdpResponse(
                originalRequest = rawPacket,
                dnsResponse = respBuf,
                dnsLength = respPacket.length
            )
            tunOutput.write(wrappedIpPacket)
        }
    }

    override fun onDestroy() {
        isRunning = false
        vpnInterface?.close()
        vpnInterface = null
        super.onDestroy()
    }
}`;
}

export function generateDnsPacketHelperCode(): string {
  return `package com.miguard.dns.vpn

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
        var pos = dnsStart + 12
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
        return packet.copyOfRange(ipHeaderLen + 8, length)
    }

    fun buildSinkholeResponse(requestPacket: ByteArray, requestLength: Int): ByteArray {
        val dnsQuery = extractUdpPayload(requestPacket, requestLength)
        val answerSection = byteArrayOf(
            0xC0.toByte(), 0x0C.toByte(),
            0x00, 0x01,
            0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,
            0x00, 0x04,
            0x00, 0x00, 0x00, 0x00 // 0.0.0.0
        )

        val dnsResponse = ByteArray(dnsQuery.size + answerSection.size)
        System.arraycopy(dnsQuery, 0, dnsResponse, 0, dnsQuery.size)
        dnsResponse[2] = 0x81.toByte()
        dnsResponse[3] = 0x80.toByte()
        dnsResponse[6] = 0x00
        dnsResponse[7] = 0x01
        System.arraycopy(answerSection, 0, dnsResponse, dnsQuery.size, answerSection.size)

        return wrapUdpResponse(requestPacket, dnsResponse, dnsResponse.size)
    }

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

        out.put(0x45.toByte())
        out.put(0x00.toByte())
        out.putShort(totalLen.toShort())
        out.putShort(0.toShort())
        out.putShort(0x4000.toShort())
        out.put(64.toByte())
        out.put(17.toByte())
        out.putShort(0.toShort())
        out.put(dstIp)
        out.put(srcIp)

        out.put(dstPort)
        out.put(srcPort)
        out.putShort((udpHeaderLen + dnsLength).toShort())
        out.putShort(0.toShort())

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
}`;
}

export function generateAndroidManifestXml(): string {
  return `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE" />
    <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />

    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:label="MiGuard DNS"
        android:supportsRtl="true"
        android:theme="@android:style/Theme.DeviceDefault.NoActionBar">

        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <service
            android:name=".vpn.MiGuardVpnService"
            android:exported="true"
            android:foregroundServiceType="specialUse"
            android:permission="android.permission.BIND_VPN_SERVICE">
            <intent-filter>
                <action android:name="android.net.VpnService" />
            </intent-filter>
        </service>
    </application>
</manifest>`;
}

export function generateAppBuildGradleKts(): string {
  return `plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.miguard.dns"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.miguard.dns"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"
    }

    signingConfigs {
        create("release") {
            val keystoreFile = file(System.getenv("KEYSTORE_PATH") ?: "release-keystore.jks")
            if (keystoreFile.exists()) {
                storeFile = keystoreFile
                storePassword = System.getenv("KEYSTORE_PASSWORD") ?: "miguard_prod_2026"
                keyAlias = System.getenv("KEY_ALIAS") ?: "miguard_key"
                keyPassword = System.getenv("KEY_PASSWORD") ?: "miguard_prod_2026"
            } else {
                val debugConfig = getByName("debug")
                storeFile = debugConfig.storeFile
                storePassword = debugConfig.storePassword
                keyAlias = debugConfig.keyAlias
                keyPassword = debugConfig.keyPassword
            }
        }
    }

    buildTypes {
        release {
            // Bản Production thực thụ: Bật R8 thu gọn code, xóa tài nguyên thừa và ký số APK
            isMinifyEnabled = true
            isShrinkResources = true
            isDebuggable = false
            signingConfig = signingConfigs.getByName("release")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.14"
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "DebugProbesKt.bin"
        }
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.06.00")
    implementation(composeBom)
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.3")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
}`;
}

export function generateGitHubActionsApkYaml(): string {
  return `name: Build MiGuard DNS Production Release APK

on:
  push:
    branches: [ "main", "master" ]
  workflow_dispatch:

jobs:
  build-apk:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up JDK 17
        uses: actions/setup-java@v4
        with:
          java-version: '17'
          distribution: 'temurin'

      - name: Setup Gradle 8.7
        uses: gradle/actions/setup-gradle@v3
        with:
          gradle-version: '8.7'

      - name: Generate Production Release Keystore
        working-directory: ./android/app
        run: |
          if [ ! -f release-keystore.jks ]; then
            keytool -genkeypair -v \\
              -keystore release-keystore.jks \\
              -alias miguard_key \\
              -keyalg RSA \\
              -keysize 2048 \\
              -validity 10000 \\
              -storepass miguard_prod_2026 \\
              -keypass miguard_prod_2026 \\
              -dname "CN=MiGuard DNS, OU=Mobile, O=MiGuard, L=Hanoi, S=HN, C=VN"
          fi

      - name: Build Signed Production Release APK (R8 Minified & Shrunk)
        working-directory: ./android
        env:
          KEYSTORE_PASSWORD: miguard_prod_2026
          KEY_ALIAS: miguard_key
          KEY_PASSWORD: miguard_prod_2026
        run: gradle assembleRelease --no-daemon

      - name: Upload MiGuard-DNS-Production-Release.apk
        uses: actions/upload-artifact@v4
        with:
          name: MiGuard-DNS-Production-Release-APK
          path: android/app/build/outputs/apk/release/app-release.apk`;
}

export function generateFullAndroidSetupScript(
  rules: DomainRule[],
  upstreamDns: DnsUpstream,
  secondaryDns: DnsUpstream,
  filterMode: AppFilterMode,
  packages: SystemPackageItem[],
  logRetentionDays: LogRetentionDays
): string {
  const vpnServiceKt = generateKotlinVpnServiceCode(
    rules,
    upstreamDns,
    secondaryDns,
    filterMode,
    packages,
    logRetentionDays
  );
  const packetHelperKt = generateDnsPacketHelperCode();
  const manifestXml = generateAndroidManifestXml();
  const appGradle = generateAppBuildGradleKts();
  const workflowYml = generateGitHubActionsApkYaml();

  return `#!/usr/bin/env bash
# Script tự động tạo trọn bộ dự án Android MiGuard DNS (Bản Production Release đã cấu hình R8 & Keystore)
set -e

mkdir -p MiGuardDNS/android/app/src/main/java/com/miguard/dns/vpn
mkdir -p MiGuardDNS/.github/workflows

cat << 'EOF' > MiGuardDNS/android/gradle.properties
org.gradle.jvmargs=-Xmx2048m -Dfile.encoding=UTF-8
android.useAndroidX=true
android.nonTransitiveRClass=true
kotlin.code.style=official
EOF

cat << 'EOF' > MiGuardDNS/android/settings.gradle.kts
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "MiGuardDNS"
include(":app")
EOF

cat << 'EOF' > MiGuardDNS/android/build.gradle.kts
plugins {
    id("com.android.application") version "8.5.2" apply false
    id("org.jetbrains.kotlin.android") version "1.9.24" apply false
}
EOF

cat << 'EOF' > MiGuardDNS/android/app/proguard-rules.pro
-optimizationpasses 5
-keep public class com.miguard.dns.vpn.MiGuardVpnService { *; }
-keep public class com.miguard.dns.MainActivity { *; }
EOF

cat << 'EOF' > MiGuardDNS/android/app/build.gradle.kts
${appGradle}
EOF

cat << 'EOF' > MiGuardDNS/android/app/src/main/AndroidManifest.xml
${manifestXml}
EOF

cat << 'EOF' > MiGuardDNS/android/app/src/main/java/com/miguard/dns/vpn/DnsPacketHelper.kt
${packetHelperKt}
EOF

cat << 'EOF' > MiGuardDNS/android/app/src/main/java/com/miguard/dns/vpn/MiGuardVpnService.kt
${vpnServiceKt}
EOF

cat << 'EOF' > MiGuardDNS/.github/workflows/build-apk.yml
${workflowYml}
EOF

echo "Đã tạo xong dự án Android Production tại ./MiGuardDNS!"
echo "Chạy lệnh: cd MiGuardDNS/android && gradle assembleRelease để xuất file app-release.apk đã ký số và tối ưu R8."
`;
}

