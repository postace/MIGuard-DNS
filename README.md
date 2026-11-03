# MiGuard DNS — Android VPN Blocker & Privacy Sinkhole

<div align="center">

<img src="public/app-icon.png" width="128" height="128" alt="MiGuard DNS Shield Icon" style="border-radius: 28px;" />

### Lightweight on-device DNS sinkhole blocking Xiaomi/MIUI telemetry to `0.0.0.0`

[![Platform](https://img.shields.io/badge/Platform-Android%208.0%2B%20(API%2026%2B)-3DDC84?style=flat-square&logo=android&logoColor=white)](https://developer.android.com)
[![Language](https://img.shields.io/badge/Kotlin-1.9.24-7F52FF?style=flat-square&logo=kotlin&logoColor=white)](https://kotlinlang.org)
[![UI](https://img.shields.io/badge/UI-Jetpack%20Compose%20M3-4285F4?style=flat-square&logo=jetpackcompose&logoColor=white)](https://developer.android.com/jetpack/compose)
[![Web Dashboard](https://img.shields.io/badge/Web%20Dashboard-React%2019%20%7C%20Tailwind-38BDF8?style=flat-square&logo=react&logoColor=white)](https://react.dev)
[![Build APK](https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6)](#)

</div>

---

## 📌 Overview

**MiGuard DNS** is a privacy-first, on-device Android VPN application and companion rule management dashboard. It intercepts local DNS requests (UDP port 53) via Android's native `VpnService` API and returns `0.0.0.0` for aggressive Xiaomi, MIUI, and HyperOS telemetry, ad, and tracking domains.

### 🛡️ Why MiGuard DNS?
- **100% Local & On-Device**: Does **not** route your traffic through an external remote VPN server. All packet inspection and sinkholing happens directly inside your device's memory.
- **Zero Battery & Latency Penalty**: Only handles DNS resolution requests (UDP port 53). Regular TCP/IP web and app traffic flows directly through your physical Wi-Fi or cellular network interface.
- **MIUI / HyperOS Telemetry Neutralized**: Blocks background tracking engines like `data.mistat.xiaomi.com`, `tracking.miui.com`, and `fraud-detection.engine.miui.com` without requiring root or bootloader unlocking.
- **Fast Upstream DNS**: Seamless fallback to Cloudflare (`1.1.1.1`) or Google (`8.8.8.8`) for clean, secure upstream resolution.

---

## ✨ Key Features

- **Local VPN Sinkhole Engine**: Captures DNS packets via a virtual TUN interface, parsing raw IPv4/UDP/DNS datagrams and crafting synthetic DNS responses locally.
- **Telemetry Blocklist Presets**: Pre-configured with known Xiaomi/MIUI tracking, telemetry, ad-server, and safety check domains.
- **Per-App Filter Rules**: Include or bypass specific system packages (e.g., `com.miui.analytics`, `com.miui.cleanmaster`, `com.xiaomi.market`) using Android `VpnService.Builder` package filters.
- **Real-Time DNS Query Inspector**: Monitor live queries with domain name, requesting package, resolution latency, status (BLOCKED / RESOLVED), and query types (A / AAAA).
- **Web Simulation & Management Dashboard**: A responsive React + Tailwind CSS dashboard to test DNS rules, simulate query logs, configure retention periods, and export `/etc/hosts` files.
- **Native Code Generator**: Live export of ready-to-compile Kotlin VPN services, packet parsers, manifest configs, and CI workflows.
- **Automated CI/CD**: GitHub Actions workflow that automatically compiles and signs optimized Release APKs (R8 minified).

---

## 📂 Project Structure

```text
MiGuard-DNS/
├── android/                             # Native Android project
│   ├── app/
│   │   ├── src/main/
│   │   │   ├── AndroidManifest.xml      # VPN permissions & service declaration
│   │   │   ├── java/com/miguard/dns/
│   │   │   │   ├── MainActivity.kt      # Jetpack Compose UI (toggle, upstream, status)
│   │   │   │   ├── data/VpnRepository.kt# Rules & SharedPreferences persistence
│   │   │   │   └── vpn/
│   │   │   │       ├── MiGuardVpnService.kt # Foreground VPN service & TUN loop
│   │   │   │       └── DnsPacketHelper.kt   # Raw IPv4/UDP DNS packet parser
│   │   │   └── res/                     # Adaptive icons, colors, layouts
│   │   └── build.gradle.kts             # App build config, Compose, R8 optimization
│   ├── build.gradle.kts
│   └── settings.gradle.kts
├── .github/workflows/
│   └── build-apk.yml                    # Automated GitHub Actions APK build workflow
├── src/                                 # Web Dashboard & Simulator
│   ├── App.tsx                          # Interactive rule editor, log viewer, simulator
│   ├── data/vpnDefaults.ts              # MIUI telemetry presets & system package lists
│   └── utils/kotlinGenerator.ts         # Dynamic Android Kotlin code exporter
├── public/                              # App icons, favicons, vector assets
├── package.json                         # Node dependencies (Vite, React 19, Tailwind)
└── README.md
```

---

## 🚀 Getting Started

### 1. Web Dashboard & Rule Simulator (Local)

The web dashboard allows you to manage rules, simulate DNS requests, and preview Kotlin code.

**Prerequisites:** [Node.js](https://nodejs.org) (v18+)

```bash
# 1. Install dependencies
npm install

# 2. Start local development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

> [!NOTE]
> No external API keys (e.g. Gemini API) are required. The application and simulator run entirely client-side.

---

### 2. Building the Android APK

**Prerequisites:**
- Android Studio Iguana (or newer) / Android SDK (API 34)
- JDK 17
- Gradle 8.7+

#### Build with Gradle CLI:

```bash
cd android

# Build Debug APK
./gradlew assembleDebug

# Build Signed Release APK
./gradlew assembleRelease
```

The compiled APK will be located at:
- **Debug:** `android/app/build/outputs/apk/debug/app-debug.apk`
- **Release:** `android/app/build/outputs/apk/release/app-release.apk`

#### Automated GitHub Actions Build:
Pushing commits to `main` or triggering the workflow manually via GitHub Actions (`build-apk.yml`) automatically builds, signs, and attaches installable APK artifacts.

---

## 📋 Default Blocked Telemetry Domains

| Domain | Category | Threat / Risk |
| :--- | :--- | :--- |
| `fraud-detection.engine.miui.com` | MIUI Anti-fraud | Scans installed apps and URLs, phoning home to remote servers |
| `data.mistat.xiaomi.com` | Xiaomi Analytics | User behavior, app usage statistics, and device telemetry |
| `tracking.miui.com` | User Tracking | Advertising tracking and user profiling |
| `flash.sec.miui.com` | Security Scanner | Periodic background security uploads and telemetry |
| `api.ad.xiaomi.com` | Ad Network | System app banner ads and recommendation feeds |
| `adv.sec.miui.com` | System Ad Engine | Ads served within Security, File Manager, and Theme apps |

*(You can add, edit, or customize any domain or import standard `/etc/hosts` blocklists via the dashboard).*

---

## 🔒 Privacy & Permissions

- **`BIND_VPN_SERVICE`**: Required to establish the local loopback VPN interface to inspect DNS port 53.
- **`QUERY_ALL_PACKAGES`**: Used strictly on-device to list installed applications so you can configure per-app bypass/block rules.
- **`FOREGROUND_SERVICE` & `FOREGROUND_SERVICE_SPECIAL_USE`**: Keeps the VPN sinkhole active reliably in the background without Android OS process killing.
- **No Remote Servers**: Zero user data, DNS queries, or device telemetry are transmitted to any third-party server.

---

## 📄 License

Distributed under the Apache 2.0 License. See `LICENSE` for more information.
