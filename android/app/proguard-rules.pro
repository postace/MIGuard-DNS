# MiGuard DNS — Production R8 / ProGuard Rules
-optimizationpasses 5
-dontusemixedcaseclassnames
-dontskipnonpubliclibraryclasses
-verbose

# Giữ nguyên lớp dịch vụ VpnService và Activity chính
-keep public class com.miguard.dns.vpn.MiGuardVpnService { *; }
-keep public class com.miguard.dns.MainActivity { *; }
-keepclassmembers class com.miguard.dns.data.** { *; }

# Giữ thông tin dòng mã tối thiểu nếu cần gỡ lỗi crash
-renamesourcefileattribute SourceFile
-keepattributes SourceFile,LineNumberTable
