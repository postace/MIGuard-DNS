# MiGuard DNS — Ứng dụng Android VPN Chặn Telemetry & Lọc DNS Tối Giản

Giải pháp VPN cục bộ (Local DNS Sinkhole) siêu nhẹ dành cho thiết bị Android/Xiaomi, giúp chặn triệt để các tên miền theo dõi và kiểm tra hệ thống của MIUI về `0.0.0.0`, đồng thời phân giải các truy vấn hợp lệ qua DNS tốc độ cao (`1.1.1.1` hoặc `8.8.8.8`) với giao diện trực quan, mượt mà.

## User Review & Critical Decisions

> [!IMPORTANT]
> Dưới đây là các quyết định thiết kế đã được chốt dựa trên câu trả lời của bạn, cùng phương án kiến trúc thực thi:

- **Quyết định 1 — Trải nghiệm Ứng dụng Android VPN & Mã nguồn Native**: Xây dựng ứng dụng theo chuẩn giao diện **Mobile & Touch-First Android** (trải nghiệm 1 chạm mượt mà, bố cục đa cột mở rộng trên màn hình lớn để vừa thao tác trực tiếp trên giao diện Android vừa xem/sao chép trọn bộ mã nguồn Kotlin `VpnService` chuẩn Android Studio để đóng gói APK).
- **Quyết định 2 — Chế độ Lọc theo Package Hệ thống (Per-App VPN)**: Cho phép chuyển đổi linh hoạt giữa 2 chế độ:
  1. **Chỉ lọc ứng dụng được chọn (Targeted Mode)**: Chỉ đưa các package hệ thống được tick chọn (như `com.miui.securitycenter`, `com.miui.analytics`, `com.miui.daemon`) đi qua VPN.
  2. **Lọc toàn thiết bị & Loại trừ (Bypass Mode)**: Bảo vệ toàn bộ thiết bị và bỏ qua các ứng dụng nằm trong danh sách loại trừ.
- **Quyết định 3 — Quản lý Danh sách Chặn (Blocklist)**: Tích hợp sẵn 5 tên miền MIUI mục tiêu mặc định, hỗ trợ thêm/xóa tên miền thủ công, bật/tắt từng quy tắc riêng lẻ và bộ **Gợi ý tự động các domain telemetry Xiaomi/MIUI** phổ biến chỉ với 1 chạm.

---

## 1. Overview & Core Concept

- **Chức năng cốt lõi**:
  - Thiết lập đường hầm `VpnService` cục bộ trên thiết bị Android mà không cần máy chủ từ xa (Zero-server, không làm giảm băng thông tải dữ liệu).
  - Chặn mặc định 5 domain mục tiêu bằng phản hồi `0.0.0.0`:
    - `fraud-detection.engine.miui.com`
    - `flash.sec.miui.com`
    - `dm.wo.com.cn`
    - `data.mistat.xiaomi.com`
    - `tracking.miui.com`
  - Chuyển tiếp toàn bộ truy vấn DNS không nằm trong danh sách chặn ra DNS phân giải sạch: **Cloudflare (`1.1.1.1`)** hoặc **Google (`8.8.8.8`)**.
  - Hiển thị **Log kết nối thời gian thực** (tên miền, ứng dụng gọi, trạng thái Chặn `0.0.0.0` / Cho phép, độ trễ `ms`) và bộ đếm thống kê trực tiếp.
- **Đối tượng sử dụng**: Người dùng thiết bị Xiaomi / MIUI / HyperOS và Android muốn kiểm soát quyền riêng tư, chặn các kết nối kiểm tra ngầm của hệ thống với thao tác đơn giản nhất.
- **Giá trị mang lại**: Nhỏ gọn, không hao pin, minh bạch hoàn toàn từng gói tin DNS đi ra khỏi thiết bị và có sẵn mã nguồn Kotlin `VpnService` hoàn chỉnh.

---

## 2. User Experience & Visual Design

### Luồng trải nghiệm người dùng (Key User Flows)

1. **Màn hình Chính (Bảng điều khiển 1 chạm)**:
   - Nút nguồn kết nối VPN cỡ lớn đặt tại vùng ngón cái dễ chạm, hiển thị trạng thái đường hầm (`Đang bảo vệ` / `Đã ngắt`) và thời gian hoạt động.
   - Bộ chọn nhanh máy chủ DNS đích: chuyển đổi tức thì giữa `1.1.1.1` (Cloudflare) và `8.8.8.8` (Google).
   - 2 thẻ thống kê số liệu rõ ràng: **Tổng truy vấn đã xử lý** và **Số request bị chặn (`0.0.0.0`)** kèm tỷ lệ phần trăm.
2. **Màn hình Nhật ký Thời gian thực (Live DNS Logs)**:
   - Dòng sự kiện cập nhật theo thời gian thực khi các package hệ thống gọi DNS.
   - Bộ lọc nhanh theo trạng thái (`Tất cả`, `Đã chặn 0.0.0.0`, `Cho phép 1.1.1.1/8.8.8.8`), thanh tìm kiếm domain/package, nút tạm dừng luồng log và công cụ **Thử nghiệm Truy vấn DNS (Test Query)** để kiểm tra ngay quy tắc chặn.
3. **Màn hình Danh sách Chặn (Blocklist & Gợi ý MIUI)**:
   - Hiển thị 5 domain mặc định cùng công tắc bật/tắt độc lập cho từng mục.
   - Ô nhập nhanh domain mới (hỗ trợ cả cú pháp `0.0.0.0 domain.com` hoặc chỉ nhập `domain.com`).
   - Ngăn kéo **Gợi ý Telemetry Xiaomi/MIUI** (`api.ad.xiaomi.com`, `sdkconfig.ad.xiaomi.com`, `ccc.sys.miui.com`, `data.mistat.intl.xiaomi.com`...) giúp thêm nhanh chỉ với 1 chạm.
4. **Màn hình Ứng dụng Hệ thống (Per-App Filter)**:
   - Thanh chuyển đổi 2 chế độ: **Chỉ lọc package được chọn** (`addAllowedApplication`) hoặc **Loại trừ package được chọn** (`addDisallowedApplication`).
   - Danh sách các package hệ thống Xiaomi/Android có ô tìm kiếm, bộ lọc nhóm (`MIUI Core`, `Quảng cáo & MSA`, `Hệ thống Android`) và checkbox chọn nhanh.
5. **Ngăn Mã nguồn Android Native (Kotlin VpnService Code)**:
   - Cho phép xem và sao chép trực tiếp mã nguồn Kotlin thực tế (`MiGuardVpnService.kt`, `DnsPacketParser.kt`, `AndroidManifest.xml`) được cập nhật tự động theo đúng danh sách domain và package mà người dùng đang cấu hình trên giao diện.

### Visual Identity & Theme

- **Phong cách thẩm mỹ (Aesthetic Direction)**: *Tactile Utility Minimalist* — Tối giản, sắc nét, lấy cảm hứng từ ngôn ngữ thiết kế hệ thống hiện đại, ưu tiên độ tương phản cao và phản hồi xúc giác mượt mà.
- **Bảng màu (Color Palette & 60-30-10 Discipline)**:
  - **60% Nền trung tính sâu (`--background`)**: Tông tối dịu mắt (`#090D16` / `slate-950`) hoặc sáng sạch (`#F8FAFC` / `slate-50`) hỗ trợ chuyển đổi Sáng/Tối hoàn chỉnh.
  - **30% Bề mặt cấu trúc (`--surface`)**: Thẻ thông tin phân tách bằng đường viền mảnh `1px` (`#111827` / `slate-900` ở chế độ tối, `#FFFFFF` ở chế độ sáng).
  - **10% Điểm nhấn chức năng (`--accent`)**: Xanh ngọc lục bảo (`#10B981` / `emerald-500`) cho trạng thái VPN hoạt động & DNS hợp lệ; Đỏ san hô (`#F43F5E` / `rose-500`) dành riêng cho các truy vấn bị chặn về `0.0.0.0`.
- **Typography & Hierarchy**:
  - **Font tiêu đề & thương hiệu**: `Plus Jakarta Sans` (SemiBold/Bold) tạo cảm giác hiện đại, gọn gàng.
  - **Font nội dung**: `DM Sans` dễ đọc ở kích thước nhỏ trên màn hình di động.
  - **Font dữ liệu & Log DNS**: `JetBrains Mono` kết hợp `tabular-nums` cho địa chỉ IP (`0.0.0.0`, `1.1.1.1`), tên miền, tên package và bộ đếm thời gian thực để các con số không bị nhảy lệch khung hình.
- **Ergonomics & Chuyển động**:
  - Mọi nút bấm, công tắc và hàng danh sách đều đảm bảo vùng chạm tối thiểu `44x44px`.
  - Chuyển cảnh và phản hồi nút bấm hoàn tất trong `< 180ms` sử dụng `transform` và `opacity` mượt mà.

---

## 3. Key Product Decisions & Trade-Offs

- **Quyết định 1: Kiến trúc Local VPN DNS Interceptor thay vì Proxy toàn phần**
  - *Giải pháp chọn*: Chỉ định tuyến lưu lượng truy vấn DNS (cổng UDP 53) qua giao diện TUN ảo của Android `VpnService`.
  - *Lý do*: Giúp ứng dụng cực kỳ nhỏ nhẹ, không làm chậm tốc độ tải dữ liệu hay chơi game, đồng thời không tiêu tốn pin khi chạy ngầm 24/7.
- **Quyết định 2: Hỗ trợ kép hai chế độ Per-App VPN (`Allowed` vs `Disallowed`)**
  - *Giải pháp chọn*: Cung cấp công tắc chuyển đổi trực tiếp giữa `Builder.addAllowedApplication()` và `Builder.addDisallowedApplication()`.
  - *Lý do*: Khi người dùng chỉ muốn khóa kết nối của các app hệ thống MIUI mà không muốn chạm vào các ứng dụng ngân hàng hay game, chế độ *Chỉ lọc package được chọn* mang lại sự an tâm tuyệt đối.
- **Quyết định 3: Kết hợp Trình mô phỏng Thời gian thực + Trình sinh Mã nguồn Kotlin Động**
  - *Giải pháp chọn*: Mọi thay đổi về danh sách domain chặn, DNS `1.1.1.1`/`8.8.8.8`, và danh sách package hệ thống trên giao diện đều đồng bộ trực tiếp vào luồng mô phỏng gói tin DNS lẫn mã nguồn Kotlin `VpnService` xuất ra.
  - *Lý do*: Giúp người dùng kiểm thử ngay hành vi chặn/mở trên giao diện và có ngay file code Android đã nhúng sẵn cấu hình cá nhân hóa của mình.

---

## 4. Technical Architecture & Data Strategy

### Sơ đồ Kiến trúc Hệ thống & Luồng Dữ liệu

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        MIGUARD DNS — APPLICATION STATE                       │
│  • vpnActive (boolean)              • dnsUpstream ('1.1.1.1' | '8.8.8.8')    │
│  • blockRules (DomainRule[])        • appFilterMode ('allowlist'|'blocklist')│
│  • systemPackages (PackageItem[])   • dnsLogs (DnsLogEntry[])                │
└──────────────────┬───────────────────────────────────────┬───────────────────┘
                   │                                       │
                   ▼                                       ▼
┌─────────────────────────────────────┐ ┌──────────────────────────────────────┐
│   LOCAL DNS INTERCEPTOR ENGINE      │ │   DYNAMIC KOTLIN CODE GENERATOR      │
│  • Kiểm tra Package gửi request     │ │  • MiGuardVpnService.kt              │
│  • Đối chiếu bảng băm Blocklist     │ │  • DnsPacketSinkhole.kt              │
│  • Trả về 0.0.0.0 nếu trùng khớp    │ │  • AndroidManifest.xml               │
│  • Chuyển tiếp 1.1.1.1 / 8.8.8.8    │ │  • Tự động nhúng danh sách domain &  │
│  • Phát sự kiện vào Live Log Stream │ │    package người dùng đã chọn        │
└──────────────────┬──────────────────┘ └──────────────────┬───────────────────┘
                   │                                       │
                   ▼                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                     GIAO DIỆN ĐIỀU KHIỂN TỐI GIẢN (4 TABS)                   │
├──────────────────┬──────────────────┬────────────────────┬───────────────────┤
│ 1. Bảng Điều     │ 2. Nhật Ký Kết   │ 3. Danh Sách Chặn  │ 4. Lọc Package    │
│    Khiển Chính   │    Nối (Live)    │    & Gợi Ý MIUI    │    Hệ Thống       │
│  • Nút Bật/Tắt   │  • Stream thời   │  • 5 domain mặc    │  • Chuyển đổi 2   │
│  • Chọn DNS      │    gian thực     │    định + Bật/Tắt  │    chế độ Per-App │
│    1.1.1.1/8.8.8.8│  • Lọc Chặn/Cho  │  • Thêm thủ công   │  • Tick chọn các  │
│  • Bộ đếm Chặn   │    phép & Test   │  • Gợi ý MIUI 1 chạm│    gói com.miui.* │
└──────────────────┴──────────────────┴────────────────────┴───────────────────┘
```

### Mô hình Dữ liệu & Trạng thái (Data Model)

- **`DomainRule`**: `id`, `domain` (chuẩn hóa chữ thường, tự động bóc tách tiền tố `0.0.0.0` nếu người dùng dán từ file hosts), `enabled` (bật/tắt), `category` (`Mặc định MIUI`, `Tùy chỉnh`, `Gợi ý Xiaomi`), `hitCount` (số lần bị chặn).
- **`SystemPackage`**: `packageName` (ví dụ `com.miui.securitycenter`), `appName`, `category` (`MIUI Core`, `Xiaomi Telemetry`, `Hệ thống`), `selected` (trạng thái tick chọn).
- **`DnsLogEntry`**: `id`, `timestamp`, `packageName`, `domain`, `action` (`BLOCKED` -> `0.0.0.0` | `FORWARDED` -> `1.1.1.1` / `8.8.8.8`), `latencyMs`.

### Ánh xạ Tương tác & Xử lý Trạng thái (Interactive Component Mapping)

- **Bật/Tắt VPN & Chuyển DNS (`1.1.1.1` / `8.8.8.8`)**: Kích hoạt/dừng bộ tạo luồng truy vấn DNS thời gian thực; khi đổi DNS đích, toàn bộ truy vấn hợp lệ mới sẽ ghi nhận phân giải qua IP DNS vừa chọn.
- **Trình Kiểm thử Truy vấn (Live DNS Tester)**: Cho phép chọn một package bất kỳ và nhập tên miền (hoặc bấm nhanh vào các tên miền mặc định) để bắn gói tin DNS thử nghiệm và quan sát phản hồi tức thì trong bảng log.
- **Thêm/Bật/Tắt Domain & Gợi ý MIUI**: Tự động kiểm tra trùng lặp, chuẩn hóa cú pháp `0.0.0.0 <domain>`, lưu bền vững vào `localStorage` và áp dụng ngay lập tức cho gói tin tiếp theo mà không cần khởi động lại VPN.
- **Tick chọn Package Hệ thống & Đổi chế độ Per-App**: Cập nhật ngay bộ lọc đường hầm (chỉ bắt gói tin từ các package được tick hoặc bỏ qua các package được tick) và đồng bộ trực tiếp vào đoạn code `builder.addAllowedApplication(...)` trong trình xuất mã Kotlin.
