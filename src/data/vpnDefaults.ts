export type DnsUpstream = '1.1.1.1' | '8.8.8.8';

export type AppFilterMode = 'allowlist' | 'blocklist';

export type LogRetentionDays = 1 | 3 | 7 | 14 | 30;

export interface DomainRule {
  id: string;
  domain: string;
  enabled: boolean;
  source: 'default' | 'suggested' | 'custom';
  description: string;
  hitCount: number;
}

export interface TelemetrySuggestion {
  domain: string;
  description: string;
  module: string;
}

export interface SystemPackageItem {
  packageName: string;
  appName: string;
  category: 'MIUI Security & Core' | 'Xiaomi Telemetry & Ads' | 'Hệ thống Android';
  description: string;
  selected: boolean;
  uid: number;
}

export interface DnsLogEntry {
  id: string;
  timestamp: string;
  createdAt: number;
  domain: string;
  packageName: string;
  appName: string;
  status: 'BLOCKED' | 'FORWARDED' | 'BYPASSED';
  resolvedIp: string;
  latencyMs: number;
  queryType: 'A' | 'AAAA';
}

export const INITIAL_BLOCK_RULES: DomainRule[] = [
  {
    id: 'rule-1',
    domain: 'fraud-detection.engine.miui.com',
    enabled: true,
    source: 'default',
    description: 'Kiểm tra bảo mật & xác thực thiết bị ngầm của MIUI Security',
    hitCount: 42,
  },
  {
    id: 'rule-2',
    domain: 'flash.sec.miui.com',
    enabled: true,
    source: 'default',
    description: 'Kiểm tra trạng thái разблокировки /刷机 (Unlock Bootloader & Flash)',
    hitCount: 19,
  },
  {
    id: 'rule-3',
    domain: 'dm.wo.com.cn',
    enabled: true,
    source: 'default',
    description: 'Máy chủ quản lý thiết bị nhà mạng nội địa (Device Management)',
    hitCount: 14,
  },
  {
    id: 'rule-4',
    domain: 'data.mistat.xiaomi.com',
    enabled: true,
    source: 'default',
    description: 'Thu thập số liệu thống kê hành vi & nhật ký sử dụng Xiaomi',
    hitCount: 87,
  },
  {
    id: 'rule-5',
    domain: 'tracking.miui.com',
    enabled: true,
    source: 'default',
    description: 'Hệ thống theo dõi sự kiện hệ thống & phân tích MIUI',
    hitCount: 63,
  },
];

export const MIUI_TELEMETRY_SUGGESTIONS: TelemetrySuggestion[] = [
  {
    domain: 'data.mistat.intl.xiaomi.com',
    description: 'Máy chủ thu thập thống kê MIUI/HyperOS bản Quốc tế',
    module: 'MiStat Analytics',
  },
  {
    domain: 'tracking.intl.miui.com',
    description: 'Điểm cuối theo dõi nhật ký hoạt động ROM Quốc tế',
    module: 'MIUI Analytics',
  },
  {
    domain: 'api.ad.xiaomi.com',
    description: 'Phân phối quảng cáo hệ thống trong ứng dụng mặc định',
    module: 'MSA (MIUI System Ads)',
  },
  {
    domain: 'sdkconfig.ad.xiaomi.com',
    description: 'Tải cấu hình SDK quảng cáo động trên thiết bị Xiaomi',
    module: 'MSA SDK',
  },
  {
    domain: 'ccc.sys.miui.com',
    description: 'Đồng bộ chính sách kiểm soát đám mây của hệ thống MIUI',
    module: 'Cloud Control',
  },
  {
    domain: 'abtest.mistat.xiaomi.com',
    description: 'Theo dõi thử nghiệm A/B tính năng ngầm trên thiết bị',
    module: 'MiStat A/B',
  },
  {
    domain: 'metok.sys.miui.com',
    description: 'Định vị trạm thu phát và thu thập thông tin mạng ngầm',
    module: 'Metok NLP',
  },
  {
    domain: 'sec-cdn.static.xiaomi.net',
    description: 'Tải danh sách đen kiểm duyệt ứng dụng cài đặt ngoài',
    module: 'MIUI Guard',
  },
];

export const INITIAL_SYSTEM_PACKAGES: SystemPackageItem[] = [
  {
    packageName: 'com.miui.securitycenter',
    appName: 'Bảo mật MIUI (Security Center)',
    category: 'MIUI Security & Core',
    description: 'Gửi truy vấn tới fraud-detection.engine.miui.com và flash.sec.miui.com',
    selected: true,
    uid: 1000,
  },
  {
    packageName: 'com.miui.analytics',
    appName: 'MIUI Analytics',
    category: 'Xiaomi Telemetry & Ads',
    description: 'Dịch vụ thu thập dữ liệu chẩn đoán và gửi về tracking.miui.com',
    selected: true,
    uid: 10042,
  },
  {
    packageName: 'com.miui.daemon',
    appName: 'MIUI Daemon',
    category: 'Xiaomi Telemetry & Ads',
    description: 'Tiến trình nền thu thập thống kê hiệu năng gửi về data.mistat.xiaomi.com',
    selected: true,
    uid: 10045,
  },
  {
    packageName: 'com.miui.msa.global',
    appName: 'MSA (MIUI System Ads)',
    category: 'Xiaomi Telemetry & Ads',
    description: 'Dịch vụ quảng cáo hệ thống và theo dõi hiển thị',
    selected: true,
    uid: 10051,
  },
  {
    packageName: 'com.xiaomi.joyose',
    appName: 'Joyose',
    category: 'MIUI Security & Core',
    description: 'Quản lý cấu hình đám mây, giới hạn hiệu năng và dịch vụ nhà mạng',
    selected: true,
    uid: 10058,
  },
  {
    packageName: 'com.xiaomi.finddevice',
    appName: 'Tìm thiết bị & Xác thực SIM',
    category: 'MIUI Security & Core',
    description: 'Kiểm tra trạng thái khóa thiết bị và kết nối dm.wo.com.cn',
    selected: true,
    uid: 10063,
  },
  {
    packageName: 'com.miui.guardprovider',
    appName: 'MIUI Guard Provider',
    category: 'MIUI Security & Core',
    description: 'Quét cài đặt APK và đối chiếu máy chủ kiểm duyệt MIUI',
    selected: true,
    uid: 10070,
  },
  {
    packageName: 'com.android.updater',
    appName: 'Trình cập nhật hệ thống',
    category: 'MIUI Security & Core',
    description: 'Kiểm tra bản cập nhật OTA và xác thực ROM',
    selected: false,
    uid: 10012,
  },
  {
    packageName: 'com.google.android.gms',
    appName: 'Dịch vụ của Google Play',
    category: 'Hệ thống Android',
    description: 'Dịch vụ nền tảng Google, thông báo đẩy FCM và đồng bộ tài khoản',
    selected: false,
    uid: 10088,
  },
  {
    packageName: 'com.android.vending',
    appName: 'Cửa hàng Google Play',
    category: 'Hệ thống Android',
    description: 'Tải xuống và cập nhật ứng dụng từ Google Play',
    selected: false,
    uid: 10089,
  },
];

export const SAMPLE_SAFE_DOMAINS: Array<{ domain: string; packageName: string; appName: string }> = [
  {
    domain: 'connectivitycheck.gstatic.com',
    packageName: 'com.google.android.gms',
    appName: 'Dịch vụ của Google Play',
  },
  {
    domain: 'time.android.com',
    packageName: 'com.miui.securitycenter',
    appName: 'Bảo mật MIUI (Security Center)',
  },
  {
    domain: 'account.xiaomi.com',
    packageName: 'com.xiaomi.finddevice',
    appName: 'Tìm thiết bị & Xác thực SIM',
  },
  {
    domain: 'play.googleapis.com',
    packageName: 'com.android.vending',
    appName: 'Cửa hàng Google Play',
  },
  {
    domain: 'api.sec.miui.com',
    packageName: 'com.miui.guardprovider',
    appName: 'MIUI Guard Provider',
  },
  {
    domain: 'cloud.xiaomi.com',
    packageName: 'com.xiaomi.joyose',
    appName: 'Joyose',
  },
];
