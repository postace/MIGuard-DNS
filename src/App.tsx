/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  Check,
  Clock,
  Code2,
  Copy,
  Download,
  Filter,
  Layers,
  Moon,
  Pause,
  Play,
  Plus,
  Power,
  RefreshCw,
  Search,
  Shield,
  Sun,
  Trash2,
  X,
} from 'lucide-react';
import {
  AppFilterMode,
  DnsLogEntry,
  DnsUpstream,
  DomainRule,
  INITIAL_BLOCK_RULES,
  INITIAL_SYSTEM_PACKAGES,
  LogRetentionDays,
  MIUI_TELEMETRY_SUGGESTIONS,
  SAMPLE_SAFE_DOMAINS,
  SystemPackageItem,
} from './data/vpnDefaults';
import {
  generateAndroidManifestXml,
  generateAppBuildGradleKts,
  generateDnsPacketHelperCode,
  generateFullAndroidSetupScript,
  generateGitHubActionsApkYaml,
  generateHostsFileContent,
  generateKotlinVpnServiceCode,
} from './utils/kotlinGenerator';

type ActiveTab = 'dashboard' | 'logs' | 'blocklist' | 'packages';
type CodeTab = 'kotlin' | 'packet' | 'gradle' | 'workflow' | 'hosts' | 'manifest';

const STORAGE_KEYS = {
  RULES: 'miguard_dns_rules_v1',
  PACKAGES: 'miguard_dns_packages_v1',
  UPSTREAM: 'miguard_dns_upstream_v1',
  FILTER_MODE: 'miguard_dns_filter_mode_v1',
  RETENTION_DAYS: 'miguard_dns_retention_days_v1',
  THEME: 'miguard_dns_theme_v1',
};

const RETENTION_OPTIONS: Array<{ value: LogRetentionDays; label: string }> = [
  { value: 1, label: '1 ngày' },
  { value: 3, label: '3 ngày' },
  { value: 7, label: '7 ngày (Mặc định)' },
  { value: 14, label: '14 ngày' },
  { value: 30, label: '30 ngày' },
];

const DAY_MS = 24 * 60 * 60 * 1000;

function formatTimeFromMs(epochMs: number): string {
  const d = new Date(epochMs);
  const h = String(d.getHours()).padStart(2, '0');
  const m = String(d.getMinutes()).padStart(2, '0');
  const s = String(d.getSeconds()).padStart(2, '0');
  return `${h}:${m}:${s}`;
}

function formatRelativeAge(createdAt: number): string {
  const diffMs = Math.max(0, Date.now() - createdAt);
  const diffDays = Math.floor(diffMs / DAY_MS);
  if (diffDays === 0) return 'Hôm nay';
  if (diffDays === 1) return '1 ngày trước';
  return `${diffDays} ngày trước`;
}

function formatDuration(seconds: number): string {
  const hrs = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;
  return [hrs, mins, secs].map((v) => String(v).padStart(2, '0')).join(':');
}

function normalizeDomainInput(raw: string): string {
  const cleaned = raw
    .trim()
    .toLowerCase()
    .replace(/^0\.0\.0\.0\s+/, '')
    .replace(/^127\.0\.0\.1\s+/, '')
    .replace(/^https?:\/\//, '')
    .split('/')[0]
    .split('#')[0]
    .trim();
  return cleaned;
}

function buildInitialSampleLogs(): DnsLogEntry[] {
  const now = Date.now();
  const samples: Array<{
    offsetMs: number;
    domain: string;
    packageName: string;
    appName: string;
    status: 'BLOCKED' | 'FORWARDED' | 'BYPASSED';
    resolvedIp: string;
    latencyMs: number;
  }> = [
    {
      offsetMs: 2000,
      domain: 'fraud-detection.engine.miui.com',
      packageName: 'com.miui.securitycenter',
      appName: 'Bảo mật MIUI (Security Center)',
      status: 'BLOCKED',
      resolvedIp: '0.0.0.0',
      latencyMs: 1,
    },
    {
      offsetMs: 15000,
      domain: 'data.mistat.xiaomi.com',
      packageName: 'com.miui.daemon',
      appName: 'MIUI Daemon',
      status: 'BLOCKED',
      resolvedIp: '0.0.0.0',
      latencyMs: 1,
    },
    {
      offsetMs: 42000,
      domain: 'connectivitycheck.gstatic.com',
      packageName: 'com.google.android.gms',
      appName: 'Dịch vụ của Google Play',
      status: 'FORWARDED',
      resolvedIp: '1.1.1.1',
      latencyMs: 16,
    },
    {
      offsetMs: 1.2 * DAY_MS,
      domain: 'flash.sec.miui.com',
      packageName: 'com.miui.securitycenter',
      appName: 'Bảo mật MIUI (Security Center)',
      status: 'BLOCKED',
      resolvedIp: '0.0.0.0',
      latencyMs: 1,
    },
    {
      offsetMs: 2.4 * DAY_MS,
      domain: 'tracking.miui.com',
      packageName: 'com.miui.analytics',
      appName: 'MIUI Analytics',
      status: 'BLOCKED',
      resolvedIp: '0.0.0.0',
      latencyMs: 1,
    },
    {
      offsetMs: 4.5 * DAY_MS,
      domain: 'dm.wo.com.cn',
      packageName: 'com.xiaomi.finddevice',
      appName: 'Tìm thiết bị & Xác thực SIM',
      status: 'BLOCKED',
      resolvedIp: '0.0.0.0',
      latencyMs: 1,
    },
    {
      offsetMs: 6.2 * DAY_MS,
      domain: 'play.googleapis.com',
      packageName: 'com.android.vending',
      appName: 'Cửa hàng Google Play',
      status: 'FORWARDED',
      resolvedIp: '1.1.1.1',
      latencyMs: 19,
    },
  ];

  return samples.map((item, index) => {
    const createdAt = now - Math.floor(item.offsetMs);
    return {
      id: `init-${index + 1}`,
      timestamp: formatTimeFromMs(createdAt),
      createdAt,
      domain: item.domain,
      packageName: item.packageName,
      appName: item.appName,
      status: item.status,
      resolvedIp: item.resolvedIp,
      latencyMs: item.latencyMs,
      queryType: 'A',
    };
  });
}

export default function App() {
  // Theme state synced with <html class="dark">
  const [isDark, setIsDark] = useState<boolean>(() => {
    const saved = localStorage.getItem(STORAGE_KEYS.THEME);
    return saved ? saved === 'dark' : true;
  });

  useEffect(() => {
    const root = document.documentElement;
    if (isDark) {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
    localStorage.setItem(STORAGE_KEYS.THEME, isDark ? 'dark' : 'light');
  }, [isDark]);

  // Navigation & Modal State
  const [activeTab, setActiveTab] = useState<ActiveTab>('dashboard');
  const [showCodeModal, setShowCodeModal] = useState<boolean>(false);
  const [activeCodeTab, setActiveCodeTab] = useState<CodeTab>('kotlin');
  const [copiedFeedback, setCopiedFeedback] = useState<string | null>(null);

  // Core VPN State
  const [vpnConnected, setVpnConnected] = useState<boolean>(true);
  const [uptimeSeconds, setUptimeSeconds] = useState<number>(854);
  const [primaryDns, setPrimaryDns] = useState<DnsUpstream>(() => {
    const saved = localStorage.getItem(STORAGE_KEYS.UPSTREAM);
    return saved === '8.8.8.8' ? '8.8.8.8' : '1.1.1.1';
  });

  const secondaryDns: DnsUpstream = primaryDns === '1.1.1.1' ? '8.8.8.8' : '1.1.1.1';

  // Auto-Purge Log Retention State (Default: 7 days)
  const [logRetentionDays, setLogRetentionDays] = useState<LogRetentionDays>(() => {
    const saved = Number(localStorage.getItem(STORAGE_KEYS.RETENTION_DAYS));
    if (saved === 1 || saved === 3 || saved === 7 || saved === 14 || saved === 30) {
      return saved;
    }
    return 7;
  });
  const [purgeNotice, setPurgeNotice] = useState<string | null>(null);

  // Blocklist Rules State
  const [rules, setRules] = useState<DomainRule[]>(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEYS.RULES);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      }
    } catch {
      // ignore parse errors
    }
    return INITIAL_BLOCK_RULES;
  });

  // Per-App System Packages State
  const [filterMode, setFilterMode] = useState<AppFilterMode>(() => {
    const saved = localStorage.getItem(STORAGE_KEYS.FILTER_MODE);
    return saved === 'blocklist' ? 'blocklist' : 'allowlist';
  });

  const [packages, setPackages] = useState<SystemPackageItem[]>(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEYS.PACKAGES);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      }
    } catch {
      // ignore
    }
    return INITIAL_SYSTEM_PACKAGES;
  });

  // Persist user settings
  useEffect(() => {
    localStorage.setItem(STORAGE_KEYS.RULES, JSON.stringify(rules));
  }, [rules]);

  useEffect(() => {
    localStorage.setItem(STORAGE_KEYS.PACKAGES, JSON.stringify(packages));
  }, [packages]);

  useEffect(() => {
    localStorage.setItem(STORAGE_KEYS.UPSTREAM, primaryDns);
  }, [primaryDns]);

  useEffect(() => {
    localStorage.setItem(STORAGE_KEYS.FILTER_MODE, filterMode);
  }, [filterMode]);

  useEffect(() => {
    localStorage.setItem(STORAGE_KEYS.RETENTION_DAYS, String(logRetentionDays));
  }, [logRetentionDays]);

  // Real-time Connection Logs State
  const [logs, setLogs] = useState<DnsLogEntry[]>(() => buildInitialSampleLogs());

  const [streamPaused, setStreamPaused] = useState<boolean>(false);
  const [logFilter, setLogFilter] = useState<'ALL' | 'BLOCKED' | 'FORWARDED'>('ALL');
  const [logSearch, setLogSearch] = useState<string>('');
  const [longPressedLog, setLongPressedLog] = useState<DnsLogEntry | null>(null);
  const [pressingLogId, setPressingLogId] = useState<string | null>(null);
  const longPressTimerRef = React.useRef<number | null>(null);

  // Custom Blocklist Input State
  const [newDomainInput, setNewDomainInput] = useState<string>('');
  const [newDomainDesc, setNewDomainDesc] = useState<string>('');
  const [domainInputError, setDomainInputError] = useState<string | null>(null);
  const [ruleSearch, setRuleSearch] = useState<string>('');
  const [ruleFilter, setRuleFilter] = useState<'all' | 'default' | 'enabled' | 'disabled'>('all');

  // Package Filter UI State
  const [pkgSearch, setPkgSearch] = useState<string>('');

  // Test DNS Query UI State
  const [testDomain, setTestDomain] = useState<string>('fraud-detection.engine.miui.com');
  const [testPackage, setTestPackage] = useState<string>('com.miui.securitycenter');

  // Automatically purge logs older than logRetentionDays whenever retention period changes
  useEffect(() => {
    const cutoff = Date.now() - logRetentionDays * DAY_MS;
    setLogs((prev) => {
      const valid = prev.filter((entry) => entry.createdAt >= cutoff);
      const removedCount = prev.length - valid.length;
      if (removedCount > 0) {
        setPurgeNotice(
          `Đã tự động xóa ${removedCount} bản ghi kết nối cũ hơn ${logRetentionDays} ngày.`
        );
      }
      return valid;
    });
  }, [logRetentionDays]);

  // Auto-hide purge notice after 4 seconds
  useEffect(() => {
    if (!purgeNotice) return;
    const t = window.setTimeout(() => setPurgeNotice(null), 4000);
    return () => window.clearTimeout(t);
  }, [purgeNotice]);

  // Manual purge handler by custom days threshold
  const handlePurgeLogsOlderThanDays = (days: number) => {
    const cutoff = Date.now() - days * DAY_MS;
    setLogs((prev) => {
      const remaining = prev.filter((entry) => entry.createdAt >= cutoff);
      const removed = prev.length - remaining.length;
      setPurgeNotice(
        removed > 0
          ? `Đã dọn sạch ${removed} bản ghi log cũ hơn ${days} ngày.`
          : `Không có bản ghi nào cũ hơn ${days} ngày cần xóa.`
      );
      return remaining;
    });
  };

  // Uptime Counter
  useEffect(() => {
    if (!vpnConnected) return;
    const timer = window.setInterval(() => {
      setUptimeSeconds((prev) => prev + 1);
    }, 1000);
    return () => window.clearInterval(timer);
  }, [vpnConnected]);

  // Helper: Check if a package is routed through VPN based on Per-App mode
  const isPackageRoutedInVpn = (pkgName: string): boolean => {
    const pkg = packages.find((p) => p.packageName === pkgName);
    if (!pkg) return true;
    if (filterMode === 'allowlist') {
      return pkg.selected;
    } else {
      return !pkg.selected;
    }
  };

  // Helper: Evaluate a DNS request against active rules, Per-App filter, and Retention window
  const evaluateDnsQuery = (domainInput: string, packageName: string) => {
    const cleanDomain = normalizeDomainInput(domainInput);
    const pkgObj = packages.find((p) => p.packageName === packageName);
    const appName = pkgObj ? pkgObj.appName : packageName;
    const nowMs = Date.now();
    const retentionCutoff = nowMs - logRetentionDays * DAY_MS;

    const routedToVpn = isPackageRoutedInVpn(packageName);

    if (!routedToVpn) {
      const entry: DnsLogEntry = {
        id: `log-${nowMs}-${Math.random().toString(36).slice(2, 6)}`,
        timestamp: formatTimeFromMs(nowMs),
        createdAt: nowMs,
        domain: cleanDomain,
        packageName,
        appName,
        status: 'BYPASSED',
        resolvedIp: `Trực tiếp (Bỏ qua VPN)`,
        latencyMs: 22,
        queryType: 'A',
      };
      setLogs((prev) =>
        [entry, ...prev.filter((item) => item.createdAt >= retentionCutoff)].slice(
          0,
          150
        )
      );
      return;
    }

    const matchedRule = rules.find(
      (r) =>
        r.enabled &&
        (cleanDomain === r.domain || cleanDomain.endsWith(`.${r.domain}`))
    );

    if (matchedRule) {
      setRules((prev) =>
        prev.map((r) =>
          r.id === matchedRule.id ? { ...r, hitCount: r.hitCount + 1 } : r
        )
      );
      const entry: DnsLogEntry = {
        id: `log-${nowMs}-${Math.random().toString(36).slice(2, 6)}`,
        timestamp: formatTimeFromMs(nowMs),
        createdAt: nowMs,
        domain: cleanDomain,
        packageName,
        appName,
        status: 'BLOCKED',
        resolvedIp: '0.0.0.0',
        latencyMs: 1,
        queryType: 'A',
      };
      setLogs((prev) =>
        [entry, ...prev.filter((item) => item.createdAt >= retentionCutoff)].slice(
          0,
          150
        )
      );
    } else {
      const simulatedLatency =
        primaryDns === '1.1.1.1'
          ? Math.floor(11 + Math.random() * 14)
          : Math.floor(16 + Math.random() * 18);
      const entry: DnsLogEntry = {
        id: `log-${nowMs}-${Math.random().toString(36).slice(2, 6)}`,
        timestamp: formatTimeFromMs(nowMs),
        createdAt: nowMs,
        domain: cleanDomain,
        packageName,
        appName,
        status: 'FORWARDED',
        resolvedIp: primaryDns,
        latencyMs: simulatedLatency,
        queryType: 'A',
      };
      setLogs((prev) =>
        [entry, ...prev.filter((item) => item.createdAt >= retentionCutoff)].slice(
          0,
          150
        )
      );
    }
  };

  // Real-time background DNS traffic simulation when VPN is active
  useEffect(() => {
    if (!vpnConnected || streamPaused) return;

    const interval = window.setInterval(() => {
      const shouldSimulateTelemetry = Math.random() < 0.62;
      if (shouldSimulateTelemetry && rules.length > 0) {
        const randomRule = rules[Math.floor(Math.random() * rules.length)];
        const miuiPackages = [
          'com.miui.securitycenter',
          'com.miui.analytics',
          'com.miui.daemon',
          'com.xiaomi.finddevice',
          'com.miui.msa.global',
        ];
        const pkg = miuiPackages[Math.floor(Math.random() * miuiPackages.length)];
        evaluateDnsQuery(randomRule.domain, pkg);
      } else {
        const sample =
          SAMPLE_SAFE_DOMAINS[Math.floor(Math.random() * SAMPLE_SAFE_DOMAINS.length)];
        evaluateDnsQuery(sample.domain, sample.packageName);
      }
    }, 2600);

    return () => window.clearInterval(interval);
  }, [vpnConnected, streamPaused, rules, primaryDns, packages, filterMode, logRetentionDays]);

  // Derived Statistics
  const stats = useMemo(() => {
    const totalBlockedHits = rules.reduce((acc, r) => acc + r.hitCount, 0);
    const forwardedLogsCount = logs.filter((l) => l.status !== 'BLOCKED').length + 148;
    const totalQueries = totalBlockedHits + forwardedLogsCount;
    const blockRate =
      totalQueries > 0 ? Math.round((totalBlockedHits / totalQueries) * 100) : 0;
    const enabledRulesCount = rules.filter((r) => r.enabled).length;
    const selectedPackagesCount = packages.filter((p) => p.selected).length;

    return {
      totalBlockedHits,
      totalQueries,
      blockRate,
      enabledRulesCount,
      selectedPackagesCount,
    };
  }, [rules, logs, packages]);

  // Filtered Logs
  const filteredLogs = useMemo(() => {
    return logs.filter((entry) => {
      if (logFilter === 'BLOCKED' && entry.status !== 'BLOCKED') return false;
      if (logFilter === 'FORWARDED' && entry.status === 'BLOCKED') return false;
      if (logSearch.trim()) {
        const q = logSearch.toLowerCase();
        return (
          entry.domain.toLowerCase().includes(q) ||
          entry.packageName.toLowerCase().includes(q) ||
          entry.appName.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [logs, logFilter, logSearch]);

  // Filtered Rules
  const filteredRules = useMemo(() => {
    return rules.filter((rule) => {
      if (ruleFilter === 'default' && rule.source !== 'default') return false;
      if (ruleFilter === 'enabled' && !rule.enabled) return false;
      if (ruleFilter === 'disabled' && rule.enabled) return false;
      if (ruleSearch.trim()) {
        const q = ruleSearch.toLowerCase();
        return (
          rule.domain.toLowerCase().includes(q) ||
          rule.description.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [rules, ruleFilter, ruleSearch]);

  // Remaining Xiaomi/MIUI Suggestions (not yet in rules)
  const availableSuggestions = useMemo(() => {
    const existingSet = new Set(rules.map((r) => r.domain.toLowerCase()));
    return MIUI_TELEMETRY_SUGGESTIONS.filter(
      (s) => !existingSet.has(s.domain.toLowerCase())
    );
  }, [rules]);

  // Filtered Packages
  const filteredPackages = useMemo(() => {
    return packages.filter((pkg) => {
      if (pkgSearch.trim()) {
        const q = pkgSearch.toLowerCase();
        return (
          pkg.packageName.toLowerCase().includes(q) ||
          pkg.appName.toLowerCase().includes(q) ||
          pkg.description.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [packages, pkgSearch]);

  // Handlers
  const handleAddCustomDomain = (e: React.FormEvent) => {
    e.preventDefault();
    setDomainInputError(null);

    const lines = newDomainInput
      .split(/[\n,;]+/)
      .map((l) => normalizeDomainInput(l))
      .filter(Boolean);

    if (lines.length === 0) {
      setDomainInputError('Vui lòng nhập tên miền hợp lệ (ví dụ: 0.0.0.0 tracking.miui.com).');
      return;
    }

    const domainRegex = /^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$/i;
    const invalidLine = lines.find((d) => !domainRegex.test(d));
    if (invalidLine) {
      setDomainInputError(`Định dạng tên miền không hợp lệ: "${invalidLine}"`);
      return;
    }

    const existingDomains = new Set(rules.map((r) => r.domain));
    const newItems: DomainRule[] = [];

    lines.forEach((domain) => {
      if (!existingDomains.has(domain)) {
        existingDomains.add(domain);
        newItems.push({
          id: `custom-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
          domain,
          enabled: true,
          source: 'custom',
          description:
            newDomainDesc.trim() || 'Quy tắc chặn tùy chỉnh do người dùng thêm (0.0.0.0)',
          hitCount: 0,
        });
      }
    });

    if (newItems.length === 0) {
      setDomainInputError('Tên miền này đã có trong danh sách chặn.');
      return;
    }

    setRules((prev) => [...newItems, ...prev]);
    setNewDomainInput('');
    setNewDomainDesc('');
  };

  const handleAddSuggestion = (domain: string, description: string) => {
    if (rules.some((r) => r.domain === domain)) return;
    const newRule: DomainRule = {
      id: `sug-${Date.now()}-${Math.random().toString(36).slice(2, 5)}`,
      domain,
      enabled: true,
      source: 'suggested',
      description,
      hitCount: 0,
    };
    setRules((prev) => [newRule, ...prev]);
  };

  const handleAddAllSuggestions = () => {
    const newRules: DomainRule[] = availableSuggestions.map((s, idx) => ({
      id: `sug-batch-${Date.now()}-${idx}`,
      domain: s.domain,
      enabled: true,
      source: 'suggested',
      description: `${s.module} — ${s.description}`,
      hitCount: 0,
    }));
    setRules((prev) => [...newRules, ...prev]);
  };

  const handleToggleRule = (id: string) => {
    setRules((prev) =>
      prev.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r))
    );
  };

  const handleDeleteRule = (id: string) => {
    setRules((prev) => prev.filter((r) => r.id !== id));
  };

  const handleResetDefaultRules = () => {
    setRules(INITIAL_BLOCK_RULES);
  };

  const handleLogPointerDown = (entry: DnsLogEntry) => {
    setPressingLogId(entry.id);
    if (longPressTimerRef.current) {
      window.clearTimeout(longPressTimerRef.current);
    }
    longPressTimerRef.current = window.setTimeout(() => {
      setPressingLogId(null);
      if (typeof navigator !== 'undefined' && navigator.vibrate) {
        navigator.vibrate(40);
      }
      setLongPressedLog(entry);
    }, 500);
  };

  const handleLogPointerEnd = () => {
    if (longPressTimerRef.current) {
      window.clearTimeout(longPressTimerRef.current);
      longPressTimerRef.current = null;
    }
    setPressingLogId(null);
  };

  const handleLogContextMenu = (e: React.MouseEvent, entry: DnsLogEntry) => {
    e.preventDefault();
    handleLogPointerEnd();
    setLongPressedLog(entry);
  };

  const handleBlockHostFromLog = (entry: DnsLogEntry) => {
    const cleanDomain = normalizeDomainInput(entry.domain);
    if (!cleanDomain) return;

    setRules((prev) => {
      const existingIdx = prev.findIndex((r) => r.domain.toLowerCase() === cleanDomain);
      if (existingIdx >= 0) {
        return prev.map((r, idx) =>
          idx === existingIdx ? { ...r, enabled: true } : r
        );
      }
      const newRule: DomainRule = {
        id: `log-rule-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        domain: cleanDomain,
        enabled: true,
        source: 'custom',
        description: `Chặn từ nhật ký kết nối (${entry.appName} — ${entry.packageName})`,
        hitCount: 1,
      };
      return [newRule, ...prev];
    });

    setLogs((prev) =>
      prev.map((item) =>
        item.domain.toLowerCase() === cleanDomain ||
        item.domain.toLowerCase().endsWith(`.${cleanDomain}`)
          ? { ...item, status: 'BLOCKED', resolvedIp: '0.0.0.0' }
          : item
      )
    );

    setPurgeNotice(`Đã thêm 0.0.0.0 ${cleanDomain} vào danh sách chặn.`);
    setLongPressedLog(null);
  };

  const handleUnblockHostFromLog = (entry: DnsLogEntry) => {
    const cleanDomain = normalizeDomainInput(entry.domain);
    setRules((prev) =>
      prev.map((r) =>
        cleanDomain === r.domain.toLowerCase() ||
        cleanDomain.endsWith(`.${r.domain.toLowerCase()}`)
          ? { ...r, enabled: false }
          : r
      )
    );
    setPurgeNotice(`Đã tắt chặn cho tên miền ${cleanDomain}.`);
    setLongPressedLog(null);
  };

  const handleTogglePackage = (packageName: string) => {
    setPackages((prev) =>
      prev.map((p) =>
        p.packageName === packageName ? { ...p, selected: !p.selected } : p
      )
    );
  };

  const handleSelectAllMiuiPackages = () => {
    setPackages((prev) =>
      prev.map((p) => ({
        ...p,
        selected:
          p.packageName.startsWith('com.miui.') ||
          p.packageName.startsWith('com.xiaomi.'),
      }))
    );
  };

  const handleCopyText = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedFeedback(label);
    window.setTimeout(() => setCopiedFeedback(null), 2000);
  };

  const handleDownloadFile = (filename: string, content: string) => {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const generatedKotlinCode = useMemo(
    () =>
      generateKotlinVpnServiceCode(
        rules,
        primaryDns,
        secondaryDns,
        filterMode,
        packages,
        logRetentionDays
      ),
    [rules, primaryDns, secondaryDns, filterMode, packages, logRetentionDays]
  );

  const generatedHostsContent = useMemo(
    () => generateHostsFileContent(rules),
    [rules]
  );

  const generatedManifestXml = useMemo(() => generateAndroidManifestXml(), []);
  const generatedPacketHelperCode = useMemo(() => generateDnsPacketHelperCode(), []);
  const generatedGradleCode = useMemo(() => generateAppBuildGradleKts(), []);
  const generatedWorkflowYaml = useMemo(() => generateGitHubActionsApkYaml(), []);
  const generatedSetupScript = useMemo(
    () =>
      generateFullAndroidSetupScript(
        rules,
        primaryDns,
        secondaryDns,
        filterMode,
        packages,
        logRetentionDays
      ),
    [rules, primaryDns, secondaryDns, filterMode, packages, logRetentionDays]
  );

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 pb-20 lg:pb-10">
      {/* TOP BAR CONTRACT: Strictly 3 zones separated by gap-8 */}
      <header className="sticky top-0 z-30 bg-white/90 dark:bg-slate-950/90 backdrop-blur-md border-b border-slate-200 dark:border-slate-800">
        <div className="max-w-7xl mx-auto flex items-center justify-between gap-8 px-4 sm:px-6 h-14">
          {/* Zone 1: Single text element wordmark */}
          <a
            href="#top"
            onClick={(e) => {
              e.preventDefault();
              setActiveTab('dashboard');
            }}
            className="flex items-center gap-2.5 text-lg font-bold tracking-tight text-slate-900 dark:text-white font-display whitespace-nowrap shrink-0"
          >
            <img src="/favicon.svg" alt="MiGuard Shield" className="w-7 h-7 rounded-lg shadow-xs" />
            <span>MiGuard DNS</span>
          </a>

          {/* Zone 2: 4 concise single-line navigation links */}
          <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-600 dark:text-slate-400">
            <button
              type="button"
              onClick={() => setActiveTab('dashboard')}
              className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 cursor-pointer ${
                activeTab === 'dashboard'
                  ? 'text-slate-900 dark:text-white border-emerald-500'
                  : 'border-transparent hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              Bảng điều khiển
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('logs')}
              className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 cursor-pointer ${
                activeTab === 'logs'
                  ? 'text-slate-900 dark:text-white border-emerald-500'
                  : 'border-transparent hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              Nhật ký kết nối
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('blocklist')}
              className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 cursor-pointer ${
                activeTab === 'blocklist'
                  ? 'text-slate-900 dark:text-white border-emerald-500'
                  : 'border-transparent hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              Danh sách chặn
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('packages')}
              className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 cursor-pointer ${
                activeTab === 'packages'
                  ? 'text-slate-900 dark:text-white border-emerald-500'
                  : 'border-transparent hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              Gói hệ thống
            </button>
          </nav>

          {/* Zone 3: 1 primary action */}
          <div className="flex items-center shrink-0">
            <button
              type="button"
              onClick={() => setShowCodeModal(true)}
              className="min-h-[40px] px-4 py-2 text-xs font-medium text-white bg-emerald-600 hover:bg-emerald-500 rounded-lg transition-colors whitespace-nowrap shrink-0 flex items-center gap-2 cursor-pointer"
            >
              <Code2 className="w-4 h-4" />
              <span>Mã nguồn Android</span>
            </button>
          </div>
        </div>
      </header>

      {/* Secondary Workspace Bar (DNS Selector, Log Retention Metadata & Theme Switch) */}
      <div className="border-b border-slate-200 dark:border-slate-900 bg-slate-100/60 dark:bg-slate-900/40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-2.5 flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2 text-slate-600 dark:text-slate-400 font-mono">
            <span>
              Trạng thái: {vpnConnected ? 'Đang bảo vệ (TUN 10.111.222.1)' : 'Đã ngắt kết nối'}
            </span>
            <span aria-hidden="true">·</span>
            <span>Sinkhole: 0.0.0.0</span>
            <span aria-hidden="true">·</span>
            <span className="hidden sm:inline">
              Tự xóa log sau: {logRetentionDays} ngày
            </span>
          </div>

          <div className="flex items-center gap-3">
            {/* Segmented Upstream DNS Switcher */}
            <div className="flex items-center gap-1 p-1 bg-slate-200/80 dark:bg-slate-800 rounded-lg">
              <button
                type="button"
                onClick={() => setPrimaryDns('1.1.1.1')}
                className={`px-2.5 py-1 text-xs font-mono font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  primaryDns === '1.1.1.1'
                    ? 'bg-white dark:bg-slate-950 text-slate-900 dark:text-emerald-400 shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                DNS 1.1.1.1
              </button>
              <button
                type="button"
                onClick={() => setPrimaryDns('8.8.8.8')}
                className={`px-2.5 py-1 text-xs font-mono font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  primaryDns === '8.8.8.8'
                    ? 'bg-white dark:bg-slate-950 text-slate-900 dark:text-emerald-400 shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                DNS 8.8.8.8
              </button>
            </div>

            {/* Theme Toggle */}
            <button
              type="button"
              onClick={() => setIsDark((prev) => !prev)}
              aria-label="Chuyển đổi giao diện Sáng / Tối"
              className="min-h-[36px] px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
            >
              {isDark ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
              <span className="hidden sm:inline">{isDark ? 'Giao diện Sáng' : 'Giao diện Tối'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Content Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* LEFT / PRIMARY INTERACTIVE WORKSPACE (7 columns on desktop) */}
          <div className="lg:col-span-7 space-y-6">
            {/* TAB 1: DASHBOARD */}
            {activeTab === 'dashboard' && (
              <>
                {/* Primary VPN Tunnel Control Card */}
                <section className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-6">
                    <div className="space-y-2">
                      <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400 font-mono">
                        <span>ANDROID VPNSERVICE</span>
                        <span aria-hidden="true">·</span>
                        <span>UDP PORT 53</span>
                        <span aria-hidden="true">·</span>
                        <span>{formatDuration(uptimeSeconds)}</span>
                      </div>
                      <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900 dark:text-white font-display">
                        {vpnConnected
                          ? 'Đường hầm lọc DNS đang bật'
                          : 'Đường hầm lọc DNS đang tắt'}
                      </h1>
                      <p className="text-sm text-slate-600 dark:text-slate-400 max-w-xl leading-relaxed">
                        {vpnConnected
                          ? `Đang chặn ${stats.enabledRulesCount} tên miền Xiaomi/MIUI về 0.0.0.0 và chuyển tiếp mọi truy vấn hợp lệ khác qua DNS ${primaryDns} (dự phòng ${secondaryDns}).`
                          : 'Bấm nút nguồn để kích hoạt dịch vụ VPN cục bộ. Không sử dụng máy chủ trung gian, không làm giảm tốc độ mạng.'}
                      </p>
                    </div>

                    {/* Tactile 1-Tap Connect Button */}
                    <div className="shrink-0 flex sm:flex-col items-center gap-3">
                      <button
                        type="button"
                        onClick={() => {
                          setVpnConnected((prev) => !prev);
                          if (!vpnConnected) setUptimeSeconds(0);
                        }}
                        className={`w-20 h-20 rounded-2xl flex flex-col items-center justify-center gap-1 transition-transform active:scale-95 cursor-pointer border ${
                          vpnConnected
                            ? 'bg-emerald-600 hover:bg-emerald-500 text-white border-emerald-500 shadow-lg shadow-emerald-950/20'
                            : 'bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-700'
                        }`}
                      >
                        <Power className="w-7 h-7" />
                        <span className="text-[11px] font-semibold tracking-tight">
                          {vpnConnected ? 'ĐANG BẬT' : 'ĐÃ TẮT'}
                        </span>
                      </button>
                    </div>
                  </div>

                  {/* Quick Routing Architecture Strip */}
                  <div className="mt-6 pt-5 border-t border-slate-100 dark:border-slate-800/80 grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
                    <div>
                      <p className="text-slate-500 dark:text-slate-400">Chuyển hướng bị chặn</p>
                      <p className="mt-1 font-mono font-semibold text-rose-600 dark:text-rose-400 text-sm">
                        0.0.0.0 (Local Sinkhole)
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-500 dark:text-slate-400">DNS phân giải ngoài danh sách</p>
                      <p className="mt-1 font-mono font-semibold text-emerald-600 dark:text-emerald-400 text-sm">
                        {primaryDns} · {secondaryDns}
                      </p>
                    </div>
                    <div>
                      <p className="text-slate-500 dark:text-slate-400">Tự động xóa log kết nối</p>
                      <p className="mt-1 font-medium text-slate-900 dark:text-slate-200 text-sm">
                        Sau {logRetentionDays} ngày {logRetentionDays === 7 ? '(Mặc định)' : ''}
                      </p>
                    </div>
                  </div>
                </section>

                {/* 4-Card KPI Telemetry Row */}
                <section className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
                  <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-4">
                    <p className="text-xs text-slate-500 dark:text-slate-400">Đã chặn (0.0.0.0)</p>
                    <p className="mt-1.5 text-2xl font-bold font-mono tabular-nums text-rose-600 dark:text-rose-400">
                      {stats.totalBlockedHits.toLocaleString('vi-VN')}
                    </p>
                    <p className="mt-1 text-xs text-slate-500 dark:text-slate-400 font-mono">
                      {stats.blockRate}% tổng truy vấn
                    </p>
                  </div>

                  <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-4">
                    <p className="text-xs text-slate-500 dark:text-slate-400">Tổng request DNS</p>
                    <p className="mt-1.5 text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-white">
                      {stats.totalQueries.toLocaleString('vi-VN')}
                    </p>
                    <p className="mt-1 text-xs text-slate-500 dark:text-slate-400 font-mono">
                      Qua cổng UDP 53
                    </p>
                  </div>

                  <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-4">
                    <p className="text-xs text-slate-500 dark:text-slate-400">Tên miền đang chặn</p>
                    <p className="mt-1.5 text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-white">
                      {stats.enabledRulesCount}
                    </p>
                    <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                      Trên tổng {rules.length} quy tắc
                    </p>
                  </div>

                  <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-4">
                    <p className="text-xs text-slate-500 dark:text-slate-400">Chu kỳ giữ log</p>
                    <p className="mt-1.5 text-2xl font-bold font-mono tabular-nums text-emerald-600 dark:text-emerald-400">
                      {logRetentionDays} ngày
                    </p>
                    <p className="mt-1 text-xs text-slate-500 dark:text-slate-400 font-mono">
                      Đang lưu {logs.length} mục
                    </p>
                  </div>
                </section>

                {/* Core 5 Xiaomi/MIUI Blocked Hosts Quick Control */}
                <section className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6">
                  <div className="flex flex-wrap items-center justify-between gap-2 pb-4 border-b border-slate-100 dark:border-slate-800">
                    <div>
                      <h2 className="text-base font-bold text-slate-900 dark:text-white font-display">
                        Danh sách tên miền chặn mục tiêu (0.0.0.0)
                      </h2>
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                        Bật hoặc tắt nhanh từng máy chủ Xiaomi/MIUI. Mọi tên miền không thuộc danh sách này sẽ đi qua {primaryDns}.
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setActiveTab('blocklist')}
                      className="min-h-[36px] px-3 py-1.5 text-xs font-medium text-emerald-600 dark:text-emerald-400 hover:underline whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      Tùy chỉnh & Thêm mới ({rules.length})
                    </button>
                  </div>

                  <div className="divide-y divide-slate-100 dark:divide-slate-800/80">
                    {rules.slice(0, 7).map((rule) => (
                      <div
                        key={rule.id}
                        className="py-3.5 flex items-center justify-between gap-4"
                      >
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span
                              className={`font-mono text-sm font-medium truncate ${
                                rule.enabled
                                  ? 'text-slate-900 dark:text-slate-100'
                                  : 'text-slate-400 dark:text-slate-500 line-through'
                              }`}
                            >
                              0.0.0.0 {rule.domain}
                            </span>
                          </div>
                          <div className="mt-0.5 flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
                            <span className="truncate">{rule.description}</span>
                            <span aria-hidden="true">·</span>
                            <span className="font-mono tabular-nums shrink-0">
                              Đã chặn {rule.hitCount} lần
                            </span>
                          </div>
                        </div>

                        <button
                          type="button"
                          role="switch"
                          aria-checked={rule.enabled}
                          onClick={() => handleToggleRule(rule.id)}
                          className={`min-h-[36px] min-w-[64px] px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors shrink-0 cursor-pointer border ${
                            rule.enabled
                              ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30 hover:bg-rose-500/20'
                              : 'bg-slate-100 dark:bg-slate-800 text-slate-500 border-slate-200 dark:border-slate-700 hover:text-slate-800 dark:hover:text-slate-200'
                          }`}
                        >
                          {rule.enabled ? 'CHẶN' : 'TẮT'}
                        </button>
                      </div>
                    ))}
                  </div>
                </section>

                {/* Quick Per-App & Auto-Purge Settings Summary Card */}
                <section className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6 space-y-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <h2 className="text-base font-bold text-slate-900 dark:text-white font-display">
                        Phạm vi áp dụng trên Package hệ thống
                      </h2>
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                        {filterMode === 'allowlist'
                          ? 'Chỉ định tuyến DNS cho các package hệ thống được tick chọn (các ứng dụng cá nhân khác đi trực tiếp).'
                          : 'Định tuyến DNS cho toàn bộ thiết bị và bỏ qua các package được tick chọn.'}
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setActiveTab('packages')}
                      className="min-h-[40px] px-3.5 py-2 rounded-lg text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      Chọn package hệ thống ({stats.selectedPackagesCount})
                    </button>
                  </div>
                </section>
              </>
            )}

            {/* TAB 2: FULL REAL-TIME LOGS, RETENTION SCHEDULE & DNS TESTER */}
            {activeTab === 'logs' && (
              <section className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6 space-y-5">
                <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-100 dark:border-slate-800">
                  <div>
                    <h1 className="text-xl font-bold text-slate-900 dark:text-white font-display">
                      Nhật ký kết nối DNS thời gian thực
                    </h1>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                      Theo dõi trực tiếp mọi gói tin DNS đi qua giao diện TUN và tự động dọn dẹp theo chu kỳ.
                    </p>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setStreamPaused((prev) => !prev)}
                      className="min-h-[40px] px-3 py-2 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/70 hover:bg-slate-100 dark:hover:bg-slate-800 flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      {streamPaused ? (
                        <>
                          <Play className="w-3.5 h-3.5 text-emerald-500" />
                          <span>Tiếp tục luồng</span>
                        </>
                      ) : (
                        <>
                          <Pause className="w-3.5 h-3.5 text-amber-500" />
                          <span>Tạm dừng</span>
                        </>
                      )}
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setLogs([]);
                        setPurgeNotice('Đã xóa toàn bộ nhật ký kết nối hiện tại.');
                      }}
                      className="min-h-[40px] px-3 py-2 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 hover:text-rose-500 flex items-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      <span>Xóa toàn bộ</span>
                    </button>
                  </div>
                </div>

                {/* Configurable Log Retention Schedule (Default: 7 Days) */}
                <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Clock className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                      <span className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                        Tự động xóa log kết nối theo thời gian định trước
                      </span>
                    </div>
                    <span className="text-xs font-mono text-slate-500 dark:text-slate-400">
                      Đang áp dụng: {logRetentionDays} ngày {logRetentionDays === 7 ? '(Mặc định)' : ''}
                    </span>
                  </div>

                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="flex flex-wrap items-center gap-1.5">
                      {RETENTION_OPTIONS.map((opt) => (
                        <button
                          key={opt.value}
                          type="button"
                          onClick={() => setLogRetentionDays(opt.value)}
                          className={`min-h-[36px] px-3 py-1.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer border ${
                            logRetentionDays === opt.value
                              ? 'bg-emerald-600 text-white border-emerald-600'
                              : 'bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-800 hover:border-emerald-500/50'
                          }`}
                        >
                          {opt.label}
                        </button>
                      ))}
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => handlePurgeLogsOlderThanDays(logRetentionDays)}
                        className="min-h-[36px] px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-200/80 dark:bg-slate-800 hover:bg-slate-300/70 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        Dọn log quá {logRetentionDays} ngày ngay
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setLogs(buildInitialSampleLogs());
                          setLogRetentionDays(7);
                          setPurgeNotice('Đã khôi phục dữ liệu mẫu và đặt chu kỳ mặc định 7 ngày.');
                        }}
                        className="min-h-[36px] px-2.5 py-1.5 rounded-lg text-xs text-slate-500 hover:text-slate-900 dark:hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        Đặt lại mặc định (7 ngày)
                      </button>
                    </div>
                  </div>

                  {purgeNotice && (
                    <p className="text-xs text-emerald-600 dark:text-emerald-400 font-medium">
                      {purgeNotice}
                    </p>
                  )}
                </div>

                {/* Interactive DNS Query Simulator Box */}
                <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-800 dark:text-slate-200">
                      Kiểm thử truy vấn DNS (Giả lập gói tin từ ứng dụng)
                    </span>
                    <span className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                      DNS đích: {primaryDns}
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-12 gap-2.5">
                    <div className="sm:col-span-5">
                      <label className="sr-only">Chọn Package</label>
                      <select
                        value={testPackage}
                        onChange={(e) => setTestPackage(e.target.value)}
                        className="w-full min-h-[42px] px-3 py-2 rounded-lg text-xs font-mono bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-emerald-500"
                      >
                        {packages.map((p) => (
                          <option key={p.packageName} value={p.packageName}>
                            {p.packageName}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div className="sm:col-span-5">
                      <label className="sr-only">Tên miền</label>
                      <input
                        type="text"
                        value={testDomain}
                        onChange={(e) => setTestDomain(e.target.value)}
                        placeholder="Nhập domain cần kiểm tra..."
                        className="w-full min-h-[42px] px-3 py-2 rounded-lg text-xs font-mono bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-emerald-500"
                      />
                    </div>
                    <div className="sm:col-span-2">
                      <button
                        type="button"
                        onClick={() => {
                          if (testDomain.trim()) {
                            evaluateDnsQuery(testDomain, testPackage);
                          }
                        }}
                        className="w-full min-h-[42px] px-3 py-2 rounded-lg text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        Gửi thử
                      </button>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
                    <span>Thử nhanh:</span>
                    {[
                      'fraud-detection.engine.miui.com',
                      'flash.sec.miui.com',
                      'dm.wo.com.cn',
                      'play.googleapis.com',
                    ].map((sampleDom) => (
                      <button
                        key={sampleDom}
                        type="button"
                        onClick={() => {
                          setTestDomain(sampleDom);
                          evaluateDnsQuery(sampleDom, testPackage);
                        }}
                        className="font-mono text-xs text-slate-700 dark:text-slate-300 hover:text-emerald-500 dark:hover:text-emerald-400 underline underline-offset-2 cursor-pointer"
                      >
                        {sampleDom}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Filter & Search Bar */}
                <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-800 rounded-lg">
                    <button
                      type="button"
                      onClick={() => setLogFilter('ALL')}
                      className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                        logFilter === 'ALL'
                          ? 'bg-white dark:bg-slate-950 text-slate-900 dark:text-white shadow-xs'
                          : 'text-slate-600 dark:text-slate-400'
                      }`}
                    >
                      Tất cả ({logs.length})
                    </button>
                    <button
                      type="button"
                      onClick={() => setLogFilter('BLOCKED')}
                      className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                        logFilter === 'BLOCKED'
                          ? 'bg-white dark:bg-slate-950 text-rose-600 dark:text-rose-400 shadow-xs'
                          : 'text-slate-600 dark:text-slate-400'
                      }`}
                    >
                      Đã chặn 0.0.0.0
                    </button>
                    <button
                      type="button"
                      onClick={() => setLogFilter('FORWARDED')}
                      className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                        logFilter === 'FORWARDED'
                          ? 'bg-white dark:bg-slate-950 text-emerald-600 dark:text-emerald-400 shadow-xs'
                          : 'text-slate-600 dark:text-slate-400'
                      }`}
                    >
                      Cho phép ({primaryDns})
                    </button>
                  </div>

                  <div className="relative flex-1 max-w-xs">
                    <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      value={logSearch}
                      onChange={(e) => setLogSearch(e.target.value)}
                      placeholder="Tìm domain hoặc package..."
                      className="w-full min-h-[38px] pl-9 pr-3 py-1.5 rounded-lg text-xs bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-emerald-500"
                    />
                  </div>
                </div>

                {/* Log Stream List */}
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Mẹo: Nhấn giữ (Long press) vào bất kỳ dòng nhật ký nào để thêm nhanh host đó vào danh sách chặn (0.0.0.0).
                </p>
                <div className="divide-y divide-slate-100 dark:divide-slate-800/80 max-h-[540px] overflow-y-auto">
                  {filteredLogs.length === 0 ? (
                    <div className="py-12 text-center text-sm text-slate-500 dark:text-slate-400">
                      Không có bản ghi kết nối nào trong khoảng {logRetentionDays} ngày khớp với bộ lọc.
                    </div>
                  ) : (
                    filteredLogs.map((item) => (
                      <div
                        key={item.id}
                        onPointerDown={() => handleLogPointerDown(item)}
                        onPointerUp={handleLogPointerEnd}
                        onPointerLeave={handleLogPointerEnd}
                        onPointerCancel={handleLogPointerEnd}
                        onContextMenu={(e) => handleLogContextMenu(e, item)}
                        title="Nhấn giữ để thêm vào danh sách chặn"
                        className={`py-3 px-2 -mx-2 rounded-lg flex items-center justify-between gap-4 text-xs select-none cursor-pointer transition-colors ${
                          pressingLogId === item.id
                            ? 'bg-emerald-500/10 dark:bg-emerald-500/15'
                            : 'hover:bg-slate-50 dark:hover:bg-slate-800/50'
                        }`}
                      >
                        <div className="min-w-0 space-y-1">
                          <div className="flex items-center gap-2">
                            <span
                              className={`font-mono font-semibold text-sm truncate ${
                                item.status === 'BLOCKED'
                                  ? 'text-rose-600 dark:text-rose-400'
                                  : 'text-slate-900 dark:text-slate-100'
                              }`}
                            >
                              {item.domain}
                            </span>
                          </div>
                          {/* Unboxed clean metadata with typographic separators */}
                          <div className="flex flex-wrap items-center gap-1.5 text-slate-500 dark:text-slate-400 font-mono">
                            <span>{formatRelativeAge(item.createdAt)}</span>
                            <span aria-hidden="true">·</span>
                            <span>{item.timestamp}</span>
                            <span aria-hidden="true">·</span>
                            <span>{item.packageName}</span>
                            <span aria-hidden="true">·</span>
                            <span>{item.appName}</span>
                          </div>
                        </div>

                        <div className="text-right shrink-0 font-mono tabular-nums">
                          <div
                            className={`font-semibold ${
                              item.status === 'BLOCKED'
                                ? 'text-rose-600 dark:text-rose-400'
                                : item.status === 'BYPASSED'
                                ? 'text-amber-600 dark:text-amber-400'
                                : 'text-emerald-600 dark:text-emerald-400'
                            }`}
                          >
                            {item.status === 'BLOCKED'
                              ? 'CHẶN → 0.0.0.0'
                              : item.status === 'BYPASSED'
                              ? 'BỎ QUA VPN'
                              : `CHO PHÉP → ${item.resolvedIp}`}
                          </div>
                          <div className="text-slate-400 dark:text-slate-500 mt-0.5">
                            {item.queryType} · {item.latencyMs} ms
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </section>
            )}

            {/* TAB 3: BLOCKLIST MANAGER & XIAOMI/MIUI SUGGESTIONS */}
            {activeTab === 'blocklist' && (
              <div className="space-y-6">
                {/* Manual Domain Rule Entry Card */}
                <section className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6">
                  <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
                    <div>
                      <h1 className="text-xl font-bold text-slate-900 dark:text-white font-display">
                        Tùy chỉnh danh sách chặn (0.0.0.0)
                      </h1>
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                        Thêm tên miền thủ công hoặc dán trực tiếp định dạng hosts (0.0.0.0 domain.com).
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={handleResetDefaultRules}
                      className="min-h-[36px] px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white flex items-center gap-1.5 cursor-pointer"
                    >
                      <RefreshCw className="w-3.5 h-3.5" />
                      <span>Khôi phục 5 domain gốc</span>
                    </button>
                  </div>

                  <form onSubmit={handleAddCustomDomain} className="space-y-3">
                    <div className="grid grid-cols-1 sm:grid-cols-12 gap-3">
                      <div className="sm:col-span-6">
                        <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                          Tên miền hoặc dòng cấu hình hosts
                        </label>
                        <input
                          type="text"
                          value={newDomainInput}
                          onChange={(e) => setNewDomainInput(e.target.value)}
                          placeholder="0.0.0.0 api.ad.xiaomi.com"
                          className="w-full min-h-[42px] px-3.5 py-2 rounded-lg text-xs font-mono bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-emerald-500"
                        />
                      </div>
                      <div className="sm:col-span-4">
                        <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                          Ghi chú (Tùy chọn)
                        </label>
                        <input
                          type="text"
                          value={newDomainDesc}
                          onChange={(e) => setNewDomainDesc(e.target.value)}
                          placeholder="Ví dụ: Chặn quảng cáo MIUI"
                          className="w-full min-h-[42px] px-3.5 py-2 rounded-lg text-xs bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-emerald-500"
                        />
                      </div>
                      <div className="sm:col-span-2 flex items-end">
                        <button
                          type="submit"
                          className="w-full min-h-[42px] px-4 py-2 rounded-lg text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white transition-colors flex items-center justify-center gap-1.5 whitespace-nowrap shrink-0 cursor-pointer"
                        >
                          <Plus className="w-4 h-4" />
                          <span>Thêm</span>
                        </button>
                      </div>
                    </div>

                    {domainInputError && (
                      <p className="text-xs text-rose-600 dark:text-rose-400">
                        {domainInputError}
                      </p>
                    )}
                  </form>
                </section>

                {/* Auto-Suggested Xiaomi / MIUI Telemetry Domains */}
                <section className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6">
                  <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-100 dark:border-slate-800">
                    <div>
                      <h2 className="text-base font-bold text-slate-900 dark:text-white font-display">
                        Gợi ý tự động: Tên miền Telemetry & Quảng cáo Xiaomi/MIUI
                      </h2>
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                        Các máy chủ thu thập dữ liệu ngầm phổ biến trên ROM MIUI và HyperOS. Bấm để thêm vào danh sách chặn.
                      </p>
                    </div>
                    {availableSuggestions.length > 0 && (
                      <button
                        type="button"
                        onClick={handleAddAllSuggestions}
                        className="min-h-[38px] px-3.5 py-1.5 rounded-lg text-xs font-medium bg-emerald-600/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30 hover:bg-emerald-600/20 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        Thêm tất cả ({availableSuggestions.length})
                      </button>
                    )}
                  </div>

                  {availableSuggestions.length === 0 ? (
                    <p className="py-6 text-center text-xs text-slate-500 dark:text-slate-400">
                      Toàn bộ tên miền gợi ý của Xiaomi/MIUI đã được thêm vào danh sách chặn của bạn.
                    </p>
                  ) : (
                    <div className="divide-y divide-slate-100 dark:divide-slate-800/80">
                      {availableSuggestions.map((sug) => (
                        <div
                          key={sug.domain}
                          className="py-3 flex items-center justify-between gap-4"
                        >
                          <div className="min-w-0">
                            <p className="font-mono text-sm font-medium text-slate-900 dark:text-slate-100 truncate">
                              0.0.0.0 {sug.domain}
                            </p>
                            <div className="mt-0.5 flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
                              <span>{sug.module}</span>
                              <span aria-hidden="true">·</span>
                              <span className="truncate">{sug.description}</span>
                            </div>
                          </div>
                          <button
                            type="button"
                            onClick={() =>
                              handleAddSuggestion(
                                sug.domain,
                                `${sug.module} — ${sug.description}`
                              )
                            }
                            className="min-h-[36px] px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-700 hover:border-emerald-500 hover:text-emerald-500 transition-colors flex items-center gap-1 shrink-0 cursor-pointer"
                          >
                            <Plus className="w-3.5 h-3.5" />
                            <span>Chặn</span>
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </section>

                {/* Active Rules List */}
                <section className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-800 rounded-lg">
                      <button
                        type="button"
                        onClick={() => setRuleFilter('all')}
                        className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                          ruleFilter === 'all'
                            ? 'bg-white dark:bg-slate-950 text-slate-900 dark:text-white shadow-xs'
                            : 'text-slate-600 dark:text-slate-400'
                        }`}
                      >
                        Tất cả ({rules.length})
                      </button>
                      <button
                        type="button"
                        onClick={() => setRuleFilter('default')}
                        className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                          ruleFilter === 'default'
                            ? 'bg-white dark:bg-slate-950 text-slate-900 dark:text-white shadow-xs'
                            : 'text-slate-600 dark:text-slate-400'
                        }`}
                      >
                        Mặc định (5)
                      </button>
                      <button
                        type="button"
                        onClick={() => setRuleFilter('enabled')}
                        className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                          ruleFilter === 'enabled'
                            ? 'bg-white dark:bg-slate-950 text-slate-900 dark:text-white shadow-xs'
                            : 'text-slate-600 dark:text-slate-400'
                        }`}
                      >
                        Đang bật ({stats.enabledRulesCount})
                      </button>
                    </div>

                    <div className="relative flex-1 max-w-xs">
                      <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                      <input
                        type="text"
                        value={ruleSearch}
                        onChange={(e) => setRuleSearch(e.target.value)}
                        placeholder="Lọc tên miền trong danh sách..."
                        className="w-full min-h-[38px] pl-9 pr-3 py-1.5 rounded-lg text-xs bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-emerald-500"
                      />
                    </div>
                  </div>

                  <div className="divide-y divide-slate-100 dark:divide-slate-800/80">
                    {filteredRules.map((rule) => (
                      <div
                        key={rule.id}
                        className="py-3.5 flex items-center justify-between gap-4"
                      >
                        <div className="min-w-0">
                          <p
                            className={`font-mono text-sm font-medium truncate ${
                              rule.enabled
                                ? 'text-slate-900 dark:text-slate-100'
                                : 'text-slate-400 dark:text-slate-500 line-through'
                            }`}
                          >
                            0.0.0.0 {rule.domain}
                          </p>
                          <div className="mt-0.5 flex flex-wrap items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
                            <span>
                              {rule.source === 'default'
                                ? 'Mặc định'
                                : rule.source === 'suggested'
                                ? 'Gợi ý MIUI'
                                : 'Tùy chỉnh'}
                            </span>
                            <span aria-hidden="true">·</span>
                            <span>{rule.description}</span>
                            <span aria-hidden="true">·</span>
                            <span className="font-mono tabular-nums">
                              Chặn {rule.hitCount} lần
                            </span>
                          </div>
                        </div>

                        <div className="flex items-center gap-2 shrink-0">
                          <button
                            type="button"
                            onClick={() => handleToggleRule(rule.id)}
                            className={`min-h-[36px] min-w-[64px] px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors cursor-pointer border ${
                              rule.enabled
                                ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30'
                                : 'bg-slate-100 dark:bg-slate-800 text-slate-500 border-slate-200 dark:border-slate-700'
                            }`}
                          >
                            {rule.enabled ? 'ĐANG BẬT' : 'ĐÃ TẮT'}
                          </button>
                          <button
                            type="button"
                            onClick={() => handleDeleteRule(rule.id)}
                            aria-label={`Xóa ${rule.domain}`}
                            className="min-h-[36px] min-w-[36px] flex items-center justify-center rounded-lg text-slate-400 hover:text-rose-500 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </section>
              </div>
            )}

            {/* TAB 4: PER-APP SYSTEM PACKAGE SELECTOR */}
            {activeTab === 'packages' && (
              <section className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6 space-y-5">
                <div>
                  <h1 className="text-xl font-bold text-slate-900 dark:text-white font-display">
                    Lọc theo Package hệ thống (Per-App VPN)
                  </h1>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    Sử dụng API VpnService.Builder của Android để chỉ định chính xác những package nào đi qua bộ lọc DNS.
                  </p>
                </div>

                {/* Flexible 2-Mode Switcher */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <button
                    type="button"
                    onClick={() => setFilterMode('allowlist')}
                    className={`p-4 rounded-xl border text-left transition-colors cursor-pointer ${
                      filterMode === 'allowlist'
                        ? 'border-emerald-500 bg-emerald-500/5 dark:bg-emerald-500/10'
                        : 'border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-bold text-slate-900 dark:text-white">
                        Chỉ lọc package được chọn
                      </span>
                      <span className="font-mono text-xs text-emerald-600 dark:text-emerald-400">
                        addAllowedApplication
                      </span>
                    </div>
                    <p className="mt-1 text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                      Khuyên dùng: Chỉ định tuyến các gói hệ thống MIUI/Xiaomi được tick qua VPN. Mọi ứng dụng khác kết nối trực tiếp.
                    </p>
                  </button>

                  <button
                    type="button"
                    onClick={() => setFilterMode('blocklist')}
                    className={`p-4 rounded-xl border text-left transition-colors cursor-pointer ${
                      filterMode === 'blocklist'
                        ? 'border-emerald-500 bg-emerald-500/5 dark:bg-emerald-500/10'
                        : 'border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-bold text-slate-900 dark:text-white">
                        Lọc toàn máy & Loại trừ
                      </span>
                      <span className="font-mono text-xs text-emerald-600 dark:text-emerald-400">
                        addDisallowedApplication
                      </span>
                    </div>
                    <p className="mt-1 text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                      Áp dụng DNS VPN cho toàn bộ thiết bị Android, ngoại trừ các package được tick trong danh sách bên dưới.
                    </p>
                  </button>
                </div>

                {/* Package Search & Quick Actions */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <button
                      type="button"
                      onClick={handleSelectAllMiuiPackages}
                      className="min-h-[36px] px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 transition-colors cursor-pointer"
                    >
                      Chọn tất cả gói MIUI/Xiaomi
                    </button>
                    <button
                      type="button"
                      onClick={() =>
                        setPackages((prev) =>
                          prev.map((p) => ({ ...p, selected: false }))
                        )
                      }
                      className="min-h-[36px] px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors cursor-pointer"
                    >
                      Bỏ chọn tất cả
                    </button>
                  </div>

                  <div className="relative flex-1 max-w-xs">
                    <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      value={pkgSearch}
                      onChange={(e) => setPkgSearch(e.target.value)}
                      placeholder="Tìm com.miui.* hoặc tên ứng dụng..."
                      className="w-full min-h-[38px] pl-9 pr-3 py-1.5 rounded-lg text-xs bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-emerald-500"
                    />
                  </div>
                </div>

                {/* Package Checkboxes List */}
                <div className="divide-y divide-slate-100 dark:divide-slate-800/80">
                  {filteredPackages.map((pkg) => (
                    <label
                      key={pkg.packageName}
                      className="py-3.5 flex items-center justify-between gap-4 cursor-pointer select-none"
                    >
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                            {pkg.appName}
                          </span>
                        </div>
                        <div className="mt-0.5 flex flex-wrap items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400 font-mono">
                          <span className="text-emerald-600 dark:text-emerald-400">
                            {pkg.packageName}
                          </span>
                          <span aria-hidden="true">·</span>
                          <span>UID {pkg.uid}</span>
                          <span aria-hidden="true">·</span>
                          <span className="font-sans">{pkg.category}</span>
                        </div>
                        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                          {pkg.description}
                        </p>
                      </div>

                      <input
                        type="checkbox"
                        checked={pkg.selected}
                        onChange={() => handleTogglePackage(pkg.packageName)}
                        className="w-5 h-5 rounded accent-emerald-600 cursor-pointer shrink-0"
                      />
                    </label>
                  ))}
                </div>
              </section>
            )}
          </div>

          {/* RIGHT SIDEBAR: LIVE REAL-TIME DNS STREAM & QUICK TESTER (5 columns on desktop) */}
          <aside className="lg:col-span-5 space-y-6">
            <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-5 space-y-4">
              <div className="flex items-center justify-between gap-2 pb-3 border-b border-slate-100 dark:border-slate-800">
                <div>
                  <h2 className="text-base font-bold text-slate-900 dark:text-white font-display">
                    Giám sát gói tin trực tiếp
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Tự xóa log quá {logRetentionDays} ngày {logRetentionDays === 7 ? '(mặc định)' : ''}
                  </p>
                </div>

                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => setStreamPaused((prev) => !prev)}
                    className="min-h-[36px] px-2.5 py-1.5 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
                  >
                    {streamPaused ? 'Tiếp tục' : 'Tạm dừng'}
                  </button>
                  {activeTab !== 'logs' && (
                    <button
                      type="button"
                      onClick={() => setActiveTab('logs')}
                      className="min-h-[36px] px-2.5 py-1.5 rounded-lg text-xs font-medium text-emerald-600 dark:text-emerald-400 hover:underline cursor-pointer"
                    >
                      Cài đặt log
                    </button>
                  )}
                </div>
              </div>

              {/* Compact Quick Test Trigger */}
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-medium text-slate-700 dark:text-slate-300">
                    Bắn gói tin DNS kiểm thử nhanh:
                  </span>
                  <span className="font-mono text-slate-500">
                    {testPackage.replace('com.', '')}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    value={testDomain}
                    onChange={(e) => setTestDomain(e.target.value)}
                    placeholder="Nhập domain..."
                    className="flex-1 min-h-[38px] px-3 py-1.5 rounded-lg text-xs font-mono bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:border-emerald-500"
                  />
                  <button
                    type="button"
                    onClick={() => {
                      if (testDomain.trim()) {
                        evaluateDnsQuery(testDomain, testPackage);
                      }
                    }}
                    className="min-h-[38px] px-3 py-1.5 rounded-lg text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    Kiểm tra
                  </button>
                </div>
              </div>

              {/* Live Feed Rows */}
              <div className="divide-y divide-slate-100 dark:divide-slate-800/80 max-h-[390px] overflow-y-auto pr-1">
                {logs.slice(0, 12).map((entry) => (
                  <div
                    key={entry.id}
                    onPointerDown={() => handleLogPointerDown(entry)}
                    onPointerUp={handleLogPointerEnd}
                    onPointerLeave={handleLogPointerEnd}
                    onPointerCancel={handleLogPointerEnd}
                    onContextMenu={(e) => handleLogContextMenu(e, entry)}
                    title="Nhấn giữ để thêm vào danh sách chặn"
                    className={`py-2.5 px-2 -mx-2 rounded-lg flex items-center justify-between gap-3 text-xs select-none cursor-pointer transition-colors ${
                      pressingLogId === entry.id
                        ? 'bg-emerald-500/10 dark:bg-emerald-500/15'
                        : 'hover:bg-slate-50 dark:hover:bg-slate-800/50'
                    }`}
                  >
                    <div className="min-w-0">
                      <p
                        className={`font-mono font-medium truncate ${
                          entry.status === 'BLOCKED'
                            ? 'text-rose-600 dark:text-rose-400'
                            : 'text-slate-900 dark:text-slate-100'
                        }`}
                      >
                        {entry.domain}
                      </p>
                      <div className="mt-0.5 flex items-center gap-1.5 text-[11px] text-slate-500 dark:text-slate-400 font-mono">
                        <span>{formatRelativeAge(entry.createdAt)}</span>
                        <span aria-hidden="true">·</span>
                        <span>{entry.timestamp}</span>
                        <span aria-hidden="true">·</span>
                        <span className="truncate">{entry.packageName}</span>
                      </div>
                    </div>

                    <div className="text-right font-mono tabular-nums shrink-0">
                      <span
                        className={`font-semibold ${
                          entry.status === 'BLOCKED'
                            ? 'text-rose-600 dark:text-rose-400'
                            : entry.status === 'BYPASSED'
                            ? 'text-amber-500'
                            : 'text-emerald-600 dark:text-emerald-400'
                        }`}
                      >
                        {entry.resolvedIp}
                      </span>
                      <p className="text-[11px] text-slate-400">
                        {entry.latencyMs} ms
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Export Hosts & Native Kotlin Code Card */}
            <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-5 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-slate-900 dark:text-white font-display">
                  Đóng gói APK & Mã nguồn Android
                </h3>
                <span className="text-xs font-mono text-slate-500">
                  /android
                </span>
              </div>
              <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                Môi trường trình duyệt không có bộ biên dịch Android SDK (JDK/aapt2). Bạn có thể tải trọn bộ Project Android đã nhúng cấu hình hiện tại để xuất file <code className="font-mono">.apk</code> bằng Android Studio hoặc GitHub Actions miễn phí.
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 pt-1">
                <button
                  type="button"
                  onClick={() =>
                    handleDownloadFile('build-miguard-android.sh', generatedSetupScript)
                  }
                  className="min-h-[40px] px-3 py-2 rounded-lg text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white flex items-center justify-center gap-1.5 whitespace-nowrap cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Tải Project Android (.sh)</span>
                </button>
                <button
                  type="button"
                  onClick={() => setShowCodeModal(true)}
                  className="min-h-[40px] px-3 py-2 rounded-lg text-xs font-medium bg-slate-900 dark:bg-white text-white dark:text-slate-950 hover:opacity-90 flex items-center justify-center gap-1.5 whitespace-nowrap cursor-pointer"
                >
                  <Code2 className="w-3.5 h-3.5" />
                  <span>Xem code & Build APK</span>
                </button>
              </div>
            </div>
          </aside>
        </div>
      </main>

      {/* MOBILE BOTTOM NAVIGATION BAR (Ergonomic Thumb Zone, <15% viewport height) */}
      <nav
        aria-label="Điều hướng di động"
        className="md:hidden fixed bottom-0 left-0 right-0 z-40 h-16 bg-white/95 dark:bg-slate-950/95 backdrop-blur-md border-t border-slate-200 dark:border-slate-800 grid grid-cols-4 items-center px-2"
      >
        <button
          type="button"
          onClick={() => setActiveTab('dashboard')}
          className={`min-h-[48px] flex flex-col items-center justify-center rounded-xl transition-colors cursor-pointer ${
            activeTab === 'dashboard'
              ? 'text-emerald-600 dark:text-emerald-400'
              : 'text-slate-500 dark:text-slate-400'
          }`}
        >
          <Shield className="w-5 h-5" />
          <span className="text-[11px] font-medium mt-1 whitespace-nowrap">
            Điều khiển
          </span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('logs')}
          className={`min-h-[48px] flex flex-col items-center justify-center rounded-xl transition-colors cursor-pointer ${
            activeTab === 'logs'
              ? 'text-emerald-600 dark:text-emerald-400'
              : 'text-slate-500 dark:text-slate-400'
          }`}
        >
          <Activity className="w-5 h-5" />
          <span className="text-[11px] font-medium mt-1 whitespace-nowrap">
            Nhật ký
          </span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('blocklist')}
          className={`min-h-[48px] flex flex-col items-center justify-center rounded-xl transition-colors cursor-pointer ${
            activeTab === 'blocklist'
              ? 'text-emerald-600 dark:text-emerald-400'
              : 'text-slate-500 dark:text-slate-400'
          }`}
        >
          <Filter className="w-5 h-5" />
          <span className="text-[11px] font-medium mt-1 whitespace-nowrap">
            Danh sách chặn
          </span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('packages')}
          className={`min-h-[48px] flex flex-col items-center justify-center rounded-xl transition-colors cursor-pointer ${
            activeTab === 'packages'
              ? 'text-emerald-600 dark:text-emerald-400'
              : 'text-slate-500 dark:text-slate-400'
          }`}
        >
          <Layers className="w-5 h-5" />
          <span className="text-[11px] font-medium mt-1 whitespace-nowrap">
            Gói hệ thống
          </span>
        </button>
      </nav>

      {/* MODAL: DYNAMIC ANDROID KOTLIN VPNSERVICE SOURCE CODE & HOSTS EXPORT */}
      {showCodeModal && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl max-w-4xl w-full max-h-[88vh] flex flex-col overflow-hidden shadow-2xl">
            <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-4">
              <div>
                <h2 className="text-base font-bold text-slate-900 dark:text-white font-display">
                  Mã nguồn Android VPN & Cấu hình Hosts (Tự động đồng bộ)
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Đã nhúng {stats.enabledRulesCount} domain chặn (0.0.0.0), DNS {primaryDns}, tự xóa log sau {logRetentionDays} ngày và {stats.selectedPackagesCount} package hệ thống.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowCodeModal(false)}
                aria-label="Đóng cửa sổ mã nguồn"
                className="min-h-[40px] min-w-[40px] rounded-lg flex items-center justify-center text-slate-500 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="px-6 py-3 bg-slate-50 dark:bg-slate-950 border-b border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-3">
              <div className="flex flex-wrap items-center gap-1 p-1 bg-slate-200/70 dark:bg-slate-900 rounded-lg">
                <button
                  type="button"
                  onClick={() => setActiveCodeTab('kotlin')}
                  className={`px-3 py-1.5 text-xs font-mono font-medium rounded-md transition-colors cursor-pointer ${
                    activeCodeTab === 'kotlin'
                      ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-emerald-400 shadow-xs'
                      : 'text-slate-600 dark:text-slate-400'
                  }`}
                >
                  MiGuardVpnService.kt
                </button>
                <button
                  type="button"
                  onClick={() => setActiveCodeTab('packet')}
                  className={`px-3 py-1.5 text-xs font-mono font-medium rounded-md transition-colors cursor-pointer ${
                    activeCodeTab === 'packet'
                      ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-emerald-400 shadow-xs'
                      : 'text-slate-600 dark:text-slate-400'
                  }`}
                >
                  DnsPacketHelper.kt
                </button>
                <button
                  type="button"
                  onClick={() => setActiveCodeTab('gradle')}
                  className={`px-3 py-1.5 text-xs font-mono font-medium rounded-md transition-colors cursor-pointer ${
                    activeCodeTab === 'gradle'
                      ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-emerald-400 shadow-xs'
                      : 'text-slate-600 dark:text-slate-400'
                  }`}
                >
                  app/build.gradle.kts
                </button>
                <button
                  type="button"
                  onClick={() => setActiveCodeTab('workflow')}
                  className={`px-3 py-1.5 text-xs font-mono font-medium rounded-md transition-colors cursor-pointer ${
                    activeCodeTab === 'workflow'
                      ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-emerald-400 shadow-xs'
                      : 'text-slate-600 dark:text-slate-400'
                  }`}
                >
                  build-apk.yml (Auto APK)
                </button>
                <button
                  type="button"
                  onClick={() => setActiveCodeTab('manifest')}
                  className={`px-3 py-1.5 text-xs font-mono font-medium rounded-md transition-colors cursor-pointer ${
                    activeCodeTab === 'manifest'
                      ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-emerald-400 shadow-xs'
                      : 'text-slate-600 dark:text-slate-400'
                  }`}
                >
                  AndroidManifest.xml
                </button>
                <button
                  type="button"
                  onClick={() => setActiveCodeTab('hosts')}
                  className={`px-3 py-1.5 text-xs font-mono font-medium rounded-md transition-colors cursor-pointer ${
                    activeCodeTab === 'hosts'
                      ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-emerald-400 shadow-xs'
                      : 'text-slate-600 dark:text-slate-400'
                  }`}
                >
                  hosts.txt (0.0.0.0)
                </button>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() =>
                    handleDownloadFile('build-miguard-android.sh', generatedSetupScript)
                  }
                  className="min-h-[36px] px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 flex items-center gap-1.5 cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Tải toàn bộ Project</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    const content =
                      activeCodeTab === 'kotlin'
                        ? generatedKotlinCode
                        : activeCodeTab === 'packet'
                        ? generatedPacketHelperCode
                        : activeCodeTab === 'gradle'
                        ? generatedGradleCode
                        : activeCodeTab === 'workflow'
                        ? generatedWorkflowYaml
                        : activeCodeTab === 'hosts'
                        ? generatedHostsContent
                        : generatedManifestXml;
                    handleCopyText(content, activeCodeTab);
                  }}
                  className="min-h-[36px] px-3 py-1.5 rounded-lg text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white flex items-center gap-1.5 cursor-pointer"
                >
                  {copiedFeedback === activeCodeTab ? (
                    <>
                      <Check className="w-3.5 h-3.5" />
                      <span>Đã sao chép</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Sao chép mã</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto p-6 bg-slate-950 text-slate-100 font-mono text-xs leading-relaxed">
              <pre className="whitespace-pre-wrap break-words">
                {activeCodeTab === 'kotlin'
                  ? generatedKotlinCode
                  : activeCodeTab === 'packet'
                  ? generatedPacketHelperCode
                  : activeCodeTab === 'gradle'
                  ? generatedGradleCode
                  : activeCodeTab === 'workflow'
                  ? generatedWorkflowYaml
                  : activeCodeTab === 'hosts'
                  ? generatedHostsContent
                  : generatedManifestXml}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: LONG PRESS LOG ENTRY TO ADD TO BLOCKLIST */}
      {longPressedLog && (() => {
        const cleanHost = normalizeDomainInput(longPressedLog.domain);
        const isAlreadyBlocked = rules.some(
          (r) =>
            r.enabled &&
            (cleanHost === r.domain.toLowerCase() ||
              cleanHost.endsWith(`.${r.domain.toLowerCase()}`))
        );
        return (
          <div
            className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4"
            onClick={() => setLongPressedLog(null)}
          >
            <div
              className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h2 className="text-base font-bold text-slate-900 dark:text-white font-display">
                    {isAlreadyBlocked
                      ? 'Tên miền đã trong danh sách chặn'
                      : 'Chặn tên miền từ nhật ký?'}
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    {longPressedLog.appName} ({longPressedLog.packageName})
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setLongPressedLog(null)}
                  aria-label="Đóng"
                  className="min-h-[36px] min-w-[36px] rounded-lg flex items-center justify-center text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1.5">
                <p className="font-mono text-sm font-semibold text-emerald-600 dark:text-emerald-400 break-all">
                  0.0.0.0 {longPressedLog.domain}
                </p>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  {isAlreadyBlocked
                    ? 'Host này hiện đang bị chặn về 0.0.0.0. Bạn có thể tắt chặn nếu muốn cho phép kết nối lại.'
                    : 'Thêm host này vào danh sách chặn (Sinkhole 0.0.0.0) để ngăn mọi kết nối tiếp theo.'}
                </p>
              </div>

              <div className="flex items-center justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => setLongPressedLog(null)}
                  className="min-h-[40px] px-4 py-2 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
                >
                  Hủy
                </button>
                {isAlreadyBlocked ? (
                  <button
                    type="button"
                    onClick={() => handleUnblockHostFromLog(longPressedLog)}
                    className="min-h-[40px] px-4 py-2 rounded-lg text-xs font-medium bg-amber-500 hover:bg-amber-400 text-slate-950 flex items-center gap-1.5 cursor-pointer"
                  >
                    <span>Bỏ chặn host này</span>
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={() => handleBlockHostFromLog(longPressedLog)}
                    className="min-h-[40px] px-4 py-2 rounded-lg text-xs font-medium bg-rose-600 hover:bg-rose-500 text-white flex items-center gap-1.5 cursor-pointer"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    <span>Thêm vào danh sách chặn</span>
                  </button>
                )}
              </div>
            </div>
          </div>
        );
      })()}
    </div>
  );
}
