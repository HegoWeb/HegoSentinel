export type SupportedLocale = 'tr' | 'en';

export interface PlatformDictionary {
  brandSubtitle: string;
  nav: {
    dashboard: string;
    projects: string;
    scanner: string;
    vulnerabilities: string;
    remediation: string;
    rechecks: string;
    reports: string;
    settings: string;
    auth: string;
  };
  status: {
    remoteBlocked: string;
    auditChainValid: string;
    realTarget: string;
    demoSandbox: string;
    realScan: string;
    demoSeed: string;
  };
  dashboard: {
    title: string;
    subtitle: string;
    totalProjects: string;
    totalScans: string;
    totalFindings: string;
    remediationTasks: string;
    riskDistribution: string;
    securityPosture: string;
    recentScans: string;
    recentRechecks: string;
    recentAudit: string;
  };
  projects: {
    title: string;
    subtitle: string;
    createProject: string;
    approveGrant: string;
    projectName: string;
    environment: string;
    stack: string;
    hostname: string;
    repoPath: string;
    writtenPermissionRef: string;
    domainControlProof: string;
    submitProject: string;
    submitGrant: string;
  };
  scanner: {
    title: string;
    subtitle: string;
    launchScan: string;
    emergencyStop: string;
    coverageMatrix: string;
    selectProject: string;
    selectMode: string;
    selectVariant: string;
  };
  vulnerabilities: {
    title: string;
    subtitle: string;
    filterPriority: string;
    filterRule: string;
    filterSource: string;
    suppressButton: string;
    suppressRationalePlaceholder: string;
  };
  remediation: {
    title: string;
    subtitle: string;
    markInProgress: string;
    markReadyRetest: string;
    markVerifiedClosed: string;
  };
  rechecks: {
    title: string;
    subtitle: string;
    baselineScan: string;
    currentScan: string;
    runComparison: string;
  };
  reports: {
    title: string;
    subtitle: string;
    exportFormat: string;
    downloadReport: string;
    sendNotification: string;
    recipientLabel: string;
    channelLabel: string;
    summaryLabel: string;
  };
  settings: {
    title: string;
    subtitle: string;
    teamRbac: string;
    inviteMember: string;
    auditLedger: string;
  };
  auth: {
    title: string;
    subtitle: string;
    quickRoleSwitch: string;
    loginTab: string;
    registerTab: string;
    resetTab: string;
    email: string;
    password: string;
    fullName: string;
    organizationName: string;
    signIn: string;
    signUp: string;
    sendReset: string;
    signOut: string;
  };
}

export const PLATFORM_I18N: Record<SupportedLocale, PlatformDictionary> = {
  tr: {
    brandSubtitle: 'YETKİLİ GÜVENLİK TARAMA, KANIT NORMALİZASYONU VE YENİDEN TEST PLATFORMU',
    nav: {
      dashboard: 'Genel Bakış',
      projects: 'Projeler & Kapsam',
      scanner: 'Güvenlik Tarayıcı',
      vulnerabilities: 'Zafiyet Bulguları',
      remediation: 'Çözüm Merkezi',
      rechecks: 'Yeniden Test & Fark',
      reports: 'Raporlar & Bildirim',
      settings: 'Ayarlar & Denetim',
      auth: 'Oturum & Rol'
    },
    status: {
      remoteBlocked: 'RESTRICTED-REMOTE: KAPALI (FAIL-CLOSED)',
      auditChainValid: 'SHA-256 DENETİM ZİNCİRİ: DOĞRULANDI',
      realTarget: 'GERÇEK HEDEF',
      demoSandbox: 'SENTETİK DEMO',
      realScan: 'GERÇEK TARAMA VERİSİ',
      demoSeed: 'SENTETİK DEMO VERİSİ'
    },
    dashboard: {
      title: 'Siber Güvenlik Komuta Merkezi',
      subtitle: 'Gerçek Semgrep CE (1.183.0), Trivy (0.76.1) ve pasif web güvenlik kontrolleri ile çok kiracılı güvenlik telemetrisi.',
      totalProjects: 'Yetkili Projeler',
      totalScans: 'Toplam Tarama',
      totalFindings: 'Normalize Bulgular',
      remediationTasks: 'Düzeltme Görevleri',
      riskDistribution: 'Öncelik Dağılımı (Internal Priority & CVSS v4)',
      securityPosture: 'Çalışma Zamanı Güvenlik Sınırları',
      recentScans: 'Son Tarama Çalışmaları',
      recentRechecks: 'Son Yeniden Test Karşılaştırmaları',
      recentAudit: 'Kriptografik Denetim Kayıtları (SHA-256)'
    },
    projects: {
      title: 'Projeler, Hedef Varlıklar ve Kapsam Yetkisi',
      subtitle: 'SEC-001 ve SEC-002 kapsamında alan adı sahipliği kanıtı ve yazılı tarama izni (ScopeAuthorizationGrant) yönetimi.',
      createProject: 'Yeni Yetkili Proje Oluştur',
      approveGrant: 'Yeni Kapsam Yetkisi (Grant) Onayla',
      projectName: 'Proje Adı',
      environment: 'Ortam',
      stack: 'Teknoloji Yığını',
      hostname: 'Hedef Alan Adı (Hostname)',
      repoPath: 'Yerel Kaynak Depo Yolu',
      writtenPermissionRef: 'Yazılı İzin Referans No (SEC-001)',
      domainControlProof: 'Alan Adı Sahiplik Kanıtı (DNS TXT)',
      submitProject: 'Projeyi ve Kapsam Yetkisini Kaydet',
      submitGrant: 'Kapsam Versiyonunu Onayla'
    },
    scanner: {
      title: 'Yetkili Güvenlik Tarayıcı & Kapsam Matrisi',
      subtitle: 'Yalnızca aktif ScopeAuthorizationGrant bulunan hedeflerde izole alt süreç ile tarama başlatın veya Acil Durdurma (SEC-012) uygulayın.',
      launchScan: 'Yetkili Taramayı Başlat',
      emergencyStop: 'ACİL DURDURMA (SEC-012 KILL-SWITCH)',
      coverageMatrix: 'Kural Kapsam Matrisi (Gerçek Kapsam Doğrulaması)',
      selectProject: 'Hedef Proje Seçin',
      selectMode: 'Çalışma Modu',
      selectVariant: 'Hedef / Fikstür Durumu'
    },
    vulnerabilities: {
      title: 'Zafiyet Bulguları ve Kanıt İnceleme',
      subtitle: 'Dokuz aşamalı gizli veri maskelemesi uygulanmış kanıt özetleri, OWASP ASVS/WSTG eşlemeleri ve kapsam bazlı yanlış pozitif (SEC-010) yönetimi.',
      filterPriority: 'Öncelik Filtresi',
      filterRule: 'Kural Filtresi',
      filterSource: 'Veri Kaynağı',
      suppressButton: 'Yanlış Pozitif (False Positive) Olarak Bastır',
      suppressRationalePlaceholder: 'En az 12 karakterlik teknik gerekçe girin (SEC-010)...'
    },
    remediation: {
      title: 'Geliştirici Çözüm ve Yama Merkezi',
      subtitle: 'Laravel, Next.js ve Node.js için çerçeveye özel kod yamaları, sorumlu geliştirici ataması ve yeniden test hazırlığı.',
      markInProgress: 'Üzerinde Çalışılıyor',
      markReadyRetest: 'Yeniden Teste Hazır',
      markVerifiedClosed: 'Doğrulandı & Kapatıldı'
    },
    rechecks: {
      title: 'Yeniden Test (Re-Test) ve Karşılaştırma Motoru',
      subtitle: 'Temel (Baseline) tarama ile düzeltme sonrası taramayı parmak izi ve kapsam versiyonuna göre yan yana karşılaştırın.',
      baselineScan: 'Temel (Baseline) Tarama',
      currentScan: 'Güncel (Düzeltme Sonrası) Tarama',
      runComparison: 'Karşılaştırmayı Çalıştır'
    },
    reports: {
      title: 'Güvenli Rapor Dışa Aktarımı ve Onaylı Bildirimler',
      subtitle: 'JSON, Markdown, HTML, SARIF 2.1.0, PDF-HTML dışa aktarımı ve doğrulanmış alan adlarına güvenli bildirim (SEC-013).',
      exportFormat: 'Rapor Formatı',
      downloadReport: 'Raporu Oluştur & Önizle',
      sendNotification: 'Onaylı Bildirim Gönder (SEC-013)',
      recipientLabel: 'Alıcı E-Posta veya Doğrulanmış Webhook',
      channelLabel: 'Kanal',
      summaryLabel: 'Maskelenmiş Bildirim Özeti'
    },
    settings: {
      title: 'Organizasyon, RBAC Rolleri ve Denetim Zinciri',
      subtitle: 'Çok kiracılı izolasyon (SEC-011), ekip üyeleri, doğrulanmış bildirim alan adları ve değiştirilemez SHA-256 denetim kayıtları.',
      teamRbac: 'Ekip Üyeleri ve RBAC Yetki Matrisi',
      inviteMember: 'Ekip Üyesi Ekle / Rol Güncelle',
      auditLedger: 'Değiştirilemez SHA-256 Denetim Kayıtları (Audit Logs)'
    },
    auth: {
      title: 'Kimlik Doğrulama, Oturum ve Hızlı RBAC Testi',
      subtitle: 'Gerçek Bearer oturum anahtarı ile giriş yapın veya SEC-011 RBAC sınırlarını test etmek için hazır roller arasında geçiş yapın.',
      quickRoleSwitch: 'Tek Tıkla Canlı RBAC & Kiracı (Tenant) Oturumu Değiştir',
      loginTab: 'Giriş Yap',
      registerTab: 'Yeni Kayıt',
      resetTab: 'Şifre Sıfırlama',
      email: 'E-Posta Adresi',
      password: 'Şifre',
      fullName: 'Ad Soyad',
      organizationName: 'Organizasyon Adı',
      signIn: 'Güvenli Oturum Aç',
      signUp: 'Organizasyon & Hesap Oluştur',
      sendReset: 'Sıfırlama Anahtarı Gönder',
      signOut: 'Oturumu Kapat'
    }
  },
  en: {
    brandSubtitle: 'AUTHORIZED SECURITY ASSESSMENT, EVIDENCE NORMALIZATION & RE-TEST PLATFORM',
    nav: {
      dashboard: 'Dashboard',
      projects: 'Projects & Scope',
      scanner: 'Security Scanner',
      vulnerabilities: 'Vulnerabilities',
      remediation: 'Remediation Center',
      rechecks: 'Re-Test Comparison',
      reports: 'Reports & Notify',
      settings: 'Settings & Audit',
      auth: 'Session & RBAC'
    },
    status: {
      remoteBlocked: 'RESTRICTED-REMOTE: BLOCKED (FAIL-CLOSED)',
      auditChainValid: 'SHA-256 AUDIT CHAIN: VERIFIED',
      realTarget: 'REAL TARGET',
      demoSandbox: 'DEMO SANDBOX',
      realScan: 'REAL SCAN DATA',
      demoSeed: 'SYNTHETIC DEMO DATA'
    },
    dashboard: {
      title: 'Cybersecurity Command Center',
      subtitle: 'Multi-tenant security telemetry powered by real Semgrep CE (1.183.0), Trivy (0.76.1), and passive web security checks.',
      totalProjects: 'Authorized Projects',
      totalScans: 'Total Scans',
      totalFindings: 'Normalized Findings',
      remediationTasks: 'Remediation Tasks',
      riskDistribution: 'Priority Distribution (Internal Priority & CVSS v4)',
      securityPosture: 'Runtime Security Boundaries',
      recentScans: 'Recent Scan Executions',
      recentRechecks: 'Recent Re-Test Comparisons',
      recentAudit: 'Cryptographic Audit Ledger (SHA-256)'
    },
    projects: {
      title: 'Projects, Target Assets & Scope Authorization',
      subtitle: 'Manage domain ownership proofs and written scan permissions (ScopeAuthorizationGrant) under SEC-001 & SEC-002.',
      createProject: 'Create Authorized Project',
      approveGrant: 'Approve New Scope Grant',
      projectName: 'Project Name',
      environment: 'Environment',
      stack: 'Technology Stack',
      hostname: 'Target Hostname',
      repoPath: 'Local Repository Path',
      writtenPermissionRef: 'Written Permission Reference (SEC-001)',
      domainControlProof: 'Domain Control Proof (DNS TXT)',
      submitProject: 'Save Project & Scope Grant',
      submitGrant: 'Approve Scope Version'
    },
    scanner: {
      title: 'Authorized Security Scanner & Coverage Matrix',
      subtitle: 'Launch isolated subprocess scans strictly on targets with an active ScopeAuthorizationGrant or trigger Emergency Stop (SEC-012).',
      launchScan: 'Launch Authorized Scan',
      emergencyStop: 'EMERGENCY STOP (SEC-012 KILL-SWITCH)',
      coverageMatrix: 'Check Coverage Matrix (Truthful Coverage Accounting)',
      selectProject: 'Select Target Project',
      selectMode: 'Execution Mode',
      selectVariant: 'Target / Fixture Variant'
    },
    vulnerabilities: {
      title: 'Vulnerability Findings & Evidence Inspector',
      subtitle: 'Inspect 9-pass redacted evidence summaries, OWASP ASVS/WSTG mappings, and scoped false-positive suppressions (SEC-010).',
      filterPriority: 'Filter Priority',
      filterRule: 'Filter Rule',
      filterSource: 'Data Source',
      suppressButton: 'Suppress as Scoped False Positive',
      suppressRationalePlaceholder: 'Enter technical rationale (>= 12 chars, SEC-010)...'
    },
    remediation: {
      title: 'Developer Remediation & Patch Center',
      subtitle: 'Framework-specific code patches for Laravel, Next.js, and Node.js, developer assignment, and re-test readiness.',
      markInProgress: 'Mark In Progress',
      markReadyRetest: 'Mark Ready for Re-Test',
      markVerifiedClosed: 'Verified & Closed'
    },
    rechecks: {
      title: 'Re-Test Verification & Comparison Engine',
      subtitle: 'Compare baseline vs. post-remediation scans side-by-side by deterministic fingerprint and scope version.',
      baselineScan: 'Baseline Scan Run',
      currentScan: 'Current (Post-Fix) Scan Run',
      runComparison: 'Run Re-Test Comparison'
    },
    reports: {
      title: 'Safe Report Export & Approved Notifications',
      subtitle: 'Export sanitized JSON, Markdown, HTML, SARIF 2.1.0, PDF-HTML reports and dispatch verified notifications (SEC-013).',
      exportFormat: 'Report Format',
      downloadReport: 'Generate & Preview Report',
      sendNotification: 'Dispatch Approved Notification (SEC-013)',
      recipientLabel: 'Recipient Email or Verified Webhook',
      channelLabel: 'Channel',
      summaryLabel: 'Sanitized Notification Summary'
    },
    settings: {
      title: 'Organization, RBAC Roles & Audit Chain',
      subtitle: 'Multi-tenant isolation (SEC-011), team members, verified notification domains, and tamper-evident SHA-256 audit logs.',
      teamRbac: 'Team Members & RBAC Permission Matrix',
      inviteMember: 'Invite Member / Update Role',
      auditLedger: 'Tamper-Evident SHA-256 Audit Logs'
    },
    auth: {
      title: 'Authentication, Session & Live RBAC Switcher',
      subtitle: 'Sign in with a real Bearer session token or switch between pre-seeded roles to test SEC-011 RBAC boundaries live.',
      quickRoleSwitch: 'One-Click Live RBAC & Tenant Session Switcher',
      loginTab: 'Sign In',
      registerTab: 'Register',
      resetTab: 'Password Reset',
      email: 'Email Address',
      password: 'Password',
      fullName: 'Full Name',
      organizationName: 'Organization Name',
      signIn: 'Sign In Securely',
      signUp: 'Create Organization & Account',
      sendReset: 'Send Reset Token',
      signOut: 'Sign Out'
    }
  }
};

