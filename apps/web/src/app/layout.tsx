import './globals.css';
import { headers } from 'next/headers.js';
import type { ReactNode } from 'react';

export const metadata = {
  title: 'HegoSentinel — Yetkili Güvenlik Tarama, Kanıt Normalizasyonu ve Yeniden Test Platformu',
  description:
    'HegoSentinel: Gerçek Semgrep CE (1.183.0), Trivy (0.76.1), Laravel 11 API, PostgreSQL 16 RLS, Trusted Egress Broker ve SHA-256 denetim zinciri ile açık kaynak siber güvenlik platformu.',
  openGraph: {
    title: 'HegoSentinel Security Platform (Sprint 10 Production Architecture)',
    description:
      'Authorized web & source code security assessment with real Semgrep CE, Trivy, Trusted Egress Broker, and SHA-256 audit logs.',
    type: 'website',
    url: 'http://127.0.0.1:3000/'
  }
};

export default async function RootLayout({ children }: { children: ReactNode }) {
  const hdrs = await headers();
  const nonce = hdrs.get('x-nonce') ?? undefined;

  const jsonLd = {
    '@context': 'https://schema.org',
    '@type': 'SoftwareApplication',
    name: 'HegoSentinel Security Platform',
    applicationCategory: 'SecurityApplication',
    operatingSystem: 'Linux, Windows, macOS',
    softwareVersion: '0.2.0-sprint10',
    description:
      'Developer-first, self-hosted security assessment, evidence normalization, remediation, and re-test verification platform.'
  };

  return (
    <html lang="tr">
      <head>
        <meta name="color-scheme" content="dark" />
        <link rel="canonical" href="http://127.0.0.1:3000/" />
        <script
          nonce={nonce}
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
