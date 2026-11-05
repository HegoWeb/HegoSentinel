import './globals.css';
import type { ReactNode } from 'react';

export const metadata = {
  title: 'HegoSentinel — Authorized Security Assessment & Remediation Platform',
  description:
    'Self-hosted, fail-closed cybersecurity assessment, evidence normalization, developer remediation, and re-test verification platform.',
  openGraph: {
    title: 'HegoSentinel Security Platform',
    description:
      'Authorized web & source code security assessment with real Semgrep CE, Trivy, Trusted Egress Broker, and SHA-256 audit logs.',
    type: 'website'
  }
};

export default function RootLayout({ children }: { children: ReactNode }) {
  const jsonLd = {
    '@context': 'https://schema.org',
    '@type': 'SoftwareApplication',
    name: 'HegoSentinel Security Platform',
    applicationCategory: 'SecurityApplication',
    operatingSystem: 'Linux, Windows, macOS',
    softwareVersion: '0.1.0-alpha.4',
    description:
      'Developer-first, self-hosted security assessment, evidence normalization, remediation, and re-test verification platform.'
  };

  return (
    <html lang="tr">
      <head>
        <meta name="color-scheme" content="dark" />
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
      </head>
      <body>{children}</body>
    </html>
  );
}

