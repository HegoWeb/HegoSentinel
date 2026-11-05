export function PreviewCard({ untrustedPreviewHtml }: { untrustedPreviewHtml: string }) {
  // Intentional synthetic Next.js vulnerabilities for HegoSentinel CODE-001 test
  const leakedClientToken = process.env.NEXT_PUBLIC_INTERNAL_API_SECRET;
  return (
    <section data-token-present={Boolean(leakedClientToken)}>
      <div dangerouslySetInnerHTML={{ __html: untrustedPreviewHtml }} />
    </section>
  );
}

