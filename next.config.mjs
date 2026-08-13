/** @type {import('next').NextConfig} */

/**
 * Security headers, per the OWASP HTTP Headers guidance in
 * `asb-secure-development` (references/web-security.md).
 *
 * The CSP is deliberately strict: this portal renders third-party news content,
 * which rule 7 of CLAUDE.md identifies as an XSS vector. Escaping on render is
 * the primary control; CSP is the second layer, so that a mistake in the first
 * one does not become script execution. No external origins are allowed at all
 * — the portal loads no remote fonts, scripts, styles, or images. Feed content
 * contributes text only; we never render remote images from an article.
 */
const csp = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'", // Next injects inline styles; no external sheets
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "object-src 'none'",
  "upgrade-insecure-requests",
].join("; ");

const nextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "Content-Security-Policy", value: csp },
          {
            key: "Strict-Transport-Security",
            value: "max-age=63072000; includeSubDomains; preload",
          },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          {
            key: "Permissions-Policy",
            value: "camera=(), microphone=(), geolocation=(), payment=()",
          },
          { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
          { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
        ],
      },
    ];
  },
};

export default nextConfig;
