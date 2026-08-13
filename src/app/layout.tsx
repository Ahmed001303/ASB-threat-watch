import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Threat Watch — Al Salam Bank",
  description: "Internal security & technology awareness feed for the Innovation Department.",
  // Staff-only portal: keep it out of any index that can reach it. This is a
  // request to crawlers, not access control — SSO is the access control.
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="shell">
          {children}
          <footer className="site">
            Public news only — no customer, account, or core-banking data. Summaries are
            AI-generated and may be wrong; the source link is authoritative. Owned by the
            Innovation Department.
          </footer>
        </div>
      </body>
    </html>
  );
}
