import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SentinelReview | PR Security Analysis",
  description: "Security analysis for GitHub pull requests using Bandit, Semgrep, and optional contextual AI reasoning.",
  openGraph: {
    title: "SentinelReview | PR Security Analysis",
    description: "Security analysis for GitHub pull requests using Bandit, Semgrep, and optional contextual AI reasoning.",
    siteName: "SentinelReview",
    type: "website",
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full">{children}</body>
    </html>
  );
}
