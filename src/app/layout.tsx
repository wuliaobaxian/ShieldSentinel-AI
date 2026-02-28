import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "ShieldSentinel AI — Enterprise AI Security Gateway",
  description:
    "Enterprise-grade AI security middleware — Prompt injection defense, PII masking, and real-time threat monitoring.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} antialiased sentinel-grid min-h-screen`}>
        {children}
      </body>
    </html>
  );
}
