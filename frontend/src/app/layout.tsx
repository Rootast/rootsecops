import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "RootSecOps | Security Orchestration",
  description: "Multi-scanner security analysis for images, repositories, Dockerfiles, and files.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="h-full font-mono antialiased">
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
