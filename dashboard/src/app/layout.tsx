import type { Metadata } from "next";
import "./globals.css";
import Sidebar from "@/components/Sidebar";

export const metadata: Metadata = {
  title: "YaraTrix v2 — Detection Intelligence Platform",
  description:
    "Evidence-driven YARA-to-MITRE ATT&CK Detection Intelligence Platform. Scan files, map threats, analyze behavioral patterns, and monitor detection quality.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="app-shell">
          <Sidebar />
          <div className="main-content">{children}</div>
        </div>
      </body>
    </html>
  );
}
