"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";

const navItems = [
  { href: "/", icon: "⬡", label: "Overview", id: "nav-overview" },
  { href: "/scan", icon: "⬡", label: "Scan File", id: "nav-scan" },
  { href: "/jobs", icon: "⬡", label: "Async Jobs", id: "nav-jobs" },
];

const analyticsItems = [
  { href: "/analytics", icon: "⬡", label: "Analytics", id: "nav-analytics" },
  { href: "/rules", icon: "⬡", label: "YARA Rules", id: "nav-rules" },
];

// Cyber hex icons
const icons: Record<string, string> = {
  "/": "◈",
  "/scan": "⬡",
  "/jobs": "⟳",
  "/analytics": "▦",
  "/rules": "≡",
};

export default function Sidebar() {
  const pathname = usePathname();
  const [apiStatus, setApiStatus] = useState<"loading" | "connected" | "disconnected">("loading");
  const [rulesCount, setRulesCount] = useState<number | null>(null);
  const [version, setVersion] = useState<string>("v2.0");

  useEffect(() => {
    api.health()
      .then((h) => {
        setApiStatus("connected");
        setRulesCount(h.rules_loaded);
        setVersion(h.version || "v2.0");
      })
      .catch(() => setApiStatus("disconnected"));
  }, []);

  const isActive = (href: string) => {
    if (href === "/") return pathname === "/";
    return pathname.startsWith(href);
  };

  return (
    <aside className="sidebar">
      {/* Logo */}
      <div className="sidebar-logo">
        <div className="sidebar-logo-icon">🛡</div>
        <div>
          <div className="sidebar-logo-text">YaraTrix</div>
          <div className="sidebar-logo-version">v2 Enterprise</div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="sidebar-nav">
        <span className="nav-section-label">Platform</span>
        {navItems.map((item) => (
          <Link
            key={item.href}
            href={item.href}
            id={item.id}
            className={`nav-item ${isActive(item.href) ? "active" : ""}`}
          >
            <span className="nav-icon">{icons[item.href]}</span>
            {item.label}
          </Link>
        ))}

        <span className="nav-section-label">Intelligence</span>
        {analyticsItems.map((item) => (
          <Link
            key={item.href}
            href={item.href}
            id={item.id}
            className={`nav-item ${isActive(item.href) ? "active" : ""}`}
          >
            <span className="nav-icon">{icons[item.href]}</span>
            {item.label}
          </Link>
        ))}
      </nav>

      {/* Footer: API Status */}
      <div className="sidebar-footer">
        <div className="api-status">
          <div className={`status-dot ${apiStatus}`} />
          <div>
            <div style={{ fontWeight: 600, fontSize: "12px" }}>
              {apiStatus === "connected"
                ? "API Connected"
                : apiStatus === "disconnected"
                ? "API Offline"
                : "Connecting…"}
            </div>
            {rulesCount !== null && (
              <div style={{ fontSize: "11px", marginTop: "2px", color: "var(--text-muted)" }}>
                {rulesCount} rules loaded
              </div>
            )}
          </div>
        </div>
      </div>
    </aside>
  );
}
