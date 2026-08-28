"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import {
  IconShieldSolid,
  IconDashboard,
  IconScanner,
  IconQueue,
  IconChart,
  IconFileCode,
} from "@/components/icons";

const navItems = [
  { href: "/", icon: IconDashboard, label: "Overview", id: "nav-overview" },
  { href: "/scan", icon: IconScanner, label: "Scan File", id: "nav-scan" },
  { href: "/jobs", icon: IconQueue, label: "Async Jobs", id: "nav-jobs" },
];

const analyticsItems = [
  { href: "/analytics", icon: IconChart, label: "Analytics", id: "nav-analytics" },
  { href: "/rules", icon: IconFileCode, label: "YARA Rules", id: "nav-rules" },
];

export default function Sidebar() {
  const pathname = usePathname();
  const [apiStatus, setApiStatus] = useState<"loading" | "connected" | "disconnected">("loading");
  const [rulesCount, setRulesCount] = useState<number | null>(null);

  useEffect(() => {
    api.health()
      .then((h) => {
        setApiStatus("connected");
        setRulesCount(h.rules_loaded);
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
        <div className="sidebar-logo-icon">
          <IconShieldSolid size={22} />
        </div>
        <div>
          <div className="sidebar-logo-text">YaraTrix</div>
          <div className="sidebar-logo-version">Threat Intelligence Platform</div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="sidebar-nav">
        <span className="nav-section-label">Platform</span>
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              id={item.id}
              className={`nav-item ${isActive(item.href) ? "active" : ""}`}
            >
              <span className="nav-icon">
                <Icon size={18} color={isActive(item.href) ? "var(--accent)" : "currentColor"} />
              </span>
              {item.label}
            </Link>
          );
        })}

        <span className="nav-section-label">Intelligence</span>
        {analyticsItems.map((item) => {
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              id={item.id}
              className={`nav-item ${isActive(item.href) ? "active" : ""}`}
            >
              <span className="nav-icon">
                <Icon size={18} color={isActive(item.href) ? "var(--accent)" : "currentColor"} />
              </span>
              {item.label}
            </Link>
          );
        })}
      </nav>

      {/* Footer: API Status */}
      <div className="sidebar-footer">
        <div className="api-status">
          <div className="status-dot-wrapper">
            <div className={`status-dot ${apiStatus}`} />
          </div>
          <div>
            <div style={{ fontWeight: 600, fontSize: "12px" }}>
              {apiStatus === "connected"
                ? "API Connected"
                : apiStatus === "disconnected"
                ? "API Offline"
                : "Connecting…"}
            </div>
            {rulesCount !== null && (
              <div style={{ fontSize: "10px", marginTop: "2px", color: "var(--text-muted)" }}>
                {rulesCount} rules loaded
              </div>
            )}
          </div>
        </div>
      </div>
    </aside>
  );
}
