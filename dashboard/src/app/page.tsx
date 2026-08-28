"use client";

import { useEffect, useState } from "react";
import { api, AnalyticsSummary } from "@/lib/api";
import { IconSearch, IconAlertTriangle, IconTarget, IconCheckCircle, IconZap, IconActivity } from "@/components/icons";
import { RadialGauge } from "@/components/icons";

export default function OverviewPage() {
  const [summary, setSummary] = useState<AnalyticsSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.getAnalyticsSummary()
      .then(setSummary)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  return (
    <>
      <div className="topbar">
        <div>
          <div className="topbar-title">Command Center</div>
          <div className="topbar-subtitle">Real-time platform intelligence</div>
        </div>
      </div>
      <div className="page-content">
        <div className="page-header">
          <h1>Detection Intelligence Dashboard</h1>
          <p>Real-time threat visibility across all scanned artifacts</p>
        </div>

        {/* Stats Grid */}
        {loading ? (
          <div className="stats-grid">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="stat-card">
                <div className="skeleton" style={{ height: 90 }} />
              </div>
            ))}
          </div>
        ) : error ? (
          <div className="card" style={{ textAlign: "center", padding: "48px" }}>
            <IconAlertTriangle size={40} color="var(--threat-critical)" style={{ margin: "0 auto 12px", display: "block" }} />
            <p style={{ color: "var(--threat-critical)", fontWeight: 600 }}>
              Cannot reach API: {error}
            </p>
            <p style={{ color: "var(--text-muted)", marginTop: 8, fontSize: 13 }}>
              Make sure <code style={{ color: "var(--accent)" }}>uvicorn</code> is running on port 8000.
            </p>
          </div>
        ) : summary ? (
          <>
            <div className="stats-grid stagger-children">
              <div className="stat-card" style={{ "--stat-accent": "var(--gradient-brand)" } as React.CSSProperties}>
                <div className="stat-icon" style={{ background: "var(--accent-dim)" }}>
                  <IconSearch size={18} color="var(--accent)" />
                </div>
                <div className="stat-value">{summary.scan_jobs.total}</div>
                <div className="stat-label">Total Scan Jobs</div>
                <div className="stat-delta up">
                  <IconCheckCircle size={12} /> {summary.scan_jobs.completed} completed
                </div>
              </div>

              <div className="stat-card" style={{ "--stat-accent": "linear-gradient(90deg, var(--threat-critical), var(--threat-high))" } as React.CSSProperties}>
                <div className="stat-icon" style={{ background: "var(--threat-critical-dim)" }}>
                  <IconAlertTriangle size={18} color="var(--threat-critical)" />
                </div>
                <div className="stat-value" style={{ color: "var(--threat-critical)" }}>
                  {summary.artifacts.threats_detected}
                </div>
                <div className="stat-label">Threats Detected</div>
                <div className="stat-delta">
                  of {summary.artifacts.total_scanned} files scanned
                </div>
              </div>

              <div className="stat-card" style={{ "--stat-accent": "linear-gradient(90deg, var(--accent), var(--accent-secondary))" } as React.CSSProperties}>
                <div className="stat-icon" style={{ background: "var(--accent-dim)" }}>
                  <IconTarget size={18} color="var(--accent)" />
                </div>
                <div className="stat-value" style={{ color: "var(--accent)" }}>
                  {Math.round(summary.artifacts.average_confidence * 100)}%
                </div>
                <div className="stat-label">Avg Confidence</div>
                <div className="stat-delta">
                  across threat files
                </div>
              </div>

              <div className="stat-card" style={{ "--stat-accent": "linear-gradient(90deg, var(--threat-low), #34d399)" } as React.CSSProperties}>
                <div className="stat-icon" style={{ background: "var(--threat-low-dim)" }}>
                  <IconCheckCircle size={18} color="var(--threat-low)" />
                </div>
                <div className="stat-value" style={{ color: "var(--threat-low)" }}>
                  {summary.artifacts.clean_files}
                </div>
                <div className="stat-label">Clean Files</div>
                <div className="stat-delta">
                  no matches found
                </div>
              </div>
            </div>

            {/* Two column layout */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              {/* Top Rules — Bar Chart */}
              <div className="card">
                <div className="card-title">
                  <IconZap size={14} color="var(--threat-high)" /> Top Triggered Rules
                </div>
                {summary.top_triggered_rules.length === 0 ? (
                  <div className="empty-state" style={{ padding: "32px" }}>
                    <IconActivity size={32} color="var(--text-muted)" style={{ margin: "0 auto 12px", display: "block", opacity: 0.3 }} />
                    <p>No rules triggered yet. Run a scan to get started.</p>
                  </div>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                    {summary.top_triggered_rules.map((r, i) => {
                      const maxHits = Math.max(...summary.top_triggered_rules.map(x => x.hits));
                      const pct = maxHits > 0 ? (r.hits / maxHits) * 100 : 0;
                      return (
                        <div key={i}>
                          <div className="flex justify-between items-center" style={{ marginBottom: 6 }}>
                            <span className="mono" style={{ fontSize: 12, color: "var(--text-primary)" }}>{r.rule}</span>
                            <span style={{ fontSize: 13, fontWeight: 800, color: "var(--accent)", fontVariantNumeric: "tabular-nums" }}>{r.hits}</span>
                          </div>
                          <div style={{ height: 4, borderRadius: "var(--radius-full)", background: "rgba(255,255,255,0.04)", overflow: "hidden" }}>
                            <div style={{
                              height: "100%",
                              width: `${pct}%`,
                              borderRadius: "var(--radius-full)",
                              background: "var(--gradient-brand)",
                              transition: "width 0.8s cubic-bezier(0.16, 1, 0.3, 1)",
                            }} />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Platform Health — Circular Gauges */}
              <div className="card">
                <div className="card-title">
                  <IconActivity size={14} color="var(--accent)" /> Platform Health
                </div>
                <div style={{ display: "flex", justifyContent: "space-around", alignItems: "center", padding: "12px 0" }}>
                  <RadialGauge
                    value={summary.scan_jobs.total > 0 ? summary.scan_jobs.completed / summary.scan_jobs.total : 0}
                    size={100}
                    strokeWidth={6}
                    color="var(--threat-low)"
                    label="Completed"
                    sublabel={`${summary.scan_jobs.completed}/${summary.scan_jobs.total}`}
                  />
                  <RadialGauge
                    value={summary.scan_jobs.total > 0 ? summary.scan_jobs.failed / summary.scan_jobs.total : 0}
                    size={100}
                    strokeWidth={6}
                    color="var(--threat-critical)"
                    label="Failed"
                    sublabel={`${summary.scan_jobs.failed}/${summary.scan_jobs.total}`}
                  />
                  <RadialGauge
                    value={summary.match_events.total > 0 ? summary.match_events.confirmed_false_positives / summary.match_events.total : 0}
                    size={100}
                    strokeWidth={6}
                    color="var(--threat-medium)"
                    label="False Pos"
                    sublabel={`${summary.match_events.confirmed_false_positives} confirmed`}
                  />
                </div>
              </div>
            </div>
          </>
        ) : null}
      </div>
    </>
  );
}
