"use client";

import { useEffect, useState } from "react";
import { api, AnalyticsSummary } from "@/lib/api";

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
          <div className="topbar-title">Overview</div>
          <div className="topbar-subtitle">Platform intelligence summary</div>
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
                <div className="skeleton" style={{ height: 80 }} />
              </div>
            ))}
          </div>
        ) : error ? (
          <div className="card" style={{ textAlign: "center", padding: "48px" }}>
            <span style={{ fontSize: 40 }}>⚠️</span>
            <p style={{ color: "var(--threat-critical)", marginTop: 12, fontWeight: 600 }}>
              Cannot reach API: {error}
            </p>
            <p style={{ color: "var(--text-secondary)", marginTop: 8, fontSize: 13 }}>
              Make sure <code style={{ color: "var(--accent)" }}>uvicorn</code> is running on port 8000.
            </p>
          </div>
        ) : summary ? (
          <>
            <div className="stats-grid">
              <div className="stat-card">
                <span className="stat-icon">🔍</span>
                <div className="stat-value">{summary.scan_jobs.total}</div>
                <div className="stat-label">Total Scan Jobs</div>
                <div className="stat-delta up">
                  ✓ {summary.scan_jobs.completed} completed
                </div>
              </div>

              <div className="stat-card">
                <span className="stat-icon">⚠️</span>
                <div className="stat-value" style={{ color: "var(--threat-critical)" }}>
                  {summary.artifacts.threats_detected}
                </div>
                <div className="stat-label">Threats Detected</div>
                <div className="stat-delta">
                  <span style={{ color: "var(--text-secondary)" }}>
                    of {summary.artifacts.total_scanned} files
                  </span>
                </div>
              </div>

              <div className="stat-card">
                <span className="stat-icon">🎯</span>
                <div className="stat-value" style={{ color: "var(--accent)" }}>
                  {Math.round(summary.artifacts.average_confidence * 100)}%
                </div>
                <div className="stat-label">Avg Confidence</div>
                <div className="stat-delta">
                  <span style={{ color: "var(--text-secondary)" }}>across threat files</span>
                </div>
              </div>

              <div className="stat-card">
                <span className="stat-icon">✅</span>
                <div className="stat-value" style={{ color: "var(--threat-low)" }}>
                  {summary.artifacts.clean_files}
                </div>
                <div className="stat-label">Clean Files</div>
                <div className="stat-delta">
                  <span style={{ color: "var(--text-secondary)" }}>no matches found</span>
                </div>
              </div>
            </div>

            {/* Two column layout */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
              {/* Top Rules */}
              <div className="card">
                <div className="card-title">🔥 Top Triggered Rules</div>
                {summary.top_triggered_rules.length === 0 ? (
                  <div className="empty-state" style={{ padding: "24px" }}>
                    <p>No rules triggered yet. Run a scan to get started.</p>
                  </div>
                ) : (
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Rule Name</th>
                        <th>Hits</th>
                      </tr>
                    </thead>
                    <tbody>
                      {summary.top_triggered_rules.map((r, i) => (
                        <tr key={i}>
                          <td>
                            <span className="mono">{r.rule}</span>
                          </td>
                          <td>
                            <span className="threat-badge high">{r.hits}</span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>

              {/* Platform Health */}
              <div className="card">
                <div className="card-title">⚙️ Platform Health</div>
                <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                  <HealthRow label="Scan Jobs Completed" value={summary.scan_jobs.completed} total={summary.scan_jobs.total} color="var(--threat-low)" />
                  <HealthRow label="Jobs Failed" value={summary.scan_jobs.failed} total={summary.scan_jobs.total} color="var(--threat-critical)" />
                  <HealthRow label="False Positives Confirmed" value={summary.match_events.confirmed_false_positives} total={summary.match_events.total} color="var(--threat-medium)" />
                </div>
              </div>
            </div>
          </>
        ) : null}
      </div>
    </>
  );
}

function HealthRow({ label, value, total, color }: { label: string; value: number; total: number; color: string }) {
  const pct = total > 0 ? (value / total) * 100 : 0;
  return (
    <div>
      <div className="flex justify-between items-center" style={{ marginBottom: 6 }}>
        <span style={{ fontSize: 13, color: "var(--text-secondary)" }}>{label}</span>
        <span style={{ fontSize: 14, fontWeight: 700, color }}>{value}</span>
      </div>
      <div className="progress-bar">
        <div className="progress-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  );
}
