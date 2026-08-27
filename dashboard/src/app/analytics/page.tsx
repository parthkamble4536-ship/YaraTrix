"use client";

import { useEffect, useState } from "react";
import { api, CoverageReport, RuleStat } from "@/lib/api";

const ALL_TACTICS = [
  "Initial Access", "Execution", "Persistence", "Privilege Escalation",
  "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
  "Collection", "Command & Control", "Exfiltration", "Impact",
];

export default function AnalyticsPage() {
  const [rules, setRules] = useState<RuleStat[]>([]);
  const [coverage, setCoverage] = useState<CoverageReport | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([api.getRuleEffectiveness(), api.getCoverage()])
      .then(([ruleData, cov]) => {
        setRules(ruleData.rules);
        setCoverage(cov);
      })
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <>
        <div className="topbar"><div className="topbar-title">Analytics</div></div>
        <div className="page-content">
          <div className="stats-grid">
            {[...Array(3)].map((_, i) => <div key={i} className="card"><div className="skeleton" style={{ height: 120 }} /></div>)}
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <div className="topbar">
        <div>
          <div className="topbar-title">Analytics</div>
          <div className="topbar-subtitle">Rule effectiveness & ATT&CK coverage intelligence</div>
        </div>
      </div>
      <div className="page-content">
        <div className="page-header">
          <h1>Detection Quality Analytics</h1>
          <p>ATT&CK coverage gaps, rule effectiveness, and analyst feedback integration</p>
        </div>

        {/* Coverage Summary */}
        {coverage && (
          <div className="card card-glow" style={{ marginBottom: 24 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20 }}>
              <div>
                <div className="card-title" style={{ marginBottom: 6 }}>▦ MITRE ATT&CK Coverage</div>
                <div style={{ fontSize: 40, fontWeight: 800, color: coverage.coverage_percentage >= 50 ? "var(--threat-low)" : "var(--threat-medium)" }}>
                  {coverage.coverage_percentage.toFixed(0)}%
                </div>
                <div style={{ fontSize: 13, color: "var(--text-secondary)", marginTop: 4 }}>
                  {coverage.tactic_count} of {ALL_TACTICS.length} tactics covered
                </div>
              </div>
              <div style={{ textAlign: "right" }}>
                <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8 }}>
                  {coverage.covered_techniques.length} unique techniques
                </div>
              </div>
            </div>

            <div className="progress-bar" style={{ marginBottom: 20, height: 8 }}>
              <div className="progress-fill" style={{ width: `${coverage.coverage_percentage}%` }} />
            </div>

            {/* Heatmap grid */}
            <div className="tactic-grid">
              {ALL_TACTICS.map((t) => {
                const covered = coverage.covered_tactics.includes(t);
                return (
                  <div key={t} className={`tactic-cell ${covered ? "covered" : "missing"}`}>
                    <span className="tactic-indicator">{covered ? "⬡" : "○"}</span>
                    {t}
                  </div>
                );
              })}
            </div>

            {coverage.missing_tactics.length > 0 && (
              <div style={{ marginTop: 16, padding: "12px 16px", background: "rgba(255,170,0,0.08)", borderRadius: "var(--radius-md)", border: "1px solid rgba(255,170,0,0.2)", fontSize: 13, color: "var(--threat-medium)" }}>
                💡 {coverage.detection_gap_advice}
              </div>
            )}
          </div>
        )}

        {/* Rule Effectiveness Table */}
        <div className="card">
          <div className="card-title">⬡ Rule Effectiveness Scoreboard ({rules.length} rules)</div>
          {rules.length === 0 ? (
            <div className="empty-state" style={{ padding: "32px" }}>
              <p>No rules have triggered yet. Run some scans to generate analytics.</p>
            </div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Rule Name</th>
                  <th>Total Hits</th>
                  <th>True +</th>
                  <th>False +</th>
                  <th>Effectiveness</th>
                  <th>Noise Level</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((r, i) => (
                  <tr key={i}>
                    <td><span className="mono">{r.rule_name}</span></td>
                    <td style={{ fontWeight: 700 }}>{r.total_hits}</td>
                    <td style={{ color: "var(--threat-low)", fontWeight: 600 }}>{r.true_positives}</td>
                    <td style={{ color: "var(--threat-critical)", fontWeight: 600 }}>{r.false_positives}</td>
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <div style={{ flex: 1, background: "rgba(255,255,255,0.06)", borderRadius: 3, height: 6, overflow: "hidden", minWidth: 60 }}>
                          <div style={{ height: "100%", width: `${r.effectiveness_score * 100}%`, background: r.effectiveness_score >= 0.7 ? "var(--threat-low)" : "var(--threat-medium)", borderRadius: 3 }} />
                        </div>
                        <span style={{ fontSize: 12, fontWeight: 700, minWidth: 32 }}>
                          {r.true_positives + r.false_positives > 0 ? `${Math.round(r.effectiveness_score * 100)}%` : "—"}
                        </span>
                      </div>
                    </td>
                    <td>
                      <span className={`severity-badge ${r.noise_level === "high" ? "critical" : r.noise_level === "medium" ? "medium" : "low"}`}>
                        {r.noise_level}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
}
