"use client";

import { useEffect, useState } from "react";
import { api, CoverageReport, RuleStat } from "@/lib/api";
import { IconChart, IconTarget, IconActivity, IconAlertTriangle, IconCheckCircle, IconHexagon } from "@/components/icons";
import { RadialGauge } from "@/components/icons";

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
          <div className="card card-glow" style={{ marginBottom: 20, animation: "fadeInUp 0.4s var(--ease-out)" }}>
            <div style={{ display: "flex", gap: 32, alignItems: "center", flexWrap: "wrap" }}>
              {/* Radial Gauge */}
              <RadialGauge
                value={coverage.coverage_percentage / 100}
                size={140}
                strokeWidth={10}
                color={coverage.coverage_percentage >= 50 ? "var(--threat-low)" : "var(--threat-medium)"}
                label="ATT&CK Coverage"
                sublabel={`${coverage.tactic_count} of ${ALL_TACTICS.length} tactics`}
              />

              <div style={{ flex: 1, minWidth: 250 }}>
                <div className="card-title" style={{ marginBottom: 8 }}>
                  <IconTarget size={14} /> MITRE ATT&CK Coverage
                </div>
                <div style={{ display: "flex", gap: 24, marginBottom: 12 }}>
                  <div>
                    <div style={{ fontSize: 24, fontWeight: 800, color: "var(--accent)", fontVariantNumeric: "tabular-nums" }}>
                      {coverage.covered_techniques.length}
                    </div>
                    <div style={{ fontSize: 10, color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.5px" }}>Techniques</div>
                  </div>
                  <div>
                    <div style={{ fontSize: 24, fontWeight: 800, color: "var(--threat-low)", fontVariantNumeric: "tabular-nums" }}>
                      {coverage.tactic_count}
                    </div>
                    <div style={{ fontSize: 10, color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.5px" }}>Tactics Covered</div>
                  </div>
                  <div>
                    <div style={{ fontSize: 24, fontWeight: 800, color: "var(--threat-critical)", fontVariantNumeric: "tabular-nums" }}>
                      {coverage.missing_count}
                    </div>
                    <div style={{ fontSize: 10, color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.5px" }}>Gaps</div>
                  </div>
                </div>
              </div>
            </div>

            {/* Heatmap grid */}
            <div className="tactic-grid stagger-children" style={{ marginTop: 20 }}>
              {ALL_TACTICS.map((t) => {
                const covered = coverage.covered_tactics.includes(t);
                return (
                  <div key={t} className={`tactic-cell ${covered ? "covered" : "missing"}`}>
                    <span className="tactic-indicator">
                      {covered
                        ? <IconCheckCircle size={18} color="var(--accent)" />
                        : <IconAlertTriangle size={18} color="var(--text-muted)" />}
                    </span>
                    {t}
                  </div>
                );
              })}
            </div>

            {coverage.missing_tactics.length > 0 && (
              <div style={{ marginTop: 16, padding: "12px 16px", background: "var(--threat-medium-dim)", borderRadius: "var(--radius-md)", border: "1px solid rgba(255,170,0,0.15)", fontSize: 12, color: "var(--threat-medium)", display: "flex", alignItems: "flex-start", gap: 8 }}>
                <IconAlertTriangle size={14} color="var(--threat-medium)" style={{ flexShrink: 0, marginTop: 1 }} />
                <span>{coverage.detection_gap_advice}</span>
              </div>
            )}
          </div>
        )}

        {/* Rule Effectiveness Table */}
        <div className="card" style={{ animation: "fadeInUp 0.4s var(--ease-out) 0.1s both" }}>
          <div className="card-title">
            <IconChart size={14} /> Rule Effectiveness Scoreboard ({rules.length} rules)
          </div>
          {rules.length === 0 ? (
            <div className="empty-state" style={{ padding: "32px" }}>
              <IconActivity size={32} color="var(--text-muted)" style={{ margin: "0 auto 12px", display: "block", opacity: 0.3 }} />
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
                    <td style={{ fontWeight: 700, fontVariantNumeric: "tabular-nums" }}>{r.total_hits}</td>
                    <td style={{ color: "var(--threat-low)", fontWeight: 700, fontVariantNumeric: "tabular-nums" }}>{r.true_positives}</td>
                    <td style={{ color: "var(--threat-critical)", fontWeight: 700, fontVariantNumeric: "tabular-nums" }}>{r.false_positives}</td>
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <div style={{ flex: 1, background: "rgba(255,255,255,0.04)", borderRadius: "var(--radius-full)", height: 4, overflow: "hidden", minWidth: 60 }}>
                          <div style={{
                            height: "100%",
                            width: `${r.effectiveness_score * 100}%`,
                            background: r.effectiveness_score >= 0.7 ? "var(--threat-low)" : r.effectiveness_score >= 0.4 ? "var(--threat-medium)" : "var(--threat-critical)",
                            borderRadius: "var(--radius-full)",
                            transition: "width 0.6s var(--ease-out)",
                          }} />
                        </div>
                        <span style={{ fontSize: 12, fontWeight: 700, minWidth: 32, fontVariantNumeric: "tabular-nums" }}>
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
