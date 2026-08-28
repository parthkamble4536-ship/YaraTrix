"use client";

import { useEffect, useState } from "react";
import { api, YaraRule } from "@/lib/api";
import { IconFileCode, IconSearch, IconFilter, IconX, IconHexagon } from "@/components/icons";

export default function RulesPage() {
  const [rules, setRules] = useState<YaraRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<string>("all");

  useEffect(() => {
    api.getRules()
      .then((data) => setRules(data.rules))
      .finally(() => setLoading(false));
  }, []);

  const tactics = Array.from(new Set(rules.map((r) => r.mitre_tactic).filter(Boolean)));

  const filtered = rules.filter((r) => {
    const matchSearch = r.name.toLowerCase().includes(search.toLowerCase()) ||
                        r.description.toLowerCase().includes(search.toLowerCase());
    const matchFilter = filter === "all" || r.mitre_tactic === filter;
    return matchSearch && matchFilter;
  });

  // Severity counts for summary bar
  const severityCounts = rules.reduce((acc, r) => {
    const s = (r.severity || "medium").toLowerCase();
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <>
      <div className="topbar">
        <div>
          <div className="topbar-title">YARA Rules</div>
          <div className="topbar-subtitle">Loaded detection ruleset explorer</div>
        </div>
        {!loading && (
          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8 }}>
            <span className="tactic-tag" style={{ fontSize: 10 }}>
              <IconFileCode size={12} style={{ marginRight: 4 }} />
              {rules.length} rules loaded
            </span>
          </div>
        )}
      </div>
      <div className="page-content">
        <div className="page-header">
          <h1>YARA Rule Explorer</h1>
          <p>Browse all loaded detection rules with ATT&CK mappings and severity ratings</p>
        </div>

        {/* Severity Summary Bar */}
        {!loading && rules.length > 0 && (
          <div className="summary-bar stagger-children" style={{ animation: "fadeInUp 0.3s var(--ease-out)" }}>
            {(["critical", "high", "medium", "low"] as const).map((s) => {
              const count = severityCounts[s] || 0;
              const colors: Record<string, string> = { critical: "var(--threat-critical)", high: "var(--threat-high)", medium: "var(--threat-medium)", low: "var(--threat-low)" };
              return (
                <div key={s} className="summary-item">
                  <div className="summary-count" style={{ color: colors[s] }}>{count}</div>
                  <div className="summary-label">{s}</div>
                </div>
              );
            })}
            <div style={{ marginLeft: "auto" }}>
              <div className="severity-bar" style={{ width: 120, height: 6 }}>
                {(["critical", "high", "medium", "low"] as const).map((s) => {
                  const count = severityCounts[s] || 0;
                  if (count === 0) return null;
                  const colors: Record<string, string> = { critical: "var(--threat-critical)", high: "var(--threat-high)", medium: "var(--threat-medium)", low: "var(--threat-low)" };
                  return <div key={s} style={{ width: `${(count / rules.length) * 100}%`, background: colors[s] }} />;
                })}
              </div>
            </div>
          </div>
        )}

        {/* Filters */}
        <div className="flex items-center gap-3" style={{ marginBottom: 20, flexWrap: "wrap" }}>
          <div style={{ position: "relative" }}>
            <IconSearch size={14} color="var(--text-muted)" style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)", pointerEvents: "none" }} />
            <input
              id="rule-search"
              type="text"
              placeholder="Search rules…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="form-input"
              style={{ paddingLeft: 32, width: 220 }}
            />
          </div>
          <select
            id="tactic-filter"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="form-input"
          >
            <option value="all">All Tactics</option>
            {tactics.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          {(search || filter !== "all") && (
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => { setSearch(""); setFilter("all"); }}
            >
              <IconX size={12} /> Clear
            </button>
          )}
        </div>

        {/* Rules grid */}
        {loading ? (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))", gap: 14 }}>
            {[...Array(6)].map((_, i) => (
              <div key={i} className="card"><div className="skeleton" style={{ height: 100 }} /></div>
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <div className="empty-state">
            <IconFileCode size={36} color="var(--text-muted)" style={{ margin: "0 auto 16px", display: "block", opacity: 0.3 }} />
            <h3>No rules match</h3>
            <p>Try adjusting your search or filter</p>
          </div>
        ) : (
          <div className="stagger-children" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))", gap: 14 }}>
            {filtered.map((rule, index) => (
              <RuleCard key={`${rule.name}-${index}`} rule={rule} />
            ))}
          </div>
        )}
      </div>
    </>
  );
}

function RuleCard({ rule }: { rule: YaraRule }) {
  const severityClass = `severity-${(rule.severity || "medium").toLowerCase()}`;

  return (
    <div className={`rule-card ${severityClass}`}>
      <div className="flex justify-between items-center" style={{ marginBottom: 10 }}>
        <span className={`severity-badge ${rule.severity || "medium"}`}>{rule.severity || "medium"}</span>
        {rule.mitre_technique && (
          <span className="mono" style={{ color: "var(--accent)", fontSize: 11, background: "var(--accent-dim)", padding: "3px 8px", borderRadius: 4 }}>
            {rule.mitre_technique}
          </span>
        )}
      </div>

      <div style={{ fontWeight: 700, fontSize: 13, color: "var(--text-primary)", marginBottom: 6, fontFamily: "'JetBrains Mono', monospace", lineHeight: 1.4 }}>
        {rule.name}
      </div>

      {rule.description && (
        <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.6, marginBottom: 12 }}>
          {rule.description.length > 110 ? rule.description.slice(0, 110) + "…" : rule.description}
        </div>
      )}

      {rule.mitre_tactic && (
        <span className="tactic-tag" style={{ fontSize: 9, padding: "3px 8px" }}>
          {rule.mitre_tactic.replace(/_/g, " ").replace(/-/g, " ").toUpperCase()}
        </span>
      )}
    </div>
  );
}
