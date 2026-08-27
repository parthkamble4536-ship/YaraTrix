"use client";

import { useEffect, useState } from "react";
import { api, YaraRule } from "@/lib/api";

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

  return (
    <>
      <div className="topbar">
        <div>
          <div className="topbar-title">YARA Rules</div>
          <div className="topbar-subtitle">Loaded detection ruleset explorer</div>
        </div>
        {!loading && (
          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8 }}>
            <span className="tactic-tag">{rules.length} rules loaded</span>
          </div>
        )}
      </div>
      <div className="page-content">
        <div className="page-header">
          <h1>YARA Rule Explorer</h1>
          <p>Browse all loaded detection rules with ATT&CK mappings and severity ratings</p>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-3" style={{ marginBottom: 20, flexWrap: "wrap" }}>
          <input
            id="rule-search"
            type="text"
            placeholder="Search rules…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{
              background: "var(--bg-input)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-md)",
              padding: "9px 14px",
              color: "var(--text-primary)",
              fontSize: 14,
              width: 240,
              fontFamily: "inherit",
              outline: "none",
            }}
          />
          <select
            id="tactic-filter"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            style={{
              background: "var(--bg-input)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-md)",
              padding: "9px 14px",
              color: "var(--text-primary)",
              fontSize: 14,
              fontFamily: "inherit",
              outline: "none",
              cursor: "pointer",
            }}
          >
            <option value="all">All Tactics</option>
            {tactics.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          {(search || filter !== "all") && (
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => { setSearch(""); setFilter("all"); }}
            >
              Clear filters
            </button>
          )}
        </div>

        {/* Rules grid */}
        {loading ? (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))", gap: 16 }}>
            {[...Array(6)].map((_, i) => (
              <div key={i} className="card"><div className="skeleton" style={{ height: 100 }} /></div>
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <div className="empty-state">
            <span className="empty-state-icon">≡</span>
            <h3>No rules match</h3>
            <p>Try adjusting your search or filter</p>
          </div>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))", gap: 16 }}>
            {filtered.map((rule) => (
              <RuleCard key={rule.name} rule={rule} />
            ))}
          </div>
        )}
      </div>
    </>
  );
}

function RuleCard({ rule }: { rule: YaraRule }) {
  return (
    <div className="card" style={{ transition: "var(--transition)" }}>
      <div className="flex justify-between items-center" style={{ marginBottom: 10 }}>
        <span className={`severity-badge ${rule.severity || "medium"}`}>{rule.severity || "medium"}</span>
        {rule.mitre_technique && (
          <span className="mono" style={{ color: "var(--accent)", fontSize: 11, background: "var(--accent-dim)", padding: "2px 8px", borderRadius: 4 }}>
            {rule.mitre_technique}
          </span>
        )}
      </div>

      <div style={{ fontWeight: 700, fontSize: 14, color: "var(--text-primary)", marginBottom: 6, fontFamily: "'JetBrains Mono', monospace" }}>
        {rule.name}
      </div>

      {rule.description && (
        <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.6, marginBottom: 12 }}>
          {rule.description.length > 120 ? rule.description.slice(0, 120) + "…" : rule.description}
        </div>
      )}

      {rule.mitre_tactic && (
        <span className="tactic-tag" style={{ fontSize: 10 }}>
          {rule.mitre_tactic.replace("_", " ").toUpperCase()}
        </span>
      )}
    </div>
  );
}
