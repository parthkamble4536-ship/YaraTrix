"use client";

import { useState, useRef } from "react";
import { api, ScanResponse, IntelligenceReport } from "@/lib/api";
import { IconUpload, IconScanner, IconChevronDown, IconChevronRight, IconFileCode } from "@/components/icons";
import { RadialGauge } from "@/components/icons";

function confidenceColor(score: number): string {
  if (score >= 0.8) return "var(--threat-critical)";
  if (score >= 0.6) return "var(--threat-high)";
  if (score >= 0.4) return "var(--threat-medium)";
  if (score > 0)   return "var(--threat-low)";
  return "var(--threat-info)";
}

export default function ScanPage() {
  const [file, setFile] = useState<File | null>(null);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [expandedRow, setExpandedRow] = useState<number | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFile = (f: File) => { setFile(f); setResult(null); setError(null); };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files[0];
    if (f) handleFile(f);
  };

  const handleScan = async () => {
    if (!file) return;
    setScanning(true);
    setError(null);
    setResult(null);
    try {
      const res = await api.scanFile(file);
      setResult(res);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Scan failed");
    } finally {
      setScanning(false);
    }
  };

  const intel: IntelligenceReport | undefined = result?.intelligence;

  // Severity distribution
  const severityCounts = result?.matches?.reduce(
    (acc, m) => {
      const s = m.severity || "medium";
      acc[s] = (acc[s] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  ) || {};
  const totalMatches = result?.matches?.length || 0;

  return (
    <>
      <div className="topbar">
        <div>
          <div className="topbar-title">File Scanner</div>
          <div className="topbar-subtitle">YARA scan with Intelligence Engine enrichment</div>
        </div>
        {result && (
          <div style={{ marginLeft: "auto" }}>
            <span className={`threat-badge ${intel?.threat_level || "none"}`}>
              {intel?.confidence_label || "Unknown"}
            </span>
          </div>
        )}
      </div>
      <div className="page-content">
        <div className="page-header">
          <h1>Intelligence Scanner</h1>
          <p>Upload any file to scan with YARA rules and get instant MITRE ATT&CK intelligence</p>
        </div>

        {/* Upload Zone */}
        <div
          className={`upload-zone ${dragOver ? "drag-over" : ""}`}
          onClick={() => inputRef.current?.click()}
          onDrop={handleDrop}
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          id="upload-zone"
        >
          <input
            ref={inputRef}
            type="file"
            style={{ display: "none" }}
            id="file-input"
            onChange={(e) => e.target.files?.[0] && handleFile(e.target.files[0])}
          />
          <div className="upload-icon">
            {file ? <IconFileCode size={24} /> : <IconUpload size={24} />}
          </div>
          <div className="upload-title">
            {file ? file.name : "Drop a file here or click to browse"}
          </div>
          <div className="upload-subtitle">
            {file
              ? `${(file.size / 1024).toFixed(1)} KB — Ready to scan`
              : "Supports any file type · Max 50 MB"}
          </div>
        </div>

        <div className="flex items-center gap-3 mt-4">
          <button
            id="scan-btn"
            className="btn btn-primary btn-lg"
            onClick={handleScan}
            disabled={!file || scanning}
          >
            {scanning ? (
              <><span className="spinning"><IconScanner size={16} /></span> Analyzing…</>
            ) : (
              <><IconScanner size={16} /> Run Intelligence Scan</>
            )}
          </button>
          {file && (
            <button
              className="btn btn-secondary"
              onClick={() => { setFile(null); setResult(null); setError(null); setExpandedRow(null); }}
            >
              Clear
            </button>
          )}
        </div>

        {/* Scanning Animation */}
        {scanning && (
          <div className="scan-animation" style={{ marginTop: 32 }}>
            <div className="radar-container">
              <div className="radar-ring" />
              <div className="radar-ring" />
              <div className="radar-ring" />
              <div className="radar-sweep" />
              <div className="radar-dot" />
            </div>
            <div className="scan-text">Scanning</div>
            <div className="scan-subtext">Running YARA engine + Intelligence enrichment</div>
          </div>
        )}

        {error && (
          <div className="card" style={{ marginTop: 24, borderColor: "rgba(255,45,85,0.2)", background: "rgba(255,45,85,0.04)" }}>
            <span style={{ color: "var(--threat-critical)", fontWeight: 600, fontSize: 13 }}>⚠ {error}</span>
          </div>
        )}

        {/* Results */}
        {result && intel && (
          <div style={{ marginTop: 28 }}>
            {/* Intelligence Report */}
            <div className="card card-glow" style={{ animation: "fadeInUp 0.5s var(--ease-out)" }}>
              <div className="flex justify-between items-center" style={{ marginBottom: 20 }}>
                <div className="card-title" style={{ marginBottom: 0 }}>Intelligence Report</div>
                <span className={`threat-badge ${intel.threat_level}`}>
                  {intel.threat_level === "none" ? "✓ Clean" : `⚠ ${intel.confidence_label}`}
                </span>
              </div>

              {/* Confidence Gauge + Info */}
              <div style={{ display: "flex", gap: 32, alignItems: "center", flexWrap: "wrap" }}>
                <RadialGauge
                  value={intel.confidence_score}
                  size={140}
                  strokeWidth={10}
                  label="Confidence"
                />

                <div style={{ flex: 1, minWidth: 250 }}>
                  {/* Severity distribution mini-bar */}
                  {totalMatches > 0 && (
                    <div style={{ marginBottom: 16 }}>
                      <div style={{ fontSize: 10, fontWeight: 700, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "1px", marginBottom: 8 }}>
                        Severity Distribution
                      </div>
                      <div className="severity-bar" style={{ height: 8, borderRadius: 4 }}>
                        {(["critical", "high", "medium", "low"] as const).map((s) => {
                          const count = severityCounts[s] || 0;
                          if (count === 0) return null;
                          const colors: Record<string, string> = { critical: "var(--threat-critical)", high: "var(--threat-high)", medium: "var(--threat-medium)", low: "var(--threat-low)" };
                          return <div key={s} style={{ width: `${(count / totalMatches) * 100}%`, background: colors[s] }} />;
                        })}
                      </div>
                      <div className="flex gap-3 mt-2" style={{ flexWrap: "wrap" }}>
                        {(["critical", "high", "medium", "low"] as const).map((s) => {
                          const count = severityCounts[s] || 0;
                          if (count === 0) return null;
                          return (
                            <span key={s} style={{ fontSize: 10, display: "flex", alignItems: "center", gap: 4, color: "var(--text-secondary)" }}>
                              <span className={`severity-badge ${s}`} style={{ padding: "1px 6px", fontSize: 9 }}>{s}</span>
                              {count}
                            </span>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* Tactics & Techniques */}
                  {intel.tactic_coverage.length > 0 && (
                    <div style={{ marginBottom: 12 }}>
                      <div style={{ fontSize: 10, fontWeight: 700, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "1px", marginBottom: 6 }}>
                        Tactics Detected
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {intel.tactic_coverage.map((t) => (
                          <span key={t} className="tactic-tag" style={{ fontSize: 10 }}>{t}</span>
                        ))}
                      </div>
                    </div>
                  )}

                  {intel.technique_ids.length > 0 && (
                    <div>
                      <div style={{ fontSize: 10, fontWeight: 700, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "1px", marginBottom: 6 }}>
                        Techniques
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {intel.technique_ids.map((t) => (
                          <span key={t} className="mono" style={{ color: "var(--accent)", background: "var(--accent-dim)", padding: "3px 8px", borderRadius: 4, fontSize: 11 }}>
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {intel.behavioral_narrative && (
                <div className="narrative-block" style={{ marginTop: 20, marginBottom: 8 }}>
                  <div className="narrative-label">Behavioral Narrative</div>
                  <div className="narrative-text">{intel.behavioral_narrative}</div>
                </div>
              )}

              <div style={{ marginTop: 16, display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
                <MetaItem label="Rules Triggered" value={intel.rule_count} />
                <MetaItem label="Tactics Covered" value={intel.tactic_count} />
                <MetaItem label="Job ID" value={`#${result.scan_job_id}`} />
              </div>
            </div>

            {/* Matched Rules — Expandable Table */}
            {result.matches?.length > 0 && (
              <div className="card" style={{ marginTop: 16, animation: "fadeInUp 0.5s var(--ease-out) 0.1s both" }}>
                <div className="card-title">
                  <IconFileCode size={14} /> Matched YARA Rules ({result.matches.length})
                </div>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th style={{ width: 28 }}></th>
                      <th>Rule</th>
                      <th>Severity</th>
                      <th>Technique</th>
                      <th>Tactic</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.matches.map((m, i) => (
                      <>
                        <tr
                          key={`row-${i}`}
                          className="expandable-row"
                          onClick={() => setExpandedRow(expandedRow === i ? null : i)}
                          style={{ cursor: "pointer" }}
                        >
                          <td style={{ width: 28, padding: "12px 8px 12px 16px" }}>
                            {expandedRow === i
                              ? <IconChevronDown size={14} color="var(--accent)" />
                              : <IconChevronRight size={14} color="var(--text-muted)" />}
                          </td>
                          <td><span className="mono">{m.rule_name}</span></td>
                          <td>
                            <span className={`severity-badge ${m.severity || "medium"}`}>
                              {m.severity || "medium"}
                            </span>
                          </td>
                          <td><span className="mono">{m.mitre_technique || "—"}</span></td>
                          <td style={{ color: "var(--text-secondary)", fontSize: 12 }}>
                            {m.mitre_tactic || "—"}
                          </td>
                        </tr>
                        {expandedRow === i && (
                          <tr key={`expand-${i}`} className="expand-content">
                            <td colSpan={5}>
                              <div style={{ padding: "4px 8px" }}>
                                {m.description && (
                                  <div style={{ marginBottom: 12 }}>
                                    <div style={{ fontSize: 10, fontWeight: 700, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "1px", marginBottom: 4 }}>Description</div>
                                    <div style={{ fontSize: 13, color: "var(--text-primary)", lineHeight: 1.7 }}>{m.description}</div>
                                  </div>
                                )}
                                <div style={{ fontSize: 10, fontWeight: 700, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "1px", marginBottom: 4 }}>Source</div>
                                <div className="mono" style={{ fontSize: 11, color: "var(--text-secondary)" }}>{m.rule_file}</div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
    </>
  );
}

function MetaItem({ label, value }: { label: string; value: string | number }) {
  return (
    <div style={{ background: "var(--bg-input)", borderRadius: "var(--radius-md)", padding: "12px 16px", border: "1px solid var(--border)" }}>
      <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.8px", fontWeight: 700, marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 18, fontWeight: 800, color: "var(--text-primary)", fontVariantNumeric: "tabular-nums" }}>{value}</div>
    </div>
  );
}
