"use client";

import { useState, useRef } from "react";
import { api, ScanResponse, IntelligenceReport } from "@/lib/api";

function confidenceColor(score: number): string {
  if (score >= 0.8) return "var(--threat-critical)";
  if (score >= 0.6) return "var(--threat-high)";
  if (score >= 0.4) return "var(--threat-medium)";
  if (score > 0)   return "var(--threat-low)";
  return "var(--threat-none)";
}

export default function ScanPage() {
  const [file, setFile] = useState<File | null>(null);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
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

  return (
    <>
      <div className="topbar">
        <div>
          <div className="topbar-title">Scan File</div>
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
          <h1>File Scanner</h1>
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
          <span className="upload-icon">{file ? "📄" : "⬆️"}</span>
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
              <><span className="spinning">⟳</span> Scanning…</>
            ) : "⬡ Run Intelligence Scan"}
          </button>
          {file && (
            <button
              className="btn btn-secondary"
              onClick={() => { setFile(null); setResult(null); setError(null); }}
            >
              Clear
            </button>
          )}
        </div>

        {error && (
          <div className="card" style={{ marginTop: 24, borderColor: "rgba(255,45,85,0.3)", background: "rgba(255,45,85,0.05)" }}>
            <span style={{ color: "var(--threat-critical)", fontWeight: 600 }}>⚠ {error}</span>
          </div>
        )}

        {/* Results */}
        {result && intel && (
          <div style={{ marginTop: 28 }}>
            {/* Confidence Meter */}
            <div className="card card-glow">
              <div className="flex justify-between items-center" style={{ marginBottom: 16 }}>
                <div className="card-title" style={{ marginBottom: 0 }}>Intelligence Report</div>
                <span className={`threat-badge ${intel.threat_level}`}>
                  {intel.threat_level === "none" ? "✓ Clean" : `⚠ ${intel.confidence_label}`}
                </span>
              </div>

              <div className="confidence-meter">
                <div className="confidence-header">
                  <span className="confidence-label">Confidence Score</span>
                  <span className="confidence-value" style={{ color: confidenceColor(intel.confidence_score) }}>
                    {Math.round(intel.confidence_score * 100)}%
                  </span>
                </div>
                <div className="confidence-track">
                  <div
                    className="confidence-fill"
                    style={{
                      width: `${intel.confidence_score * 100}%`,
                      background: `linear-gradient(90deg, ${confidenceColor(intel.confidence_score)}, ${confidenceColor(intel.confidence_score)}88)`,
                    }}
                  />
                </div>
              </div>

              {intel.behavioral_narrative && (
                <div className="narrative-block">
                  <div className="narrative-label">Behavioral Narrative</div>
                  <div className="narrative-text">{intel.behavioral_narrative}</div>
                </div>
              )}

              {intel.tactic_coverage.length > 0 && (
                <div style={{ marginTop: 16 }}>
                  <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 8, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.8px" }}>
                    Tactics Detected
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {intel.tactic_coverage.map((t) => (
                      <span key={t} className="tactic-tag">{t}</span>
                    ))}
                  </div>
                </div>
              )}

              {intel.technique_ids.length > 0 && (
                <div style={{ marginTop: 16 }}>
                  <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 8, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.8px" }}>
                    Technique IDs
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {intel.technique_ids.map((t) => (
                      <span key={t} className="mono" style={{ color: "var(--accent)", background: "var(--accent-dim)", padding: "3px 10px", borderRadius: 4 }}>
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div style={{ marginTop: 16, display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
                <MetaItem label="Rules Triggered" value={intel.rule_count} />
                <MetaItem label="Tactics Covered" value={intel.tactic_count} />
                <MetaItem label="Job ID" value={`#${result.scan_job_id}`} />
              </div>
            </div>

            {/* Matched Rules */}
            {result.matches?.length > 0 && (
              <div className="card" style={{ marginTop: 20 }}>
                <div className="card-title">⬡ Matched YARA Rules ({result.matches.length})</div>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Rule</th>
                      <th>Severity</th>
                      <th>Technique</th>
                      <th>Tactic</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.matches.map((m, i) => (
                      <tr key={i}>
                        <td><span className="mono">{m.rule}</span></td>
                        <td>
                          <span className={`severity-badge ${m.meta?.severity || "medium"}`}>
                            {m.meta?.severity || "medium"}
                          </span>
                        </td>
                        <td><span className="mono">{m.meta?.mitre_technique || "—"}</span></td>
                        <td style={{ color: "var(--text-secondary)", fontSize: 12 }}>
                          {m.meta?.mitre_tactic || "—"}
                        </td>
                      </tr>
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
      <div style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 18, fontWeight: 700, color: "var(--text-primary)" }}>{value}</div>
    </div>
  );
}
