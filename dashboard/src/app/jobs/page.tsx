"use client";

import { useEffect, useState, useRef } from "react";
import { api, JobResponse, SubmitJobResponse } from "@/lib/api";

export default function JobsPage() {
  const [jobs, setJobs] = useState<JobResponse[]>([]);
  const [file, setFile] = useState<File | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [submitResult, setSubmitResult] = useState<SubmitJobResponse | null>(null);
  const [pollingId, setPollingId] = useState<number | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const pollJob = async (jobId: number) => {
    try {
      const job = await api.getJob(jobId);
      setJobs((prev) => {
        const exists = prev.find((j) => j.job_id === jobId);
        if (exists) return prev.map((j) => (j.job_id === jobId ? job : j));
        return [job, ...prev];
      });
      if (job.status === "completed" || job.status === "failed") {
        if (pollingRef.current) clearInterval(pollingRef.current);
        setPollingId(null);
      }
    } catch (_) {}
  };

  const handleSubmit = async () => {
    if (!file) return;
    setSubmitting(true);
    setSubmitResult(null);
    try {
      const res = await api.submitJob(file);
      setSubmitResult(res);
      setPollingId(res.job_id);
      // Start polling
      pollingRef.current = setInterval(() => pollJob(res.job_id), 2000);
      // Add placeholder immediately
      setJobs((prev) => [
        { job_id: res.job_id, status: "pending", target: file.name, created_at: new Date().toISOString(), completed_at: null },
        ...prev,
      ]);
      setFile(null);
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : "Submission failed");
    } finally {
      setSubmitting(false);
    }
  };

  useEffect(() => {
    return () => { if (pollingRef.current) clearInterval(pollingRef.current); };
  }, []);

  return (
    <>
      <div className="topbar">
        <div>
          <div className="topbar-title">Async Jobs</div>
          <div className="topbar-subtitle">Non-blocking distributed scan queue</div>
        </div>
        {pollingId && (
          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8, color: "var(--accent)", fontSize: 13 }}>
            <span className="spinning">⟳</span> Polling job #{pollingId}…
          </div>
        )}
      </div>
      <div className="page-content">
        <div className="page-header">
          <h1>Async Scan Jobs</h1>
          <p>Submit files to the Celery worker queue and poll results in real time</p>
        </div>

        {/* Submit form */}
        <div className="card" style={{ marginBottom: 24 }}>
          <div className="card-title">⟳ Submit New Job</div>
          <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
            <input
              ref={inputRef}
              type="file"
              style={{ display: "none" }}
              id="job-file-input"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
            />
            <button
              id="choose-file-btn"
              className="btn btn-secondary"
              onClick={() => inputRef.current?.click()}
            >
              {file ? `📄 ${file.name}` : "Choose File"}
            </button>
            <button
              id="submit-job-btn"
              className="btn btn-primary"
              onClick={handleSubmit}
              disabled={!file || submitting}
            >
              {submitting ? <><span className="spinning">⟳</span> Submitting…</> : "⟳ Submit to Queue"}
            </button>
          </div>
          {submitResult && (
            <div style={{ marginTop: 12, padding: "10px 14px", background: "var(--accent-dim)", borderRadius: "var(--radius-md)", border: "1px solid var(--border-bright)", fontSize: 13, color: "var(--accent)" }}>
              Job #{submitResult.job_id} submitted. Auto-polling every 2 seconds…
            </div>
          )}
        </div>

        {/* Jobs list */}
        {jobs.length === 0 ? (
          <div className="empty-state">
            <span className="empty-state-icon">⟳</span>
            <h3>No jobs yet</h3>
            <p>Submit a file above to add it to the Celery worker queue</p>
          </div>
        ) : (
          <div className="card">
            <div className="card-title">Recent Jobs ({jobs.length})</div>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Job ID</th>
                  <th>File</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th>Completed</th>
                  <th>Confidence</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((job) => {
                  const artifact = job.artifacts?.[0];
                  return (
                    <tr key={job.job_id}>
                      <td><span className="mono" style={{ color: "var(--accent)" }}>#{job.job_id}</span></td>
                      <td style={{ maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis" }}>{job.target}</td>
                      <td>
                        <span className={`job-status ${job.status}`}>
                          {job.status === "running" && <span className="spinning">⟳</span>}
                          {job.status}
                        </span>
                      </td>
                      <td style={{ color: "var(--text-secondary)", fontSize: 12 }}>
                        {job.created_at ? new Date(job.created_at).toLocaleTimeString() : "—"}
                      </td>
                      <td style={{ color: "var(--text-secondary)", fontSize: 12 }}>
                        {job.completed_at ? new Date(job.completed_at).toLocaleTimeString() : "—"}
                      </td>
                      <td>
                        {artifact ? (
                          <span style={{ color: artifact.confidence_score >= 0.6 ? "var(--threat-critical)" : artifact.confidence_score > 0 ? "var(--threat-medium)" : "var(--threat-low)", fontWeight: 700 }}>
                            {Math.round(artifact.confidence_score * 100)}%
                          </span>
                        ) : "—"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}
