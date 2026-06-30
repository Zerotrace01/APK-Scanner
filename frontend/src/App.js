import React, { useCallback, useEffect, useRef, useState } from "react";

const API_BASE = process.env.REACT_APP_API_URL || "/api";

const STAGES = [
  { min: 0, label: "Queued" },
  { min: 10, label: "Static analysis" },
  { min: 30, label: "Obfuscation scan" },
  { min: 40, label: "Dynamic sandbox" },
  { min: 70, label: "C2 detection" },
  { min: 85, label: "Correlation" },
  { min: 100, label: "Complete" },
];

function stageForProgress(progress) {
  let current = STAGES[0];
  for (const s of STAGES) {
    if (progress >= s.min) current = s;
  }
  return current.label;
}

function TableSection({ columns, rows, empty }) {
  if (!rows || rows.length === 0) {
    return <p className="empty">{empty}</p>;
  }
  return (
    <table>
      <thead>
        <tr>
          {columns.map((c) => (
            <th key={c.key}>{c.label}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((row, i) => (
          <tr key={i}>
            {columns.map((c) => (
              <td key={c.key}>{row[c.key]}</td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function App() {
  const [health, setHealth] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [jobId, setJobId] = useState(null);
  const [filename, setFilename] = useState("");
  const [status, setStatus] = useState(null);
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState("overview");
  const fileInputRef = useRef(null);
  const pollRef = useRef(null);

  useEffect(() => {
    fetch(`${API_BASE}/health`)
      .then((r) => r.json())
      .then((d) => setHealth(d.status === "ok"))
      .catch(() => setHealth(false));
  }, []);

  const clearPoll = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  useEffect(() => () => clearPoll(), []);

  const pollJob = useCallback((id) => {
    clearPoll();
    pollRef.current = setInterval(async () => {
      try {
        const res = await fetch(`${API_BASE}/status/${id}`);
        if (!res.ok) throw new Error("Failed to fetch status");
        const data = await res.json();
        setStatus(data);

        if (data.status === "DONE") {
          clearPoll();
          const reportRes = await fetch(`${API_BASE}/report/${id}`);
          if (!reportRes.ok) throw new Error("Failed to fetch report");
          setReport(await reportRes.json());
          setUploading(false);
        } else if (data.status === "FAILED") {
          clearPoll();
          setError(data.error_message || "Analysis failed");
          setUploading(false);
        }
      } catch (e) {
        clearPoll();
        setError(e.message);
        setUploading(false);
      }
    }, 2000);
  }, []);

  const uploadApk = async (file) => {
    if (!file || !file.name.toLowerCase().endsWith(".apk")) {
      setError("Please select a valid .apk file");
      return;
    }

    setError(null);
    setReport(null);
    setStatus(null);
    setUploading(true);
    setFilename(file.name);

    const form = new FormData();
    form.append("file", file);

    try {
      const res = await fetch(`${API_BASE}/analyze`, { method: "POST", body: form });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Upload failed");
      }
      const data = await res.json();
      setJobId(data.job_id);
      setStatus({ status: "QUEUED", progress: 0, filename: file.name });
      pollJob(data.job_id);
    } catch (e) {
      setError(e.message);
      setUploading(false);
    }
  };

  const onDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    uploadApk(file);
  };

  const downloadPdf = () => {
    if (!jobId) return;
    window.open(`${API_BASE}/report/${jobId}/pdf`, "_blank");
  };

  const reset = () => {
    clearPoll();
    setJobId(null);
    setFilename("");
    setStatus(null);
    setReport(null);
    setError(null);
    setUploading(false);
    setTab("overview");
  };

  const progress = status?.progress ?? 0;
  const verdict = report?.verdict ?? "";
  const score = report?.final_score ?? 0;
  const staticData = report?.static ?? {};
  const dynamicData = report?.dynamic ?? {};
  const c2Data = report?.c2 ?? {};
  const correlation = report?.correlation ?? {};

  return (
    <div className="app">
      <header>
        <div>
          <h1>DroidScan</h1>
          <p>APK Threat Analysis with C2 Detection</p>
        </div>
        <div className={`health ${health ? "ok" : ""}`}>
          API: {health === null ? "checking…" : health ? "online" : "offline"}
        </div>
      </header>

      {!report && (
        <div
          className={`upload-zone ${dragOver ? "dragover" : ""}`}
          onDragOver={(e) => {
            e.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={onDrop}
          onClick={() => fileInputRef.current?.click()}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".apk"
            onChange={(e) => uploadApk(e.target.files[0])}
          />
          <h2>Drop APK here or click to upload</h2>
          <p>Static analysis, obfuscation detection, C2 scoring, MITRE mapping</p>
        </div>
      )}

      {uploading && status && !report && (
        <div className="progress-card">
          <strong>{filename || status.filename}</strong>
          <div className="progress-bar">
            <div className="progress-fill" style={{ width: `${progress}%` }} />
          </div>
          <div>
            {status.status} — {progress}% — {stageForProgress(progress)}
          </div>
          <div className="stages">
            {STAGES.map((s) => (
              <span
                key={s.label}
                className={`stage ${
                  progress >= s.min ? (progress >= 100 ? "done" : "active") : ""
                }`}
              >
                {s.label}
              </span>
            ))}
          </div>
        </div>
      )}

      {error && <div className="error-box">{error}</div>}

      {report && (
        <div className="results">
          <div className="verdict-row">
            <div className="gauge">
              <span className="score">{score}</span>
              <span className="label">Risk score</span>
            </div>
            <div>
              <span className={`verdict-badge ${verdict}`}>{verdict}</span>
              <p style={{ color: "var(--muted)", marginTop: 8 }}>{filename}</p>
              <div className="actions">
                <button type="button" onClick={downloadPdf}>
                  Download PDF report
                </button>
                <button type="button" className="secondary" onClick={reset}>
                  Analyze another APK
                </button>
              </div>
            </div>
          </div>

          <div className="tabs">
            {[
              "overview",
              "permissions",
              "c2",
              "mitre",
              "network",
              "correlation",
              "obfuscation",
            ].map((t) => (
              <button
                key={t}
                type="button"
                className={`tab ${tab === t ? "active" : ""}`}
                onClick={() => setTab(t)}
              >
                {t.charAt(0).toUpperCase() + t.slice(1)}
              </button>
            ))}
          </div>

          <div className="panel">
            {tab === "overview" && (
              <>
                <h3>Application metadata</h3>
                <div className="meta-grid">
                  {Object.entries(staticData.meta || {}).map(([k, v]) => (
                    <div key={k} className="meta-item">
                      <div className="key">{k.replace(/_/g, " ")}</div>
                      <div className="val">{String(v)}</div>
                    </div>
                  ))}
                </div>
                <h3 style={{ marginTop: 20 }}>Summary</h3>
                <ul>
                  <li>Static risk: {staticData.risk_score ?? 0}/100</li>
                  <li>
                    ML score: {c2Data.ml_result?.ml_score ?? "—"} (
                    {c2Data.ml_result?.source ?? "n/a"})
                  </li>
                  <li>
                    Confirmed patterns: {correlation.total_confirmed ?? 0}
                  </li>
                  <li>
                    Obfuscation:{" "}
                    {staticData.obfuscation?.obfuscation_level ?? "UNKNOWN"} (
                    {staticData.obfuscation?.obfuscation_score ?? 0}/100)
                  </li>
                  <li>YARA hits: {(staticData.yara || []).length}</li>
                  <li>
                    Frida events: {(dynamicData.frida_events || []).length}
                  </li>
                </ul>
              </>
            )}

            {tab === "permissions" && (
              <>
                <h3>Dangerous permissions ({staticData.permissions?.total ?? 0} total)</h3>
                <TableSection
                  empty="No dangerous permissions flagged."
                  columns={[
                    { key: "permission", label: "Permission" },
                    { key: "risk", label: "Risk" },
                  ]}
                  rows={(staticData.permissions?.flagged || []).map((p) => ({
                    permission: p.permission.split(".").pop(),
                    risk: p.risk,
                  }))}
                />
                <h3 style={{ marginTop: 20 }}>Suspicious APIs</h3>
                <TableSection
                  empty="No suspicious API calls found."
                  columns={[
                    { key: "api", label: "API" },
                    { key: "description", label: "Description" },
                  ]}
                  rows={staticData.apis || []}
                />
              </>
            )}

            {tab === "c2" && (
              <>
                <h3>C2 indicators</h3>
                <TableSection
                  empty="No C2 indicators detected."
                  columns={[
                    { key: "id", label: "ID" },
                    { key: "name", label: "Name" },
                    { key: "severity", label: "Severity" },
                  ]}
                  rows={c2Data.c2_indicators || []}
                />
                <h3 style={{ marginTop: 20 }}>Threat intelligence</h3>
                <TableSection
                  empty="No IOCs checked or no API keys configured."
                  columns={[
                    { key: "target", label: "Target" },
                    { key: "result", label: "Result" },
                  ]}
                  rows={[
                    ...(c2Data.threat_intel?.ips || []).map((r) => ({
                      target: r.ip,
                      result: r.is_malicious
                        ? `Malicious (score ${r.abuse_score}%)`
                        : r.note || "Clean / unknown",
                    })),
                    ...(c2Data.threat_intel?.domains || []).map((r) => ({
                      target: r.domain,
                      result: r.is_malicious
                        ? `Malicious (${r.malicious} VT hits)`
                        : r.note || "Clean / unknown",
                    })),
                  ]}
                />
              </>
            )}

            {tab === "mitre" && (
              <>
                <h3>MITRE ATT&amp;CK for Mobile</h3>
                <TableSection
                  empty="No MITRE techniques mapped."
                  columns={[
                    { key: "technique_id", label: "ID" },
                    { key: "name", label: "Technique" },
                    { key: "tactic", label: "Tactic" },
                  ]}
                  rows={c2Data.mitre_tags || []}
                />
              </>
            )}

            {tab === "network" && (
              <>
                <h3>Captured network traffic</h3>
                <TableSection
                  empty="No network traffic captured (sandbox may be skipped)."
                  columns={[
                    { key: "method", label: "Method" },
                    { key: "host", label: "Host" },
                    { key: "url", label: "URL" },
                  ]}
                  rows={(dynamicData.network_traffic || []).slice(0, 50)}
                />
                <h3 style={{ marginTop: 20 }}>Frida runtime events</h3>
                <TableSection
                  empty="No runtime events captured."
                  columns={[
                    { key: "type", label: "Type" },
                    { key: "data", label: "Data" },
                  ]}
                  rows={(dynamicData.frida_events || []).slice(0, 50).map((e) => ({
                    type: e.type,
                    data: JSON.stringify(e.data).slice(0, 120),
                  }))}
                />
                {(dynamicData.sandbox_errors || []).length > 0 && (
                  <>
                    <h3 style={{ marginTop: 20 }}>Sandbox notes</h3>
                    <ul>
                      {dynamicData.sandbox_errors.map((msg, i) => (
                        <li key={i}>{msg}</li>
                      ))}
                    </ul>
                  </>
                )}
              </>
            )}

            {tab === "correlation" && (
              <>
                <h3>Confirmed attack patterns</h3>
                {(correlation.confirmed || []).length === 0 ? (
                  <p className="empty">No attack patterns confirmed.</p>
                ) : (
                  correlation.confirmed.map((p) => (
                    <div key={p.id} className={`pattern-card ${p.severity}`}>
                      <div className="title">
                        {p.id}: {p.name} ({p.confidence}% confidence)
                      </div>
                      <p>{p.description}</p>
                      <ul className="evidence-list">
                        {(p.evidence || []).map((ev, i) => (
                          <li key={i}>{ev}</li>
                        ))}
                      </ul>
                    </div>
                  ))
                )}
                <h3 style={{ marginTop: 20 }}>Partial matches</h3>
                {(correlation.partial || []).length === 0 ? (
                  <p className="empty">No partial patterns.</p>
                ) : (
                  correlation.partial.map((p) => (
                    <div key={p.id} className="pattern-card HIGH">
                      <div className="title">
                        {p.id}: {p.name} ({p.signals_hit}/{p.signals_total} signals)
                      </div>
                    </div>
                  ))
                )}
              </>
            )}

            {tab === "obfuscation" && (
              <>
                <h3>
                  Level: {staticData.obfuscation?.obfuscation_level ?? "UNKNOWN"} —{" "}
                  {staticData.obfuscation?.obfuscation_score ?? 0}/100
                </h3>
                <p>{staticData.obfuscation?.summary}</p>
                {Object.entries(staticData.obfuscation?.checks || {}).map(
                  ([name, check]) => (
                    <div key={name} style={{ marginTop: 16 }}>
                      <strong>{name.replace(/_/g, " ")}</strong> (score{" "}
                      {check.score ?? 0})
                      <p>{check.detail}</p>
                    </div>
                  )
                )}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
