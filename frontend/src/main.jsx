import React from "react";
import { createRoot } from "react-dom/client";
import { apiRequest, watchAlerts } from "./api.js";
import "./style.css";

const roleTabs = {
  forwarder: [{ id: "upload", label: "Ingestion" }],
  analyst: [
    { id: "overview", label: "Overview" },
    { id: "logs", label: "Log search" },
    { id: "alerts", label: "Alerts" },
    { id: "topology", label: "Topology" },
    { id: "benchmarks", label: "Benchmarks" },
  ],
  admin: [
    { id: "overview", label: "Overview" },
    { id: "logs", label: "Log search" },
    { id: "alerts", label: "Alerts" },
    { id: "topology", label: "Topology" },
    { id: "benchmarks", label: "Benchmarks" },
    { id: "users", label: "Team access" },
  ],
};

function App() {
  const [health, setHealth] = React.useState("checking");
  const [token, setToken] = React.useState("");
  const [user, setUser] = React.useState(null);
  const [notice, setNotice] = React.useState(null);
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    fetch("/api/health/ready")
      .then((response) => { if (!response.ok) throw new Error("Services unavailable"); setHealth("ready"); })
      .catch(() => setHealth("offline"));
  }, []);

  async function signIn(username, password) {
    setBusy(true);
    setNotice(null);
    try {
      const session = await apiRequest("/auth/login", null, {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      const profile = await apiRequest("/auth/me", session.access_token);
      setToken(session.access_token);
      setUser(profile);
    } catch (error) {
      setNotice({ kind: "error", text: error.message || "Sign in failed" });
    } finally {
      setBusy(false);
    }
  }

  function signOut() {
    setToken("");
    setUser(null);
    setNotice({ kind: "info", text: "You have signed out." });
  }

  return user && token ? (
    <Dashboard
      token={token}
      user={user}
      onSignOut={signOut}
      notice={notice}
      setNotice={setNotice}
    />
  ) : (
    <SignIn
      health={health}
      busy={busy}
      notice={notice}
      onSignIn={signIn}
    />
  );
}

function SignIn({ health, busy, notice, onSignIn }) {
  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  function submit(event) {
    event.preventDefault();
    onSignIn(username, password);
  }
  return (
    <main className="login-layout">
      <section className="login-aside">
        <div className="brand-mark" aria-hidden="true">SL</div>
        <p className="eyebrow">SECURELOGPATH · MINI-SIEM</p>
        <h1>See the signal.<br /><span>Understand the path.</span></h1>
        <p className="login-copy">A hands-on security operations demonstrator for encrypted log intake, detection, and investigation.</p>
        <div className="service-pill"><span className={`health-dot ${health}`} />{health === "ready" ? "Services ready" : health === "offline" ? "Waiting for services" : "Checking services"}</div>
        <p className="aside-foot">Use synthetic scenarios only. This demo does not monitor or control real systems.</p>
      </section>
      <section className="login-panel">
        <div className="login-form-wrap">
          <p className="eyebrow accent">WELCOME BACK</p>
          <h2>Sign in</h2>
          <p className="muted">Use the account created by your SecureLogPath administrator.</p>
          {notice && <Notice notice={notice} />}
          <form onSubmit={submit} className="form-stack">
            <label>Username<input autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} required /></label>
            <label>Password<input autoComplete="current-password" type="password" value={password} onChange={(event) => setPassword(event.target.value)} required /></label>
            <button className="button primary full" disabled={busy || health === "offline"}>{busy ? "Signing in…" : "Sign in"}<span aria-hidden="true">→</span></button>
          </form>
          <p className="privacy-note">Your session token stays in this browser tab and is cleared when you sign out or refresh.</p>
        </div>
      </section>
    </main>
  );
}

function Dashboard({ token, user, onSignOut, notice, setNotice }) {
  const tabs = roleTabs[user.role] || [];
  const [active, setActive] = React.useState(tabs[0]?.id || "overview");
  const [streamStatus, setStreamStatus] = React.useState("connecting");
  const [liveAlerts, setLiveAlerts] = React.useState([]);
  const noticeTimer = React.useRef(null);

  React.useEffect(() => {
    if (!new Set(["analyst", "admin"]).has(user.role)) return undefined;
    const controller = new AbortController();
    watchAlerts(token, {
      signal: controller.signal,
      onStatus: setStreamStatus,
      onAlert: (alert) => setLiveAlerts((current) => [alert, ...current].slice(0, 30)),
    });
    return () => controller.abort();
  }, [token, user.role]);

  function showNotice(kind, text) {
    setNotice({ kind, text });
    window.clearTimeout(noticeTimer.current);
    noticeTimer.current = window.setTimeout(() => setNotice(null), 5000);
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand"><div className="brand-mark small">SL</div><div><strong>SecureLogPath</strong><span>Security operations lab</span></div></div>
        <div className="workspace-label">WORKSPACE</div>
        <nav aria-label="Main navigation" className="side-nav">
          {tabs.map((tab) => <button key={tab.id} className={`nav-item ${active === tab.id ? "selected" : ""}`} onClick={() => setActive(tab.id)}><NavIcon name={tab.id} /><span>{tab.label}</span>{tab.id === "alerts" && liveAlerts.length > 0 && <b className="nav-count">{liveAlerts.length}</b>}</button>)}
        </nav>
        <div className="sidebar-bottom">
          <div className="connection-card"><span className={`health-dot ${streamStatus === "live" ? "ready" : streamStatus === "attention" ? "offline" : "checking"}`} /><div><b>{streamStatus === "live" ? "Alert stream live" : streamStatus === "attention" ? "Alert stream needs attention" : "Connecting alert stream"}</b><span>Live alert updates</span></div></div>
          <button className="profile-button" onClick={onSignOut}><div className="avatar">{user.username.slice(0, 1).toUpperCase()}</div><div className="profile-copy"><b>{user.username}</b><span>{user.role}</span></div><span className="signout">Sign out</span></button>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar"><div><span className="topbar-kicker">SECURELOGPATH</span><span className="breadcrumb">/ {tabs.find((tab) => tab.id === active)?.label || "Workspace"}</span></div><div className="topbar-right"><span className="environment-tag"><i /> Local demo</span><button className="icon-button" title="Sign out" onClick={onSignOut}><NavIcon name="signout" /></button></div></header>
        {notice && <div className="toast-wrap"><Notice notice={notice} onClose={() => setNotice(null)} /></div>}
        <div className="page-content">
          {active === "overview" && <Overview token={token} user={user} onNavigate={setActive} liveAlerts={liveAlerts} streamStatus={streamStatus} />}
          {active === "upload" && <UploadPanel token={token} onNotice={showNotice} />}
          {active === "logs" && <LogsPanel token={token} />}
          {active === "alerts" && <AlertsPanel token={token} liveAlerts={liveAlerts} streamStatus={streamStatus} />}
          {active === "topology" && <TopologyPanel token={token} onNotice={showNotice} />}
          {active === "benchmarks" && <BenchmarksPanel token={token} onNotice={showNotice} />}
          {active === "users" && <UsersPanel token={token} onNotice={showNotice} />}
        </div>
        <footer className="app-footer"><span>SecureLogPath · academic demonstrator</span><span>Containment is simulated · use synthetic data</span></footer>
      </main>
    </div>
  );
}

function Overview({ token, user, onNavigate, liveAlerts, streamStatus }) {
  const [data, setData] = React.useState({ logs: [], alerts: [] });
  const [loading, setLoading] = React.useState(true);
  React.useEffect(() => {
    let current = true;
    Promise.all([
      apiRequest("/logs?limit=6", token),
      apiRequest("/alerts?limit=6", token),
    ]).then(([logs, alerts]) => {
      if (current) setData({ logs: logs.items, alerts: alerts.items });
    }).catch(() => {}).finally(() => current && setLoading(false));
    return () => { current = false; };
  }, [token]);

  if (user.role === "forwarder") return <UploadPanel token={token} />;
  const latestAlerts = [...liveAlerts, ...data.alerts].filter((alert, index, list) => list.findIndex((item) => item.id === alert.id) === index).slice(0, 5);
  return (
    <>
      <PageHeading eyebrow="OPERATIONS SNAPSHOT" title={`Good to see you, ${user.username}`} subtitle="A current view of ingested events, detections, and the simulated environment." />
      <section className="metric-grid">
        <MetricCard label="Recent log records" value={loading ? "—" : data.logs.length} meta="Safe searchable metadata" icon="logs" tone="blue" />
        <MetricCard label="Recent alerts" value={loading ? "—" : data.alerts.length} meta="Latest page · up to 6" icon="alerts" tone="orange" />
        <MetricCard label="Live updates" value={streamStatus === "live" ? "Live" : "Connecting"} meta="Resumable alert stream" icon="activity" tone="green" />
      </section>
      <section className="content-grid overview-grid">
        <div className="panel">
          <div className="panel-heading"><div><span className="eyebrow">DETECTION FEED</span><h3>Recent alerts</h3></div><button className="text-button" onClick={() => onNavigate("alerts")}>View all <span>→</span></button></div>
          <AlertList alerts={latestAlerts} emptyText="No alerts yet. Upload a synthetic scenario to see detections here." />
        </div>
        <div className="panel quick-panel"><span className="eyebrow">QUICK ACCESS</span><h3>Investigate a signal</h3><p className="muted">Search safe event metadata, trace a modeled path, or compare algorithms on a repeatable dataset.</p>
          <button className="quick-link" onClick={() => onNavigate("logs")}><span className="quick-icon blue"><NavIcon name="logs" /></span><span><b>Search logs</b><small>Filter by time, asset, or event type</small></span><span className="chevron">→</span></button>
          <button className="quick-link" onClick={() => onNavigate("topology")}><span className="quick-icon purple"><NavIcon name="topology" /></span><span><b>Explore topology</b><small>Find modeled paths and simulate blocks</small></span><span className="chevron">→</span></button>
          <button className="quick-link" onClick={() => onNavigate("benchmarks")}><span className="quick-icon green"><NavIcon name="benchmarks" /></span><span><b>Run a benchmark</b><small>Compare sort and sample estimates</small></span><span className="chevron">→</span></button>
        </div>
      </section>
      <div className="privacy-banner"><span className="privacy-icon">✦</span><div><b>Privacy by design</b><span>Search and dashboard responses show safe metadata only. Sensitive event fields remain encrypted at rest.</span></div></div>
    </>
  );
}

function UploadPanel({ token, onNotice }) {
  const [file, setFile] = React.useState(null);
  const [job, setJob] = React.useState(null);
  const [uploading, setUploading] = React.useState(false);
  const [error, setError] = React.useState("");

  React.useEffect(() => {
    if (!job?.job_id || !["queued", "processing", "submitted"].includes(job.status)) return undefined;
    let cancelled = false;
    let timer;
    const poll = async () => {
      try {
        const next = await apiRequest(`/ingestion/jobs/${job.job_id}`, token);
        if (!cancelled) setJob(next);
        if (!cancelled && ["queued", "processing", "submitted"].includes(next.status)) timer = window.setTimeout(poll, 1200);
      } catch (requestError) {
        if (!cancelled) setError(requestError.message);
      }
    };
    timer = window.setTimeout(poll, 700);
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [job?.job_id, job?.status, token]);

  async function submit(event) {
    event.preventDefault();
    if (!file) return;
    const formElement = event.currentTarget;
    setUploading(true);
    setError("");
    const form = new FormData();
    form.append("file", file);
    try {
      const result = await apiRequest("/ingestion/uploads", token, { method: "POST", body: form });
      setJob({ ...result, job_id: result.job_id, line_errors: [] });
      setFile(null);
      formElement.reset();
      onNotice?.("success", "Upload accepted. Processing has started.");
    } catch (uploadError) {
      setError(uploadError.message || "Upload could not be submitted.");
    } finally {
      setUploading(false);
    }
  }

  return (
    <>
      <PageHeading eyebrow="SECURE INGESTION" title="Send encrypted event logs" subtitle="Upload a JSONL file prepared by your Forwarder. Each line is validated and processed independently." />
      <div className="content-grid upload-grid">
        <section className="panel">
          <div className="panel-heading"><div><span className="eyebrow">NEW UPLOAD</span><h3>Choose a JSONL file</h3></div><span className="badge neutral">Encrypted JSONL</span></div>
          <form onSubmit={submit} className="form-stack">
            <label className={`dropzone ${file ? "has-file" : ""}`} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); setFile(event.dataTransfer.files?.[0] || null); }}>
              <input type="file" accept=".jsonl,application/jsonl,application/x-ndjson" onChange={(event) => setFile(event.target.files?.[0] || null)} />
              <span className="upload-cloud">↑</span><b>{file ? file.name : "Choose a JSONL file"}</b><small>{file ? `${formatBytes(file.size)} · ready to upload` : "Browse to select a file, or drop it here"}</small>
            </label>
            <div className="upload-facts"><span><b>2 MB</b><small>maximum file</small></span><span><b>5,000</b><small>maximum lines</small></span><span><b>Encrypted</b><small>before upload</small></span></div>
            {error && <Notice notice={{ kind: "error", text: error }} />}
            <button className="button primary" type="submit" disabled={!file || uploading}>{uploading ? "Submitting…" : "Upload and process"}<span>→</span></button>
          </form>
        </section>
        <aside className="panel side-note-panel"><span className="eyebrow">BEFORE YOU UPLOAD</span><h3>Protect sensitive data</h3><ul className="check-list"><li><span>✓</span>Upload only encrypted JSONL created for this project.</li><li><span>✓</span>Use synthetic data in the public demo.</li><li><span>✓</span>Do not upload real organization or personal logs.</li></ul><div className="note-box">Need a sample? Run <code>docker compose exec backend python -m app.demo_forwarder</code> from the project folder to send one synthetic encrypted event.</div></aside>
      </div>
      {job && <section className="panel job-panel"><div className="panel-heading"><div><span className="eyebrow">INGESTION JOB</span><h3>{job.source_filename || "Upload job"}</h3></div><StatusBadge status={job.status} /></div><div className="job-id">Job ID <code>{job.job_id}</code><button className="text-button" onClick={() => navigator.clipboard?.writeText(job.job_id)}>Copy</button></div><div className="job-stats"><MetricInline label="Total lines" value={job.total_lines} /><MetricInline label="Accepted" value={job.accepted_lines} tone="good" /><MetricInline label="Rejected" value={job.rejected_lines} tone={job.rejected_lines ? "bad" : ""} /></div>{job.line_errors?.length > 0 && <div className="error-list"><b>Safe validation codes</b>{job.line_errors.map((item) => <span key={`${item.line_number}-${item.error_code}`}>Line {item.line_number} · {item.error_code}</span>)}</div>}</section>}
      <p className="subtle-copy">Job status can be checked again after a refresh by entering its ID in the API documentation. The Forwarder account can only view its own jobs.</p>
    </>
  );
}

function LogsPanel({ token }) {
  const [filters, setFilters] = React.useState({ q: "", event_type: "", asset_id: "", severity: "", start: "", end: "" });
  const [page, setPage] = React.useState({ items: [], next_cursor: null });
  const [cursor, setCursor] = React.useState(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  async function search(nextCursor = null) {
    setLoading(true); setError(""); setCursor(nextCursor);
    const params = new URLSearchParams({ limit: "50" });
    for (const [key, value] of Object.entries(filters)) if (value) params.set(key, ["start", "end"].includes(key) ? new Date(value).toISOString() : value);
    if (nextCursor) params.set("cursor", nextCursor);
    try { setPage(await apiRequest(`/logs?${params}`, token)); }
    catch (requestError) { setError(requestError.message); }
    finally { setLoading(false); }
  }
  return <>
    <PageHeading eyebrow="INVESTIGATION" title="Search security logs" subtitle="Find records using indexed timestamps and safe metadata. Encrypted event contents are never included." />
    <section className="panel search-panel"><div className="filter-grid"><label>Search ID or event<input value={filters.q} onChange={(e) => setFilters({ ...filters, q: e.target.value })} placeholder="Log ID, asset ID, or event text" /></label><label>Event type<input value={filters.event_type} onChange={(e) => setFilters({ ...filters, event_type: e.target.value })} placeholder="e.g. demo_http_request" /></label><label>Asset ID<input value={filters.asset_id} onChange={(e) => setFilters({ ...filters, asset_id: e.target.value })} placeholder="Any source or destination" /></label><label>Alert severity<select value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })}><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select></label><label>From (inclusive)<input type="datetime-local" value={filters.start} onChange={(e) => setFilters({ ...filters, start: e.target.value })} /></label><label>To (exclusive)<input type="datetime-local" value={filters.end} onChange={(e) => setFilters({ ...filters, end: e.target.value })} /></label></div><div className="filter-actions"><span className="muted">Search uses safe event, asset, and alert metadata.</span><button className="button primary" onClick={() => search(null)} disabled={loading}>{loading ? "Searching…" : "Search logs"}<span>⌕</span></button></div>{error && <Notice notice={{ kind: "error", text: error }} />}</section>
    <section className="panel table-panel"><div className="panel-heading"><div><span className="eyebrow">RESULTS</span><h3>Log records <span className="count-tag">{page.items.length}</span></h3></div>{cursor && <button className="text-button" onClick={() => search(null)}>Reset pages</button>}</div><div className="table-scroll"><table><thead><tr><th>Time</th><th>Event</th><th>Source</th><th>Destination</th><th>Detection</th><th>Log ID</th></tr></thead><tbody>{page.items.map((item) => <tr key={item.log_id}><td className="nowrap">{formatDate(item.occurred_at)}</td><td><span className="event-label">{item.event_type}</span></td><td>{item.source_asset_id || "—"}</td><td>{item.destination_asset_id || "—"}</td><td><SeverityList values={item.severities} /></td><td><code className="short-id">{item.log_id.slice(0, 8)}…</code></td></tr>)}</tbody></table>{!page.items.length && <EmptyState title={loading ? "Searching records…" : "No records to show"} body="Choose filters and search, or try the synthetic demo event type." />}</div>{page.next_cursor && <div className="pagination"><span>Showing this page of matching records</span><button className="button secondary" onClick={() => search(page.next_cursor)} disabled={loading}>Older records <span>→</span></button></div>}</section>
  </>;
}

function AlertsPanel({ token, liveAlerts, streamStatus }) {
  const [filters, setFilters] = React.useState({ severity: "", category: "", asset_id: "", start: "", end: "" });
  const [page, setPage] = React.useState({ items: [], next_cursor: null });
  const [cursor, setCursor] = React.useState(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  async function refresh(nextCursor = null) {
    setLoading(true); setError("");
    const params = new URLSearchParams({ limit: "50" });
    for (const [key, value] of Object.entries(filters)) if (value) params.set(key, ["start", "end"].includes(key) ? new Date(value).toISOString() : value);
    if (nextCursor) params.set("cursor", nextCursor);
    setCursor(nextCursor);
    try { setPage(await apiRequest(`/alerts?${params}`, token)); }
    catch (requestError) { setError(requestError.message); }
    finally { setLoading(false); }
  }
  React.useEffect(() => { refresh(); }, [token]);
  const merged = [...liveAlerts, ...page.items].filter((alert, index, all) => all.findIndex((item) => item.id === alert.id) === index).slice(0, 50);
  return <>
    <PageHeading eyebrow="DETECTION CENTER" title="Alerts" subtitle="Review persisted detections and watch new alerts arrive live." action={<span className={`stream-pill ${streamStatus}`}><i />{streamStatus === "live" ? "Live stream connected" : streamStatus === "attention" ? "Stream reconnecting" : "Connecting"}</span>} />
    <section className="panel search-panel compact-search"><div className="filter-grid"><label>Severity<select value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })}><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select></label><label>Category<input value={filters.category} onChange={(e) => setFilters({ ...filters, category: e.target.value })} placeholder="e.g. sql_injection" /></label><label>Asset ID<input value={filters.asset_id} onChange={(e) => setFilters({ ...filters, asset_id: e.target.value })} placeholder="Source or destination" /></label><label>From (inclusive)<input type="datetime-local" value={filters.start} onChange={(e) => setFilters({ ...filters, start: e.target.value })} /></label><label>To (exclusive)<input type="datetime-local" value={filters.end} onChange={(e) => setFilters({ ...filters, end: e.target.value })} /></label></div><div className="filter-actions"><span className="muted">Persisted alerts plus recent live events.</span><button className="button secondary" onClick={() => refresh(null)} disabled={loading}>{loading ? "Refreshing…" : "Apply filters"}</button></div>{error && <Notice notice={{ kind: "error", text: error }} />}</section>
    <section className="panel"><div className="panel-heading"><div><span className="eyebrow">PERSISTED + LIVE</span><h3>Detection feed <span className="count-tag">{merged.length}</span></h3></div></div><AlertList alerts={merged} emptyText="No alerts found. Try a different filter or send a synthetic scenario." />{page.next_cursor && <div className="pagination"><span>{cursor ? "Older alerts" : "More persisted alerts"}</span><button className="button secondary" onClick={() => refresh(page.next_cursor)} disabled={loading}>Older alerts <span>→</span></button></div>}</section>
    <div className="privacy-banner"><span className="privacy-icon">↻</span><div><b>Reconnects recover missed alerts</b><span>The stream resumes from its last event cursor. Alert details contain safe metadata only.</span></div></div>
  </>;
}

function TopologyPanel({ token, onNotice }) {
  const [topology, setTopology] = React.useState({ nodes: [], edges: [] });
  const [path, setPath] = React.useState(null);
  const [source, setSource] = React.useState("internet");
  const [destination, setDestination] = React.useState("db-server-01");
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");
  async function refresh() {
    setLoading(true); setError("");
    try { setTopology(await apiRequest("/topology", token)); }
    catch (requestError) { setError(requestError.message); }
    finally { setLoading(false); }
  }
  React.useEffect(() => { refresh(); }, [token]);
  async function findPath(event) {
    event.preventDefault(); setError("");
    try { setPath(await apiRequest("/topology/path", token, { method: "POST", body: JSON.stringify({ source_id: source, destination_id: destination }) })); }
    catch (requestError) { setError(requestError.message); }
  }
  async function toggleEdge(edge) {
    const blocked = !edge.is_blocked;
    try {
      await apiRequest("/topology/containment", token, { method: "POST", body: JSON.stringify({ source_id: edge.source_id, destination_id: edge.destination_id, blocked }) });
      await refresh();
      onNotice(blocked ? "success" : "info", blocked ? "Simulated edge blocked." : "Simulated edge restored.");
    } catch (requestError) { setError(requestError.message); }
  }
  return <>
    <PageHeading eyebrow="NETWORK MODEL" title="Topology & path analysis" subtitle="Explore the seeded environment and test how simulated edge blocks affect modeled reachability." action={<button className="button secondary" onClick={refresh}>Refresh topology</button>} />
    <div className="content-grid topology-grid">
      <section className="panel path-panel"><div className="panel-heading"><div><span className="eyebrow">ROUTE ANALYSIS</span><h3>Find a modeled path</h3></div><span className="quick-icon purple"><NavIcon name="topology" /></span></div><form className="path-form" onSubmit={findPath}><label>From<select value={source} onChange={(e) => setSource(e.target.value)}>{topology.nodes.map((node) => <option value={node.id} key={node.id}>{node.label}</option>)}</select></label><span className="path-arrow">→</span><label>To<select value={destination} onChange={(e) => setDestination(e.target.value)}>{topology.nodes.map((node) => <option value={node.id} key={node.id}>{node.label}</option>)}</select></label><button className="button primary" disabled={loading}>Analyze path</button></form>{path && <div className={`path-result ${path.reachable ? "reachable" : "unreachable"}`}><div className="path-result-heading"><b>{path.reachable ? "Path found" : "No available path"}</b><span>{path.reachable ? `${path.edge_count} hops · modeled cost ${path.total_modeled_cost}` : "Try restoring a blocked edge"}</span></div>{path.reachable && <div className="path-nodes">{path.nodes.map((node, index) => <React.Fragment key={node}><span className="path-node">{node}</span>{index < path.nodes.length - 1 && <span className="path-arrow">→</span>}</React.Fragment>)}</div>}<small>{path.cost_interpretation}</small></div>}{error && <Notice notice={{ kind: "error", text: error }} />}</section>
      <aside className="panel topology-summary"><span className="eyebrow">SIMULATED ENVIRONMENT</span><h3>Network at a glance</h3><div className="topology-counts"><MetricInline label="Assets" value={topology.nodes.length} /><MetricInline label="Connections" value={topology.edges.length} /><MetricInline label="Blocked" value={topology.edges.filter((edge) => edge.is_blocked).length} tone={topology.edges.some((edge) => edge.is_blocked) ? "bad" : ""} /></div><div className="note-box"><b>Simulation only</b><br />Changes apply only to this demo graph. They never send commands to real firewalls, endpoints, or cloud systems.</div></aside>
    </div>
    <section className="panel table-panel"><div className="panel-heading"><div><span className="eyebrow">ENVIRONMENT MAP</span><h3>Assets and connections</h3></div></div><div className="table-scroll"><table><thead><tr><th>From</th><th>To</th><th>Risk score</th><th>State</th><th>Simulation control</th></tr></thead><tbody>{topology.edges.map((edge) => <tr key={`${edge.source_id}-${edge.destination_id}`}><td><code>{edge.source_id}</code></td><td><code>{edge.destination_id}</code></td><td><span className="risk-value">{edge.risk_score}<small>/ 10</small></span></td><td><span className={`badge ${edge.is_blocked ? "danger" : "success"}`}>{edge.is_blocked ? "Blocked" : "Open"}</span></td><td><button className={`text-button ${edge.is_blocked ? "restore-action" : "block-action"}`} onClick={() => toggleEdge(edge)}>{edge.is_blocked ? "Restore edge" : "Block edge"}</button></td></tr>)}</tbody></table>{!topology.edges.length && <EmptyState title={loading ? "Loading topology…" : "Topology unavailable"} body="Refresh to load the simulated environment." />}</div></section>
  </>;
}

function BenchmarksPanel({ token, onNotice }) {
  const [form, setForm] = React.useState({ dataset_size: 5000, seed: 42, sample_fraction: 0.1 });
  const [latest, setLatest] = React.useState(null);
  const [history, setHistory] = React.useState([]);
  const [historyCursor, setHistoryCursor] = React.useState(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  async function loadHistory(cursor = null, append = false) {
    try {
      const params = new URLSearchParams({ limit: "20" });
      if (cursor) params.set("cursor", cursor);
      const result = await apiRequest(`/analytics/benchmarks?${params}`, token);
      setHistory((current) => append ? [...current, ...result.items] : result.items);
      setHistoryCursor(result.next_cursor);
    }
    catch (requestError) { setError(requestError.message); }
  }
  React.useEffect(() => { loadHistory(); }, [token]);
  async function run(event) {
    event.preventDefault(); setLoading(true); setError("");
    try {
      const result = await apiRequest("/analytics/benchmarks", token, { method: "POST", body: JSON.stringify({ dataset_size: Number(form.dataset_size), seed: Number(form.seed), sample_fraction: Number(form.sample_fraction) }) });
      setLatest(result); await loadHistory(); onNotice("success", "Benchmark run saved to history.");
    } catch (requestError) { setError(requestError.message); }
    finally { setLoading(false); }
  }
  const exactBaseline = latest?.result?.sampling?.exact_baseline;
  return <>
    <PageHeading eyebrow="ALGORITHM LAB" title="Benchmarks" subtitle="Run a reproducible synthetic workload. Results describe this demo environment, not production capacity." />
    <div className="content-grid benchmark-grid">
      <section className="panel"><div className="panel-heading"><div><span className="eyebrow">NEW RUN</span><h3>Configure the workload</h3></div><span className="quick-icon green"><NavIcon name="benchmarks" /></span></div><form onSubmit={run} className="form-stack"><div className="filter-grid three-col"><label>Dataset size<input type="number" min="100" max="20000" step="100" value={form.dataset_size} onChange={(e) => setForm({ ...form, dataset_size: e.target.value })} /></label><label>Random seed<input type="number" min="0" max="4294967295" value={form.seed} onChange={(e) => setForm({ ...form, seed: e.target.value })} /></label><label>Sample fraction<input type="number" min="0.01" max="0.3" step="0.01" value={form.sample_fraction} onChange={(e) => setForm({ ...form, sample_fraction: e.target.value })} /></label></div><p className="muted small-copy">Uses generated values only. A fixed seed reproduces the same dataset and sample.</p>{error && <Notice notice={{ kind: "error", text: error }} />}<button className="button primary" disabled={loading}>{loading ? "Running benchmark…" : "Run benchmark"}<span>→</span></button></form></section>
      <aside className="panel side-note-panel"><span className="eyebrow">WHAT YOU’LL SEE</span><h3>Two algorithm views</h3><div className="algorithm-note"><b>Randomized QuickSort</b><span>Compared with Python’s built-in sort; output equality is checked.</span></div><div className="algorithm-note"><b>Monte Carlo estimate</b><span>Sample-based proportion with a confidence interval and exact baseline when available.</span></div><div className="note-box">Timing is affected by the machine and current load. Compare runs on the same environment.</div></aside>
    </div>
    {latest && <section className="panel result-panel"><div className="panel-heading"><div><span className="eyebrow">LATEST RESULT · {formatDate(latest.created_at)}</span><h3>Run {latest.run_id.slice(0, 8)}</h3></div><span className={`badge ${latest.result.sorting.output_matches_reference ? "success" : "danger"}`}>{latest.result.sorting.output_matches_reference ? "Results match" : "Check result"}</span></div><div className="result-metrics"><MetricCard label="QuickSort" value={`${latest.result.sorting.elapsed_ms} ms`} meta={`Built-in sort: ${latest.result.sorting.reference_elapsed_ms} ms`} tone="blue" /><MetricCard label="Monte Carlo" value={`${(latest.result.sampling.estimate * 100).toFixed(1)}%`} meta={`Exact baseline: ${exactBaseline == null ? "not calculated for this size" : `${(exactBaseline * 100).toFixed(1)}%`}`} tone="green" /><MetricCard label="Confidence interval" value={`${(latest.result.sampling.confidence_interval[0] * 100).toFixed(1)}–${(latest.result.sampling.confidence_interval[1] * 100).toFixed(1)}%`} meta={`${latest.result.sampling.confidence_level * 100}% confidence`} tone="purple" /></div></section>}
    <section className="panel table-panel"><div className="panel-heading"><div><span className="eyebrow">SAVED RUNS</span><h3>Benchmark history <span className="count-tag">{history.length}</span></h3></div><button className="text-button" onClick={() => loadHistory()}>Refresh <span>↻</span></button></div><div className="table-scroll"><table><thead><tr><th>Created</th><th>Dataset</th><th>Seed</th><th>QuickSort</th><th>Match</th><th>Estimate</th></tr></thead><tbody>{history.map((run) => <tr key={run.run_id}><td>{formatDate(run.created_at)}</td><td>{run.dataset_size.toLocaleString()}</td><td>{run.seed}</td><td>{run.result.sorting.elapsed_ms} ms</td><td><span className={`badge ${run.result.sorting.output_matches_reference ? "success" : "danger"}`}>{run.result.sorting.output_matches_reference ? "Yes" : "No"}</span></td><td>{(run.result.sampling.estimate * 100).toFixed(1)}%</td></tr>)}</tbody></table>{!history.length && <EmptyState title="No benchmark runs yet" body="Run a synthetic benchmark to create the first history entry." />}</div>{historyCursor && <div className="pagination"><span>Showing {history.length} saved runs</span><button className="button secondary" onClick={() => loadHistory(historyCursor, true)}>Older runs <span>→</span></button></div>}</section>
  </>;
}

function UsersPanel({ token, onNotice }) {
  const [form, setForm] = React.useState({ username: "", password: "", role: "forwarder" });
  const [created, setCreated] = React.useState(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  async function submit(event) {
    event.preventDefault(); setLoading(true); setError("");
    const formElement = event.currentTarget;
    try {
      const result = await apiRequest("/admin/users", token, { method: "POST", body: JSON.stringify(form) });
      setCreated(result); setForm({ username: "", password: "", role: "forwarder" }); formElement.reset();
      onNotice("success", `${result.role} account created.`);
    } catch (requestError) { setError(requestError.message); }
    finally { setLoading(false); }
  }
  return <>
    <PageHeading eyebrow="ADMINISTRATION" title="Team access" subtitle="Create role-based accounts for the local demonstrator. Passwords are never shown after submission." />
    <div className="content-grid users-grid"><section className="panel"><div className="panel-heading"><div><span className="eyebrow">NEW ACCOUNT</span><h3>Create a user</h3></div><span className="quick-icon blue"><NavIcon name="users" /></span></div><form className="form-stack" onSubmit={submit}><label>Username<input autoComplete="off" minLength="3" maxLength="80" pattern="[A-Za-z0-9][A-Za-z0-9._-]*" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required /></label><label>Temporary password<input type="password" autoComplete="new-password" minLength="12" maxLength="128" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required /><small>At least 12 characters. Share it with the user through a secure channel.</small></label><label>Role<select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}><option value="forwarder">Forwarder · uploads encrypted logs</option><option value="analyst">Analyst · investigation and analytics</option><option value="admin">Admin · full demo access</option></select></label>{error && <Notice notice={{ kind: "error", text: error }} />}<button className="button primary" disabled={loading}>{loading ? "Creating…" : "Create account"}<span>→</span></button></form>{created && <div className="created-card"><span className="success-mark">✓</span><div><b>{created.username} is ready</b><span>{created.role} · created {formatDate(created.created_at)}</span></div></div>}</section><aside className="panel side-note-panel"><span className="eyebrow">ROLE GUIDE</span><h3>Choose the right access</h3><div className="role-row"><span className="role-dot forwarder"/><div><b>Forwarder</b><span>Uploads encrypted JSONL and checks its own job status.</span></div></div><div className="role-row"><span className="role-dot analyst"/><div><b>Analyst</b><span>Searches safe metadata, reviews alerts, explores paths, and runs benchmarks.</span></div></div><div className="role-row"><span className="role-dot admin"/><div><b>Admin</b><span>All Analyst capabilities plus account provisioning.</span></div></div></aside></div>
  </>;
}

function PageHeading({ eyebrow, title, subtitle, action }) {
  return <div className="page-heading"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p className="page-subtitle">{subtitle}</p></div>{action && <div className="heading-action">{action}</div>}</div>;
}

function MetricCard({ label, value, meta, icon, tone = "blue" }) {
  return <div className="metric-card"><span className={`metric-icon ${tone}`}>{icon && <NavIcon name={icon} />}</span><div className="metric-main"><span>{label}</span><strong>{value}</strong><small>{meta}</small></div></div>;
}

function MetricInline({ label, value, tone = "" }) {
  return <div className={`metric-inline ${tone}`}><span>{label}</span><b>{value}</b></div>;
}

function AlertList({ alerts, emptyText }) {
  if (!alerts.length) return <EmptyState title="Nothing new" body={emptyText} />;
  return <div className="alert-list">{alerts.map((alert) => <article className="alert-row" key={alert.id}><span className={`severity-mark ${alert.severity}`} /><div className="alert-content"><div className="alert-title-row"><b>{alert.signature_id}</b><Severity value={alert.severity} /></div><p>{alert.explanation}</p><div className="alert-meta"><span>{alert.category.replaceAll("_", " ")}</span><span>{alert.source_asset_id || "Unknown source"} → {alert.destination_asset_id || "Unknown destination"}</span><span>{formatDate(alert.detected_at)}</span></div></div></article>)}</div>;
}

function SeverityList({ values }) {
  if (!values?.length) return <span className="muted">None</span>;
  return <span className="severity-stack">{values.map((value) => <Severity key={value} value={value} />)}</span>;
}

function Severity({ value }) {
  return <span className={`severity-chip ${value}`}>{value}</span>;
}

function StatusBadge({ status }) {
  const tone = ["completed"].includes(status) ? "success" : ["failed", "interrupted", "completed_with_errors"].includes(status) ? "danger" : "neutral";
  return <span className={`badge ${tone}`}><i />{status?.replaceAll("_", " ") || "queued"}</span>;
}

function Notice({ notice, onClose }) {
  return <div className={`notice-banner ${notice.kind || "info"}`} role="status"><span>{notice.kind === "error" ? "!" : notice.kind === "success" ? "✓" : "i"}</span><p>{notice.text}</p>{onClose && <button onClick={onClose} aria-label="Dismiss">×</button>}</div>;
}

function EmptyState({ title, body }) {
  return <div className="empty-state"><span className="empty-symbol">⌕</span><b>{title}</b><span>{body}</span></div>;
}

function NavIcon({ name }) {
  const paths = {
    overview: <><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="4" rx="1"/><rect x="14" y="10" width="7" height="11" rx="1"/><rect x="3" y="13" width="7" height="8" rx="1"/></>,
    upload: <><path d="M12 16V4"/><path d="m7 9 5-5 5 5"/><path d="M5 20h14"/></>,
    logs: <><path d="M8 6h13M8 12h13M8 18h13"/><path d="M3 6h.01M3 12h.01M3 18h.01"/></>,
    alerts: <><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9"/><path d="M10 21h4"/></>,
    topology: <><circle cx="6" cy="6" r="3"/><circle cx="18" cy="6" r="3"/><circle cx="12" cy="18" r="3"/><path d="m8.5 7.5 2 7m5-7-2 7M9 6h6"/></>,
    benchmarks: <><path d="M4 19V5m0 14h17"/><path d="m7 15 4-4 3 2 6-7"/></>,
    users: <><path d="M16 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="10" cy="7" r="4"/><path d="M20 8v6m3-3h-6"/></>,
    activity: <><path d="M3 12h4l3-8 4 16 3-8h4"/></>,
    signout: <><path d="M10 17l5-5-5-5"/><path d="M15 12H3"/><path d="M12 3h6a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-6"/></>,
  };
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name] || paths.overview}</svg>;
}

function formatDate(value) {
  if (!value) return "—";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

function formatBytes(bytes) {
  return bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(0)} KB` : `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

createRoot(document.getElementById("root")).render(
  <React.StrictMode><App /></React.StrictMode>,
);
