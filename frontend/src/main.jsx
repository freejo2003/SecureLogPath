import React from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

function App() {
  const [apiStatus, setApiStatus] = React.useState("Checking services…");

  React.useEffect(() => {
    fetch("/api/health/ready")
      .then((response) => {
        if (!response.ok) throw new Error("API is not ready");
        return response.json();
      })
      .then(() => setApiStatus("API and database are ready"))
      .catch(() => setApiStatus("Waiting for API and database"));
  }, []);

  return (
    <main className="shell">
      <div className="eyebrow">ACADEMIC MINI-SIEM</div>
      <h1>SecureLogPath</h1>
      <p className="intro">
        An inspectable demonstrator for secure log processing and security
        algorithms.
      </p>
      <section className="status" aria-live="polite">
        <span className="status-dot" />
        <span>{apiStatus}</span>
      </section>
      <p className="notice">
        Phase 1 foundation. Use synthetic scenarios only; this is not a
        production SIEM.
      </p>
    </main>
  );
}

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
