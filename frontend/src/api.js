const API_ROOT = "/api/v1";

export async function apiRequest(path, token, options = {}) {
  const headers = new Headers(options.headers || {});
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (options.body && !(options.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(`${API_ROOT}${path}`, { ...options, headers });
  if (response.status === 204) return null;
  const contentType = response.headers.get("content-type") || "";
  const body = contentType.includes("application/json")
    ? await response.json()
    : await response.text();
  if (!response.ok) {
    const detail = typeof body === "object" && body?.detail
      ? body.detail
      : `Request failed (${response.status})`;
    const error = new Error(String(detail));
    error.status = response.status;
    throw error;
  }
  return body;
}

function parseEvent(block) {
  let id = "";
  let event = "message";
  const data = [];
  for (const line of block.split("\n")) {
    if (!line || line.startsWith(":")) continue;
    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    const value = colon === -1 ? "" : line.slice(colon + 1).replace(/^ /, "");
    if (field === "id") id = value;
    if (field === "event") event = value;
    if (field === "data") data.push(value);
  }
  return { id, event, data: data.join("\n") };
}

export async function watchAlerts(token, { signal, onAlert, onStatus }) {
  let lastEventId = "";
  while (!signal.aborted) {
    try {
      onStatus("connecting");
      const headers = new Headers({ Authorization: `Bearer ${token}` });
      if (lastEventId) headers.set("Last-Event-ID", lastEventId);
      const response = await fetch(`${API_ROOT}/alerts/stream`, { headers, signal });
      if (!response.ok || !response.body) {
        let message = `Alert stream unavailable (${response.status})`;
        try {
          const result = await response.json();
          if (result?.detail) message = String(result.detail);
        } catch {
          // Keep the safe status-only message.
        }
        throw new Error(message);
      }

      onStatus("live");
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (!signal.aborted) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g, "\n");
        let boundary;
        while ((boundary = buffer.indexOf("\n\n")) !== -1) {
          const block = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + 2);
          const message = parseEvent(block);
          if (message.id) lastEventId = message.id;
          if (message.event === "alert" && message.data) {
            try {
              onAlert(JSON.parse(message.data));
            } catch {
              // Ignore malformed events and keep the stream alive.
            }
          }
        }
      }
      if (!signal.aborted) onStatus("reconnecting");
    } catch (error) {
      if (signal.aborted) return;
      onStatus(error instanceof TypeError ? "reconnecting" : "attention");
    }
    await new Promise((resolve) => setTimeout(resolve, 1500));
  }
}
