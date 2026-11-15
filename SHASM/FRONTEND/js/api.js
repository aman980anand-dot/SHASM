const API_BASE = "http://127.0.0.1:5000/api";

async function apiRequest(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      ...(options.headers || {}),
      ...(options.body ? { "Content-Type": "application/json" } : {})
    }
  });
  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error(`Server returned a non-JSON response (HTTP ${response.status}).`);
  }
  if (!response.ok) {
    throw new Error(data?.error || `Request failed (HTTP ${response.status}).`);
  }
  return data;
}

async function createScan(payload) {
  return apiRequest("/scan", { method: "POST", body: JSON.stringify(payload) });
}
async function getScan(id) {
  return apiRequest(`/scan/${encodeURIComponent(id)}`);
}
async function getResults(id) {
  return apiRequest(`/results/${encodeURIComponent(id)}`);
}
