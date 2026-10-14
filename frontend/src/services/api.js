// Default to Nginx reverse proxy port (8080) for all traffic routing
const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
  ? `http://${window.location.hostname}:8080`
  : '';

let _token = localStorage.getItem('cs_token') || null;

export function setAuthToken(token) {
  _token = token;
  if (token) localStorage.setItem('cs_token', token);
  else localStorage.removeItem('cs_token');
}

export function getAuthHeaders() {
  const headers = { 'Content-Type': 'application/json' };
  if (_token) headers['Authorization'] = `Bearer ${_token}`;
  return headers;
}

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/api/v1/health`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
}

export async function fetchIncidents() {
  try {
    const res = await fetch(`${API_BASE}/api/v1/incidents/`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    return [];
  }
}

export async function fetchTelemetryMetrics() {
  try {
    const res = await fetch(`${API_BASE}/api/v1/monitoring/metrics`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    return null;
  }
}

export async function fetchTelemetryHistory() {
  try {
    const res = await fetch(`${API_BASE}/api/v1/monitoring/history`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    return [];
  }
}

export async function fetchDetectionStatus() {
  try {
    const res = await fetch(`${API_BASE}/api/v1/detection/status`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    return null;
  }
}

export async function fetchMitigationStatus() {
  try {
    const res = await fetch(`${API_BASE}/api/v1/mitigation/status`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    return null;
  }
}

export async function loginAdmin(username, password) {
  const res = await fetch(`${API_BASE}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  if (!res.ok) throw new Error('Invalid credentials');
  const data = await res.json();
  setAuthToken(data.access_token);
  return data;
}

export async function checkSession() {
  if (!_token) return { authenticated: false };
  try {
    const res = await fetch(`${API_BASE}/api/v1/auth/me`, { headers: getAuthHeaders() });
    return await res.json();
  } catch (err) {
    return { authenticated: false };
  }
}

export async function setMitigationTier(tier, reason = 'Operator override') {
  const res = await fetch(`${API_BASE}/api/v1/mitigation/tier`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify({ tier, reason })
  });
  return await res.json();
}

export async function blockIp(ip, reason = 'Operator manual block') {
  const res = await fetch(`${API_BASE}/api/v1/mitigation/block`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify({ ip, reason })
  });
  return await res.json();
}

export async function unblockIp(ip) {
  const res = await fetch(`${API_BASE}/api/v1/mitigation/unblock`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify({ ip, reason: 'Operator unblock' })
  });
  return await res.json();
}

export async function resetSystem() {
  const res = await fetch(`${API_BASE}/api/v1/admin/reset`, {
    method: 'POST',
    headers: getAuthHeaders()
  });
  return await res.json();
}

export async function triggerHoneypot() {
  try {
    await fetch(`${API_BASE}/admin-backup/`, { method: 'GET' });
  } catch (e) {}
}

export async function sendSampleRequest() {
  const res = await fetch(`${API_BASE}/api/v1/sample/hello`);
  const servedBy = res.headers.get('X-Served-By') || 'unknown';
  const proxyEngine = res.headers.get('X-Proxy-Engine') || 'unknown';
  const data = await res.json();
  return {
    ...data,
    header_served_by: servedBy,
    header_proxy_engine: proxyEngine
  };
}

export async function createDemoIncident(classification = "SUSPICIOUS", tier = "TIER_1", customData = {}) {
  const payload = {
    classification,
    mitigation_tier: tier,
    source_ip: "198.51.100.99",
    requests_per_sec: 420.5,
    baseline_rps: 85.0,
    url_entropy: 0.82,
    ip_entropy: 1.15,
    verdict_reason: "High requests/sec surge with low URL entropy. Single-path flood signature.",
    is_active: true,
    ...customData
  };
  const res = await fetch(`${API_BASE}/api/v1/incidents/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  return await res.json();
}

export async function sendBackendSimulation(classification, tier, url_entropy = 0.0, rps = 1.0, reason = "") {
  try {
    const res = await fetch(`${API_BASE}/api/v1/detection/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        classification,
        mitigation_tier: tier,
        url_entropy,
        requests_per_sec: rps,
        verdict_reason: reason
      })
    });
    return await res.json();
  } catch (err) {
    console.error("sendBackendSimulation error:", err);
    return null;
  }
}
