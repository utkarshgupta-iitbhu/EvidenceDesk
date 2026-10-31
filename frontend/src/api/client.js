// Production API Client for EvidenceDesk v1.2.0
export const API_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

function getSessionToken() {
  let token = sessionStorage.getItem('evidencedesk_session_token');
  if (!token) {
    token = 'session_' + Math.random().toString(36).substring(2, 12) + '_' + Date.now();
    sessionStorage.setItem('evidencedesk_session_token', token);
  }
  return token;
}

export async function checkBackendHealth() {
  try {
    const res = await fetch(`${API_BASE}/api/health`, { method: 'GET' });
    if (!res.ok) return { online: false, version: null };
    const data = await res.json();
    return { online: true, version: data.version || '1.2.0' };
  } catch (err) {
    return { online: false, version: null };
  }
}

export async function postScan(endpoint, formData) {
  const url = `${API_BASE}${endpoint}`;
  const sessionToken = getSessionToken();

  try {
    const res = await fetch(url, {
      method: 'POST',
      body: formData,
      headers: {
        'X-Session-Token': sessionToken,
      },
    });

    const contentType = res.headers.get('content-type') || '';
    let responseData = null;

    if (contentType.includes('application/json')) {
      responseData = await res.json();
    } else {
      const text = await res.text();
      responseData = { detail: text || `HTTP ${res.status}: Unexpected response format.` };
    }

    if (!res.ok) {
      const errorMsg = responseData?.detail || responseData?.message || `Server returned error ${res.status}`;
      const err = new Error(errorMsg);
      err.status = res.status;
      err.data = responseData;
      throw err;
    }

    return responseData;
  } catch (err) {
    if (err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
      throw new Error(`Cannot connect to EvidenceDesk API at ${API_BASE}. Ensure the backend server is running.`);
    }
    throw err;
  }
}

export async function downloadReportFile(scanId, moduleName) {
  const sessionToken = getSessionToken();
  const res = await fetch(`${API_BASE}/api/export/report/${scanId}`, {
    headers: { 'X-Session-Token': sessionToken },
  });

  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.detail || `Report export failed (HTTP ${res.status})`);
  }

  const blob = await res.blob();
  const blobUrl = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = blobUrl;
  a.download = `EvidenceDesk_${(moduleName || 'triage').toUpperCase()}_Report_${scanId.substring(0, 8)}.pdf`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.URL.revokeObjectURL(blobUrl);
}

export async function downloadManifestFile(scanId, moduleName) {
  const sessionToken = getSessionToken();
  const res = await fetch(`${API_BASE}/api/export/manifest/${scanId}`, {
    headers: { 'X-Session-Token': sessionToken },
  });

  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.detail || `Manifest export failed (HTTP ${res.status})`);
  }

  const blob = await res.blob();
  const blobUrl = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = blobUrl;
  a.download = `EvidenceDesk_${(moduleName || 'triage').toUpperCase()}_Manifest_${scanId.substring(0, 8)}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.URL.revokeObjectURL(blobUrl);
}

export async function deleteServerScan(scanId) {
  const sessionToken = getSessionToken();
  const res = await fetch(`${API_BASE}/api/scan/${scanId}`, {
    method: 'DELETE',
    headers: { 'X-Session-Token': sessionToken },
  });
  return res.ok;
}
