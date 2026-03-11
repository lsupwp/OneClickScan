const LS_KEY = 'ocs_session_v1'

export function loadSession() {
  try {
    const raw = localStorage.getItem(LS_KEY)
    return raw ? JSON.parse(raw) : null
  } catch { return null }
}

export function saveSession(data) {
  try { localStorage.setItem(LS_KEY, JSON.stringify(data)) } catch { /* quota */ }
}

export function clearSession() {
  try { localStorage.removeItem(LS_KEY) } catch {}
}
