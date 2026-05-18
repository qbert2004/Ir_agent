const BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

async function request(path, options = {}, timeoutMs = 120000) {
  const controller = new AbortController()
  const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs)

  try {
    const res = await fetch(`${BASE_URL}${path}`, {
      ...options,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
      },
    })

    if (!res.ok) {
      const body = await res.json().catch(() => ({}))
      throw new Error(body.detail || body.message || `HTTP ${res.status}`)
    }

    return res.json()
  } catch (error) {
    if (error?.name === 'AbortError') {
      throw new Error('Превышено время ожидания ответа IR-Agent')
    }
    throw error
  } finally {
    window.clearTimeout(timeoutId)
  }
}

export function fetchMetrics() {
  return request('/ingest/metrics')
}

export function fetchMlStatus() {
  return request('/ingest/ml/status')
}

export function fetchIncidents() {
  return request('/ingest/incidents')
}

export function investigateEvents(incidentId, events) {
  return request('/ml/investigate', {
    method: 'POST',
    body: JSON.stringify({
      incident_id: incidentId,
      events,
    }),
  }, 180000)
}

export function classifyEvent(event) {
  return request('/ml/classify', {
    method: 'POST',
    body: JSON.stringify({ event }),
  })
}

export function queryAgent(question, sessionId = 'frontend') {
  return request('/agent/query', {
    method: 'POST',
    body: JSON.stringify({
      query: question,
      question,
      session_id: sessionId,
    }),
  }, 240000)
}
