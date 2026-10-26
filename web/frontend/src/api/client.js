const API_BASE = (import.meta.env.VITE_API_BASE || '/api').replace(/\/$/, '')

let csrfToken = null
let unauthorizedHandler = null

export class ApiError extends Error {
  constructor(message, status, payload) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.payload = payload
  }

  /** Ошибки валидации FastAPI в виде { поле: сообщение }. */
  get fieldErrors() {
    const detail = this.payload && this.payload.detail
    if (!Array.isArray(detail)) return {}
    const result = {}
    for (const item of detail) {
      const location = Array.isArray(item.loc) ? item.loc.filter((part) => part !== 'body') : []
      const field = location.join('.') || '_'
      if (!result[field]) result[field] = item.msg
    }
    return result
  }
}

export function setCsrfToken(token) {
  csrfToken = token || null
}

export function getCsrfToken() {
  return csrfToken
}

export function setUnauthorizedHandler(handler) {
  unauthorizedHandler = handler
}

function buildQuery(params) {
  if (!params) return ''
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue
    search.set(key, String(value))
  }
  const query = search.toString()
  return query ? `?${query}` : ''
}

async function readPayload(response) {
  const text = await response.text()
  if (!text) return null
  try {
    return JSON.parse(text)
  } catch {
    return text
  }
}

function extractMessage(payload, status) {
  if (!payload) return `Ошибка запроса (${status})`
  if (typeof payload === 'string') return payload
  const detail = payload.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        const location = Array.isArray(item.loc)
          ? item.loc.filter((part) => part !== 'body').join('.')
          : ''
        return location ? `${location}: ${item.msg}` : item.msg
      })
      .join('; ')
  }
  return `Ошибка запроса (${status})`
}

async function ensureCsrf() {
  if (csrfToken) return csrfToken
  const response = await fetch(`${API_BASE}/auth/csrf`, {
    method: 'GET',
    credentials: 'include',
    headers: { Accept: 'application/json' },
  })
  const payload = await readPayload(response)
  if (!response.ok) {
    throw new ApiError(extractMessage(payload, response.status), response.status, payload)
  }
  csrfToken = payload.csrf_token
  return csrfToken
}

async function request(path, options = {}) {
  const { method = 'GET', body, params, withCsrf = false, retryOnCsrf = true } = options
  const url = `${API_BASE}${path}${buildQuery(params)}`

  const headers = { Accept: 'application/json' }
  const init = { method, credentials: 'include', headers }

  if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
    init.body = JSON.stringify(body)
  }

  if (withCsrf) {
    headers['X-CSRF-Token'] = await ensureCsrf()
  }

  const response = await fetch(url, init)
  const payload = await readPayload(response)

  if (
    response.status === 403 &&
    retryOnCsrf &&
    payload &&
    payload.code === 'csrf_failed'
  ) {
    csrfToken = null
    return request(path, { ...options, retryOnCsrf: false })
  }

  if (response.status === 401) {
    csrfToken = null
    if (unauthorizedHandler) unauthorizedHandler()
  }

  if (!response.ok) {
    throw new ApiError(extractMessage(payload, response.status), response.status, payload)
  }

  return payload
}

const mutate = (method) => (path, body, params) =>
  request(path, { method, body, params, withCsrf: true })

export const api = {
  get: (path, params) => request(path, { method: 'GET', params }),
  post: mutate('POST'),
  put: mutate('PUT'),
  patch: mutate('PATCH'),
  delete: (path, params) => request(path, { method: 'DELETE', params, withCsrf: true }),
  ensureCsrf,
}

export default api
