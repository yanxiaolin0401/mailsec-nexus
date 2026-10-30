const BASE = '/api/platform/v1'

export type User = { id: number; username: string; display_name: string; role: 'user' | 'admin'; tenant_id: number | null; is_active?: boolean }
export type Session = { user: User; csrf_token: string }
export type Tenant = { id: number; name: string; slug: string; is_active?: boolean }
export type Mail = Record<string, unknown> & { id?: string; event_id?: string; event_time?: string; sender_account?: string; receiver_accounts?: string[]; text_content?: string; subject?: string; sender?: string; recipient?: string; risk_level?: string; received_at?: string; body_text?: string }
export type SearchResponse = { items: Mail[]; total: number; limit: number; offset: number; may_have_more: boolean }
export type Audit = Record<string, unknown>
export type Integration = Record<string, unknown>
export type Module = Record<string, unknown>

let csrfToken = ''
export function setCsrfToken(token: string) { csrfToken = token }

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) { super(message); this.status = status; this.name = 'ApiError' }
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const method = options.method?.toUpperCase() ?? 'GET'
  const headers = new Headers(options.headers)
  if (options.body) headers.set('Content-Type', 'application/json')
  if (method !== 'GET' && method !== 'HEAD' && path !== '/auth/login' && csrfToken) headers.set('X-CSRF-Token', csrfToken)
  let response: Response
  try { response = await fetch(BASE + path, { ...options, headers, credentials: 'same-origin' }) }
  catch { throw new ApiError(0, '无法连接平台服务，请检查后端是否运行。') }
  const raw = await response.text()
  let payload: unknown
  try { payload = raw ? JSON.parse(raw) : null } catch { payload = null }
  if (!response.ok) {
    if (response.status === 401 && path !== '/auth/login' && typeof window !== 'undefined') window.dispatchEvent(new Event('mailsec:unauthorized'))
    const data = payload && typeof payload === 'object' ? payload as Record<string, unknown> : {}
    const detail = data.detail ?? data.message ?? data.error
    throw new ApiError(response.status, typeof detail === 'string' ? detail : `请求失败（HTTP ${response.status}）`)
  }
  return payload as T
}

export function text(value: unknown, fallback = '—'): string {
  if (typeof value === 'string' && value.trim()) return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return fallback
}
export function dateText(value: unknown): string {
  if (typeof value !== 'string' || !value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN', { hour12: false })
}
