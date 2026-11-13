const BASE = '/api/platform/v1'

export type User = { id: number; username: string; display_name: string; role: 'user' | 'admin'; tenant_id: number | null; is_active?: boolean }
export type Session = { user: User; csrf_token: string }
export type Tenant = { id: number; name: string; slug: string; is_active?: boolean }
export type MailSource = 'event' | 'legacy'
export type Mail = Record<string, unknown> & { id?: string; event_id?: string; mail_id?: string; event_time?: string; sent_at?: string; ingested_at?: string; sender_account?: string; receiver_accounts?: string[]; recipients?: string[]; text_content?: string; subject?: string; sender?: string; recipient?: string; risk_level?: string; received_at?: string; body_text?: string; body_preview?: string }
export type SearchResponse = { items: Mail[]; total: number | null; limit: number; offset: number; may_have_more?: boolean }
export type MailStats = { total: number; with_attachment?: number; parse_failed?: number }
export type MailFilters = { source: MailSource; q?: string; sender?: string; subject?: string; recipient?: string; risk_level?: string; tenant_id?: number; from_time?: string; to_time?: string; sender_domain?: string; has_attachment?: boolean; attachment_suffix?: string; sender_ip?: string; attachment_md5?: string; risk_verdict?: string; subject_or_attachment_contains?: string; attachment_name_contains?: string; source_system_id?: string }

export function canGoNextPage(results: SearchResponse | null, offset: number, limit: number): boolean {
  if (!results || offset + limit > 10000) return false
  if (typeof results.total === 'number') return offset + results.items.length < results.total
  return results.may_have_more !== false && results.items.length > 0
}
export type LlmConfig = { provider: 'openai' | 'anthropic' | ''; base_url: string; model: string; external_authorized: boolean; api_key_set: boolean; configured: boolean }
export type LlmProvider = { id: string; name: string; website: string; base_url: string; provider: 'openai' | 'anthropic'; models: string[]; docs_url: string }
export type NlPlan = { plan_token: string; plan: Record<string, unknown>; executed: false }
export type PlanExecution = { plan: Record<string, unknown>; executed: true; result: SearchResponse | MailStats }
export function planPageSize(plan: Record<string, unknown>, fallback = 20): number {
  const filters = plan.filters as Record<string, unknown> | undefined
  const limit = filters?.limit
  return typeof limit === 'number' && Number.isInteger(limit) && limit >= 1 && limit <= 200 ? limit : fallback
}
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
  if (method !== 'GET' && method !== 'HEAD' && path !== '/auth/login' && path !== '/auth/register' && csrfToken) headers.set('X-CSRF-Token', csrfToken)
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

export function mailTime(mail: Mail, source: MailSource): string {
  return dateText(source === 'legacy' ? mail.sent_at : (mail.event_time ?? mail.received_at))
}
