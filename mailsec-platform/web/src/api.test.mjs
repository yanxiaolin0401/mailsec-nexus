import { test } from 'node:test'
import assert from 'node:assert/strict'
import { api, ApiError, canGoNextPage, setCsrfToken, text, dateText, mailTime, planPageSize } from './api.ts'

test('API sends same-origin cookies and CSRF for authenticated writes', async () => {
  const original = globalThis.fetch
  const calls = []
  globalThis.fetch = async (url, options) => { calls.push({ url, options }); return new Response(JSON.stringify({ ok: true }), { status: 200 }) }
  try {
    setCsrfToken('token-123')
    await api('/mail/search', { method: 'POST', body: JSON.stringify({ q: 'test' }) })
    await api('/auth/login', { method: 'POST', body: '{}' })
    await api('/auth/register', { method: 'POST', body: JSON.stringify({ username: 'new-user', display_name: 'New', password: 'long-password-123', tenant_slug: 'cloud-test' }) })
    assert.equal(calls[0].url, '/api/platform/v1/mail/search')
    assert.equal(calls[0].options.credentials, 'same-origin')
    assert.equal(calls[0].options.headers.get('X-CSRF-Token'), 'token-123')
    assert.equal(calls[1].options.headers.get('X-CSRF-Token'), null)
    assert.equal(calls[2].url, '/api/platform/v1/auth/register')
    assert.equal(calls[2].options.headers.get('X-CSRF-Token'), null)
    assert.equal(calls[2].options.credentials, 'same-origin')
  } finally { globalThis.fetch = original; setCsrfToken('') }
})

test('API surfaces backend errors without fabricated data', async () => {
  const original = globalThis.fetch
  globalThis.fetch = async () => new Response(JSON.stringify({ detail: '该租户未配置专用检索实例' }), { status: 503 })
  try { await assert.rejects(api('/mail/search'), error => error instanceof ApiError && error.status === 503 && error.message.includes('专用检索实例')) }
  finally { globalThis.fetch = original }
})

test('statistics requests stay on the platform API with session CSRF', async () => {
  const original = globalThis.fetch
  let call
  globalThis.fetch = async (url, options) => {
    call = { url, options }
    return new Response(JSON.stringify({ total: 109516, with_attachment: 12, parse_failed: 1 }), { status: 200 })
  }
  try {
    setCsrfToken('csrf-for-stats')
    const stats = await api('/mail/stats', { method: 'POST', body: JSON.stringify({ source: 'legacy' }) })
    assert.equal(call.url, '/api/platform/v1/mail/stats')
    assert.equal(call.options.credentials, 'same-origin')
    assert.equal(call.options.headers.get('X-CSRF-Token'), 'csrf-for-stats')
    assert.equal(stats.total, 109516)
  } finally { globalThis.fetch = original; setCsrfToken('') }
})

test('safe display helpers do not turn missing values into success indicators', () => {
  assert.equal(text(null), '—')
  assert.equal(dateText('invalid'), 'invalid')
})

test('pagination uses known event total even without may_have_more', () => {
  const page = { items: Array.from({ length: 20 }, (_, id) => ({ id })), total: 45, limit: 20, offset: 0 }
  assert.equal(canGoNextPage(page, 0, 20), true)
  assert.equal(canGoNextPage({ ...page, items: Array.from({ length: 5 }, (_, id) => ({ id })) }, 40, 20), false)
})

test('legacy pagination can return from empty terminal page and respects offset bound', () => {
  const full = { items: Array.from({ length: 20 }, (_, id) => ({ id })), total: null, limit: 20, offset: 0, may_have_more: true }
  assert.equal(canGoNextPage(full, 0, 20), true)
  assert.equal(canGoNextPage({ ...full, items: [], offset: 20, may_have_more: false }, 20, 20), false)
  assert.equal(canGoNextPage(full, 10000, 20), false)
})

test('mail time labels never substitute legacy ingestion for unknown sent time', () => {
  const mail = { sent_at: null, ingested_at: '2026-10-30T10:00:00Z', event_time: '2026-10-29T10:00:00Z' }
  assert.equal(mailTime(mail, 'legacy'), '—')
  assert.notEqual(mailTime(mail, 'event'), '—')
  assert.equal(mailTime({ received_at: '2026-10-28T10:00:00Z' }, 'event'), dateText('2026-10-28T10:00:00Z'))
})

test('model configuration and preview execution stay behind platform API and do not include a browser-held key', async () => {
  const previous = globalThis.fetch
  const calls = []
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options })
    const body = url.endsWith('/mail/nl/plan')
      ? { plan_token: 'opaque-token', plan: { tool: 'search', filters: { sender: 'sender@example.com' } }, executed: false }
      : { plan: { tool: 'search' }, executed: true, result: { items: [], total: null, limit: 20, offset: 0 } }
    return new Response(JSON.stringify(body), { status: 200 })
  }
  try {
    setCsrfToken('csrf-model')
    const plan = await api('/mail/nl/plan', { method: 'POST', body: JSON.stringify({ source: 'legacy', text: '找邮件' }) })
    assert.equal(plan.executed, false)
    assert.equal(plan.plan_token, 'opaque-token')
    const execution = await api('/mail/plan/execute', { method: 'POST', body: JSON.stringify({ source: 'legacy', plan_token: plan.plan_token, limit: 20, offset: 0 }) })
    assert.equal(execution.result.total, null)
    await api('/admin/llm/config', { method: 'PUT', body: JSON.stringify({ provider: 'openai', base_url: 'https://api.example.com/v1', model: 'demo', external_authorized: false }) })
    assert.deepEqual(calls.map(call => call.url), ['/api/platform/v1/mail/nl/plan', '/api/platform/v1/mail/plan/execute', '/api/platform/v1/admin/llm/config'])
    assert.ok(calls.every(call => call.options.headers.get('X-CSRF-Token') === 'csrf-model'))
    assert.ok(calls.every(call => call.options.credentials === 'same-origin'))
    assert.equal(JSON.parse(calls[2].options.body).api_key, undefined)
  } finally { globalThis.fetch = previous; setCsrfToken('') }
})


test('NL page size follows previewed plan instead of replacing a five-mail request', () => {
  assert.equal(planPageSize({ tool: 'search', filters: { limit: 5 } }), 5)
  assert.equal(planPageSize({ tool: 'search', filters: {} }), 20)
  assert.equal(planPageSize({ tool: 'search', filters: { limit: 201 } }), 20)
})
