import { test } from 'node:test'
import assert from 'node:assert/strict'
import { api, ApiError, setCsrfToken, text, dateText } from './api.ts'

test('API sends same-origin cookies and CSRF for authenticated writes', async () => {
  const original = globalThis.fetch
  const calls = []
  globalThis.fetch = async (url, options) => { calls.push({ url, options }); return new Response(JSON.stringify({ ok: true }), { status: 200 }) }
  try {
    setCsrfToken('token-123')
    await api('/mail/search', { method: 'POST', body: JSON.stringify({ q: 'test' }) })
    await api('/auth/login', { method: 'POST', body: '{}' })
    assert.equal(calls[0].url, '/api/platform/v1/mail/search')
    assert.equal(calls[0].options.credentials, 'same-origin')
    assert.equal(calls[0].options.headers.get('X-CSRF-Token'), 'token-123')
    assert.equal(calls[1].options.headers.get('X-CSRF-Token'), null)
  } finally { globalThis.fetch = original; setCsrfToken('') }
})

test('API surfaces backend errors without fabricated data', async () => {
  const original = globalThis.fetch
  globalThis.fetch = async () => new Response(JSON.stringify({ detail: '该租户未配置专用检索实例' }), { status: 503 })
  try { await assert.rejects(api('/mail/search'), error => error instanceof ApiError && error.status === 503 && error.message.includes('专用检索实例')) }
  finally { globalThis.fetch = original }
})

test('safe display helpers do not turn missing values into success indicators', () => {
  assert.equal(text(null), '—')
  assert.equal(dateText('invalid'), 'invalid')
})
