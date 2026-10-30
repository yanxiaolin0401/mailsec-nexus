// Dependency-free DOM harness for the console's source-aware query routing.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

class Element {
  constructor(id = '') {
    this.id = id;
    this.value = '';
    this.textContent = '';
    this.children = [];
    this.listeners = {};
    this.classList = {toggle() {}};
    this.dataset = {};
    this.hidden = false;
    this.disabled = false;
    this.open = false;
  }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  replaceChildren() { this.children = []; }
  appendChild(child) { this.children.push(child); return child; }
  querySelectorAll() { return this.controls || []; }
  showModal() { this.open = true; }
  close() { this.open = false; }
}

const elements = new Map();
const get = id => {
  if (!elements.has(id)) elements.set(id, new Element(id));
  return elements.get(id);
};
const eventInput = new Element(); eventInput.name = 'sender_ip';
const legacyInput = new Element(); legacyInput.name = 'body_contains';
const eventLabel = new Element(); eventLabel.dataset.source = 'event'; eventLabel.controls = [eventInput];
const legacyLabel = new Element(); legacyLabel.dataset.source = 'legacy'; legacyLabel.controls = [legacyInput];
const document = {
  getElementById: get,
  createElement: () => new Element(),
  querySelectorAll: () => [eventLabel, legacyLabel],
};
get('token').value = 'synthetic-token';
get('source').value = 'event';
const calls = [];
const fetch = async (url, options) => {
  calls.push({url, options});
  let data;
  if (url.startsWith('/api/v1/mails?')) {
    data = {items: [{event_id: 'event-1', event_time: '2026-01-01', sender_account: 'e@test', receiver_accounts: ['r@test'], subject: 'event', risk_level: 'unknown'}], total: 1, may_have_more: false};
  } else if (url === '/v1/search') {
    data = {items: [{mail_id: 'mail-1', sent_at: null, sender: 'l@test', subject: 'legacy', parse_status: 'ok'}], count: 1, may_have_more: false};
  } else if (url === '/v1/mail/mail-1') {
    data = {mail_id: 'mail-1', recipients: ['r@test']};
  } else if (url === '/v1/stats') {
    data = {total: 42, with_attachment: 3};
  } else if (url === '/v1/nl/query') {
    data = {plan: {tool: 'stats', filters: {body_contains: 'invoice'}}, executed: false};
  } else throw new Error(`unexpected request ${url}`);
  return {ok: true, text: async () => JSON.stringify(data)};
};
const context = vm.createContext({document, fetch, URLSearchParams, FormData, JSON, Number, String, Error});
const code = fs.readFileSync(path.join(__dirname, '../src/mailsec_smart_search/static/console.js'), 'utf8');
vm.runInContext(code, context);

async function run() {
  await vm.runInContext('search({q:"invoice",limit:20,offset:0})', context);
  assert.match(calls.at(-1).url, /^\/api\/v1\/mails\?/);
  assert.equal(get('count').textContent, '共 1 条 · 本页 1 条');

  get('source').value = 'legacy';
  get('source').listeners.change();
  assert.equal(eventInput.disabled, true);
  assert.equal(legacyInput.disabled, false);
  assert.equal(get('count').textContent, '尚未检索');
  await vm.runInContext('search({body_contains:"invoice",limit:20,offset:0})', context);
  assert.equal(calls.at(-1).url, '/v1/search');
  assert.deepEqual(JSON.parse(calls.at(-1).options.body), {body_contains: 'invoice', limit: 20, offset: 0});
  assert.equal(get('count').textContent, '本页 1 条 · 总数未计算');
  assert.equal(get('rows').children[0].children[2].textContent, '查看详情');
  get('rows').children[0].children[5].children[0].listeners.click();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(calls.at(-1).url, '/v1/mail/mail-1');

  get('question').value = '统计 invoice';
  get('nl-form').listeners.submit({preventDefault() {}});
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(calls.at(-1).url, '/v1/nl/query');
  assert.equal(JSON.parse(calls.at(-1).options.body).execute, false);
  get('execute-plan').listeners.click();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(calls.at(-1).url, '/v1/stats');
  assert.equal(get('count').textContent, '统计匹配 42 条');

  get('source').value = 'event';
  get('source').listeners.change();
  assert.equal(get('execute-plan').disabled, true);
  assert.equal(get('count').textContent, '尚未检索');
}

run().catch(error => { console.error(error); process.exitCode = 1; });
