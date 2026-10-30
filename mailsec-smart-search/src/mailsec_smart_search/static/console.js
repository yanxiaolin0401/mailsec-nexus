'use strict';
const $ = id => document.getElementById(id);
let currentFilters = null;
let currentPlan = null;
let planSource = null;
let jobId = null;
let selectedEvent = null;
let selectedSource = null;
let busy = 0;
const source = () => $('source').value;
function status(message, error = false) {
  $('status').textContent = message;
  $('status').classList.toggle('error', error);
}
async function api(path, options = {}) {
  const token = $('token').value.trim();
  if (!token) throw new Error('请先填写 API 访问令牌。');
  const response = await fetch(path, {...options, headers: {'X-Mailsec-Token': token,
    ...(options.body ? {'Content-Type': 'application/json'} : {}), ...options.headers}});
  const text = await response.text();
  let result;
  try { result = JSON.parse(text); } catch { result = {detail: text}; }
  if (!response.ok) throw new Error(`${response.status} · ${typeof result.detail === 'string' ? result.detail : '请求参数校验失败，请检查输入。'}`);
  return result;
}
async function run(action) {
  if (busy) return;
  busy++;
  $('source').disabled = true;
  status('处理中…');
  try { await action(); } catch (error) { status(error.message, true); }
  finally { busy--; $('source').disabled = false; }
}
function clearSearch() {
  currentFilters = null; currentPlan = null; planSource = null;
  selectedEvent = null; selectedSource = null;
  $('execute-plan').disabled = true;
  $('plan').textContent = '尚未生成计划';
  $('rows').replaceChildren();
  $('count').textContent = '尚未检索';
  $('page').textContent = '第 1 页';
  $('prev').disabled = true; $('next').disabled = true;
  $('detail-content').textContent = '';
  $('analysis-result').textContent = '尚未研判';
  if ($('detail').open) $('detail').close();
}
function setSource() {
  const legacy = source() === 'legacy';
  for (const label of document.querySelectorAll('#search-form [data-source]')) {
    const active = label.dataset.source === source();
    label.hidden = !active;
    for (const control of label.querySelectorAll('input,select')) control.disabled = !active;
  }
  $('result-title').textContent = legacy ? '历史 EML 邮件' : '邮件事件';
  $('time-heading').textContent = legacy ? '发送时间' : '事件时间';
  $('risk-heading').textContent = legacy ? '解析状态' : '风险';
  $('detail-title').textContent = legacy ? '历史 EML 邮件详情' : '邮件事件详情';
  $('analysis-note').textContent = legacy
    ? '历史 EML 分析需要本机原始邮件证据及扫描服务；迁移到 Cloud 的索引不包含原文。'
    : '仅分析获授权的脱敏元数据；无附件内容，不运行规则 / 杀毒融合。结果独立存证，不覆盖事件风险基线。';
  clearSearch();
  status(legacy ? '历史 EML 检索已启用；发送时间为空的邮件不会命中时间筛选。' : 'JSON 邮件事件检索已启用。');
}
$('source').addEventListener('change', setSource);
function formFilters() {
  const data = new FormData($('search-form'));
  const values = {};
  for (const [key, value] of data.entries()) {
    if (!value.trim()) continue;
    if (key === 'has_attachment') values[key] = value === 'true';
    else values[key] = key.endsWith('_time') ? new Date(value).toISOString() : value.trim();
  }
  values.limit = Number(values.limit || 20);
  values.offset = 0;
  return values;
}
function queryParams(filters) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) if (value !== null && value !== undefined) params.set(key, String(value));
  return params.toString();
}
function cell(row, text) {
  const td = document.createElement('td');
  td.textContent = text == null ? '-' : String(text);
  row.appendChild(td);
  return td;
}
function display(result, filters, dataset) {
  currentFilters = {...filters};
  const legacy = dataset === 'legacy';
  const rows = $('rows');
  rows.replaceChildren();
  for (const item of result.items || []) {
    const tr = document.createElement('tr');
    cell(tr, legacy ? item.sent_at : item.event_time);
    cell(tr, legacy ? item.sender : item.sender_account);
    // Legacy summary intentionally excludes recipients; fetch them only in detail.
    cell(tr, legacy ? '查看详情' : (item.receiver_accounts || []).join(', '));
    cell(tr, item.subject);
    cell(tr, legacy ? item.parse_status : item.risk_level === 'unknown' ? '未知 / 未研判' : item.risk_level);
    const button = document.createElement('button');
    button.type = 'button'; button.textContent = '查看'; button.className = 'secondary';
    button.addEventListener('click', () => run(async () => {
      const id = legacy ? item.mail_id : item.event_id;
      const detail = await api((legacy ? '/v1/mail/' : '/api/v1/mails/') + encodeURIComponent(id));
      selectedEvent = id; selectedSource = dataset;
      $('analysis-result').textContent = '尚未研判';
      $('detail-content').textContent = JSON.stringify(detail, null, 2);
      $('detail').showModal(); status('已加载邮件详情。');
    }));
    cell(tr, '').appendChild(button);
    rows.appendChild(tr);
  }
  if (!rows.children.length) { const tr = document.createElement('tr'); const td = cell(tr, legacy ? '没有符合条件的历史 EML 邮件。' : '没有符合条件的邮件。刚接收的事件可能尚未入库。'); td.colSpan = 6; rows.appendChild(tr); }
  const offset = Number(filters.offset || 0), limit = Number(filters.limit || 50);
  $('count').textContent = legacy
    ? `本页 ${(result.items || []).length} 条 · 总数未计算`
    : `共 ${result.total ?? 0} 条 · 本页 ${(result.items || []).length} 条`;
  $('page').textContent = `第 ${Math.floor(offset / limit) + 1} 页`;
  $('prev').disabled = offset === 0;
  $('next').disabled = !result.may_have_more || offset + limit > 10000;
  status('检索完成。邮件内容仅按文本展示。');
}
async function search(filters, dataset = source()) {
  const result = dataset === 'legacy'
    ? await api('/v1/search', {method: 'POST', body: JSON.stringify(filters)})
    : await api('/api/v1/mails?' + queryParams(filters));
  display(result, filters, dataset);
}
$('search-form').addEventListener('submit', event => { event.preventDefault(); run(() => search(formFilters())); });
$('prev').addEventListener('click', () => run(() => search({...currentFilters, offset: Math.max(0, Number(currentFilters.offset || 0) - Number(currentFilters.limit || 50))})));
$('next').addEventListener('click', () => run(() => search({...currentFilters, offset: Number(currentFilters.offset || 0) + Number(currentFilters.limit || 50)})));
$('nl-form').addEventListener('submit', event => {
  event.preventDefault();
  currentPlan = null; planSource = null; $('execute-plan').disabled = true;
  run(async () => {
    const dataset = source();
    const result = await api(dataset === 'legacy' ? '/v1/nl/query' : '/api/v1/nl/query',
      {method: 'POST', body: JSON.stringify({text: $('question').value, execute: false})});
    currentPlan = result.plan;
    planSource = dataset;
    $('plan').textContent = JSON.stringify(currentPlan, null, 2);
    $('execute-plan').disabled = false;
    status('计划已生成，请核对条件后执行。');
  });
});
$('execute-plan').addEventListener('click', () => run(async () => {
  if (!currentPlan || planSource !== source()) return;
  // Execute the exact validated preview filters locally, without asking the model again.
  if (currentPlan.tool === 'stats') {
    const result = planSource === 'legacy'
      ? await api('/v1/stats', {method: 'POST', body: JSON.stringify(currentPlan.filters)})
      : await api('/api/v1/stats?' + queryParams(currentPlan.filters));
    currentFilters = null; $('prev').disabled = true; $('next').disabled = true;
    $('rows').replaceChildren(); $('count').textContent = `统计匹配 ${result.total} 条`;
    status(`统计结果：共 ${result.total} 条匹配邮件；未拉取邮件列表。`);
  } else {
    await search(currentPlan.filters, planSource);
  }
}));
$('ingest-form').addEventListener('submit', event => {
  event.preventDefault();
  run(async () => {
    const payload = JSON.parse($('payload').value);
    const result = await api('/api/v2/mails', {method: 'POST', body: JSON.stringify(payload)});
    jobId = result.jobId;
    $('receipt').textContent = JSON.stringify(result, null, 2);
    $('job-status').disabled = false;
    status('事件已被持久队列接收，等待 worker 批量写入。');
  });
});
$('job-status').addEventListener('click', () => run(async () => {
  $('receipt').textContent = JSON.stringify(await api('/api/v2/jobs/' + encodeURIComponent(jobId)), null, 2);
  status('队列状态已更新。');
}));
$('close-detail').addEventListener('click', () => $('detail').close());
$('forget').addEventListener('click', () => {
  $('token').value = ''; jobId = null;
  $('job-status').disabled = true; $('receipt').textContent = '尚未提交';
  clearSearch(); status('令牌与检索结果已清除。');
});

$('analyze-event').addEventListener('click', () => run(async () => {
  if (!selectedEvent) return;
  const base = selectedSource === 'legacy' ? '/v1/mail/' : '/api/v1/mails/';
  const result = await api(base + encodeURIComponent(selectedEvent) + '/analysis', {method: 'POST'});
  $('analysis-result').textContent = JSON.stringify(result, null, 2);
  status(selectedSource === 'legacy' ? '历史 EML 分析结果已独立存证。' : result.status === 'ok' ? '模型辅助意见已独立存证，需人工复核。' : '模型未完成研判，风险保持未知；降级状态已存证。');
}));
