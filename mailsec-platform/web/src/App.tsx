import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { api, ApiError, canGoNextPage, dateText, mailTime, setCsrfToken, text, type Audit, type Integration, type Mail, type Module, type SearchResponse, type MailSource, type MailStats, type MailFilters, type Session, type Tenant, type User, type LlmConfig, type LlmProvider, type NlPlan, type PlanExecution, planPageSize } from './api'

type Page = 'overview' | 'search' | 'storage' | 'header-parser' | 'threat-trace' | 'users' | 'tenants' | 'audit' | 'llm'
const pageNames: Record<Page, string> = { overview: '总览', search: '智能检索', storage: '存储与队列', 'header-parser': '邮件头解析', 'threat-trace': '威胁溯源', users: '账号管理', tenants: '租户管理', audit: '操作审计', llm: '大模型接入' }
const humanError = (error: unknown) => error instanceof Error ? error.message : '操作失败，请稍后重试。'
const qs = (params: Record<string, string>) => '?' + new URLSearchParams(params).toString()
const mailId = (mail: Mail) => text(mail.mail_id ?? mail.event_id ?? mail.id, '')
const mailSender = (mail: Mail) => text(mail.sender_account ?? mail.sender)

function Icon({ name, size = 18 }: { name: string; size?: number }) {
  const paths: Record<string, ReactNode> = {
    grid: <><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></>,
    search: <><circle cx="10.8" cy="10.8" r="6.8"/><path d="m16 16 5 5"/></>,
    mail: <><rect x="2.5" y="4" width="19" height="16" rx="2"/><path d="m3 6 9 7 9-7"/></>,
    trace: <><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 2v6m0 8v6M2 12h6m8 0h6"/></>,
    users: <><circle cx="9" cy="8" r="3.2"/><path d="M3 20v-2a6 6 0 0 1 12 0v2M17 5a3 3 0 0 1 0 6m1 3a5 5 0 0 1 3 5v1"/></>,
    tenant: <><rect x="4" y="3" width="16" height="18" rx="2"/><path d="M9 7h2m3 0h2M9 11h2m3 0h2M9 15h2m3 0h2M11 21v-4h2v4"/></>,
    llm: <><circle cx="12" cy="12" r="9"/><path d="M9 9h6M8 13h8m-5 3h2"/></>,
    audit: <><path d="M5 3h14v18H5zM8 8h8M8 12h8M8 16h5"/></>,
    logout: <><path d="M10 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h5M14 7l5 5-5 5M9 12h10"/></>,
    arrow: <path d="m9 5 7 7-7 7"/>,
    close: <path d="M5 5 19 19M19 5 5 19"/>,
    shield: <><path d="M12 2 21 6v6c0 5-4 8-9 10-5-2-9-5-9-10V6z"/><path d="m9 12 2 2 4-4"/></>,
    menu: <path d="M4 6h16M4 12h16M4 18h16"/>,
    plus: <path d="M12 4v16M4 12h16"/>,
  }
  return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">{paths[name] ?? paths.grid}</svg>
}

function Brand() { return <div className="brand"><span className="brand-mark"><Icon name="shield" size={21}/></span><span><strong>MailSec Nexus</strong><small>邮件综合安全平台</small></span></div> }
function Button({ children, loading, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement> & { loading?: boolean }) { return <button {...props} disabled={props.disabled || loading}>{loading ? '处理中…' : children}</button> }
function Notice({ message, onClose }: { message: string; onClose: () => void }) { return <div className="notice" role="alert"><span>{message}</span><button className="icon-button" onClick={onClose} aria-label="关闭提示"><Icon name="close" size={16}/></button></div> }
function Empty({ title, description }: { title: string; description?: string }) { return <div className="empty"><span className="empty-icon"><Icon name="mail" size={23}/></span><strong>{title}</strong>{description && <p>{description}</p>}</div> }
function Pill({ value }: { value: unknown }) { const label = text(value); const lower = label.toLowerCase(); const color = ['high', 'critical', '高', '严重'].includes(lower) ? 'danger' : ['medium', '中'].includes(lower) ? 'warning' : ['low', '低', 'safe', '正常'].includes(lower) ? 'success' : 'neutral'; return <span className={`pill ${color}`}>{label}</span> }

function Login({ onLogin }: { onLogin: (session: Session) => void }) {
  const [mode, setMode] = useState<'user' | 'admin' | 'register'>('user')
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [tenantSlug, setTenantSlug] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  function changeMode(next: 'user' | 'admin' | 'register') {
    if (busy) return
    setMode(next); setPassword(''); setConfirmPassword(''); setError(''); setSuccess('')
  }
  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError(''); setSuccess('')
    try {
      if (mode === 'register') {
        if (password !== confirmPassword) { setError('两次输入的密码不一致。'); return }
        await api('/auth/register', { method: 'POST', body: JSON.stringify({ username: username.trim(), display_name: displayName.trim(), password, tenant_slug: tenantSlug.trim() }) })
        setPassword(''); setConfirmPassword('')
        setSuccess('注册已提交，等待管理员在账号管理中启用后再登录。')
        return
      }
      await api('/auth/login', { method: 'POST', body: JSON.stringify({ username: username.trim(), password, mode, ...(mode === 'user' ? { tenant_slug: tenantSlug.trim() } : {}) }) })
      const session = await api<Session>('/session')
      if (!session?.user || !session.csrf_token) throw new Error('登录成功，但无法验证会话，请重试。')
      onLogin(session)
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 429) setError('尝试过于频繁，请稍后重试。')
        else if (err.status === 403) setError('请求来源不允许，请从当前平台页面重试。')
        else if (mode === 'register' && err.status === 409) setError('该账号已被使用，请换一个账号。')
        else if (mode === 'register' && err.status === 404) setError('租户标识不存在，请向管理员核对。')
        else if (mode !== 'register' && err.status === 401) setError('账号、密码、登录模式或租户标识不匹配，或账号尚未启用。')
        else setError(humanError(err))
      } else setError(humanError(err))
    } finally { setBusy(false) }
  }
  return <div className="login-screen"><div className="login-side"><Brand/><div className="login-illustration"><div className="orbit orbit-1"/><div className="orbit orbit-2"/><span><Icon name="shield" size={56}/></span></div><div className="login-copy"><div className="eyebrow">SECURITY OPERATIONS PLATFORM</div><h1>看清每一封邮件背后的风险。</h1><p>统一检索、分析与管理入口，帮助安全团队从海量邮件中快速聚焦关键线索。</p></div><div className="login-foot">MAILSEC NEXUS · 企业邮件安全工作台</div></div><div className="login-main"><div className="login-mobile-brand"><Brand/></div><div className="login-card"><div className="eyebrow blue">{mode === 'register' ? 'REQUEST ACCESS' : 'WELCOME BACK'}</div><h2>{mode === 'register' ? '申请用户账号' : '欢迎回来'}</h2><p className="subtle">{mode === 'register' ? '注册后须由管理员启用，方可登录并访问邮件。' : '登录后进入您的邮件安全工作台'}</p><div className="login-tabs" role="tablist" aria-label="账号入口"><button type="button" role="tab" aria-selected={mode === 'user'} disabled={busy} onClick={() => changeMode('user')}>用户登录</button><button type="button" role="tab" aria-selected={mode === 'admin'} disabled={busy} onClick={() => changeMode('admin')}>管理员登录</button><button type="button" role="tab" aria-selected={mode === 'register'} disabled={busy} onClick={() => changeMode('register')}>用户注册</button></div><form onSubmit={submit}><label>账号<input autoFocus required minLength={mode === 'register' ? 3 : undefined} maxLength={80} pattern={mode === 'register' ? '[a-zA-Z0-9._-]{3,80}' : undefined} autoComplete="username" value={username} onChange={e => setUsername(e.target.value)} placeholder={mode === 'register' ? '3–80 位字母、数字或 . _ -' : '请输入账号'}/></label>{mode === 'register' && <label>显示名称<input required maxLength={160} value={displayName} onChange={e => setDisplayName(e.target.value)} placeholder="您的姓名或团队称呼" autoComplete="name"/></label>}<label>密码<input type="password" autoComplete={mode === 'register' ? 'new-password' : 'current-password'} value={password} onChange={e => setPassword(e.target.value)} placeholder="任意密码，可留空"/></label>{mode === 'register' && <label>确认密码<input type="password" autoComplete="new-password" value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)} placeholder="再次输入密码"/></label>}{mode !== 'admin' && <label>租户标识<input required maxLength={80} value={tenantSlug} onChange={e => setTenantSlug(e.target.value)} placeholder="例如：cloud-test" autoComplete="organization"/></label>}{mode !== 'admin' && <p className="tenant-hint">租户标识是组织空间的代号，例如 cloud-test；注册后由管理员启用账号。</p>}{error && <div className="form-error" role="alert">{error}</div>}{success && <div className="form-success" role="status">{success}</div>}<Button type="submit" className="primary full" loading={busy}>{mode === 'register' ? '提交注册申请' : '安全登录'} <Icon name="arrow" size={16}/></Button></form><p className="login-hint">{mode === 'register' ? '只可申请普通用户账号；管理员账号由管理员维护。' : '请使用管理员分配的本地账号。密码不会保存在浏览器本地。'}</p></div><div className="login-bottom">© {new Date().getFullYear()} MailSec Nexus</div></div></div>
}

function Search({ session, tenants, onError }: { session: Session; tenants: Tenant[]; onError: (message: string) => void }) {
  const admin = session.user.role === 'admin'
  const [source, setSource] = useState<MailSource>('legacy')
  const [tenantId, setTenantId] = useState('')
  const [q, setQ] = useState('')
  const [sender, setSender] = useState('')
  const [subject, setSubject] = useState('')
  const [recipient, setRecipient] = useState('')
  const [risk, setRisk] = useState('')
  const [fromTime, setFromTime] = useState('')
  const [toTime, setToTime] = useState('')
  const [senderDomain, setSenderDomain] = useState('')
  const [hasAttachment, setHasAttachment] = useState('')
  const [attachmentSuffix, setAttachmentSuffix] = useState('')
  const [senderIp, setSenderIp] = useState('')
  const [attachmentMd5, setAttachmentMd5] = useState('')
  const [riskVerdict, setRiskVerdict] = useState('')
  const [subjectOrAttachment, setSubjectOrAttachment] = useState('')
  const [attachmentName, setAttachmentName] = useState('')
  const [sourceSystemId, setSourceSystemId] = useState('')
  const [nlText, setNlText] = useState('')
  const [nlPlan, setNlPlan] = useState<NlPlan | null>(null)
  const [nlExecuting, setNlExecuting] = useState<{ token: string; scope: MailFilters; pageSize: number; stats: boolean } | null>(null)
  const [nlBusy, setNlBusy] = useState(false)
  const [nlError, setNlError] = useState('')
  const [applied, setApplied] = useState<MailFilters | null>(null)
  const [offset, setOffset] = useState(0)
  const [results, setResults] = useState<SearchResponse | null>(null)
  const [stats, setStats] = useState<MailStats | null>(null)
  const [busy, setBusy] = useState(false)
  const [statsBusy, setStatsBusy] = useState(false)
  const [detail, setDetail] = useState<Mail | null>(null)
  const [detailBusy, setDetailBusy] = useState(false)
  const [detailError, setDetailError] = useState('')
  const [analysis, setAnalysis] = useState<Record<string, unknown> | null>(null)
  const [analyses, setAnalyses] = useState<Record<string, unknown>[]>([])
  const [analysisBusy, setAnalysisBusy] = useState(false)
  const [analysisError, setAnalysisError] = useState('')
  const [searchError, setSearchError] = useState('')
  const [statsError, setStatsError] = useState('')
  const requestGeneration = useRef(0)
  const statsGeneration = useRef(0)
  const detailRequest = useRef(0)
  const planGeneration = useRef(0)
  const limit = 20

  useEffect(() => {
    if (!applied && !nlExecuting) return
    const generation = requestGeneration.current
    let cancelled = false
    setBusy(true); setSearchError('')
    const request = nlExecuting
      ? api<PlanExecution>('/mail/plan/execute', { method: 'POST', body: JSON.stringify({ plan_token: nlExecuting.token, source: nlExecuting.scope.source, ...(nlExecuting.scope.tenant_id ? { tenant_id: nlExecuting.scope.tenant_id } : {}), ...(nlExecuting.stats ? {} : { limit: nlExecuting.pageSize, offset }) }) })
      : api<SearchResponse>('/mail/search', { method: 'POST', body: JSON.stringify({ ...applied, limit, offset }) })
    request.then(data => {
      if (cancelled || generation !== requestGeneration.current) return
      if (nlExecuting) {
        const execution = data as PlanExecution
        if (execution.plan.tool === 'stats') { setStats(execution.result as MailStats); setResults(null) }
        else setResults(execution.result as SearchResponse)
      } else setResults(data as SearchResponse)
    }).catch(err => { if (!cancelled && generation === requestGeneration.current) { setSearchError(humanError(err)); setResults(null) } })
      .finally(() => { if (!cancelled && generation === requestGeneration.current) setBusy(false) })
    return () => { cancelled = true }
  }, [applied, nlExecuting, offset])

  function clearResults() {
    requestGeneration.current++
    planGeneration.current++
    statsGeneration.current++
    detailRequest.current++
    setApplied(null); setNlExecuting(null); setNlPlan(null); setResults(null); setStats(null); setOffset(0)
    setBusy(false); setStatsBusy(false); setDetail(null); setDetailBusy(false)
    setDetailError(''); setAnalysis(null); setAnalyses([]); setAnalysisError(''); setSearchError(''); setStatsError(''); setNlError(''); setNlBusy(false)
  }
  function changeSource(value: MailSource) { clearResults(); setSource(value); setRisk(''); setSenderIp(''); setAttachmentMd5(''); setRiskVerdict(''); setSubjectOrAttachment(''); setAttachmentName(''); setSourceSystemId('') }
  function changeTenant(value: string) { clearResults(); setTenantId(value) }
  function editFilter(setter: (value: string) => void, value: string) { statsGeneration.current++; setStats(null); setStatsError(''); setStatsBusy(false); setter(value) }
  function filters(): MailFilters {
    return {
      source,
      ...(q.trim() ? { q: q.trim() } : {}),
      ...(sender.trim() ? { sender: sender.trim() } : {}),
      ...(subject.trim() ? { subject: subject.trim() } : {}),
      ...(recipient.trim() ? { recipient: recipient.trim() } : {}),
      ...(source === 'event' && risk ? { risk_level: risk } : {}),
      ...(fromTime ? { from_time: new Date(fromTime).toISOString() } : {}),
      ...(toTime ? { to_time: new Date(toTime).toISOString() } : {}),
      ...(senderDomain.trim() ? { sender_domain: senderDomain.trim() } : {}),
      ...(hasAttachment ? { has_attachment: hasAttachment === 'true' } : {}),
      ...(attachmentSuffix.trim() ? { attachment_suffix: attachmentSuffix.trim() } : {}),
      ...(source === 'event' && senderIp.trim() ? { sender_ip: senderIp.trim() } : {}),
      ...(source === 'event' && attachmentMd5.trim() ? { attachment_md5: attachmentMd5.trim() } : {}),
      ...(source === 'event' && riskVerdict.trim() ? { risk_verdict: riskVerdict.trim() } : {}),
      ...(source === 'event' && subjectOrAttachment.trim() ? { subject_or_attachment_contains: subjectOrAttachment.trim() } : {}),
      ...(source === 'event' && attachmentName.trim() ? { attachment_name_contains: attachmentName.trim() } : {}),
      ...(source === 'event' && sourceSystemId.trim() ? { source_system_id: sourceSystemId.trim() } : {}),
      ...(admin ? { tenant_id: Number(tenantId) } : {}),
    }
  }
  function validateTenant(): boolean {
    if (admin && !tenantId) { setSearchError('管理员检索前必须选择租户。'); return false }
    return true
  }
  function submit(event: FormEvent) {
    event.preventDefault()
    if (!validateTenant()) return
    clearResults()
    setApplied(filters())
  }
  async function previewPlan(event: FormEvent) {
    event.preventDefault()
    if (!validateTenant()) return
    clearResults()
    const generation = planGeneration.current
    setNlBusy(true)
    try {
      const planned = await api<NlPlan>('/mail/nl/plan', { method: 'POST', body: JSON.stringify({ source, text: nlText.trim(), ...(admin ? { tenant_id: Number(tenantId) } : {}) }) })
      if (generation === planGeneration.current) setNlPlan(planned)
    } catch (err) {
      if (generation === planGeneration.current) setNlError(err instanceof ApiError && err.status === 503 ? '模型未配置或服务暂不可用，请联系管理员检查“大模型接入”。' : humanError(err))
    } finally { if (generation === planGeneration.current) setNlBusy(false) }
  }
  function executePlan() {
    if (!nlPlan) return
    const scope: MailFilters = { source, ...(admin ? { tenant_id: Number(tenantId) } : {}) }
    requestGeneration.current++
    setOffset(0); setResults(null); setStats(null); setApplied(null)
    const pageSize = planPageSize(nlPlan.plan, limit)
    setNlExecuting({ token: nlPlan.plan_token, scope, pageSize, stats: nlPlan.plan.tool === 'stats' })
  }
  async function loadStats() {
    if (!validateTenant()) return
    const generation = ++statsGeneration.current
    setStats(null); setStatsError(''); setStatsBusy(true)
    try {
      const data = await api<MailStats>('/mail/stats', { method: 'POST', body: JSON.stringify(filters()) })
      if (generation === statsGeneration.current) setStats(data)
    } catch (err) { if (generation === statsGeneration.current) setStatsError(humanError(err)) }
    finally { if (generation === statsGeneration.current) setStatsBusy(false) }
  }
  async function openDetail(id: string) {
    const detailScope = applied ?? nlExecuting?.scope
    if (!id || !detailScope) return
    const request = ++detailRequest.current
    setDetailBusy(true); setDetailError(''); setDetail(null); setAnalysis(null); setAnalyses([]); setAnalysisError('')
    try {
      const params = { source: detailScope.source, ...(admin && detailScope.tenant_id ? { tenant_id: String(detailScope.tenant_id) } : {}) }
      const mail = await api<Mail>('/mail/' + encodeURIComponent(id) + qs(params))
      if (request === detailRequest.current) setDetail(mail)
      const history = await api<{items: Record<string, unknown>[]}>('/mail/' + encodeURIComponent(id) + '/analyses' + qs(params))
      if (request === detailRequest.current) setAnalyses(Array.isArray(history.items) ? history.items : [])
    } catch (err) {
      if (request === detailRequest.current) { setDetailError(humanError(err)); onError(humanError(err)) }
    } finally { if (request === detailRequest.current) setDetailBusy(false) }
  }
  async function analyzeDetail() {
    if (!detail || analysisBusy) return
    const request = detailRequest.current
    const id = mailId(detail)
    const detailScope = applied ?? nlExecuting?.scope
    if (!id || !detailScope) return
    setAnalysisBusy(true); setAnalysisError('')
    try {
      const params = { source: detailScope.source, ...(admin && detailScope.tenant_id ? { tenant_id: String(detailScope.tenant_id) } : {}) }
      const result = await api<Record<string, unknown>>('/mail/' + encodeURIComponent(id) + '/analysis' + qs(params), { method: 'POST' })
      if (request !== detailRequest.current) return
      setAnalysis(result)
      const history = await api<{items: Record<string, unknown>[]}>('/mail/' + encodeURIComponent(id) + '/analyses' + qs(params))
      if (request === detailRequest.current) setAnalyses(Array.isArray(history.items) ? history.items : [])
    } catch (err) { if (request === detailRequest.current) setAnalysisError(humanError(err)) }
    finally { if (request === detailRequest.current) setAnalysisBusy(false) }
  }
  function closeDetail() { detailRequest.current++; setDetail(null); setDetailError(''); setDetailBusy(false); setAnalysis(null); setAnalyses([]); setAnalysisError('') }
  const legacy = source === 'legacy'
  const resultDescription = results ? (results.total === null ? `本页 ${results.items.length} 条 · 总数未计算` : `共 ${results.total} 条 · 当前显示 ${results.items.length} 条`) : '提交条件后显示实时结果'
  const pageLimit = nlExecuting?.pageSize ?? limit
  const canNext = canGoNextPage(results, offset, pageLimit)
  const recipients = (mail: Mail) => Array.isArray(mail.receiver_accounts) ? mail.receiver_accounts.join(', ') : Array.isArray(mail.recipients) ? mail.recipients.join(', ') : text(mail.recipient)
  return <>
    <div className="page-head"><div><span className="eyebrow blue">INVESTIGATION / SEARCH</span><h1>智能邮件检索</h1><p>选择数据源，再按正文、主题、地址等条件查询 Cloud 中的邮件。</p></div><span className="page-badge">SMART SEARCH</span></div>
    <section className="panel search-panel">
      <div className="panel-head"><div><h2>检索条件</h2><p>历史 EML 与 JSON 邮件事件是独立数据源，结果不会混合。</p></div><Icon name="search" size={20}/></div>
      <form onSubmit={submit} className="search-form">
        <label className="field compact"><span>数据源</span><select aria-label="数据源" value={source} onChange={e => changeSource(e.target.value as MailSource)}><option value="legacy">历史 EML 邮件</option><option value="event">JSON 邮件事件</option></select></label>
        <label className="field grow"><span>{legacy ? '正文包含' : '关键词'}</span><input value={q} onChange={e => editFilter(setQ, e.target.value)} placeholder={legacy ? '仅检索正文内容' : '主题、正文、地址或线索…'}/></label>
        <label className="field"><span>发件人</span><input value={sender} onChange={e => editFilter(setSender, e.target.value)} placeholder="sender@example.com"/></label>
        <label className="field"><span>收件人</span><input value={recipient} onChange={e => editFilter(setRecipient, e.target.value)} placeholder="recipient@example.com"/></label>
        <label className="field"><span>主题包含</span><input value={subject} onChange={e => editFilter(setSubject, e.target.value)} placeholder="主题中的文字"/></label>
        <label className="field compact"><span>风险等级{legacy ? '（仅事件）' : ''}</span><select value={legacy ? '' : risk} disabled={legacy} onChange={e => editFilter(setRisk, e.target.value)}><option value="">全部等级</option><option value="high">高风险</option><option value="medium">中风险</option><option value="low">低风险</option><option value="unknown">未知 / 未研判</option></select></label>
        {admin && <label className="field"><span>检索租户 <b className="required">*</b></span><select required value={tenantId} onChange={e => changeTenant(e.target.value)}><option value="">请选择租户</option>{tenants.map(t => <option key={t.id} value={t.id}>{t.name} ({t.slug})</option>)}</select></label>}
        <Button className="primary search-submit" type="submit" loading={busy}><Icon name="search" size={16}/> 开始检索</Button>
        <Button className="secondary search-submit" type="button" loading={statsBusy} onClick={loadStats}>统计匹配数</Button>
      </form>
      <details className="advanced-filters"><summary>高级筛选</summary><div className="advanced-grid">
        <label>开始时间<input type="datetime-local" value={fromTime} onChange={e => editFilter(setFromTime, e.target.value)}/></label>
        <label>结束时间<input type="datetime-local" value={toTime} onChange={e => editFilter(setToTime, e.target.value)}/></label>
        <label>发件域名<input value={senderDomain} onChange={e => editFilter(setSenderDomain, e.target.value)}/></label>
        <label>附件<select value={hasAttachment} onChange={e => editFilter(setHasAttachment, e.target.value)}><option value="">不限</option><option value="true">有附件</option><option value="false">无附件</option></select></label>
        <label>附件扩展名<input value={attachmentSuffix} onChange={e => editFilter(setAttachmentSuffix, e.target.value)} placeholder="pdf"/></label>
        {!legacy && <><label>发件 IP<input value={senderIp} onChange={e => editFilter(setSenderIp, e.target.value)}/></label><label>附件 MD5<input value={attachmentMd5} onChange={e => editFilter(setAttachmentMd5, e.target.value)}/></label><label>风险判定<input value={riskVerdict} onChange={e => editFilter(setRiskVerdict, e.target.value)}/></label><label>主题或附件名包含<input value={subjectOrAttachment} onChange={e => editFilter(setSubjectOrAttachment, e.target.value)}/></label><label>附件名包含<input value={attachmentName} onChange={e => editFilter(setAttachmentName, e.target.value)}/></label><label>来源系统 ID<input value={sourceSystemId} onChange={e => editFilter(setSourceSystemId, e.target.value)}/></label></>}
      </div></details>
      {admin && tenants.length === 0 && <p className="inline-hint">尚无可选租户。请先在租户管理中创建并配置检索集成。</p>}
      {legacy && <p className="inline-hint">历史邮件无风险评级；列表不计算全量总数，点击“统计匹配数”可单独查询。</p>}
      {searchError && <div className="form-error" role="alert">{searchError}</div>}
      {statsError && <div className="form-error" role="alert">{statsError}</div>}
      {stats && <p className="search-stats" role="status">匹配总数：<strong>{stats.total}</strong>{(nlExecuting?.scope.source ?? source) === 'legacy' && <> · 含附件：{text(stats.with_attachment)} · 解析失败：{text(stats.parse_failed)}</>}</p>}
    </section>
    <section className="panel nl-panel"><div className="panel-head"><div><h2>自然语言智能检索</h2><p>先预览模型生成的查询计划，确认后执行精确条件。</p></div></div>
      <form className="nl-form" onSubmit={previewPlan}><label>描述要找的邮件或统计条件<textarea required maxLength={1000} value={nlText} onChange={e => { clearResults(); setNlText(e.target.value) }} placeholder="例如：查找上周发给我的可疑邮件"/></label><Button className="primary" type="submit" loading={nlBusy}>生成查询计划</Button></form>
      {nlError && <div className="form-error" role="alert">{nlError}</div>}
      {nlPlan && <div className="nl-preview"><strong>查询计划预览</strong><pre>{JSON.stringify(nlPlan.plan, null, 2)}</pre><Button className="primary" type="button" onClick={executePlan} loading={busy}>确认并执行</Button></div>}
    </section>
    <section className="panel results-panel">
      <div className="panel-head"><div><h2>检索结果</h2><p>{resultDescription}</p></div>{results && <span className="result-count">{results.total === null ? `${results.items.length} THIS PAGE` : `${results.total} RESULTS`}</span>}</div>
      {busy ? <Empty title="正在检索邮件…"/> : results?.items.length ? <>
        <div className="table-scroll"><table><thead><tr><th>主题 / 邮件 ID</th><th>发件人</th><th>{legacy ? '解析状态' : '风险等级'}</th><th>{legacy ? '发送时间' : '接收时间'}</th><th></th></tr></thead><tbody>{results.items.map((mail, index) => <tr key={mailId(mail) || String(index)} onClick={() => openDetail(mailId(mail))} tabIndex={0} onKeyDown={e => { if (e.key === 'Enter') openDetail(mailId(mail)) }}><td><strong>{text(mail.subject, '（无主题）')}</strong><small>{mailId(mail)}</small></td><td>{mailSender(mail)}</td><td>{legacy ? text(mail.parse_status, '未报告') : <Pill value={mail.risk_level}/>}</td><td>{mailTime(mail, source)}</td><td><Icon name="arrow" size={16}/></td></tr>)}</tbody></table></div>
      </> : <Empty title={results ? (offset > 0 ? '本页没有更多邮件' : '没有找到匹配邮件') : '从一个线索开始'} description={results ? (offset > 0 ? '可返回上一页，或调整条件重新检索。' : '可以调整条件后重试。') : '可留空条件浏览邮件，或输入条件缩小范围。'}/>}
      {results && !busy && <div className="pagination"><span>第 {Math.floor(offset / pageLimit) + 1} 页{offset + pageLimit >= 10000 && ' · 最多检索至偏移量 10000'}</span><div><button className="secondary" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - pageLimit))}>上一页</button><button className="secondary" disabled={!canNext} onClick={() => setOffset(offset + pageLimit)}>下一页</button></div></div>}
    </section>
    {(detail || detailBusy || detailError) && <div className="drawer-backdrop" onClick={closeDetail}><aside className="drawer" role="dialog" aria-modal="true" aria-label="邮件详情" onClick={e => e.stopPropagation()}><div className="drawer-head"><div><span className="eyebrow blue">MAIL DETAIL</span><h2>邮件详情</h2></div><button className="icon-button" onClick={closeDetail} aria-label="关闭详情"><Icon name="close"/></button></div>{detailBusy && <Empty title="正在加载邮件…"/>}{detailError && <div className="form-error">{detailError}</div>}{detail && <div className="drawer-body"><h3>{text(detail.subject, '（无主题）')}</h3>{!legacy && <Pill value={detail.risk_level}/>}<dl><div><dt>邮件 ID</dt><dd>{mailId(detail)}</dd></div><div><dt>发件人</dt><dd>{mailSender(detail)}</dd></div><div><dt>收件人</dt><dd>{recipients(detail)}</dd></div><div><dt>{legacy ? '发送时间' : '接收时间'}</dt><dd>{mailTime(detail, source)}</dd></div>{legacy && <div><dt>入库时间</dt><dd>{dateText(detail.ingested_at)}</dd></div>}</dl><h4>正文（纯文本）</h4><pre className="body-text">{text(detail.text_content ?? detail.body_text ?? detail.body, '此邮件没有可展示的纯文本正文。')}</pre><h4>按需安全研判</h4><p className="inline-hint">{legacy ? '历史邮件研判依赖本机原始 EML 与扫描服务。' : '事件研判只使用受限元数据与脱敏片段，不扫描附件内容。'}</p><Button className="secondary" type="button" loading={analysisBusy} onClick={analyzeDetail}>研判此邮件</Button>{analysisError && <div className="form-error" role="alert">{analysisError}</div>}{analysis && <p role="status">本次意见：{text(analysis.risk_level ?? analysis.status)} · 依据字段：{Array.isArray(analysis.evidence_refs) ? analysis.evidence_refs.map(item => text(item)).join('、') : '—'}</p>}<h4>历史研判</h4>{analyses.length ? <ul>{analyses.map((item, index) => <li key={index}>{text(item.risk_level ?? item.status ?? item.analysis_id)} · {dateText(item.created_at ?? item.analyzed_at)}</li>)}</ul> : <p className="inline-hint">暂无历史研判。</p>}</div>}</aside></div>}
  </>
}

function Overview({ session, onNavigate }: { session: Session; onNavigate: (page: Page) => void }) {
  const [integration, setIntegration] = useState<Integration | null>(null)
  const [modules, setModules] = useState<Module[] | null>(null)
  const [error, setError] = useState('')
  useEffect(() => { let active = true; Promise.all([api<Integration>('/integration/status'), api<{items: Module[]} | Module[]>('/modules')]).then(([i, m]) => { if (active) { setIntegration(i); setModules(Array.isArray(m) ? m : m.items) } }).catch(err => { if (active) setError(humanError(err)) }); return () => { active = false } }, [])
  const status = integration && text((integration.smart_search as Record<string, unknown> | undefined)?.status ?? integration.status ?? integration.smart_search_status ?? integration.state, '状态未报告')
  return <><div className="page-head"><div><span className="eyebrow blue">WORKSPACE / OVERVIEW</span><h1>早上好，{session.user.display_name || session.user.username}</h1><p>这里是您的邮件安全工作台。检索服务与模块状态均来自平台实时接口。</p></div><span className="page-badge">PLATFORM OVERVIEW</span></div>{error && <div className="form-error" role="alert">{error}</div>}<div className="overview-grid"><section className="panel hero-panel"><div className="hero-pattern"/><span className="eyebrow">START INVESTIGATING</span><h2>从可疑邮件中，找到关键答案。</h2><p>跨主题、地址与正文快速定位，再深入查看邮件详情。</p><button className="white-button" onClick={() => onNavigate('search')}>打开智能检索 <Icon name="arrow" size={16}/></button></section><section className="panel status-panel"><div className="panel-head"><div><h2>服务连接</h2><p>来自集成状态接口</p></div><Icon name="shield" size={19}/></div><div className="service-row"><span className={'status-dot ' + (status?.toLowerCase().includes('connect') || status?.toLowerCase().includes('ready') || status?.toLowerCase().includes('ok') ? 'good' : '')}/><div><strong>Smart Search</strong><small>{status || '正在获取状态…'}</small></div></div><p className="status-caption">如需为租户接入专用检索实例，请联系平台管理员。</p></section></div><div className="section-title"><div><span className="eyebrow blue">CAPABILITIES</span><h2>平台模块</h2></div><span>{modules ? `${modules.length} 个模块` : '加载中…'}</span></div><div className="module-grid"><button className="module-card" onClick={() => onNavigate('search')}><span className="module-icon blue-icon"><Icon name="search" size={22}/></span><strong>智能检索</strong><p>快速查询、过滤与查看邮件详情</p><span className="module-link">进入模块 <Icon name="arrow" size={15}/></span></button><button className="module-card" onClick={() => onNavigate('header-parser')}><span className="module-icon cyan-icon"><Icon name="mail" size={22}/></span><strong>邮件头解析</strong><p>接口预留，尚未接入业务服务</p><span className="module-link">查看说明 <Icon name="arrow" size={15}/></span></button><button className="module-card" onClick={() => onNavigate('threat-trace')}><span className="module-icon amber-icon"><Icon name="trace" size={22}/></span><strong>威胁溯源</strong><p>接口预留，尚未接入业务服务</p><span className="module-link">查看说明 <Icon name="arrow" size={15}/></span></button></div></>
}

function ModulePage({ page }: { page: 'header-parser' | 'threat-trace' }) { const parser = page === 'header-parser'; return <><div className="page-head"><div><span className="eyebrow blue">CAPABILITIES / UPCOMING</span><h1>{pageNames[page]}</h1><p>{parser ? '邮件头与认证链路解析' : '威胁事件关联与来源分析'}</p></div><span className="page-badge">INTERFACE RESERVED</span></div><section className="panel module-placeholder"><span className="placeholder-icon"><Icon name={parser ? 'mail' : 'trace'} size={32}/></span><span className="eyebrow blue">COMING SOON</span><h2>模块尚未接入</h2><p>导航入口和平台接口已预留。当前版本不会展示模拟分析结果，也不会调用未配置的后端服务。</p><div className="placeholder-line"><span>状态</span><strong>等待服务接入</strong></div></section></> }

function AdminLlm() {
  const [providers, setProviders] = useState<LlmProvider[]>([])
  const [config, setConfig] = useState<LlmConfig | null>(null)
  const [selected, setSelected] = useState('')
  const [provider, setProvider] = useState<'openai' | 'anthropic'>('openai')
  const [baseUrl, setBaseUrl] = useState('')
  const [model, setModel] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [clearKey, setClearKey] = useState(false)
  const [authorized, setAuthorized] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  useEffect(() => {
    let active = true
    Promise.all([api<LlmConfig>('/llm/config'), api<{ items: LlmProvider[] }>('/llm/providers')])
      .then(([value, catalog]) => {
        if (!active) return
        setConfig(value); setProviders(catalog.items); setSelected(catalog.items.find(item => item.provider === value.provider && item.base_url === value.base_url)?.id || ''); setProvider(value.provider || 'openai')
        setBaseUrl(value.base_url); setModel(value.model); setAuthorized(value.external_authorized)
      }).catch(err => { if (active) setError(humanError(err)) })
    return () => { active = false }
  }, [])
  function choose(id: string) {
    setSelected(id)
    const item = providers.find(candidate => candidate.id === id)
    if (item) { setProvider(item.provider); setBaseUrl(item.base_url); setModel(item.models[0] || '') }
  }
  async function save(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError(''); setNotice('')
    try {
      const body = { provider, base_url: baseUrl.trim(), model: model.trim(), external_authorized: authorized,
        ...(clearKey ? { api_key: '' } : apiKey ? { api_key: apiKey } : {}) }
      const updated = await api<LlmConfig>('/admin/llm/config', { method: 'PUT', body: JSON.stringify(body) })
      setConfig(updated); setApiKey(''); setClearKey(false); setNotice('已保存模型配置。')
    } catch (err) { setError(humanError(err)) } finally { setBusy(false) }
  }
  const chosen = providers.find(item => item.id === selected)
  return <><div className="page-head"><div><span className="eyebrow blue">ADMINISTRATION / MODEL</span><h1>大模型接入</h1><p>配置自然语言检索的模型服务；密钥仅保存在服务端。</p></div></div>
    <section className="panel"><div className="panel-head"><div><h2>模型连接</h2><p>{config ? (config.configured ? '已配置' : '尚未配置') : '正在读取配置…'} · {config?.api_key_set ? '密钥已设置' : '尚无密钥'}</p></div></div>
      <form className="stack-form llm-form" onSubmit={save}>
        <label>服务商<select aria-label="服务商" value={selected} onChange={e => choose(e.target.value)}><option value="">自定义 / 当前配置</option>{providers.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
        {chosen && <p className="llm-provider-links"><a href={chosen.website} target="_blank" rel="noopener noreferrer">官网</a> · <a href={chosen.docs_url} target="_blank" rel="noopener noreferrer">API 文档</a></p>}
        <label>接口协议<select value={provider} onChange={e => setProvider(e.target.value as 'openai' | 'anthropic')}><option value="openai">OpenAI 兼容</option><option value="anthropic">Anthropic Messages</option></select></label>
        <label>Base URL<input type="url" required value={baseUrl} onChange={e => setBaseUrl(e.target.value)} placeholder="https://api.example.com/v1"/></label>
        <label>模型名<input required value={model} onChange={e => setModel(e.target.value)} list="llm-models" placeholder="选择或输入模型名"/></label>
        {chosen && <p className="llm-provider-links">预置模型：{chosen.models.join('、')}</p>}<datalist id="llm-models">{chosen?.models.map(name => <option key={name} value={name}/>)}</datalist>
        <label>API Key<input type="password" autoComplete="off" value={apiKey} disabled={clearKey} onChange={e => setApiKey(e.target.value)} placeholder={config?.api_key_set ? '留空保留现有密钥' : '输入服务商密钥'}/></label>
        <label className="llm-check"><input type="checkbox" checked={clearKey} onChange={e => { setClearKey(e.target.checked); setApiKey('') }}/>清除已保存的密钥</label>
        <label className="llm-check"><input type="checkbox" checked={authorized} onChange={e => setAuthorized(e.target.checked)}/>授权自然语言查询发送至外部模型服务</label>
        {error && <div role="alert" className="form-error">{error}</div>}{notice && <div role="status" className="form-success">{notice}</div>}
        <Button type="submit" className="primary" loading={busy}>保存配置</Button>
      </form>
    </section></>
}

function AdminUsers({ tenants, onError }: { tenants: Tenant[]; onError: (message: string) => void }) {
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [formOpen, setFormOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')
  const [emptyPassword, setEmptyPassword] = useState(false)
  const [role, setRole] = useState<'user' | 'admin'>('user')
  const [tenantId, setTenantId] = useState('')
  const [editing, setEditing] = useState<User | null>(null)
  const load = useCallback(async () => { try { const data = await api<{ items: User[] }>('/admin/users'); setUsers(data.items) } catch (e) { onError(humanError(e)) } finally { setLoading(false) } }, [onError])
  useEffect(() => { void load() }, [load])
  function clear() { setFormOpen(false); setEditing(null); setUsername(''); setDisplayName(''); setPassword(''); setEmptyPassword(false); setRole('user'); setTenantId('') }
  function edit(user: User) { setEditing(user); setDisplayName(user.display_name); setPassword(''); setEmptyPassword(false); setFormOpen(true) }
  async function submit(event: FormEvent) { event.preventDefault(); setBusy(true); try { if (editing) await api('/admin/users/' + encodeURIComponent(String(editing.id)), { method: 'PATCH', body: JSON.stringify({ display_name: displayName, ...(emptyPassword ? { password: '' } : password ? { password } : {}) }) }); else await api('/admin/users', { method: 'POST', body: JSON.stringify({ username, display_name: displayName, password, role, tenant_id: role === 'admin' ? null : Number(tenantId) }) }); clear(); await load() } catch (e) { onError(humanError(e)) } finally { setBusy(false) } }
  async function toggle(user: User) { if (!window.confirm(`确定${user.is_active === false ? '启用' : '停用'}账号 ${user.username}？`)) return; try { await api('/admin/users/' + encodeURIComponent(String(user.id)), { method: 'PATCH', body: JSON.stringify({ is_active: user.is_active === false }) }); await load() } catch (e) { onError(humanError(e)) } }
  return <><div className="page-head"><div><span className="eyebrow blue">ADMINISTRATION / ACCOUNTS</span><h1>账号管理</h1><p>创建平台账号、启用注册申请、修改名称、重置密码和停用访问权限。</p></div><button className="primary" onClick={() => { clear(); setFormOpen(true) }}><Icon name="plus" size={16}/> 创建账号</button></div><section className="panel"><div className="panel-head"><div><h2>账号列表</h2><p>注册申请默认停用；核对身份与租户后，点击“启用”方可登录。数据由平台数据库提供</p></div><span className="result-count">{users.length} ACCOUNTS</span></div>{loading ? <Empty title="正在加载账号…"/> : users.length ? <div className="table-scroll"><table><thead><tr><th>账号</th><th>角色</th><th>所属租户</th><th>状态</th><th>操作</th></tr></thead><tbody>{users.map(user => <tr key={user.id}><td><strong>{text(user.display_name)}</strong><small>{user.username}</small></td><td>{user.role === 'admin' ? '管理员' : '普通用户'}</td><td>{tenants.find(t => t.id === user.tenant_id)?.name ?? text(user.tenant_id)}</td><td><Pill value={user.is_active === false ? '待审核 / 已停用' : '正常'}/></td><td><div className="table-actions"><button className="text-button" onClick={() => edit(user)}>编辑 / 重置密码</button><button className="text-button danger-text" onClick={() => toggle(user)}>{user.is_active === false ? '启用' : '停用'}</button></div></td></tr>)}</tbody></table></div> : <Empty title="暂无账号" description="点击右上角创建第一个账号。"/>}</section>{formOpen && <div className="modal-backdrop" onMouseDown={clear}><div className="modal" role="dialog" aria-modal="true" aria-label={editing ? '编辑账号' : '创建账号'} onMouseDown={e => e.stopPropagation()}><div className="modal-head"><div><span className="eyebrow blue">ACCOUNT MANAGEMENT</span><h2>{editing ? '编辑账号' : '创建账号'}</h2></div><button className="icon-button" onClick={clear} aria-label="关闭"><Icon name="close"/></button></div><form onSubmit={submit} className="stack-form">{!editing && <label>账号<input required value={username} onChange={e => setUsername(e.target.value)} placeholder="唯一登录名"/></label>}<label>显示名称<input required value={displayName} onChange={e => setDisplayName(e.target.value)} placeholder="用户姓名"/></label><label>{editing ? '新密码（留空则不修改）' : '初始密码'}<input disabled={emptyPassword} type="password" autoComplete="new-password" value={password} onChange={e => setPassword(e.target.value)} placeholder="任意密码，可留空"/></label>{editing && <label className="checkbox-field"><input type="checkbox" checked={emptyPassword} onChange={e => setEmptyPassword(e.target.checked)}/>将密码设为空</label>}{!editing && <><label>角色<select value={role} onChange={e => setRole(e.target.value as 'user' | 'admin')}><option value="user">普通用户</option><option value="admin">管理员</option></select></label>{role === 'user' && <label>所属租户<select required value={tenantId} onChange={e => setTenantId(e.target.value)}><option value="">请选择租户</option>{tenants.map(t => <option key={t.id} value={t.id}>{t.name} ({t.slug})</option>)}</select></label>}</>}<div className="modal-actions"><button type="button" className="secondary" onClick={clear}>取消</button><Button className="primary" type="submit" loading={busy}>保存</Button></div></form></div></div>}</> }

function AdminTenants({ onError, onChange }: { onError: (message: string) => void; onChange: () => void }) {
  const [items, setItems] = useState<Tenant[]>([])
  const [loading, setLoading] = useState(true)
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')
  const [busy, setBusy] = useState(false)
  const load = useCallback(async () => { try { const data = await api<{ items: Tenant[] }>('/admin/tenants'); setItems(data.items) } catch (e) { onError(humanError(e)) } finally { setLoading(false) } }, [onError])
  useEffect(() => { void load() }, [load])
  async function submit(event: FormEvent) { event.preventDefault(); setBusy(true); try { await api('/admin/tenants', { method: 'POST', body: JSON.stringify({ name, slug }) }); setOpen(false); setName(''); setSlug(''); await load(); onChange() } catch (e) { onError(humanError(e)) } finally { setBusy(false) } }
  return <><div className="page-head"><div><span className="eyebrow blue">ADMINISTRATION / TENANTS</span><h1>租户管理</h1><p>管理隔离的组织空间；检索实例需要单独配置后才能使用。</p></div><button className="primary" onClick={() => setOpen(true)}><Icon name="plus" size={16}/> 创建租户</button></div><section className="panel"><div className="panel-head"><div><h2>租户列表</h2><p>平台用户按租户隔离访问邮件数据</p></div><span className="result-count">{items.length} TENANTS</span></div>{loading ? <Empty title="正在加载租户…"/> : items.length ? <div className="table-scroll"><table><thead><tr><th>租户名称</th><th>标识</th><th>租户 ID</th><th>状态</th></tr></thead><tbody>{items.map(t => <tr key={t.id}><td><strong>{t.name}</strong></td><td><code>{t.slug}</code></td><td className="mono">{t.id}</td><td><Pill value={t.is_active === false ? '已停用' : '正常'}/></td></tr>)}</tbody></table></div> : <Empty title="暂无租户" description="创建租户后，可以为其分配普通用户账号。"/>}</section>{open && <div className="modal-backdrop" onMouseDown={() => setOpen(false)}><div className="modal" role="dialog" aria-modal="true" aria-label="创建租户" onMouseDown={e => e.stopPropagation()}><div className="modal-head"><div><span className="eyebrow blue">TENANT MANAGEMENT</span><h2>创建租户</h2></div><button className="icon-button" onClick={() => setOpen(false)} aria-label="关闭"><Icon name="close"/></button></div><form onSubmit={submit} className="stack-form"><label>租户名称<input required value={name} onChange={e => setName(e.target.value)} placeholder="组织名称"/></label><label>租户标识<input required pattern="[a-z0-9][a-z0-9-]*" value={slug} onChange={e => setSlug(e.target.value)} placeholder="小写字母、数字、连字符"/></label><div className="modal-actions"><button type="button" className="secondary" onClick={() => setOpen(false)}>取消</button><Button className="primary" type="submit" loading={busy}>创建</Button></div></form></div></div>}</> }

function AdminAudit({ onError }: { onError: (message: string) => void }) {
  const [items, setItems] = useState<Audit[]>([])
  const [loading, setLoading] = useState(true)
  useEffect(() => { let active = true; api<{items: Audit[]}>('/admin/audit').then(data => { if (active) setItems(data.items) }).catch(err => { if (active) onError(humanError(err)) }).finally(() => { if (active) setLoading(false) }); return () => { active = false } }, [onError])
  return <><div className="page-head"><div><span className="eyebrow blue">ADMINISTRATION / AUDIT</span><h1>操作审计</h1><p>追踪平台关键管理动作，审计记录由后端持久化。</p></div></div><section className="panel"><div className="panel-head"><div><h2>审计日志</h2><p>最近的账号与租户管理操作</p></div><span className="result-count">{items.length} EVENTS</span></div>{loading ? <Empty title="正在加载审计记录…"/> : items.length ? <div className="table-scroll"><table><thead><tr><th>时间</th><th>操作</th><th>执行者</th><th>目标</th><th>详情</th></tr></thead><tbody>{items.map((item, index) => <tr key={text(item.id, String(index))}><td>{dateText(item.created_at ?? item.timestamp)}</td><td><strong>{text(item.action)}</strong></td><td>{text(item.actor_username ?? item.actor_user_id)}</td><td>{text(item.target ?? item.target_type ?? item.target_id)}</td><td>{text(item.detail ?? item.details)}</td></tr>)}</tbody></table></div> : <Empty title="暂无审计记录" description="管理操作发生后，会在此显示。"/>}</section></>
}

function PasswordDialog({ onClose, onSuccess, onError }: { onClose: () => void; onSuccess: () => void; onError: (message: string) => void }) {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [busy, setBusy] = useState(false)
  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true)
    try { await api('/session/password', { method: 'POST', body: JSON.stringify({ current_password: current, new_password: next }) }); onSuccess() }
    catch (err) { onError(humanError(err)) } finally { setBusy(false) }
  }
  return <div className="modal-backdrop" onMouseDown={onClose}><div className="modal" role="dialog" aria-modal="true" aria-label="修改我的密码" onMouseDown={e => e.stopPropagation()}><div className="modal-head"><div><span className="eyebrow blue">ACCOUNT SECURITY</span><h2>修改我的密码</h2></div><button className="icon-button" onClick={onClose} aria-label="关闭"><Icon name="close"/></button></div><p className="dialog-copy">修改后所有登录会话将失效，请使用新密码重新登录。</p><form className="stack-form" onSubmit={submit}><label>当前密码<input type="password" autoComplete="current-password" value={current} onChange={e => setCurrent(e.target.value)}/></label><label>新密码<input type="password" autoComplete="new-password" value={next} onChange={e => setNext(e.target.value)} placeholder="任意密码，可留空"/></label><div className="modal-actions"><button type="button" className="secondary" onClick={onClose}>取消</button><Button className="primary" type="submit" loading={busy}>确认修改</Button></div></form></div></div>
}

function AdminStorage({ onError }: { onError: (message: string) => void }) {
  const [storage, setStorage] = useState<Record<string, unknown> | null>(null)
  const [queue, setQueue] = useState<Record<string, unknown> | null>(null)
  const [jobs, setJobs] = useState<Record<string, unknown>[]>([])
  const [status, setStatus] = useState('')
  const [loading, setLoading] = useState(false)
  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [stored, queued, listed] = await Promise.all([
        api<Record<string, unknown>>('/admin/mail/storage'),
        api<Record<string, unknown>>('/admin/mail/queue'),
        api<{items: Record<string, unknown>[]}>('/admin/mail/jobs' + (status ? qs({ status, limit: '20' }) : '?limit=20')),
      ])
      setStorage(stored); setQueue(queued); setJobs(Array.isArray(listed.items) ? listed.items : [])
    } catch (err) { onError(humanError(err)) }
    finally { setLoading(false) }
  }, [status, onError])
  useEffect(() => { void load() }, [load])
  const database = storage?.database as Record<string, unknown> | undefined
  const tables = Array.isArray(database?.tables) ? database.tables as Record<string, unknown>[] : []
  const rows = (name: string) => text(tables.find(table => table.name === name)?.logical_rows)
  return <><div className="page-head"><div><span className="eyebrow blue">ADMINISTRATION / STORAGE</span><h1>邮件存储与队列</h1><p>只读查看全局存储与接入状态；此处不提供清理或删除操作。</p></div><Button className="secondary" loading={loading} onClick={() => void load()}>刷新</Button></div>
    <section className="panel"><h2>存储概览</h2><p>邮件事件：{rows('mail_events')} · 历史 EML：{rows('mail_records')}</p><pre className="body-text">{database ? JSON.stringify(database, null, 2) : '正在加载存储数据…'}</pre></section>
    <section className="panel"><h2>接入队列</h2><pre className="body-text">{queue ? JSON.stringify(queue, null, 2) : '正在加载队列…'}</pre></section>
    <section className="panel"><div className="panel-head"><h2>任务回执（最近 20 条）</h2><label>状态<select value={status} onChange={e => setStatus(e.target.value)}><option value="">全部</option><option value="pending">待处理</option><option value="retry">重试中</option><option value="done">已完成</option></select></label></div>{jobs.length ? <div className="table-scroll"><table><thead><tr><th>任务 ID</th><th>状态</th><th>接收时间</th></tr></thead><tbody>{jobs.map((job, index) => <tr key={index}><td>{text(job.job_id)}</td><td><Pill value={job.status}/></td><td>{dateText(job.accepted_at)}</td></tr>)}</tbody></table></div> : <Empty title="暂无任务"/>}</section></>
}

export default function App() {
  const [session, setSession] = useState<Session | null>(null)
  const [checking, setChecking] = useState(true)
  const [page, setPage] = useState<Page>('overview')
  const [notice, setNotice] = useState('')
  const [menuOpen, setMenuOpen] = useState(false)
  const [tenants, setTenants] = useState<Tenant[]>([])
  const [logoutBusy, setLogoutBusy] = useState(false)
  const [passwordOpen, setPasswordOpen] = useState(false)
  const onError = useCallback((message: string) => setNotice(message), [])
  useEffect(() => { const unauthorized = () => { setCsrfToken(''); setSession(null); setTenants([]); setPage('overview') }; window.addEventListener('mailsec:unauthorized', unauthorized); return () => window.removeEventListener('mailsec:unauthorized', unauthorized) }, [])
  const loadTenants = useCallback(async () => { try { const data = await api<{items: Tenant[]}>('/admin/tenants'); setTenants(data.items) } catch (err) { onError(humanError(err)) } }, [onError])
  useEffect(() => { api<Session>('/session').then(data => { setCsrfToken(data.csrf_token); setSession(data) }).catch(err => { if (!(err instanceof ApiError && err.status === 401)) setNotice(humanError(err)) }).finally(() => setChecking(false)) }, [])
  useEffect(() => { if (session?.user.role === 'admin') void loadTenants() }, [session, loadTenants])
  function login(data: Session) { setCsrfToken(data.csrf_token); setSession(data); setPage('overview'); setNotice('') }
  async function logout() { setLogoutBusy(true); try { await api('/session/logout', { method: 'POST' }); setCsrfToken(''); setSession(null); setPage('overview'); setTenants([]) } catch (err) { onError(humanError(err)) } finally { setLogoutBusy(false) } }
  function navigate(target: Page) { setPage(target); setMenuOpen(false); setNotice(''); window.scrollTo({ top: 0, behavior: 'smooth' }) }
  if (checking) return <div className="boot-screen"><Brand/><p>正在验证平台会话…</p></div>
  if (!session) return <>{notice && <Notice message={notice} onClose={() => setNotice('')}/>}<Login onLogin={login}/></>
  const admin = session.user.role === 'admin'
  const groups: { title: string; links: { page: Page; icon: string; hint?: string }[] }[] = [
    { title: '工作空间', links: [{ page: 'overview', icon: 'grid' }, { page: 'search', icon: 'search' }] },
    { title: '安全分析', links: [{ page: 'header-parser', icon: 'mail', hint: '待接入' }, { page: 'threat-trace', icon: 'trace', hint: '待接入' }] },
    ...(admin ? [{ title: '系统管理', links: [{ page: 'users' as Page, icon: 'users' }, { page: 'tenants' as Page, icon: 'tenant' }, { page: 'audit' as Page, icon: 'audit' }, { page: 'storage' as Page, icon: 'grid' }, { page: 'llm' as Page, icon: 'llm' }] }] : []),
  ]
  return <div className="app-shell"><button className={'mobile-scrim ' + (menuOpen ? 'visible' : '')} onClick={() => setMenuOpen(false)} aria-label="关闭导航"/><aside className={'sidebar ' + (menuOpen ? 'open' : '')}><Brand/><div className="sidebar-workspace"><span className="workspace-avatar"><Icon name="shield" size={18}/></span><span><strong>{admin ? '平台管理空间' : '安全工作空间'}</strong><small>{admin ? 'ADMIN WORKSPACE' : 'USER WORKSPACE'}</small></span></div><nav aria-label="主导航">{groups.map(group => <div className="nav-group" key={group.title}><div className="nav-label">{group.title}</div>{group.links.map(link => <button key={link.page} className={'nav-link ' + (page === link.page ? 'active' : '')} onClick={() => navigate(link.page)} aria-current={page === link.page ? 'page' : undefined}><Icon name={link.icon} size={18}/><span>{pageNames[link.page]}</span>{link.hint && <em>{link.hint}</em>}</button>)}</div>)}</nav><div className="sidebar-bottom"><div className="sidebar-service">本地账号 · 服务端鉴权</div><div className="sidebar-version">MAILSEC NEXUS · v0.1</div></div></aside><div className="app-main"><header className="topbar"><div className="topbar-left"><button className="mobile-menu icon-button" aria-label="打开导航" onClick={() => setMenuOpen(true)}><Icon name="menu"/></button><span>平台</span><Icon name="arrow" size={13}/><strong>{pageNames[page]}</strong></div><div className="topbar-right"><span className="topbar-role">{admin ? '管理员' : '用户'}</span><span className="user-avatar">{(session.user.display_name || session.user.username).slice(0, 1).toUpperCase()}</span><span className="topbar-name">{session.user.display_name || session.user.username}</span><button className="account-button" onClick={() => setPasswordOpen(true)}>修改密码</button><button className="icon-button logout-button" onClick={logout} disabled={logoutBusy} aria-label="退出登录" title="退出登录"><Icon name="logout" size={17}/></button></div></header><main className="content">{notice && <Notice message={notice} onClose={() => setNotice('')}/ >}{page === 'overview' && <Overview session={session} onNavigate={navigate}/ >}{page === 'search' && <Search session={session} tenants={tenants} onError={onError}/ >}{(page === 'header-parser' || page === 'threat-trace') && <ModulePage page={page}/ >}{admin && page === 'users' && <AdminUsers tenants={tenants} onError={onError}/ >}{admin && page === 'tenants' && <AdminTenants onError={onError} onChange={loadTenants}/ >}{admin && page === 'audit' && <AdminAudit onError={onError}/ >}{admin && page === 'storage' && <AdminStorage onError={onError}/ >}{admin && page === 'llm' && <AdminLlm/ >}</main></div>{passwordOpen && <PasswordDialog onClose={() => setPasswordOpen(false)} onSuccess={() => { setPasswordOpen(false); setCsrfToken(''); setSession(null); setPage('overview'); setTenants([]) }} onError={onError}/>}</div>
}
