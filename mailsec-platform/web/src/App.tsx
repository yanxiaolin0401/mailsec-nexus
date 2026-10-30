import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { api, ApiError, dateText, setCsrfToken, text, type Audit, type Integration, type Mail, type Module, type SearchResponse, type Session, type Tenant, type User } from './api'

type Page = 'overview' | 'search' | 'header-parser' | 'threat-trace' | 'users' | 'tenants' | 'audit'
const pageNames: Record<Page, string> = { overview: '总览', search: '智能检索', 'header-parser': '邮件头解析', 'threat-trace': '威胁溯源', users: '账号管理', tenants: '租户管理', audit: '操作审计' }
const humanError = (error: unknown) => error instanceof Error ? error.message : '操作失败，请稍后重试。'
const qs = (params: Record<string, string>) => '?' + new URLSearchParams(params).toString()
const mailId = (mail: Mail) => text(mail.event_id ?? mail.id, '')
const mailTime = (mail: Mail) => dateText(mail.event_time ?? mail.received_at)
const mailSender = (mail: Mail) => text(mail.sender_account ?? mail.sender)

function Icon({ name, size = 18 }: { name: string; size?: number }) {
  const paths: Record<string, ReactNode> = {
    grid: <><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></>,
    search: <><circle cx="10.8" cy="10.8" r="6.8"/><path d="m16 16 5 5"/></>,
    mail: <><rect x="2.5" y="4" width="19" height="16" rx="2"/><path d="m3 6 9 7 9-7"/></>,
    trace: <><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 2v6m0 8v6M2 12h6m8 0h6"/></>,
    users: <><circle cx="9" cy="8" r="3.2"/><path d="M3 20v-2a6 6 0 0 1 12 0v2M17 5a3 3 0 0 1 0 6m1 3a5 5 0 0 1 3 5v1"/></>,
    tenant: <><rect x="4" y="3" width="16" height="18" rx="2"/><path d="M9 7h2m3 0h2M9 11h2m3 0h2M9 15h2m3 0h2M11 21v-4h2v4"/></>,
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
  const [mode, setMode] = useState<'user' | 'admin'>('user')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [tenantSlug, setTenantSlug] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError('')
    try {
      await api('/auth/login', { method: 'POST', body: JSON.stringify({ username, password, mode, ...(mode === 'user' ? { tenant_slug: tenantSlug.trim() } : {}) }) })
      const session = await api<Session>('/session')
      if (!session?.user || !session.csrf_token) throw new Error('登录成功，但无法验证会话，请重试。')
      onLogin(session)
    } catch (err) { setError(humanError(err)) } finally { setBusy(false) }
  }
  return <div className="login-screen"><div className="login-side"><Brand/><div className="login-illustration"><div className="orbit orbit-1"/><div className="orbit orbit-2"/><span><Icon name="shield" size={56}/></span></div><div className="login-copy"><div className="eyebrow">SECURITY OPERATIONS PLATFORM</div><h1>看清每一封邮件背后的风险。</h1><p>统一检索、分析与管理入口，帮助安全团队从海量邮件中快速聚焦关键线索。</p></div><div className="login-foot">MAILSEC NEXUS · 企业邮件安全工作台</div></div><div className="login-main"><div className="login-mobile-brand"><Brand/></div><div className="login-card"><div className="eyebrow blue">WELCOME BACK</div><h2>欢迎回来</h2><p className="subtle">登录后进入您的邮件安全工作台</p><div className="login-tabs" role="tablist" aria-label="登录方式"><button type="button" role="tab" aria-selected={mode === 'user'} onClick={() => { setMode('user'); setError('') }}>用户登录</button><button type="button" role="tab" aria-selected={mode === 'admin'} onClick={() => { setMode('admin'); setError('') }}>管理员登录</button></div><form onSubmit={submit}><label>账号<input autoFocus required autoComplete="username" value={username} onChange={e => setUsername(e.target.value)} placeholder="请输入账号"/></label><label>密码<input required type="password" autoComplete="current-password" value={password} onChange={e => setPassword(e.target.value)} placeholder="请输入密码"/></label>{mode === 'user' && <label>租户标识<input required value={tenantSlug} onChange={e => setTenantSlug(e.target.value)} placeholder="例如：acme" autoComplete="organization"/></label>}{error && <div className="form-error" role="alert">{error}</div>}<Button type="submit" className="primary full" loading={busy}>安全登录 <Icon name="arrow" size={16}/></Button></form><p className="login-hint">请使用管理员分配的本地账号。密码不会保存在浏览器本地。</p></div><div className="login-bottom">© {new Date().getFullYear()} MailSec Nexus</div></div></div>
}

function Search({ session, tenants, onError }: { session: Session; tenants: Tenant[]; onError: (message: string) => void }) {
  const admin = session.user.role === 'admin'
  const [tenantId, setTenantId] = useState('')
  const [q, setQ] = useState('')
  const [sender, setSender] = useState('')
  const [risk, setRisk] = useState('')
  const [applied, setApplied] = useState<{ q: string; sender: string; risk_level: string; tenant_id?: number } | null>(null)
  const [offset, setOffset] = useState(0)
  const [results, setResults] = useState<SearchResponse | null>(null)
  const [busy, setBusy] = useState(false)
  const [detail, setDetail] = useState<Mail | null>(null)
  const [detailBusy, setDetailBusy] = useState(false)
  const [detailError, setDetailError] = useState('')
  const detailRequest = useRef(0)
  const [searchError, setSearchError] = useState('')
  const limit = 20
  useEffect(() => {
    if (!applied) return
    let cancelled = false
    setBusy(true); setSearchError('')
    api<SearchResponse>('/mail/search', { method: 'POST', body: JSON.stringify({ ...applied, limit, offset }) }).then(data => { if (!cancelled) setResults(data) }).catch(err => { if (!cancelled) { setSearchError(humanError(err)); setResults(null) } }).finally(() => { if (!cancelled) setBusy(false) })
    return () => { cancelled = true }
  }, [applied, offset])
  function changeTenant(value: string) { detailRequest.current++; setTenantId(value); setApplied(null); setResults(null); setOffset(0); setDetail(null); setDetailBusy(false); setDetailError(''); setSearchError('') }
  function submit(event: FormEvent) {
    event.preventDefault()
    if (admin && !tenantId) { setSearchError('管理员检索前必须选择租户。'); return }
    if (!q.trim() && !sender.trim() && !risk) { setSearchError('请至少输入一项检索条件。'); return }
    setOffset(0); setResults(null); setApplied({ ...(q.trim() ? { q: q.trim() } : {}), ...(sender.trim() ? { sender: sender.trim() } : {}), ...(risk ? { risk_level: risk } : {}), ...(admin ? { tenant_id: Number(tenantId) } : {}) } as { q: string; sender: string; risk_level: string; tenant_id?: number })
  }
  async function openDetail(id: string) {
    const request = ++detailRequest.current
    setDetailBusy(true); setDetailError(''); setDetail(null)
    try { const mail = await api<Mail>('/mail/' + encodeURIComponent(id) + (admin && applied?.tenant_id ? qs({ tenant_id: String(applied.tenant_id) }) : '')); if (request === detailRequest.current) setDetail(mail) }
    catch (err) { if (request === detailRequest.current) { setDetailError(humanError(err)); onError(humanError(err)) } } finally { if (request === detailRequest.current) setDetailBusy(false) }
  }
  return <><div className="page-head"><div><span className="eyebrow blue">INVESTIGATION / SEARCH</span><h1>智能邮件检索</h1><p>按关键字、发件人与风险等级定位邮件，查看原始内容与安全线索。</p></div><span className="page-badge">SMART SEARCH</span></div><section className="panel search-panel"><div className="panel-head"><div><h2>检索条件</h2><p>查询实时连接已配置的 Smart Search 实例</p></div><Icon name="search" size={20}/></div><form onSubmit={submit} className="search-form"><label className="field grow"><span>关键词</span><input value={q} onChange={e => setQ(e.target.value)} placeholder="主题、正文、地址或线索…"/></label><label className="field"><span>发件人</span><input value={sender} onChange={e => setSender(e.target.value)} placeholder="sender@example.com"/></label><label className="field compact"><span>风险等级</span><select value={risk} onChange={e => setRisk(e.target.value)}><option value="">全部等级</option><option value="high">高风险</option><option value="medium">中风险</option><option value="low">低风险</option><option value="unknown">未知 / 未研判</option></select></label>{admin && <label className="field"><span>检索租户 <b className="required">*</b></span><select required value={tenantId} onChange={e => changeTenant(e.target.value)}><option value="">请选择租户</option>{tenants.map(t => <option key={t.id} value={t.id}>{t.name} ({t.slug})</option>)}</select></label>}<Button className="primary search-submit" type="submit" loading={busy}><Icon name="search" size={16}/> 开始检索</Button></form>{admin && tenants.length === 0 && <p className="inline-hint">尚无可选租户。请先在租户管理中创建并配置检索集成。</p>}{searchError && <div className="form-error" role="alert">{searchError}</div>}</section><section className="panel results-panel"><div className="panel-head"><div><h2>检索结果</h2><p>{results ? `共 ${results.total} 条 · 当前显示 ${results.items.length} 条` : '提交条件后显示实时结果'}</p></div>{results && <span className="result-count">{results.total} RESULTS</span>}</div>{busy ? <Empty title="正在检索邮件…"/> : results?.items.length ? <><div className="table-scroll"><table><thead><tr><th>主题 / 邮件 ID</th><th>发件人</th><th>风险等级</th><th>接收时间</th><th></th></tr></thead><tbody>{results.items.map((mail, index) => <tr key={mailId(mail) || String(index)} onClick={() => openDetail(mailId(mail))} tabIndex={0} onKeyDown={e => { if (e.key === 'Enter') openDetail(mailId(mail)) }}><td><strong>{text(mail.subject, '（无主题）')}</strong><small>{mailId(mail)}</small></td><td>{mailSender(mail)}</td><td><Pill value={mail.risk_level}/></td><td>{mailTime(mail)}</td><td><Icon name="arrow" size={16}/></td></tr>)}</tbody></table></div><div className="pagination"><span>第 {Math.floor(offset / limit) + 1} 页</span><div><button className="secondary" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))}>上一页</button><button className="secondary" disabled={results.may_have_more === false || (typeof results.total === 'number' && offset + results.items.length >= results.total)} onClick={() => setOffset(offset + limit)}>下一页</button></div></div></> : <Empty title={results ? '没有找到匹配邮件' : '从一个线索开始'} description={results ? '可以调整关键词或筛选条件后重试。' : '输入检索条件并提交，结果将在这里显示。'}/>}</section>{(detail || detailBusy || detailError) && <div className="drawer-backdrop" onClick={() => { detailRequest.current++; setDetail(null); setDetailError(''); setDetailBusy(false) }}><aside className="drawer" role="dialog" aria-modal="true" aria-label="邮件详情" onClick={e => e.stopPropagation()}><div className="drawer-head"><div><span className="eyebrow blue">MAIL DETAIL</span><h2>邮件详情</h2></div><button className="icon-button" onClick={() => { detailRequest.current++; setDetail(null); setDetailError(''); setDetailBusy(false) }} aria-label="关闭详情"><Icon name="close"/></button></div>{detailBusy && <Empty title="正在加载邮件…"/>}{detailError && <div className="form-error">{detailError}</div>}{detail && <div className="drawer-body"><h3>{text(detail.subject, '（无主题）')}</h3><Pill value={detail.risk_level}/><dl><div><dt>邮件 ID</dt><dd>{mailId(detail)}</dd></div><div><dt>发件人</dt><dd>{mailSender(detail)}</dd></div><div><dt>收件人</dt><dd>{Array.isArray(detail.receiver_accounts) ? detail.receiver_accounts.join(', ') : text(detail.recipient ?? detail.recipients)}</dd></div><div><dt>接收时间</dt><dd>{mailTime(detail)}</dd></div></dl><h4>正文（纯文本）</h4><pre className="body-text">{text(detail.text_content ?? detail.body_text ?? detail.body, '此邮件没有可展示的纯文本正文。')}</pre></div>}</aside></div>}</>
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

function AdminUsers({ tenants, onError }: { tenants: Tenant[]; onError: (message: string) => void }) {
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [formOpen, setFormOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<'user' | 'admin'>('user')
  const [tenantId, setTenantId] = useState('')
  const [editing, setEditing] = useState<User | null>(null)
  const load = useCallback(async () => { try { const data = await api<{ items: User[] }>('/admin/users'); setUsers(data.items) } catch (e) { onError(humanError(e)) } finally { setLoading(false) } }, [onError])
  useEffect(() => { void load() }, [load])
  function clear() { setFormOpen(false); setEditing(null); setUsername(''); setDisplayName(''); setPassword(''); setRole('user'); setTenantId('') }
  function edit(user: User) { setEditing(user); setDisplayName(user.display_name); setPassword(''); setFormOpen(true) }
  async function submit(event: FormEvent) { event.preventDefault(); setBusy(true); try { if (editing) await api('/admin/users/' + encodeURIComponent(String(editing.id)), { method: 'PATCH', body: JSON.stringify({ display_name: displayName, ...(password ? { password } : {}) }) }); else await api('/admin/users', { method: 'POST', body: JSON.stringify({ username, display_name: displayName, password, role, tenant_id: role === 'admin' ? null : Number(tenantId) }) }); clear(); await load() } catch (e) { onError(humanError(e)) } finally { setBusy(false) } }
  async function toggle(user: User) { if (!window.confirm(`确定${user.is_active === false ? '启用' : '停用'}账号 ${user.username}？`)) return; try { await api('/admin/users/' + encodeURIComponent(String(user.id)), { method: 'PATCH', body: JSON.stringify({ is_active: user.is_active === false }) }); await load() } catch (e) { onError(humanError(e)) } }
  return <><div className="page-head"><div><span className="eyebrow blue">ADMINISTRATION / ACCOUNTS</span><h1>账号管理</h1><p>创建平台账号、修改显示名称、重置密码和停用访问权限。</p></div><button className="primary" onClick={() => { clear(); setFormOpen(true) }}><Icon name="plus" size={16}/> 创建账号</button></div><section className="panel"><div className="panel-head"><div><h2>账号列表</h2><p>数据由平台数据库提供</p></div><span className="result-count">{users.length} ACCOUNTS</span></div>{loading ? <Empty title="正在加载账号…"/> : users.length ? <div className="table-scroll"><table><thead><tr><th>账号</th><th>角色</th><th>所属租户</th><th>状态</th><th>操作</th></tr></thead><tbody>{users.map(user => <tr key={user.id}><td><strong>{text(user.display_name)}</strong><small>{user.username}</small></td><td>{user.role === 'admin' ? '管理员' : '普通用户'}</td><td>{tenants.find(t => t.id === user.tenant_id)?.name ?? text(user.tenant_id)}</td><td><Pill value={user.is_active === false ? '已停用' : '正常'}/></td><td><div className="table-actions"><button className="text-button" onClick={() => edit(user)}>编辑 / 重置密码</button><button className="text-button danger-text" onClick={() => toggle(user)}>{user.is_active === false ? '启用' : '停用'}</button></div></td></tr>)}</tbody></table></div> : <Empty title="暂无账号" description="点击右上角创建第一个账号。"/>}</section>{formOpen && <div className="modal-backdrop" onMouseDown={clear}><div className="modal" role="dialog" aria-modal="true" aria-label={editing ? '编辑账号' : '创建账号'} onMouseDown={e => e.stopPropagation()}><div className="modal-head"><div><span className="eyebrow blue">ACCOUNT MANAGEMENT</span><h2>{editing ? '编辑账号' : '创建账号'}</h2></div><button className="icon-button" onClick={clear} aria-label="关闭"><Icon name="close"/></button></div><form onSubmit={submit} className="stack-form">{!editing && <label>账号<input required value={username} onChange={e => setUsername(e.target.value)} placeholder="唯一登录名"/></label>}<label>显示名称<input required value={displayName} onChange={e => setDisplayName(e.target.value)} placeholder="用户姓名"/></label><label>{editing ? '新密码（留空则不修改）' : '初始密码'}<input required={!editing} type="password" autoComplete="new-password" value={password} onChange={e => setPassword(e.target.value)} placeholder="至少 12 位，建议使用随机密码"/></label>{!editing && <><label>角色<select value={role} onChange={e => setRole(e.target.value as 'user' | 'admin')}><option value="user">普通用户</option><option value="admin">管理员</option></select></label>{role === 'user' && <label>所属租户<select required value={tenantId} onChange={e => setTenantId(e.target.value)}><option value="">请选择租户</option>{tenants.map(t => <option key={t.id} value={t.id}>{t.name} ({t.slug})</option>)}</select></label>}</>}<div className="modal-actions"><button type="button" className="secondary" onClick={clear}>取消</button><Button className="primary" type="submit" loading={busy}>保存</Button></div></form></div></div>}</> }

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
  return <div className="modal-backdrop" onMouseDown={onClose}><div className="modal" role="dialog" aria-modal="true" aria-label="修改我的密码" onMouseDown={e => e.stopPropagation()}><div className="modal-head"><div><span className="eyebrow blue">ACCOUNT SECURITY</span><h2>修改我的密码</h2></div><button className="icon-button" onClick={onClose} aria-label="关闭"><Icon name="close"/></button></div><p className="dialog-copy">修改后所有登录会话将失效，请使用新密码重新登录。</p><form className="stack-form" onSubmit={submit}><label>当前密码<input required type="password" autoComplete="current-password" value={current} onChange={e => setCurrent(e.target.value)}/></label><label>新密码<input required type="password" autoComplete="new-password" value={next} onChange={e => setNext(e.target.value)} placeholder="至少 12 位"/></label><div className="modal-actions"><button type="button" className="secondary" onClick={onClose}>取消</button><Button className="primary" type="submit" loading={busy}>确认修改</Button></div></form></div></div>
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
    ...(admin ? [{ title: '系统管理', links: [{ page: 'users' as Page, icon: 'users' }, { page: 'tenants' as Page, icon: 'tenant' }, { page: 'audit' as Page, icon: 'audit' }] }] : []),
  ]
  return <div className="app-shell"><button className={'mobile-scrim ' + (menuOpen ? 'visible' : '')} onClick={() => setMenuOpen(false)} aria-label="关闭导航"/><aside className={'sidebar ' + (menuOpen ? 'open' : '')}><Brand/><div className="sidebar-workspace"><span className="workspace-avatar"><Icon name="shield" size={18}/></span><span><strong>{admin ? '平台管理空间' : '安全工作空间'}</strong><small>{admin ? 'ADMIN WORKSPACE' : 'USER WORKSPACE'}</small></span></div><nav aria-label="主导航">{groups.map(group => <div className="nav-group" key={group.title}><div className="nav-label">{group.title}</div>{group.links.map(link => <button key={link.page} className={'nav-link ' + (page === link.page ? 'active' : '')} onClick={() => navigate(link.page)} aria-current={page === link.page ? 'page' : undefined}><Icon name={link.icon} size={18}/><span>{pageNames[link.page]}</span>{link.hint && <em>{link.hint}</em>}</button>)}</div>)}</nav><div className="sidebar-bottom"><div className="sidebar-service">本地账号 · 服务端鉴权</div><div className="sidebar-version">MAILSEC NEXUS · v0.1</div></div></aside><div className="app-main"><header className="topbar"><div className="topbar-left"><button className="mobile-menu icon-button" aria-label="打开导航" onClick={() => setMenuOpen(true)}><Icon name="menu"/></button><span>平台</span><Icon name="arrow" size={13}/><strong>{pageNames[page]}</strong></div><div className="topbar-right"><span className="topbar-role">{admin ? '管理员' : '用户'}</span><span className="user-avatar">{(session.user.display_name || session.user.username).slice(0, 1).toUpperCase()}</span><span className="topbar-name">{session.user.display_name || session.user.username}</span><button className="account-button" onClick={() => setPasswordOpen(true)}>修改密码</button><button className="icon-button logout-button" onClick={logout} disabled={logoutBusy} aria-label="退出登录" title="退出登录"><Icon name="logout" size={17}/></button></div></header><main className="content">{notice && <Notice message={notice} onClose={() => setNotice('')}/ >}{page === 'overview' && <Overview session={session} onNavigate={navigate}/ >}{page === 'search' && <Search session={session} tenants={tenants} onError={onError}/ >}{(page === 'header-parser' || page === 'threat-trace') && <ModulePage page={page}/ >}{admin && page === 'users' && <AdminUsers tenants={tenants} onError={onError}/ >}{admin && page === 'tenants' && <AdminTenants onError={onError} onChange={loadTenants}/ >}{admin && page === 'audit' && <AdminAudit onError={onError}/ >}</main></div>{passwordOpen && <PasswordDialog onClose={() => setPasswordOpen(false)} onSuccess={() => { setPasswordOpen(false); setCsrfToken(''); setSession(null); setPage('overview'); setTenants([]) }} onError={onError}/>}</div>
}
