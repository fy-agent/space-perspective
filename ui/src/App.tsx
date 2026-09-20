import { useCallback, useEffect, useRef, useState } from 'react'

import {
  ApiError,
  cancelScan,
  createPreview,
  createScan,
  executePlan,
  fetchAssets,
  fetchDuplicates,
  fetchHealth,
  fetchOperations,
  fetchOverview,
  fetchQuarantine,
  fetchScan,
  fetchSuggestions,
  subscribeScan,
  undoOperation,
  type Asset,
  type DuplicateGroup,
  type FileIntelOverview,
  type HealthResponse,
  type OperationPlan,
  type OperationReceipt,
  type QuarantineItem,
  type ScanEvent,
  type ScanSession,
  type Suggestion,
} from './api'
import InventoryReportView from './InventoryReportView'
import './styles.css'

type View = 'inventory' | 'overview' | 'duplicates' | 'suggestions' | 'quarantine' | 'history'
type ConnectionState = 'checking' | 'connected' | 'degraded' | 'offline'

const navigation: Array<{ key: View; label: string; index: string }> = [
  { key: 'inventory', label: '空间报告', index: '01' },
  { key: 'overview', label: '体检总览', index: '02' },
  { key: 'duplicates', label: '重复文件', index: '03' },
  { key: 'suggestions', label: '整理建议', index: '04' },
  { key: 'quarantine', label: '隔离区', index: '05' },
  { key: 'history', label: '操作记录', index: '06' },
]

const categoryLabels: Record<string, string> = {
  photo: '图片', video: '视频', archive: '压缩包', installer: '安装包', document: '文档', pdf: 'PDF', audio: '音频', other: '其他',
}

const sourceLabels: Record<string, string> = {
  wechat: '微信文件', suspected_wechat: '疑似微信', downloads: '下载', desktop: '桌面', documents: '文档', pictures: '图片', screenshots: '截图', manual_folder: '手动目录', unknown: '未知',
}

const riskLabels = { low: '低风险', medium: '需确认', high: '受保护' }

function formatBytes(value: number) {
  if (value < 1024) return `${value} B`
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MB`
  return `${(value / 1024 ** 3).toFixed(2)} GB`
}

function filename(path: string) {
  return path.split(/[\\/]/).pop() || path
}

function errorCopy(error: unknown) {
  if (error instanceof ApiError) return `${error.message}（${error.code}）`
  if (error instanceof Error) return error.message
  return '操作未能完成，请重试。'
}

function scanStatusLabel(status: ScanSession['status']) {
  return {
    pending: '等待扫描', running: '只读扫描中', completed: '体检完成', partial: '部分完成', cancelled: '已取消', failed: '扫描失败',
  }[status]
}

export default function App() {
  const [view, setView] = useState<View>('inventory')
  const [connection, setConnection] = useState<ConnectionState>('checking')
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [path, setPath] = useState('')
  const [session, setSession] = useState<ScanSession | null>(null)
  const [assets, setAssets] = useState<Asset[]>([])
  const [overview, setOverview] = useState<FileIntelOverview | null>(null)
  const [duplicates, setDuplicates] = useState<DuplicateGroup[]>([])
  const [suggestions, setSuggestions] = useState<Suggestion[]>([])
  const [quarantine, setQuarantine] = useState<QuarantineItem[]>([])
  const [operations, setOperations] = useState<OperationReceipt[]>([])
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [plan, setPlan] = useState<OperationPlan | null>(null)
  const [receipt, setReceipt] = useState<OperationReceipt | null>(null)
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const monitorCleanup = useRef<(() => void) | null>(null)

  const refreshSecondary = useCallback(async () => {
    const [quarantineResponse, operationResponse] = await Promise.all([
      fetchQuarantine(), fetchOperations(),
    ])
    setQuarantine(quarantineResponse.items)
    setOperations(operationResponse.items)
  }, [])

  const loadScanData = useCallback(async (scanId: string) => {
    const [assetResponse, overviewResponse, duplicateResponse, suggestionResponse] = await Promise.all([
      fetchAssets(scanId), fetchOverview(scanId), fetchDuplicates(scanId), fetchSuggestions(scanId),
    ])
    setAssets(assetResponse.items)
    setOverview(overviewResponse)
    setDuplicates(duplicateResponse.items)
    setSuggestions(suggestionResponse.items)
    setSelected(new Set(
      suggestionResponse.items
        .filter((item) => item.default_selected && item.risk_level === 'low' && item.proposed_action === 'quarantine')
        .map((item) => item.id),
    ))
    await refreshSecondary()
  }, [refreshSecondary])

  const finishScan = useCallback(async (scanId: string) => {
    const latest = await fetchScan(scanId)
    setSession(latest)
    if (latest.status === 'completed' || latest.status === 'partial') {
      await loadScanData(scanId)
      setNotice(`已在本机索引 ${latest.files_indexed} 个文件；扫描阶段没有移动原文件。`)
    }
  }, [loadScanData])

  const monitorScan = useCallback((scanId: string) => {
    monitorCleanup.current?.()
    let stopped = false
    let finishing = false
    const handleTerminal = async () => {
      if (finishing || stopped) return
      finishing = true
      try {
        await finishScan(scanId)
      } catch (monitorError) {
        setError(errorCopy(monitorError))
      } finally {
        cleanup()
      }
    }
    const handleEvent = (event: ScanEvent) => {
      setSession((current) => current ? {
        ...current,
        status: event.type === 'completed' ? 'completed' : event.type === 'cancelled' ? 'cancelled' : event.type === 'failed' ? 'failed' : 'running',
        current_path: event.current_path,
        files_seen: event.files_seen,
        files_indexed: event.files_indexed,
        files_skipped: event.files_skipped,
        bytes_seen: event.bytes_seen,
      } : current)
      if (['completed', 'cancelled', 'failed'].includes(event.type)) void handleTerminal()
    }
    const closeStream = subscribeScan(scanId, handleEvent, () => undefined)
    const timer = window.setInterval(async () => {
      if (stopped || finishing) return
      try {
        const latest = await fetchScan(scanId)
        setSession(latest)
        if (['completed', 'partial', 'cancelled', 'failed'].includes(latest.status)) void handleTerminal()
      } catch (pollError) {
        setError(errorCopy(pollError))
        cleanup()
      }
    }, 700)
    function cleanup() {
      if (stopped) return
      stopped = true
      closeStream()
      window.clearInterval(timer)
      if (monitorCleanup.current === cleanup) monitorCleanup.current = null
    }
    monitorCleanup.current = cleanup
  }, [finishScan])

  useEffect(() => {
    const controller = new AbortController()
    fetchHealth(controller.signal)
      .then((payload) => {
        setHealth(payload)
        setConnection(payload.status === 'ok' && payload.db_status === 'ok' ? 'connected' : 'degraded')
      })
      .catch((healthError: unknown) => {
        if (healthError instanceof DOMException && healthError.name === 'AbortError') return
        setConnection('offline')
      })
    return () => {
      controller.abort()
      monitorCleanup.current?.()
    }
  }, [])

  async function retryHealth() {
    setConnection('checking')
    try {
      const payload = await fetchHealth()
      setHealth(payload)
      setConnection(payload.status === 'ok' && payload.db_status === 'ok' ? 'connected' : 'degraded')
    } catch {
      setConnection('offline')
    }
  }

  async function startScan() {
    if (!path.trim()) {
      setError('请输入要授权体检的本机绝对目录。')
      return
    }
    setBusy(true)
    setError(null)
    setNotice(null)
    setPlan(null)
    setReceipt(null)
    try {
      const created = await createScan(path.trim())
      setSession(created)
      monitorScan(created.id)
    } catch (scanError) {
      setError(errorCopy(scanError))
    } finally {
      setBusy(false)
    }
  }

  async function stopScan() {
    if (!session) return
    try {
      const updated = await cancelScan(session.id)
      setSession(updated)
      setNotice('已请求取消；已经索引的本地引用会保留。')
    } catch (cancelError) {
      setError(errorCopy(cancelError))
    }
  }

  async function selectView(next: View) {
    setView(next)
    setError(null)
    setNotice(null)
    if (next === 'inventory') {
      setPlan(null)
      setReceipt(null)
    }
    if (next === 'quarantine' || next === 'history') {
      try {
        await refreshSecondary()
      } catch (refreshError) {
        setError(errorCopy(refreshError))
      }
    }
  }

  function toggleSuggestion(id: string) {
    setSelected((current) => {
      const next = new Set(current)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  async function previewSelection() {
    if (!selected.size) return
    setBusy(true)
    setError(null)
    try {
      setPlan(await createPreview([...selected]))
    } catch (previewError) {
      setError(errorCopy(previewError))
    } finally {
      setBusy(false)
    }
  }

  async function confirmPlan() {
    if (!plan) return
    setBusy(true)
    setError(null)
    try {
      const executed = await executePlan(plan)
      setReceipt(executed)
      setPlan(null)
      setNotice(executed.status === 'succeeded' ? '文件已进入应用级隔离区，并生成可撤销收据。' : '操作已完成，但存在逐文件失败；请查看收据。')
      await refreshSecondary()
      if (session) await loadScanData(session.id)
    } catch (executeError) {
      setError(errorCopy(executeError))
    } finally {
      setBusy(false)
    }
  }

  async function undo(receiptId: string) {
    setBusy(true)
    setError(null)
    try {
      const undone = await undoOperation(receiptId)
      setReceipt(undone)
      setNotice(undone.status === 'undone' ? '文件已恢复到原路径。' : '撤销存在冲突，系统没有覆盖原路径文件。')
      await refreshSecondary()
      if (session) await loadScanData(session.id)
    } catch (undoError) {
      setError(errorCopy(undoError))
    } finally {
      setBusy(false)
    }
  }

  const assetById = new Map(assets.map((asset) => [asset.id, asset]))
  const activeLabel = navigation.find((item) => item.key === view)?.label ?? '工作台'
  const isScanning = session?.status === 'pending' || session?.status === 'running'

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-workspace">跳到主要内容</a>
      <aside className="sidebar" aria-label="主导航">
        <div className="brand-lockup">
          <span className="brand-mark" aria-hidden="true">透</span>
          <div><strong>空间透视</strong><span>本地资料治理</span></div>
        </div>
        <nav className="navigation">
          {navigation.map((item) => (
            <button
              className={`nav-item ${view === item.key ? 'nav-item-active' : ''}`}
              aria-current={view === item.key ? 'page' : undefined}
              key={item.key}
              type="button"
              onClick={() => void selectView(item.key)}
            >
              <span className="nav-index" aria-hidden="true">{item.index}</span>
              <span>{item.label}</span>
              <small aria-hidden="true">{item.key === 'suggestions' && selected.size ? selected.size : '→'}</small>
            </button>
          ))}
        </nav>
        <span className="mobile-nav-hint">横向滑动查看全部入口</span>
        <div className="sidebar-promise">
          <span className="promise-dot" aria-hidden="true" />
          <p>{view === 'inventory' ? '受控报告不访问本机目录' : '文件内容默认不离开本机'}</p>
          <span>{view === 'inventory' ? 'Fixture · 零内容、零网络' : 'P0 · 可预览、可回滚'}</span>
        </div>
      </aside>

      <main className="workspace" id="main-workspace" tabIndex={-1}>
        <header className="topbar">
          <span className="section-label">工作台 / {activeLabel}</span>
          <div className="topbar-status">
            <span className={`connection-dot connection-${connection}`} aria-hidden="true" />
            <span>{connection === 'connected' ? 'Core 已连接' : connection === 'offline' ? 'Core 未连接' : connection === 'degraded' ? '索引需检查' : '连接中'}</span>
            <span className="stage-chip">
              {view === 'inventory' ? '迭代 3 · Fixture' : 'P0 · 本地模式'}
            </span>
          </div>
        </header>

        {error && <div className="message message-error" role="alert"><span>{error}</span><button type="button" onClick={() => setError(null)}>关闭</button></div>}
        {notice && <div className="message message-success" role="status"><span>{notice}</span><button type="button" onClick={() => setNotice(null)}>知道了</button></div>}

        {view === 'inventory' && (
          <InventoryReportView
            connection={connection}
            onRetryHealth={retryHealth}
            onCoreFailure={() => setConnection('offline')}
          />
        )}

        {view === 'overview' && (
          <>
            <section className="page-heading">
              <div><p className="kicker">先看清，再动文件</p><h1>本机资料体检</h1></div>
              <p>只读建立资产索引和重复证据。任何文件变更都要经过预览、确认、隔离和收据。</p>
            </section>

            <section className="scan-console" aria-labelledby="scan-title">
              <div className="console-heading">
                <div><span className="section-label">授权目录</span><h2 id="scan-title">从一个本机目录开始</h2></div>
                <span className={`status-badge status-${session?.status ?? connection}`}>{session ? scanStatusLabel(session.status) : connection === 'connected' ? '等待授权' : '服务未就绪'}</span>
              </div>
              <div className="path-form">
                <label htmlFor="scan-path">本机绝对路径</label>
                <div>
                  <input id="scan-path" value={path} onChange={(event) => setPath(event.target.value)} placeholder="例如 C:\Users\你\Downloads" disabled={isScanning || connection !== 'connected'} />
                  <button className="primary-button" type="button" onClick={() => void startScan()} disabled={busy || isScanning || connection !== 'connected'}>{isScanning ? '扫描中' : '开始只读体检'}</button>
                  {isScanning && <button className="secondary-button" type="button" onClick={() => void stopScan()}>取消</button>}
                </div>
                <small>浏览器不会读取或上传文件；此路径只授权 localhost Core 的本次扫描范围。</small>
              </div>
              {session && (
                <div className="scan-progress" aria-live="polite">
                  <div><span>已发现</span><strong>{session.files_seen}</strong></div>
                  <div><span>已索引</span><strong>{session.files_indexed}</strong></div>
                  <div><span>已跳过</span><strong>{session.files_skipped}</strong></div>
                  <div><span>已读取元数据</span><strong>{formatBytes(session.bytes_seen)}</strong></div>
                  <p title={session.current_path ?? ''}>{session.current_path ? `当前：${session.current_path}` : '等待扫描进度'}</p>
                </div>
              )}
              {connection === 'offline' && <button className="secondary-button reconnect" type="button" onClick={() => void retryHealth()}>重新检查连接</button>}
            </section>

            {overview ? <OverviewContent overview={overview} /> : <EmptyState title="还没有体检记录" detail="输入一个本机绝对目录开始只读扫描；这里不会展示虚构统计。" />}
          </>
        )}

        {view === 'duplicates' && (
          <section className="view-section">
            <ViewHeading eyebrow="Exact hash" title="精确重复文件" detail="只有 size、partial hash 和 SHA-256 全部一致的文件才会进入同组。" />
            {duplicates.length ? duplicates.map((group) => (
              <article className="duplicate-group" key={group.id}>
                <header><div><span className="risk-pill risk-low">精确重复</span><h2>{group.member_count} 个相同文件</h2></div><strong>可释放 {formatBytes(group.reclaimable_size_bytes)}</strong></header>
                <p>{group.reason}</p>
                <div className="member-list">
                  {group.members.map((member) => {
                    const asset = assetById.get(member.asset_id)
                    return <div key={member.asset_id} className={member.role === 'keep_recommended' ? 'member-keep' : ''}>
                      <span>{member.role === 'keep_recommended' ? '保留' : member.role === 'protected' ? '保护' : '候选'}</span>
                      <div><strong>{asset ? filename(asset.abs_path) : member.asset_id}</strong><small>{asset?.abs_path ?? member.reason}</small></div>
                      <em>{asset ? formatBytes(asset.size_bytes) : '—'}</em>
                    </div>
                  })}
                </div>
              </article>
            )) : <EmptyState title="没有精确重复组" detail={overview ? '当前扫描没有发现内容完全一致的文件。' : '先完成一次只读体检，再查看重复证据。'} />}
          </section>
        )}

        {view === 'suggestions' && (
          <section className="view-section suggestions-view">
            <ViewHeading eyebrow="Explainable rules" title="可解释整理建议" detail="高风险与唯一原件始终受保护；只有低风险精确重复候选可进入默认选择。" />
            {suggestions.length ? <>
              <div className="selection-bar"><span>已选择 <strong>{selected.size}</strong> 项低风险候选</span><button className="primary-button" type="button" disabled={!selected.size || busy} onClick={() => void previewSelection()}>生成操作预览</button></div>
              <div className="suggestion-list">
                {suggestions.map((item) => {
                  const actionable = item.risk_level === 'low' && item.proposed_action === 'quarantine'
                  const pathEvidence = item.evidence.items.find((evidence) => evidence.type === 'path')?.value ?? item.asset_id ?? '—'
                  return <article className="suggestion-card" key={item.id}>
                    <label className="selection-control">
                      <input type="checkbox" checked={selected.has(item.id)} disabled={!actionable} onChange={() => toggleSuggestion(item.id)} />
                      <span className={`risk-pill risk-${item.risk_level}`}>{riskLabels[item.risk_level]}</span>
                    </label>
                    <div className="suggestion-copy"><h2>{filename(pathEvidence)}</h2><p>{item.reason}</p><small title={pathEvidence}>{pathEvidence}</small></div>
                    <div className="suggestion-meta"><span>{categoryLabels[assetById.get(item.asset_id ?? '')?.category ?? ''] ?? item.category}</span><strong>{assetById.get(item.asset_id ?? '') ? formatBytes(assetById.get(item.asset_id ?? '')!.size_bytes) : '—'}</strong></div>
                  </article>
                })}
              </div>
            </> : <EmptyState title="还没有整理建议" detail="完成体检后，规则会给出证据、风险等级和可回滚动作。" />}
          </section>
        )}

        {view === 'quarantine' && (
          <section className="view-section">
            <ViewHeading eyebrow="Reversible only" title="应用级隔离区" detail="P0 不永久删除文件。每个隔离项都绑定原路径、hash 和操作收据。" />
            {quarantine.length ? <div className="record-list">{quarantine.map((item) => (
              <article key={item.id}><div><span className={`risk-pill status-${item.status}`}>{item.status === 'quarantined' ? '隔离中' : item.status === 'restored' ? '已恢复' : '需处理'}</span><h2>{filename(item.original_path)}</h2><p>{item.original_path}</p></div><div className="record-side"><strong>{formatBytes(item.original_size_bytes)}</strong><small>{item.operation_id}</small></div></article>
            ))}</div> : <EmptyState title="隔离区为空" detail="只有经过预览和确认的低风险文件才会出现在这里。" />}
          </section>
        )}

        {view === 'history' && (
          <section className="view-section">
            <ViewHeading eyebrow="Audit receipts" title="操作收据" detail="成功、失败、部分失败和撤销都会保留逐文件结果。" />
            {operations.length ? <div className="record-list">{operations.map((item) => (
              <article key={item.id}><div><span className={`risk-pill status-${item.status}`}>{item.status}</span><h2>{item.action_type === 'quarantine' ? '隔离操作' : '忽略标记'} · {item.file_count} 个文件</h2><p>{item.id} · {new Date(item.started_at).toLocaleString()}</p></div><div className="record-side"><strong>{formatBytes(item.total_size_bytes)}</strong>{!['undone', 'undo_partial'].includes(item.status) && <button className="secondary-button" type="button" disabled={busy} onClick={() => void undo(item.id)}>撤销</button>}</div></article>
            ))}</div> : <EmptyState title="还没有操作收据" detail="预览不会生成收据；只有确认执行后才会留下审计记录。" />}
          </section>
        )}

        {view !== 'inventory' && plan && (
          <div className="modal-backdrop" role="presentation">
            <section className="preview-panel" role="dialog" aria-modal="true" aria-labelledby="preview-title">
              <div className="preview-heading"><span className="section-label">执行前最后确认</span><h2 id="preview-title">操作预览</h2><p>将 {plan.summary.file_count} 个文件、共 {formatBytes(plan.summary.total_size_bytes)} 移入应用级隔离区。</p></div>
              <div className="preview-items">{plan.items.map((item) => <div key={item.asset_id}><span className="risk-pill risk-low">可回滚</span><div><strong>{filename(item.display_path)}</strong><small>{item.display_path}</small></div><em>{formatBytes(item.size_bytes)}</em></div>)}</div>
              {plan.warnings.length > 0 && <ul className="warning-list">{plan.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul>}
              <div className="preview-guard"><strong>不会永久删除</strong><span>执行后生成收据；撤销遇到同名冲突时不会覆盖。</span></div>
              <div className="modal-actions"><button className="secondary-button" type="button" onClick={() => setPlan(null)} disabled={busy}>取消</button><button className="primary-button" type="button" onClick={() => void confirmPlan()} disabled={busy}>{busy ? '执行中' : '确认移入隔离区'}</button></div>
            </section>
          </div>
        )}

        {view !== 'inventory' && receipt && <aside className="receipt-toast" aria-live="polite"><div><span className="section-label">最近收据</span><strong>{receipt.status === 'undone' ? '已完成撤销' : `操作 ${receipt.status}`}</strong><small>{receipt.id}</small></div>{!['undone', 'undo_partial'].includes(receipt.status) && <button className="secondary-button" type="button" onClick={() => void undo(receipt.id)} disabled={busy}>立即撤销</button>}<button className="icon-button" type="button" aria-label="关闭收据" onClick={() => setReceipt(null)}>×</button></aside>}

        <footer>
          <span>空间透视 v{health?.version ?? '0.1.0'}</span>
          <span>
            {view === 'inventory'
              ? `文件上传：关闭 · 云元数据分析：${health?.capabilities.cloud_metadata_analysis_enabled ? '开启' : '关闭'}`
              : `真实上传：始终关闭 · 本地 mock：${health?.capabilities.mock_provider_enabled ? '已启用' : '未启用'}`}
          </span>
        </footer>
      </main>
    </div>
  )
}

function ViewHeading({ eyebrow, title, detail }: { eyebrow: string; title: string; detail: string }) {
  return <header className="view-heading"><div><span className="section-label">{eyebrow}</span><h1>{title}</h1></div><p>{detail}</p></header>
}

function EmptyState({ title, detail }: { title: string; detail: string }) {
  return <section className="empty-state"><span aria-hidden="true">⌁</span><h2>{title}</h2><p>{detail}</p></section>
}

function OverviewContent({ overview }: { overview: FileIntelOverview }) {
  const largest = Math.max(...overview.by_category.map((item) => item.size_bytes), 1)
  return <section className="overview-content" aria-label="体检结果">
    <div className="metric-grid">
      <article><span>文件总数</span><strong>{overview.total_files}</strong><small>本地引用</small></article>
      <article><span>资料体量</span><strong>{formatBytes(overview.total_size_bytes)}</strong><small>不含文件副本</small></article>
      <article><span>高风险保护</span><strong>{overview.risk_summary.find((item) => item.risk_level === 'high')?.file_count ?? 0}</strong><small>永不默认选中</small></article>
      <article><span>报告生成</span><strong>{new Date(overview.generated_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</strong><small>本机时间</small></article>
    </div>
    <div className="overview-grid">
      <article className="bucket-panel"><header><span className="section-label">按类型</span><h2>空间分布</h2></header><div className="bucket-list">{overview.by_category.map((item) => <div key={item.key}><div><strong>{categoryLabels[item.key] ?? item.key}</strong><span>{item.file_count} 个 · {formatBytes(item.size_bytes)}</span></div><i style={{ width: `${Math.max(4, item.size_bytes / largest * 100)}%` }} /></div>)}</div></article>
      <article className="bucket-panel"><header><span className="section-label">按来源</span><h2>目录线索</h2></header><div className="source-grid">{overview.by_source.map((item) => <div key={item.key}><strong>{sourceLabels[item.key] ?? item.key}</strong><span>{item.file_count} 个</span><small>{formatBytes(item.size_bytes)}</small></div>)}</div></article>
    </div>
    <article className="large-files"><header><span className="section-label">Top files</span><h2>大文件</h2></header><div>{overview.top_large_files.map((asset) => <div key={asset.id}><span>{categoryLabels[asset.category] ?? asset.category}</span><strong title={asset.abs_path}>{filename(asset.abs_path)}</strong><small>{sourceLabels[asset.source_hint] ?? asset.source_hint}</small><em>{formatBytes(asset.size_bytes)}</em></div>)}</div></article>
  </section>
}
