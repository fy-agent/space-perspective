import { useRef, useState } from 'react'

import {
  createInventoryAnalysis,
  createInventoryReport,
  createInventoryScan,
  createInventorySnapshot,
  downloadInventoryReport,
  getInventoryAnalysis,
  getInventoryReport,
  getInventoryScan,
  getInventorySnapshot,
  previewInventoryPacket,
  type InventoryAnalysisBudget,
  type InventoryAnalysisConsent,
  type InventoryProvider,
} from './api'

type ConnectionState = 'checking' | 'connected' | 'degraded' | 'offline'
type BusyStage = 'scan' | 'packet' | 'analysis' | 'report' | 'download' | null
type Preset = 'rules' | 'fake' | 'synthetic'

type InventoryScan = Awaited<ReturnType<typeof createInventoryScan>>
type InventorySnapshot = Awaited<ReturnType<typeof createInventorySnapshot>>
type PacketPreview = Awaited<ReturnType<typeof previewInventoryPacket>>
type AnalysisResult = Awaited<ReturnType<typeof createInventoryAnalysis>>
type ReportResult = Awaited<ReturnType<typeof createInventoryReport>>

interface InventoryReportViewProps {
  connection: ConnectionState
  onRetryHealth: () => Promise<void>
  onCoreFailure: () => void
}

const fieldCategories = [
  '对象类型与证据引用',
  '名称或脱敏代号',
  '位置或父级引用',
  '逻辑与分配空间',
  '规则提示与覆盖摘要',
]

const workflowSteps = [
  { key: 'scan', index: '01', label: '受控盘点' },
  { key: 'packet', index: '02', label: '证据包预览' },
  { key: 'analysis', index: '03', label: '规则 / synthetic 分析' },
  { key: 'report', index: '04', label: 'XLSX 报告' },
] as const

const syntheticBudget: InventoryAnalysisBudget = {
  max_provider_calls: 1,
  max_schema_retries: 1,
  max_input_tokens: 12_000,
  max_output_tokens: 2_500,
  max_packet_bytes: 256_000,
  timeout_ms: 90_000,
  max_estimated_cost: 0,
}

function formatBytes(value: number) {
  if (value < 1024) return `${value} B`
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MB`
  return `${(value / 1024 ** 3).toFixed(2)} GB`
}

function formatNullableBytes(value: number | null, empty: string) {
  return value === null ? empty : formatBytes(value)
}

function errorCopy(error: unknown) {
  if (error && typeof error === 'object' && 'code' in error && 'message' in error) {
    return `${String(error.message)}（${String(error.code)}）`
  }
  if (error instanceof Error) return error.message
  return '本地报告流程未能完成，请重试当前步骤。'
}

function analysisStatusCopy(
  status: AnalysisResult['analysis']['status'],
  synthetic: boolean,
) {
  if (synthetic && status === 'ai_complete') {
    return '离线受控 synthetic 分析已完成'
  }
  if (synthetic) {
    return 'Synthetic 分析未合并，已生成规则版'
  }
  return {
    deterministic_only: '规则版已完成',
    ai_complete: '受控模拟分析已完成',
    ai_failed_fallback: '模拟分析失败，已回退规则版',
  }[status]
}

function receiptStatusCopy(status: AnalysisResult['receipt']['status']) {
  return {
    not_called: '未调用 Provider',
    succeeded: '调用成功',
    cache_hit: '命中本地缓存',
    privacy_blocked: '隐私门禁阻断',
    budget_blocked: '预算门禁阻断',
    grounding_failed: '证据校验失败',
    schema_failed: 'Schema 校验失败',
    provider_failed: 'Provider 失败',
  }[status]
}

export default function InventoryReportView({
  connection,
  onRetryHealth,
  onCoreFailure,
}: InventoryReportViewProps) {
  const [preset, setPreset] = useState<Preset>('rules')
  const [busyStage, setBusyStage] = useState<BusyStage>(null)
  const [scan, setScan] = useState<InventoryScan | null>(null)
  const [snapshot, setSnapshot] = useState<InventorySnapshot | null>(null)
  const [preview, setPreview] = useState<PacketPreview | null>(null)
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null)
  const [report, setReport] = useState<ReportResult | null>(null)
  const [consentConfirmed, setConsentConfirmed] = useState(false)
  const [syntheticConsent, setSyntheticConsent] = useState<InventoryAnalysisConsent | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const requestGeneration = useRef(0)

  const provider: InventoryProvider = preset === 'rules' ? 'none' : 'fake'
  const privacyMode = preset === 'rules' ? 'local_full' : 'share_safe'
  const executionMode = preset === 'rules'
    ? 'none'
    : preset === 'fake'
      ? 'local_only'
      : 'cloud_metadata_minimized'
  const isSynthetic = preset === 'synthetic'
  const syntheticOffer = isSynthetic ? preview?.analysis_offer ?? null : null
  const lintBlocked = preview?.privacy_lint?.passed === false
  const offerMatchesLineage = Boolean(
    syntheticOffer
    && snapshot
    && preview
    && syntheticOffer.synthetic
    && syntheticOffer.consent_required
    && syntheticOffer.network_calls === 0
    && syntheticOffer.provider === 'fake'
    && syntheticOffer.snapshot_id === snapshot.snapshot_id
    && syntheticOffer.snapshot_sha256 === snapshot.snapshot_sha256
    && syntheticOffer.packet_id === preview.packet.packet_id
    && syntheticOffer.packet_sha256 === preview.packet.packet_sha256
    && syntheticOffer.packet_bytes === preview.privacy_lint?.packet_bytes,
  )
  const isBusy = busyStage !== null
  const analysisIsSynthetic = Boolean(analysis?.consent_receipt || analysis?.receipt.synthetic)

  function beginRequest() {
    requestGeneration.current += 1
    return requestGeneration.current
  }

  function isCurrentRequest(generation: number) {
    return requestGeneration.current === generation
  }

  function handleRequestError(requestError: unknown, generation: number) {
    if (!isCurrentRequest(generation)) return
    if (requestError instanceof TypeError) onCoreFailure()
    setError(errorCopy(requestError))
  }

  function invalidateDownstream() {
    setPreview(null)
    setAnalysis(null)
    setReport(null)
    setConsentConfirmed(false)
    setSyntheticConsent(null)
    setNotice(null)
    setError(null)
  }

  function choosePreset(next: Preset) {
    if (next === preset) return
    requestGeneration.current += 1
    setBusyStage(null)
    setPreset(next)
    invalidateDownstream()
  }

  async function retryCore() {
    setError(null)
    setNotice(null)
    await onRetryHealth()
  }

  async function runControlledInventory() {
    const generation = beginRequest()
    setBusyStage('scan')
    setError(null)
    setNotice(null)
    setScan(null)
    setSnapshot(null)
    setPreview(null)
    setAnalysis(null)
    setReport(null)
    setConsentConfirmed(false)
    setSyntheticConsent(null)
    try {
      const created = await createInventoryScan()
      if (!isCurrentRequest(generation)) return
      const resolvedScan = await getInventoryScan(created.scan_id)
      if (!isCurrentRequest(generation)) return
      setScan(resolvedScan)
      if (resolvedScan.status === 'failed') {
        setError('受控盘点失败；没有进入后续报告步骤。')
        return
      }
      const createdSnapshot = await createInventorySnapshot(resolvedScan.scan_id)
      if (!isCurrentRequest(generation)) return
      const resolvedSnapshot = await getInventorySnapshot(createdSnapshot.snapshot_id)
      if (!isCurrentRequest(generation)) return
      setSnapshot(resolvedSnapshot)
      setNotice(
        resolvedScan.status === 'partial'
          ? '盘点仅部分覆盖；权限缺口和限制已完整保留。'
          : '受控 fixture 盘点完成；没有读取内容、计算文件 hash 或执行文件动作。',
      )
    } catch (scanError) {
      handleRequestError(scanError, generation)
    } finally {
      if (isCurrentRequest(generation)) setBusyStage(null)
    }
  }

  async function previewPacket() {
    if (!snapshot) return
    const generation = beginRequest()
    setBusyStage('packet')
    setError(null)
    setNotice(null)
    setPreview(null)
    setAnalysis(null)
    setReport(null)
    setConsentConfirmed(false)
    setSyntheticConsent(null)
    try {
      const result = await previewInventoryPacket({
        snapshot_id: snapshot.snapshot_id,
        artifact_privacy_mode: privacyMode,
        analysis_execution_mode: executionMode,
        ...(isSynthetic ? { budget: syntheticBudget } : {}),
        top_k: 200,
      })
      if (!isCurrentRequest(generation)) return
      setPreview(result)
      if (result.privacy_lint?.passed === false) {
        setError(`可分享证据包未通过隐私检查：${result.privacy_lint.issue_codes.join('、')}`)
      } else if (isSynthetic && !result.analysis_offer) {
        setError('Core 未返回 synthetic consent 披露；本次分析已阻断。')
      } else {
        setNotice(
          preset === 'rules'
            ? '本机完整证据包已生成；它不会离开本机。'
            : isSynthetic
              ? '可分享证据包已通过隐私检查；请核对服务端披露后再决定是否逐报告同意。'
              : '可分享证据包已通过隐私检查；本轮仍不会上传或访问云服务。',
        )
      }
    } catch (packetError) {
      handleRequestError(packetError, generation)
    } finally {
      if (isCurrentRequest(generation)) setBusyStage(null)
    }
  }

  function buildSyntheticConsent(): InventoryAnalysisConsent | undefined {
    if (!snapshot || !preview || !syntheticOffer || !offerMatchesLineage) return undefined
    if (syntheticConsent) return syntheticConsent
    const consent: InventoryAnalysisConsent = {
      consent_schema_version: syntheticOffer.consent_schema_version,
      consent_receipt_id: `consent_receipt_${globalThis.crypto.randomUUID()}`,
      client_action_id: `client_action_${globalThis.crypto.randomUUID()}`,
      confirmed: true,
      snapshot_id: syntheticOffer.snapshot_id,
      snapshot_sha256: syntheticOffer.snapshot_sha256,
      packet_id: syntheticOffer.packet_id,
      packet_sha256: syntheticOffer.packet_sha256,
      packet_bytes: syntheticOffer.packet_bytes,
      artifact_privacy_mode: 'share_safe',
      analysis_execution_mode: 'cloud_metadata_minimized',
      provider: syntheticOffer.provider,
      model: syntheticOffer.model,
      prompt_version: syntheticOffer.prompt_version,
      analysis_schema_version: syntheticOffer.analysis_schema_version,
      disclosure_version: syntheticOffer.disclosure_version,
      budget: syntheticOffer.budget,
      cost_basis: syntheticOffer.cost_basis,
    }
    setSyntheticConsent(consent)
    return consent
  }

  async function generateReport() {
    if (!snapshot || !preview || lintBlocked) return
    if (isSynthetic && (!consentConfirmed || !offerMatchesLineage)) return
    const consent = isSynthetic ? buildSyntheticConsent() : undefined
    if (isSynthetic && !consent) return
    const generation = beginRequest()
    setBusyStage('analysis')
    setError(null)
    setNotice(null)
    setAnalysis(null)
    setReport(null)
    try {
      const createdAnalysis = await createInventoryAnalysis(
        preview.packet.packet_id,
        provider,
        consent,
      )
      if (!isCurrentRequest(generation)) return
      const resolvedAnalysis = await getInventoryAnalysis(
        createdAnalysis.analysis.analysis_id,
      )
      if (!isCurrentRequest(generation)) return
      setAnalysis(resolvedAnalysis)
      setBusyStage('report')
      const createdReport = await createInventoryReport({
        snapshot_id: snapshot.snapshot_id,
        packet_id: preview.packet.packet_id,
        analysis_id: resolvedAnalysis.analysis.analysis_id,
      })
      if (!isCurrentRequest(generation)) return
      const resolvedReport = await getInventoryReport(createdReport.report_id)
      if (!isCurrentRequest(generation)) return
      setReport(resolvedReport)
      setNotice('五表 XLSX 已通过 ZIP 与 reopen 校验，可以从受控下载端点获取。')
    } catch (reportError) {
      handleRequestError(reportError, generation)
    } finally {
      if (isCurrentRequest(generation)) setBusyStage(null)
    }
  }

  async function downloadReport() {
    if (!report) return
    const generation = beginRequest()
    setBusyStage('download')
    setError(null)
    setNotice(null)
    try {
      await downloadInventoryReport(report.download_url, report.manifest.filename)
      if (!isCurrentRequest(generation)) return
      setNotice('XLSX 下载已启动；报告只用于判断，不代表已授权处理文件。')
    } catch (downloadError) {
      handleRequestError(downloadError, generation)
    } finally {
      if (isCurrentRequest(generation)) setBusyStage(null)
    }
  }

  function stepState(key: (typeof workflowSteps)[number]['key']) {
    if (busyStage === key) return 'active'
    if (key === 'scan') return snapshot ? 'complete' : 'pending'
    if (key === 'packet') return preview ? 'complete' : 'pending'
    if (key === 'analysis') return analysis ? 'complete' : 'pending'
    return report ? 'complete' : 'pending'
  }

  const packetBytes = preview
    ? preview.privacy_lint?.packet_bytes
      ?? new TextEncoder().encode(JSON.stringify(preview.packet)).length
    : 0

  return (
    <section className="inventory-report-view" aria-busy={isBusy}>
      <header className="inventory-hero">
        <div>
          <p className="kicker">Fixture-only · Iteration 4A</p>
          <h1>先得到报告，再决定要不要整理</h1>
          <p className="inventory-hero-copy">
            本页只运行仓库内的 <code>standard</code> 受控示例，
            不访问本机目录，不读取文件内容，也不执行清理动作。
          </p>
        </div>
        <div className="fixture-stamp" aria-label="固定执行范围">
          <span>固定范围</span>
          <strong>standard</strong>
          <code>inventory_metadata</code>
          <small>compute_hash=false</small>
        </div>
      </header>

      {error && (
        <div className="message message-error inventory-message" role="alert">
          <span>{error}</span>
          <button type="button" onClick={() => setError(null)}>关闭</button>
        </div>
      )}
      {notice && (
        <div className="message message-success inventory-message" role="status">
          <span>{notice}</span>
          <button type="button" onClick={() => setNotice(null)}>知道了</button>
        </div>
      )}

      <section className="boundary-panel" aria-labelledby="boundary-title">
        <div className="boundary-copy">
          <span className="section-label">执行边界</span>
          <h2 id="boundary-title">四项产品副作用保持为零</h2>
          <p>这些值在盘点完成后由 API 实际返回；测试验证器的 fixture 完整性 hash 不混入产品计数。</p>
        </div>
        <div className="safety-grid">
          {[
            ['内容读取', scan ? scan.safety.product_content_reads : '—'],
            ['文件 hash', scan ? scan.safety.product_file_hashes : '—'],
            ['网络调用', scan ? scan.safety.network_calls : '—'],
            ['源文件动作', scan ? scan.safety.file_actions : '—'],
          ].map(([label, value]) => (
            <div key={label}>
              <strong>{value}</strong>
              <span>{label}</span>
            </div>
          ))}
        </div>
        <div className="boundary-actions">
          <button
            className="primary-button"
            type="button"
            disabled={connection !== 'connected' || isBusy}
            onClick={() => void runControlledInventory()}
          >
            {busyStage === 'scan'
              ? '正在运行受控盘点'
              : snapshot
                ? '重新运行受控盘点'
                : '运行受控盘点'}
          </button>
          {(connection === 'offline' || connection === 'degraded') && (
            <button
              className="secondary-button"
              type="button"
              disabled={isBusy}
              onClick={() => void retryCore()}
            >
              重新检查 Core
            </button>
          )}
          <small>
            {connection === 'connected'
              ? 'Core 已连接；当前接口同步完成，不伪造百分比或取消能力。'
              : '需要先连接本机 Core，才能运行受控 fixture。'}
          </small>
        </div>
      </section>

      <ol className="workflow-steps" aria-label="报告生成阶段" aria-live="polite">
        {workflowSteps.map((step) => (
          <li key={step.key} data-state={stepState(step.key)}>
            <span>{step.index}</span>
            <strong>{step.label}</strong>
            <small>
              {stepState(step.key) === 'complete'
                ? '已完成'
                : stepState(step.key) === 'active'
                  ? '处理中'
                  : '等待'}
            </small>
          </li>
        ))}
      </ol>

      {scan && snapshot && (
        <section className="inventory-section" aria-labelledby="coverage-title">
          <header className="inventory-section-heading">
            <div>
              <span className="section-label">Coverage & limitations</span>
              <h2 id="coverage-title">这份盘点看到了什么</h2>
            </div>
            <span className={`status-badge status-${scan.status}`}>
              {scan.status === 'completed'
                ? '完整完成'
                : scan.status === 'partial'
                  ? '部分覆盖'
                  : '盘点失败'}
            </span>
          </header>
          <div className="coverage-grid">
            <article><span>请求条目</span><strong>{snapshot.coverage.requested_entries}</strong></article>
            <article><span>已采集</span><strong>{snapshot.coverage.collected_entries}</strong></article>
            <article><span>已跳过</span><strong>{snapshot.coverage.skipped_entries}</strong></article>
            <article><span>治理对象</span><strong>{snapshot.objects.length}</strong></article>
          </div>
          <div className="coverage-details">
            <div>
              <span className="section-label">空间口径</span>
              <dl className="audit-list">
                <div><dt>逻辑大小</dt><dd>{formatBytes(snapshot.canonical_tree_logical_size_bytes)}</dd></div>
                <div><dt>实际分配</dt><dd>{formatNullableBytes(snapshot.canonical_tree_allocated_size_bytes, '未获取')}</dd></div>
                <div><dt>可能腾出</dt><dd>{formatNullableBytes(snapshot.reclaimable_estimate_bytes, '未评估')}</dd></div>
                <div><dt>平台</dt><dd>{snapshot.platform}</dd></div>
                <div><dt>内容读取</dt><dd>{snapshot.content_read ? '是' : '否'}</dd></div>
                <div><dt>hash 模式</dt><dd>{snapshot.hash_mode}</dd></div>
                <div><dt>是否取消</dt><dd>{snapshot.coverage.cancelled ? '是' : '否'}</dd></div>
              </dl>
            </div>
            <div>
              <span className="section-label">权限缺口</span>
              {snapshot.coverage.permission_gaps.length ? (
                <ul className="truth-list">
                  {snapshot.coverage.permission_gaps.map((gap) => <li key={gap}>{gap}</li>)}
                </ul>
              ) : <p className="truth-empty">当前受控 fixture 无权限缺口。</p>}
              <span className="section-label detail-label">已知限制</span>
              <ul className="truth-list">
                {snapshot.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}
              </ul>
            </div>
          </div>
        </section>
      )}

      {snapshot && (
        <section className="inventory-section" aria-labelledby="packet-title">
          <header className="inventory-section-heading">
            <div>
              <span className="section-label">Evidence packet</span>
              <h2 id="packet-title">选择报告模式并预览证据</h2>
            </div>
            <span className="stage-chip">真实云：关闭 · synthetic：本机</span>
          </header>
          <fieldset className="preset-fieldset">
            <legend>报告模式</legend>
            <label className={`preset-option ${preset === 'rules' ? 'preset-selected' : ''}`}>
              <input
                type="radio"
                name="report-preset"
                value="rules"
                checked={preset === 'rules'}
                disabled={isBusy}
                onChange={() => choosePreset('rules')}
              />
              <span>
                <strong>规则版 · 本机完整报告</strong>
                <small><code>local_full + none</code>，默认且不调用模型。</small>
              </span>
            </label>
            <label className={`preset-option ${preset === 'fake' ? 'preset-selected' : ''}`}>
              <input
                type="radio"
                name="report-preset"
                value="fake"
                checked={preset === 'fake'}
                disabled={isBusy}
                onChange={() => choosePreset('fake')}
              />
              <span>
                <strong>受控 fake · 可分享脱敏报告</strong>
                <small><code>share_safe + local_only</code>，不是真实 AI 或云服务。</small>
              </span>
            </label>
            <label className={`preset-option ${preset === 'synthetic' ? 'preset-selected' : ''}`}>
              <input
                type="radio"
                name="report-preset"
                value="synthetic"
                checked={preset === 'synthetic'}
                disabled={isBusy}
                onChange={() => choosePreset('synthetic')}
              />
              <span>
                <strong>逐报告 consent · 离线 synthetic</strong>
                <small>
                  <code>share_safe + cloud_metadata_minimized</code>，真实云能力仍关闭，
                  仅用本机 fake 演练门禁。
                </small>
              </span>
            </label>
          </fieldset>
          <div className="packet-actions">
            <button
              className="primary-button"
              type="button"
              disabled={isBusy || connection !== 'connected'}
              onClick={() => void previewPacket()}
            >
              {busyStage === 'packet' ? '正在生成证据预览' : preview ? '重新生成证据预览' : '生成证据预览'}
            </button>
            <p>切换模式会立即作废旧 packet、analysis 和 report，避免跨 lineage 混用。</p>
          </div>

          {preview && (
            <div className="packet-preview">
              <div className="packet-summary">
                <article><span>Top 对象</span><strong>{preview.packet.top_objects.length}</strong></article>
                <article><span>Packet bytes</span><strong>{formatBytes(packetBytes)}</strong></article>
                <article><span>预计输入</span><strong>{preview.estimated_input_tokens} tokens</strong></article>
                <article>
                  <span>隐私检查</span>
                  <strong>
                    {preview.privacy_lint
                      ? preview.privacy_lint.passed ? '通过' : '阻断'
                      : '仅本机'}
                  </strong>
                </article>
              </div>
              <div className="packet-meta">
                <div>
                  <span className="section-label">字段类别</span>
                  <ul className="field-list">
                    {fieldCategories.map((field) => <li key={field}>{field}</li>)}
                  </ul>
                </div>
                <div>
                  <span className="section-label">Packet audit</span>
                  <dl className="audit-list">
                    <div><dt>隐私模式</dt><dd>{preview.packet.artifact_privacy_mode}</dd></div>
                    <div><dt>执行模式</dt><dd>{preview.packet.analysis_execution_mode}</dd></div>
                    <div><dt>Top-K</dt><dd>{preview.packet.top_objects.length} / 200</dd></div>
                    <div><dt>长尾对象</dt><dd>{preview.packet.long_tail.object_count}</dd></div>
                    <div><dt>是否截断</dt><dd>{preview.packet.truncated ? '是' : '否'}</dd></div>
                  </dl>
                </div>
              </div>
              <div className="packet-hash">
                <span>Packet SHA-256</span>
                <code>{preview.packet.packet_sha256}</code>
              </div>
              <div className="packet-limitations">
                <span className="section-label">证据包限制</span>
                {preview.packet.limitations.length > 0 ? (
                  <ul className="truth-list">
                    {preview.packet.limitations.map((limitation) => (
                      <li key={limitation}>{limitation}</li>
                    ))}
                  </ul>
                ) : <p className="truth-empty">API 未声明额外限制。</p>}
              </div>
              <div className="packet-object-heading">
                <span className="section-label">对象预览</span>
                <strong>
                  前 {Math.min(5, preview.packet.top_objects.length)} / 共 {preview.packet.top_objects.length}
                </strong>
              </div>
              <div className="packet-object-list" aria-label="证据包对象预览">
                {preview.packet.top_objects.slice(0, 5).map((item) => (
                  <article key={item.object_id}>
                    <div>
                      <span>{item.object_type}</span>
                      <strong>{item.display_name}</strong>
                    </div>
                    <p>{item.location ?? '无位置字段'}</p>
                    <em>{formatBytes(item.logical_size_bytes)}</em>
                  </article>
                ))}
              </div>
              {preview.privacy_lint?.passed === false && (
                <div className="privacy-block" role="alert">
                  <strong>隐私门禁已阻断后续分析</strong>
                  <span>{preview.privacy_lint.issue_codes.join('、')}</span>
                </div>
              )}
              {isSynthetic ? (
                <section className="synthetic-consent-panel" aria-labelledby="synthetic-consent-title">
                  <header>
                    <div>
                      <span className="section-label">Server-declared offer</span>
                      <h3 id="synthetic-consent-title">本次 synthetic 分析会使用什么</h3>
                    </div>
                    <span className="stage-chip">逐报告一次性 consent</span>
                  </header>
                  {syntheticOffer ? (
                    <>
                      {!offerMatchesLineage && (
                        <div className="privacy-block" role="alert">
                          <strong>服务端披露与当前 packet 不一致</strong>
                          <span>请重新生成证据预览；不一致时不会提交 consent。</span>
                        </div>
                      )}
                      <div className="synthetic-offer-grid">
                        <article>
                          <span>Provider / model</span>
                          <strong>{syntheticOffer.provider}</strong>
                          <small>{syntheticOffer.model}</small>
                        </article>
                        <article>
                          <span>Packet bytes</span>
                          <strong>{formatBytes(syntheticOffer.packet_bytes)}</strong>
                          <small>{syntheticOffer.packet_sha256}</small>
                        </article>
                        <article>
                          <span>预计 tokens</span>
                          <strong>
                            {syntheticOffer.estimated_input_tokens.toLocaleString('en-US')}
                            {' / '}
                            {syntheticOffer.estimated_output_tokens.toLocaleString('en-US')}
                          </strong>
                          <small>input / output</small>
                        </article>
                        <article>
                          <span>外部网络</span>
                          <strong>{syntheticOffer.network_calls}</strong>
                          <small>真实云能力保持关闭</small>
                        </article>
                      </div>
                      <div className="synthetic-field-grid">
                        <div>
                          <span className="section-label">会使用</span>
                          <ul className="truth-list">
                            {syntheticOffer.included_field_categories.map((field) => (
                              <li key={field}>{field}</li>
                            ))}
                          </ul>
                        </div>
                        <div>
                          <span className="section-label">明确排除</span>
                          <ul className="truth-list">
                            {syntheticOffer.excluded_field_categories.map((field) => (
                              <li key={field}>{field}</li>
                            ))}
                          </ul>
                        </div>
                      </div>
                      <div className="synthetic-budget-grid" aria-label="本次 synthetic 硬预算">
                        <article><span>Primary calls</span><strong>{syntheticOffer.budget.max_provider_calls}</strong></article>
                        <article><span>Schema retries</span><strong>{syntheticOffer.budget.max_schema_retries}</strong></article>
                        <article><span>Input tokens</span><strong>{syntheticOffer.budget.max_input_tokens.toLocaleString('en-US')}</strong></article>
                        <article><span>Output tokens</span><strong>{syntheticOffer.budget.max_output_tokens.toLocaleString('en-US')}</strong></article>
                        <article><span>Packet cap</span><strong>{formatBytes(syntheticOffer.budget.max_packet_bytes)}</strong></article>
                        <article><span>Timeout</span><strong>{syntheticOffer.budget.timeout_ms / 1000} 秒</strong></article>
                        <article><span>Synthetic cost</span><strong>{syntheticOffer.budget.max_estimated_cost}</strong></article>
                      </div>
                      <p className="synthetic-disclosure">{syntheticOffer.disclosure}</p>
                      <label className="consent-check">
                        <input
                          type="checkbox"
                          checked={consentConfirmed}
                          disabled={isBusy || lintBlocked || !offerMatchesLineage}
                          onChange={(event) => {
                            setConsentConfirmed(event.target.checked)
                            if (!event.target.checked) setSyntheticConsent(null)
                          }}
                        />
                        <span>
                          <strong>我已核对本次证据包并同意仅用于这一份报告</strong>
                          <small>
                            同意仅绑定当前 packet、provider/model、版本与预算；任何变化都需要重新同意。
                          </small>
                        </span>
                      </label>
                      <div className="synthetic-actions">
                        <button
                          className="primary-button"
                          type="button"
                          disabled={
                            isBusy
                            || lintBlocked
                            || !offerMatchesLineage
                            || !consentConfirmed
                            || connection !== 'connected'
                          }
                          onClick={() => void generateReport()}
                        >
                          {busyStage === 'analysis'
                            ? '正在消费 consent 并分析'
                            : busyStage === 'report'
                              ? '正在生成 XLSX'
                              : '同意本次 synthetic 分析并生成 XLSX'}
                        </button>
                        <button
                          className="secondary-button"
                          type="button"
                          disabled={isBusy}
                          onClick={() => choosePreset('rules')}
                        >
                          改用规则版
                        </button>
                      </div>
                    </>
                  ) : (
                    <div className="privacy-block" role="alert">
                      <strong>未收到服务端 synthetic 披露</strong>
                      <span>本次分析已阻断；可以改用规则版。</span>
                      <button
                        className="secondary-button"
                        type="button"
                        disabled={isBusy}
                        onClick={() => choosePreset('rules')}
                      >
                        改用规则版
                      </button>
                    </div>
                  )}
                </section>
              ) : (
                <div className="report-generate-row">
                  <div>
                    <strong>
                      {provider === 'none' ? '不会调用模型' : '只调用受控 fake 一次'}
                    </strong>
                    <span>报告重渲染不会再次调用 Provider。</span>
                  </div>
                  <button
                    className="primary-button"
                    type="button"
                    disabled={isBusy || lintBlocked || connection !== 'connected'}
                    onClick={() => void generateReport()}
                  >
                    {busyStage === 'analysis'
                      ? '正在生成分析'
                      : busyStage === 'report'
                        ? '正在生成 XLSX'
                        : '生成 XLSX 报告'}
                  </button>
                </div>
              )}
            </div>
          )}
        </section>
      )}

      {analysis && (
        <section className="inventory-section" aria-labelledby="analysis-title">
          <header className="inventory-section-heading">
            <div>
              <span className="section-label">Analysis receipt</span>
              <h2 id="analysis-title">
                {analysisStatusCopy(analysis.analysis.status, analysisIsSynthetic)}
              </h2>
            </div>
            <span className={`status-badge status-${analysis.analysis.status}`}>
              {receiptStatusCopy(analysis.receipt.status)}
            </span>
          </header>
          <p className="analysis-summary">{analysis.analysis.summary}</p>
          <div className="receipt-grid">
            <article><span>Provider</span><strong>{analysis.receipt.provider}</strong><small>{analysis.receipt.model}</small></article>
            <article><span>Provider calls</span><strong>{analysis.receipt.provider_calls}</strong><small>本次请求</small></article>
            <article><span>Network calls</span><strong>{analysis.receipt.network_calls}</strong><small>必须为 0</small></article>
            <article>
              <span>Tokens</span>
              <strong>
                {analysis.receipt.input_tokens} / {analysis.receipt.cached_input_tokens} / {analysis.receipt.output_tokens}
              </strong>
              <small>input / cached / output</small>
            </article>
            <article>
              <span>Estimated cost</span>
              <strong>{analysis.receipt.estimated_cost.toFixed(4)}</strong>
              <small>
                {analysisIsSynthetic ? '受控 synthetic · 外部计费为 0' : '合同数值 · 币种未声明'}
              </small>
            </article>
            <article><span>Latency</span><strong>{analysis.receipt.latency_ms} ms</strong><small>{analysis.receipt.status}</small></article>
          </div>
          {analysis.consent_receipt && (
            <section className="consent-receipt-card" aria-labelledby="consent-receipt-title">
              <div>
                <span className="section-label">Consent receipt</span>
                <h3 id="consent-receipt-title">已一次性消费</h3>
              </div>
              <dl className="audit-list">
                <div>
                  <dt>Consent receipt ID</dt>
                  <dd><code>{analysis.consent_receipt.consent_receipt_id}</code></dd>
                </div>
                <div><dt>状态</dt><dd>{analysis.consent_receipt.status}</dd></div>
                <div><dt>Packet SHA-256</dt><dd><code>{analysis.consent_receipt.packet_sha256}</code></dd></div>
                <div><dt>Provider / model</dt><dd>{analysis.consent_receipt.provider} / {analysis.consent_receipt.model}</dd></div>
                <div><dt>Provider calls</dt><dd>{analysis.consent_receipt.provider_calls}</dd></div>
                <div><dt>Network calls</dt><dd>{analysis.consent_receipt.network_calls}</dd></div>
                <div>
                  <dt>Tokens</dt>
                  <dd>
                    {analysis.consent_receipt.input_tokens}
                    {' / '}
                    {analysis.consent_receipt.cached_input_tokens}
                    {' / '}
                    {analysis.consent_receipt.output_tokens}
                  </dd>
                </div>
                <div><dt>Latency</dt><dd>{analysis.consent_receipt.latency_ms} ms</dd></div>
                <div><dt>Fallback</dt><dd>{analysis.consent_receipt.fallback ? '是' : '否'}</dd></div>
                <div><dt>External cost</dt><dd>{analysis.consent_receipt.estimated_cost}</dd></div>
              </dl>
              <p>
                受控 synthetic 的外部计费为 0；这一收据不证明真实价格或币种，
                也不证明真实 Provider 数据政策。
              </p>
            </section>
          )}
          {analysis.analysis.limitations.length > 0 && (
            <div className="analysis-limitations">
              <span className="section-label">分析限制</span>
              <ul className="truth-list">
                {analysis.analysis.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}
              </ul>
            </div>
          )}
          <details className="technical-details">
            <summary>查看技术收据</summary>
            <dl className="audit-list">
              <div><dt>Receipt ID</dt><dd><code>{analysis.receipt.receipt_id}</code></dd></div>
              <div><dt>Cache key</dt><dd><code>{analysis.receipt.cache_key}</code></dd></div>
              <div><dt>Prompt version</dt><dd>{analysis.receipt.prompt_version}</dd></div>
              <div><dt>Schema version</dt><dd>{analysis.receipt.schema_version}</dd></div>
              <div><dt>Error code</dt><dd>{analysis.receipt.error_code ?? '无'}</dd></div>
            </dl>
          </details>
        </section>
      )}

      {report && (
        <section className="report-ready" aria-labelledby="report-title">
          <div className="report-ready-copy">
            <span className="section-label">Verified workbook</span>
            <h2 id="report-title">空间透视盘点报告已就绪</h2>
            <p>报告用于判断，不代表已授权处理文件。下载只使用受控 report ID，不接收磁盘路径。</p>
            <dl className="audit-list">
              <div><dt>状态</dt><dd>{report.status}</dd></div>
              <div><dt>隐私模式</dt><dd>{report.manifest.artifact_privacy_mode}</dd></div>
              <div><dt>Provider</dt><dd>{report.manifest.provider}</dd></div>
              <div><dt>ZIP 完整性</dt><dd>{report.manifest.zip_integrity ? '通过' : '失败'}</dd></div>
              <div><dt>Reopen 验证</dt><dd>{report.manifest.reopen_validated ? '通过' : '失败'}</dd></div>
            </dl>
          </div>
          <div className="report-artifact">
            <span className="report-filetype">XLSX</span>
            <strong>{report.manifest.filename}</strong>
            <code>{report.manifest.workbook_sha256}</code>
            <ol>
              {report.manifest.sheets.map((sheet) => <li key={sheet}>{sheet}</li>)}
            </ol>
            <button
              className="primary-button download-button"
              type="button"
              disabled={isBusy || connection !== 'connected'}
              onClick={() => void downloadReport()}
            >
              {busyStage === 'download' ? '正在下载' : '下载 XLSX 报告'}
            </button>
          </div>
        </section>
      )}
    </section>
  )
}
