export interface HealthResponse {
  status: 'ok' | 'degraded'
  version: string
  db_status: 'ok' | 'unavailable' | 'migration_required'
  capabilities: {
    real_upload_enabled: false
    mock_provider_enabled: boolean
    file_upload_enabled: false
    cloud_metadata_analysis_available: false
    cloud_metadata_analysis_enabled: false
    controlled_synthetic_consent_available: boolean
  }
  current_time: string
}

export interface ErrorResponse {
  code: string
  message: string
  details?: Record<string, unknown> | null
  request_id?: string | null
}

export type InventoryPreset = 'standard'
export type InventoryProvider = 'none' | 'fake'
export type InventoryPrivacyMode = 'local_full' | 'share_safe'
export type InventoryExecutionMode = 'none' | 'local_only' | 'cloud_metadata_minimized'
export type InventoryAnalysisStatus = 'deterministic_only' | 'ai_complete' | 'ai_failed_fallback'

export interface InventoryCoverage {
  requested_entries: number
  collected_entries: number
  skipped_entries: number
  permission_gaps: string[]
  cancelled: boolean
}

export interface InventoryCheckpoint {
  checkpoint_id: string
  scan_id: string
  status: 'running' | 'completed' | 'cancelled' | 'partial' | 'failed'
  last_relative_path: string | null
  collected_entries: number
  skipped_entries: number
  updated_at: string
}

export interface InventorySafetyCounters {
  product_content_reads: 0
  product_file_hashes: 0
  network_calls: 0
  file_actions: 0
}

export interface InventoryScan {
  scan_id: string
  status: 'completed' | 'partial' | 'failed'
  fixture_id: InventoryPreset
  profile: 'inventory_metadata'
  platform: string
  content_read: false
  hash_mode: 'none'
  coverage: InventoryCoverage
  checkpoint: InventoryCheckpoint
  snapshot_id: string
  safety: InventorySafetyCounters
}

export type InventoryTimeEvidenceType =
  | 'filesystem_birthtime'
  | 'filesystem_status_change'
  | 'filesystem_modified'
  | 'filesystem_access'
  | 'unavailable'

export type InventoryConfidence = 'high' | 'medium' | 'low' | 'unknown'

export interface InventoryTimeEvidence {
  value: string | null
  source: string
  evidence_type: InventoryTimeEvidenceType
  confidence: InventoryConfidence
  platform: string
  limitation: string | null
}

export interface InventoryRuleHint {
  rule_id: string
  rules_version: string
  message: string
  priority: '建议先看' | '有空再看' | '留意即可'
}

export type InventoryObjectType =
  | 'volume'
  | 'directory'
  | 'application'
  | 'game_library'
  | 'cache_group'
  | 'package_manager_store'
  | 'local_model'
  | 'project'
  | 'archive'
  | 'installer'
  | 'file'

export interface InventoryObject {
  schema_version: '1.0'
  object_id: string
  object_type: InventoryObjectType
  parent_object_id: string | null
  fact_ids: string[]
  name: string
  relative_path: string
  absolute_path: string
  logical_size_bytes: number
  allocated_size_bytes: number | null
  reclaimable_estimate_bytes: number | null
  created: InventoryTimeEvidence
  modified: InventoryTimeEvidence
  accessed: InventoryTimeEvidence
  rule_hints: InventoryRuleHint[]
  user_decision: null
  user_note: null
}

export interface InventoryEvidence {
  evidence_id: string
  object_id: string
  fact_ids: string[]
  evidence_type: 'filesystem_metadata' | 'classification_rule' | 'possible_duplicate' | 'permission_gap'
  statement: string
  confidence: InventoryConfidence
  logical_size_bytes: number | null
  allocated_size_bytes: number | null
  reclaimable_estimate_bytes: number | null
}

export interface InventorySnapshot {
  schema_version: '1.0'
  snapshot_id: string
  snapshot_sha256: string
  scan_id: string
  generated_at: string
  profile: 'inventory_metadata'
  platform: string
  rules_version: string
  content_read: false
  hash_mode: 'none'
  canonical_tree_logical_size_bytes: number
  canonical_tree_allocated_size_bytes: number | null
  reclaimable_estimate_bytes: number | null
  coverage: InventoryCoverage
  limitations: string[]
  objects: InventoryObject[]
  evidence: InventoryEvidence[]
}

export interface InventoryCoverageSummary {
  requested_entries: number
  collected_entries: number
  skipped_entries: number
  permission_gap_count: number
  cancelled: boolean
}

export interface InventoryPacketObject {
  object_id: string
  evidence_ids: string[]
  object_type: string
  display_name: string
  location: string | null
  name_length: number
  logical_size_bytes: number
  allocated_size_bytes: number | null
  reclaimable_estimate_bytes: number | null
  rule_hints: string[]
}

export interface InventoryLongTail {
  object_count: number
  logical_size_bytes: number
}

export interface InventoryAnalysisPacket {
  schema_version: '1.0'
  packet_id: string
  packet_sha256: string
  snapshot_id: string
  snapshot_sha256: string
  generated_at: string
  artifact_privacy_mode: InventoryPrivacyMode
  analysis_execution_mode: InventoryExecutionMode
  profile: 'inventory_metadata'
  platform: string
  content_read: false
  hash_mode: 'none'
  canonical_tree_logical_size_bytes: number
  canonical_tree_allocated_size_bytes: number | null
  reclaimable_estimate_bytes: number | null
  coverage_summary: InventoryCoverageSummary
  limitations: string[]
  top_objects: InventoryPacketObject[]
  long_tail: InventoryLongTail
  truncated: boolean
}

export interface PrivacyLintResult {
  passed: boolean
  issue_codes: string[]
  packet_bytes: number
  max_packet_bytes: number
}

export interface InventoryAnalysisBudget {
  max_provider_calls: 1
  max_schema_retries: 1
  max_input_tokens: number
  max_output_tokens: number
  max_packet_bytes: number
  timeout_ms: number
  max_estimated_cost: 0
}

export interface InventoryAnalysisOffer {
  synthetic: true
  consent_required: true
  network_calls: 0
  provider: 'fake'
  model: string
  prompt_version: string
  consent_schema_version: '1.0'
  analysis_schema_version: string
  disclosure_version: string
  snapshot_id: string
  snapshot_sha256: string
  packet_id: string
  packet_sha256: string
  packet_bytes: number
  estimated_input_tokens: number
  estimated_output_tokens: number
  included_field_categories: string[]
  excluded_field_categories: string[]
  budget: InventoryAnalysisBudget
  cost_basis: 'synthetic_zero_external_cost'
  disclosure: string
}

export interface InventoryAnalysisConsent {
  consent_schema_version: '1.0'
  consent_receipt_id: string
  client_action_id: string
  confirmed: true
  snapshot_id: string
  snapshot_sha256: string
  packet_id: string
  packet_sha256: string
  packet_bytes: number
  artifact_privacy_mode: 'share_safe'
  analysis_execution_mode: 'cloud_metadata_minimized'
  provider: 'fake'
  model: string
  prompt_version: string
  analysis_schema_version: string
  disclosure_version: string
  budget: InventoryAnalysisBudget
  cost_basis: 'synthetic_zero_external_cost'
}

export interface InventoryConsentReceipt {
  consent_receipt_id: string
  client_action_id: string
  status: 'consumed'
  confirmed: true
  synthetic: true
  snapshot_id: string
  snapshot_sha256: string
  packet_id: string
  packet_sha256: string
  packet_bytes: number
  artifact_privacy_mode: 'share_safe'
  analysis_execution_mode: 'cloud_metadata_minimized'
  provider: 'fake'
  model: string
  prompt_version: string
  consent_schema_version: '1.0'
  analysis_schema_version: string
  disclosure_version: string
  budget: InventoryAnalysisBudget
  cost_basis: 'synthetic_zero_external_cost'
  provider_calls: number
  network_calls: 0
  input_tokens: number
  cached_input_tokens: number
  output_tokens: number
  estimated_cost: 0
  latency_ms: number
  fallback: boolean
  created_at: string
  consumed_at: string
  error_code: string | null
}

export interface InventoryPacketPreview {
  packet: InventoryAnalysisPacket
  privacy_lint: PrivacyLintResult | null
  estimated_input_tokens: number
  analysis_offer?: InventoryAnalysisOffer | null
}

export interface InventoryAnalysisFinding {
  finding_id: string
  object_ids: string[]
  evidence_ids: string[]
  observation: string
  recommendation: 'review' | 'keep' | 'verify' | 'archive_consider'
}

export interface InventoryAnalysis {
  schema_version: '1.0'
  analysis_id: string
  packet_id: string
  status: InventoryAnalysisStatus
  provider: InventoryProvider
  model: string
  summary: string
  findings: InventoryAnalysisFinding[]
  questions: string[]
  limitations: string[]
}

export type ModelCallStatus =
  | 'not_called'
  | 'succeeded'
  | 'cache_hit'
  | 'privacy_blocked'
  | 'budget_blocked'
  | 'grounding_failed'
  | 'schema_failed'
  | 'provider_failed'

export interface ModelCallReceipt {
  receipt_id: string
  packet_sha256: string
  provider: InventoryProvider
  model: string
  prompt_version: string
  schema_version: string
  cache_key: string
  status: ModelCallStatus
  provider_calls: number
  network_calls: 0
  input_tokens: number
  cached_input_tokens: number
  output_tokens: number
  estimated_cost: number
  latency_ms: number
  error_code: string | null
  synthetic: boolean
  consent_receipt_id: string | null
  client_action_id: string | null
  consent_status: 'not_required' | 'consumed'
  budget: InventoryAnalysisBudget | null
  fallback: boolean
  cost_basis: 'synthetic_zero_external_cost' | null
}

export interface InventoryAnalysisResult {
  analysis: InventoryAnalysis
  receipt: ModelCallReceipt
  consent_receipt: InventoryConsentReceipt | null
}

export interface InventoryReportManifest {
  schema_version: '1.0'
  report_schema_version: '1.0'
  report_id: string
  artifact_id: string
  snapshot_id: string
  packet_id: string
  analysis_id: string
  generated_at: string
  artifact_privacy_mode: InventoryPrivacyMode
  provider: InventoryProvider
  analysis_status: InventoryAnalysisStatus
  filename: string
  workbook_sha256: string
  sheets: [
    '空间体检概览',
    '空间明细清单',
    '建议优先查看',
    '可能重复与安装包',
    '报告说明与记录',
  ]
  zip_integrity: true
  reopen_validated: true
}

export interface InventoryReport {
  report_id: string
  status: InventoryAnalysisStatus
  manifest: InventoryReportManifest
  download_url: string
}

export interface InventoryPacketPreviewInput {
  snapshot_id: string
  artifact_privacy_mode: InventoryPrivacyMode
  analysis_execution_mode: InventoryExecutionMode
  top_k?: number
  budget?: InventoryAnalysisBudget
}

export interface InventoryReportInput {
  snapshot_id: string
  packet_id: string
  analysis_id: string
}

export type ScanStatus = 'pending' | 'running' | 'completed' | 'partial' | 'cancelled' | 'failed'

export interface ScanSession {
  id: string
  status: ScanStatus
  requested_paths: string[]
  started_at: string
  finished_at: string | null
  current_path: string | null
  files_seen: number
  files_indexed: number
  files_skipped: number
  bytes_seen: number
  error_summary: Array<{ code: string; count: number }>
}

export interface ScanEvent {
  event_id: string
  scan_session_id: string
  type: 'started' | 'progress' | 'skipped' | 'completed' | 'cancelled' | 'failed'
  occurred_at: string
  current_path: string | null
  files_seen: number
  files_indexed: number
  files_skipped: number
  bytes_seen: number
  message: string | null
}

export type RiskLevel = 'low' | 'medium' | 'high'

export interface Asset {
  id: string
  abs_path: string
  path_hash: string | null
  file_hash: string | null
  partial_hash: string | null
  hash_status: 'not_started' | 'partial' | 'full' | 'failed'
  size_bytes: number
  ext: string
  mime: string | null
  category: string
  source_hint: string
  created_at: string | null
  modified_at: string | null
  accessed_at: string | null
  status: 'active' | 'quarantined' | 'missing' | 'ignored'
  scan_session_id: string
  risk_flags: string[]
}

export interface OverviewBucket {
  key: string
  file_count: number
  size_bytes: number
}

export interface FileIntelOverview {
  scan_session_id: string
  total_files: number
  total_size_bytes: number
  by_category: OverviewBucket[]
  by_source: OverviewBucket[]
  by_directory: OverviewBucket[]
  top_large_files: Asset[]
  risk_summary: Array<{ risk_level: RiskLevel; file_count: number; size_bytes: number }>
  generated_at: string
}

export interface DuplicateGroup {
  id: string
  kind: 'exact'
  file_hash: string | null
  member_count: number
  total_size_bytes: number
  reclaimable_size_bytes: number
  keep_asset_id: string
  reason: string
  members: Array<{
    asset_id: string
    role: 'keep_recommended' | 'duplicate_candidate' | 'protected'
    similarity: number
    reason: string | null
    risk_level: RiskLevel | null
  }>
}

export interface Suggestion {
  id: string
  asset_id: string | null
  dup_group_id: string | null
  category: string
  risk_level: RiskLevel
  proposed_action: 'keep' | 'review' | 'protect' | 'quarantine' | 'archive_suggested'
  reason: string
  evidence: { items: Array<{ type: string; label: string; value: string }> }
  reversible: boolean
  default_selected: boolean
  status: 'active' | 'ignored' | 'accepted'
  created_at: string | null
}

export interface OperationPlan {
  id: string
  action_type: 'quarantine' | 'mark_ignored'
  status: 'previewed' | 'expired' | 'cancelled' | 'executed'
  reversible: true
  summary: { file_count: number; total_size_bytes: number; target_policy: string | null }
  risk_summary: Array<{ risk_level: RiskLevel; file_count: number; size_bytes: number }>
  items: Array<{
    asset_id: string
    suggestion_id: string | null
    display_path: string
    size_bytes: number
    risk_level: RiskLevel
    reversible: boolean
    warnings: string[]
  }>
  warnings: string[]
  version: string
  created_at: string
  expires_at: string
}

export interface OperationFileResult {
  asset_id: string
  status: 'succeeded' | 'failed' | 'skipped'
  original_path: string | null
  quarantine_item_id: string | null
  error: { code: string; message: string } | null
}

export interface OperationReceipt {
  id: string
  operation_plan_id: string
  action_type: 'quarantine' | 'mark_ignored'
  status: 'succeeded' | 'partial' | 'failed' | 'undone' | 'undo_partial'
  reversible: true
  file_count: number
  total_size_bytes: number
  started_at: string
  finished_at: string | null
  affects_cloud_sync: boolean
  rule_version: string | null
  provider_version: string | null
  file_results: OperationFileResult[]
}

export interface QuarantineItem {
  id: string
  operation_id: string
  asset_id: string
  original_path: string
  quarantine_path: string
  original_mtime: string | null
  original_size_bytes: number
  file_hash: string
  status: 'quarantined' | 'restored' | 'restore_failed' | 'missing'
  error_message: string | null
}

export class ApiError extends Error {
  code: string
  status: number
  details: Record<string, unknown> | null
  requestId: string | null

  constructor(
    status: number,
    code: string,
    message: string,
    details: Record<string, unknown> | null = null,
    requestId: string | null = null,
  ) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.details = details
    this.requestId = requestId
  }
}

export const CORE_API_URL = (import.meta.env.VITE_CORE_API_URL ?? 'http://127.0.0.1:8765').replace(/\/$/, '')
const XLSX_MEDIA_TYPE = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
const DEFAULT_INVENTORY_REPORT_FILENAME = '空间透视盘点报告.xlsx'

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

async function apiErrorFromResponse(response: Response): Promise<ApiError> {
  const rawPayload: unknown = await response.json().catch(() => null)
  const payload = isRecord(rawPayload) ? rawPayload : null
  const code = typeof payload?.code === 'string' ? payload.code : `HTTP_${response.status}`
  const message = typeof payload?.message === 'string' ? payload.message : '本地 Core 请求失败'
  const details = isRecord(payload?.details) ? payload.details : null
  const requestId = typeof payload?.request_id === 'string' ? payload.request_id : null
  return new ApiError(response.status, code, message, details, requestId)
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${CORE_API_URL}${path}`, {
    ...init,
    headers: {
      Accept: 'application/json',
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...init?.headers,
    },
  })
  if (!response.ok) {
    throw await apiErrorFromResponse(response)
  }
  return response.json() as Promise<T>
}

function query(values: Record<string, string | number | boolean | null | undefined>): string {
  const params = new URLSearchParams()
  Object.entries(values).forEach(([key, value]) => {
    if (value !== null && value !== undefined) params.set(key, String(value))
  })
  const suffix = params.toString()
  return suffix ? `?${suffix}` : ''
}

export function fetchHealth(signal?: AbortSignal) {
  return request<HealthResponse>('/health', { signal })
}

export function createScan(path: string) {
  return request<ScanSession>('/scan', {
    method: 'POST',
    body: JSON.stringify({ paths: [path], options: { include_hidden: false, follow_symlinks: false, compute_hash: true } }),
  })
}

export function fetchScan(scanId: string) {
  return request<ScanSession>(`/scan/${encodeURIComponent(scanId)}`)
}

export function cancelScan(scanId: string) {
  return request<ScanSession>(`/scan/${encodeURIComponent(scanId)}/cancel`, { method: 'POST' })
}

export function subscribeScan(scanId: string, onEvent: (event: ScanEvent) => void, onError: () => void) {
  if (typeof EventSource === 'undefined') return () => undefined
  const source = new EventSource(`${CORE_API_URL}/scan/${encodeURIComponent(scanId)}/stream`)
  const listener = (raw: MessageEvent<string>) => {
    try {
      onEvent(JSON.parse(raw.data) as ScanEvent)
    } catch {
      onError()
    }
  }
  source.addEventListener('scan_event', listener as EventListener)
  source.onerror = onError
  return () => source.close()
}

export function fetchAssets(scanId: string) {
  return request<{ items: Asset[] }>(`/assets${query({ scan_session_id: scanId, page_size: 500 })}`)
}

export function fetchOverview(scanId: string) {
  return request<FileIntelOverview>(`/fileintel/overview${query({ scan_session_id: scanId })}`)
}

export function fetchDuplicates(scanId: string) {
  return request<{ items: DuplicateGroup[] }>(`/dups${query({ scan_session_id: scanId, page_size: 500 })}`)
}

export function fetchSuggestions(scanId: string) {
  return request<{ items: Suggestion[] }>(`/suggestions${query({ scan_session_id: scanId, page_size: 500 })}`)
}

export function createPreview(suggestionIds: string[]) {
  return request<OperationPlan>('/operations/preview', {
    method: 'POST',
    body: JSON.stringify({ action_type: 'quarantine', suggestion_ids: suggestionIds, target_policy: 'app_quarantine' }),
  })
}

export function executePlan(plan: OperationPlan) {
  return request<OperationReceipt>('/operations/execute', {
    method: 'POST',
    body: JSON.stringify({
      operation_plan_id: plan.id,
      confirm: true,
      client_seen_plan_version: plan.version,
      idempotency_key: `ui-${plan.id}`,
    }),
  })
}

export function fetchOperations() {
  return request<{ items: OperationReceipt[] }>('/operations?page_size=500')
}

export function fetchQuarantine() {
  return request<{ items: QuarantineItem[] }>('/quarantine?page_size=500')
}

export function undoOperation(operationId: string) {
  return request<OperationReceipt>(`/operations/${encodeURIComponent(operationId)}/undo`, {
    method: 'POST',
    body: JSON.stringify({ confirm: true, conflict_policy: 'fail_on_conflict' }),
  })
}

export function createInventoryScan() {
  return request<InventoryScan>('/v1/inventory/scans', {
    method: 'POST',
    body: JSON.stringify({
      fixture_id: 'standard',
      profile: 'inventory_metadata',
      compute_hash: false,
    }),
  })
}

export function getInventoryScan(scanId: string) {
  return request<InventoryScan>(`/v1/inventory/scans/${encodeURIComponent(scanId)}`)
}

export function createInventorySnapshot(scanId: string) {
  return request<InventorySnapshot>('/v1/inventory/snapshots', {
    method: 'POST',
    body: JSON.stringify({ scan_id: scanId }),
  })
}

export function getInventorySnapshot(snapshotId: string) {
  return request<InventorySnapshot>(`/v1/inventory/snapshots/${encodeURIComponent(snapshotId)}`)
}

export function previewInventoryPacket(input: InventoryPacketPreviewInput) {
  return request<InventoryPacketPreview>('/v1/inventory/analysis-packets/preview', {
    method: 'POST',
    body: JSON.stringify({
      snapshot_id: input.snapshot_id,
      artifact_privacy_mode: input.artifact_privacy_mode,
      analysis_execution_mode: input.analysis_execution_mode,
      ...(input.budget === undefined ? {} : { budget: input.budget }),
      ...(input.top_k === undefined ? {} : { top_k: input.top_k }),
    }),
  })
}

export function createInventoryAnalysis(
  packetId: string,
  provider: InventoryProvider,
  consent?: InventoryAnalysisConsent,
) {
  if (provider !== 'none' && provider !== 'fake') {
    throw new ApiError(0, 'INVALID_INVENTORY_PROVIDER', '报告分析只允许 none 或 fake Provider')
  }
  return request<InventoryAnalysisResult>('/v1/inventory/analyses', {
    method: 'POST',
    body: JSON.stringify({
      packet_id: packetId,
      provider,
      ...(consent === undefined ? {} : { consent }),
    }),
  })
}

export function getInventoryAnalysis(analysisId: string) {
  return request<InventoryAnalysisResult>(`/v1/inventory/analyses/${encodeURIComponent(analysisId)}`)
}

export function createInventoryReport(input: InventoryReportInput) {
  return request<InventoryReport>('/v1/inventory/reports', {
    method: 'POST',
    body: JSON.stringify({
      snapshot_id: input.snapshot_id,
      packet_id: input.packet_id,
      analysis_id: input.analysis_id,
    }),
  })
}

export function getInventoryReport(reportId: string) {
  return request<InventoryReport>(`/v1/inventory/reports/${encodeURIComponent(reportId)}`)
}

function resolveInventoryDownloadUrl(downloadUrl: string): string {
  const apiBase = new URL(`${CORE_API_URL}/`)
  let resolved: URL
  try {
    resolved = new URL(downloadUrl, apiBase)
  } catch {
    throw new ApiError(0, 'INVALID_INVENTORY_DOWNLOAD_URL', '报告下载地址不符合受控接口契约')
  }
  const inventoryDownloadPath = /^\/v1\/inventory\/reports\/[A-Za-z0-9_-]+\/download$/
  if (
    resolved.origin !== apiBase.origin
    || !inventoryDownloadPath.test(resolved.pathname)
    || resolved.search !== ''
    || resolved.hash !== ''
    || resolved.username !== ''
    || resolved.password !== ''
  ) {
    throw new ApiError(0, 'INVALID_INVENTORY_DOWNLOAD_URL', '报告下载地址不符合受控接口契约')
  }
  return resolved.toString()
}

function safeDownloadFilename(filename: string | null | undefined, fallbackFilename: string): string {
  const candidate = (filename || fallbackFilename)
    .replace(/\\/g, '/')
    .split('/')
    .pop()
    ?.replace(/[\u0000-\u001f\u007f]/g, '')
    .trim()
  return candidate || DEFAULT_INVENTORY_REPORT_FILENAME
}

function contentDispositionFilename(contentDisposition: string | null): string | null {
  if (!contentDisposition) return null

  const encoded = contentDisposition.match(/filename\*\s*=\s*UTF-8'[^']*'([^;]+)/i)?.[1]
  if (encoded) {
    try {
      return decodeURIComponent(encoded.trim().replace(/^"(.*)"$/, '$1'))
    } catch {
      return encoded.trim().replace(/^"(.*)"$/, '$1')
    }
  }

  const plain = contentDisposition.match(/filename\s*=\s*(?:"([^"]+)"|([^;]+))/i)
  return plain?.[1]?.trim() ?? plain?.[2]?.trim() ?? null
}

export async function downloadInventoryReport(
  downloadUrl: string,
  fallbackFilename = DEFAULT_INVENTORY_REPORT_FILENAME,
): Promise<string> {
  const response = await fetch(resolveInventoryDownloadUrl(downloadUrl), {
    headers: { Accept: XLSX_MEDIA_TYPE },
  })
  if (!response.ok) {
    throw await apiErrorFromResponse(response)
  }
  const contentType = response.headers.get('Content-Type')?.split(';', 1)[0]?.trim()
  if (contentType !== XLSX_MEDIA_TYPE) {
    throw new ApiError(
      0,
      'INVALID_INVENTORY_REPORT_MEDIA_TYPE',
      '报告下载响应不是受支持的 XLSX 文件',
    )
  }

  const blob = await response.blob()
  const filename = safeDownloadFilename(
    contentDispositionFilename(response.headers.get('Content-Disposition')),
    fallbackFilename,
  )
  const objectUrl = URL.createObjectURL(blob)
  try {
    const anchor = document.createElement('a')
    anchor.href = objectUrl
    anchor.download = filename
    anchor.rel = 'noopener'
    anchor.style.display = 'none'
    document.body.append(anchor)
    anchor.click()
    anchor.remove()
  } finally {
    URL.revokeObjectURL(objectUrl)
  }
  return filename
}
