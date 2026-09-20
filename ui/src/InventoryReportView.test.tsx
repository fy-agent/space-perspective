import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { useState } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import InventoryReportView from './InventoryReportView'
import { CORE_API_URL } from './api'

function jsonResponse(payload: unknown, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const scan = {
  scan_id: 'scan_1',
  status: 'completed',
  fixture_id: 'standard',
  profile: 'inventory_metadata',
  platform: 'darwin_fixture',
  content_read: false,
  hash_mode: 'none',
  coverage: {
    requested_entries: 3,
    collected_entries: 2,
    skipped_entries: 1,
    permission_gaps: ['fixture/restricted'],
    cancelled: false,
  },
  checkpoint: {
    checkpoint_id: 'checkpoint_1',
    scan_id: 'scan_1',
    status: 'completed',
    last_relative_path: null,
    collected_entries: 2,
    skipped_entries: 1,
    updated_at: '2026-07-27T09:00:00Z',
  },
  snapshot_id: 'snapshot_1',
  safety: {
    product_content_reads: 0,
    product_file_hashes: 0,
    network_calls: 0,
    file_actions: 0,
  },
}

const snapshot = {
  schema_version: '1.0',
  snapshot_id: 'snapshot_1',
  snapshot_sha256: 'snapshot-sha-1',
  scan_id: 'scan_1',
  generated_at: '2026-07-27T09:00:00Z',
  profile: 'inventory_metadata',
  platform: 'darwin_fixture',
  rules_version: 'fixture-rules-v1',
  content_read: false,
  hash_mode: 'none',
  canonical_tree_logical_size_bytes: 1536,
  canonical_tree_allocated_size_bytes: null,
  reclaimable_estimate_bytes: null,
  coverage: scan.coverage,
  limitations: ['受控 fixture 仅用于验证'],
  objects: [{ object_id: 'object_1' }],
  evidence: [],
}

function packetPreview(
  privacyMode: 'local_full' | 'share_safe',
  lint: null | { passed: boolean; issue_codes: string[]; packet_bytes: number; max_packet_bytes: number },
) {
  return {
    packet: {
      schema_version: '1.0',
      packet_id: privacyMode === 'local_full' ? 'packet_rules_1' : 'packet_fake_1',
      packet_sha256: privacyMode === 'local_full' ? 'packet-rules-sha' : 'packet-fake-sha',
      snapshot_id: 'snapshot_1',
      snapshot_sha256: 'snapshot-sha-1',
      generated_at: '2026-07-27T09:01:00Z',
      artifact_privacy_mode: privacyMode,
      analysis_execution_mode: privacyMode === 'local_full' ? 'none' : 'local_only',
      profile: 'inventory_metadata',
      platform: 'darwin_fixture',
      content_read: false,
      hash_mode: 'none',
      canonical_tree_logical_size_bytes: 1536,
      canonical_tree_allocated_size_bytes: null,
      reclaimable_estimate_bytes: null,
      coverage_summary: {
        requested_entries: 3,
        collected_entries: 2,
        skipped_entries: 1,
        permission_gap_count: 1,
        cancelled: false,
      },
      limitations: ['仅含受控元数据'],
      top_objects: [{
        object_id: 'object_1',
        evidence_ids: ['evidence_1'],
        object_type: 'directory',
        display_name: privacyMode === 'local_full' ? 'Fixture Documents' : '对象-001',
        location: privacyMode === 'local_full' ? 'fixture/Documents' : null,
        name_length: 17,
        logical_size_bytes: 1024,
        allocated_size_bytes: null,
        reclaimable_estimate_bytes: null,
        rule_hints: ['建议先看'],
      }],
      long_tail: { object_count: 1, logical_size_bytes: 512 },
      truncated: false,
    },
    privacy_lint: lint,
    estimated_input_tokens: 321,
  }
}

const syntheticBudget = {
  max_provider_calls: 1,
  max_schema_retries: 1,
  max_input_tokens: 12_000,
  max_output_tokens: 2_500,
  max_packet_bytes: 256_000,
  timeout_ms: 90_000,
  max_estimated_cost: 0,
}

const syntheticConsentReceiptId = 'consent_receipt_00000000-0000-4000-8000-000000000001'
const syntheticClientActionId = 'client_action_00000000-0000-4000-8000-000000000002'

function syntheticPacketPreview(
  lint = {
    passed: true,
    issue_codes: [] as string[],
    packet_bytes: 800,
    max_packet_bytes: 256_000,
  },
) {
  const preview = packetPreview('share_safe', lint)
  return {
    ...preview,
    packet: {
      ...preview.packet,
      packet_id: 'packet_synthetic_1',
      packet_sha256: 'packet-synthetic-sha',
      analysis_execution_mode: 'cloud_metadata_minimized',
    },
    analysis_offer: {
      synthetic: true,
      consent_required: true,
      network_calls: 0,
      provider: 'fake',
      model: 'fixture-analyst-v1',
      prompt_version: 'report-analysis-v1',
      consent_schema_version: '1.0',
      analysis_schema_version: 'ai-analysis-v1',
      disclosure_version: 'synthetic-disclosure-v1',
      snapshot_id: 'snapshot_1',
      snapshot_sha256: 'snapshot-sha-1',
      packet_id: 'packet_synthetic_1',
      packet_sha256: 'packet-synthetic-sha',
      packet_bytes: 800,
      estimated_input_tokens: 321,
      estimated_output_tokens: 240,
      included_field_categories: [
        '对象类型与 evidence/object 引用',
        '脱敏代号与父级引用',
        '空间聚合、覆盖、Top-K 与长尾',
      ],
      excluded_field_categories: [
        '文件内容与绝对路径',
        '原始名称、用户名与主机名',
        '文件 hash、SQLite 与 API key',
      ],
      budget: syntheticBudget,
      cost_basis: 'synthetic_zero_external_cost',
      disclosure: '本轮不发送、不读取 key、不产生外部计费；不证明真实 Provider 数据政策。',
    },
  }
}

function analysisResult(provider: 'none' | 'fake') {
  const fake = provider === 'fake'
  return {
    analysis: {
      schema_version: '1.0',
      analysis_id: fake ? 'analysis_fake_1' : 'analysis_rules_1',
      packet_id: fake ? 'packet_fake_1' : 'packet_rules_1',
      status: fake ? 'ai_complete' : 'deterministic_only',
      provider,
      model: fake ? 'fixture-fake-v1' : 'none',
      summary: fake ? '受控 fake 分析摘要' : '规则分析摘要',
      findings: [],
      questions: [],
      limitations: ['不代表真实文件判断'],
    },
    receipt: {
      receipt_id: fake ? 'receipt_fake_1' : 'receipt_rules_1',
      packet_sha256: fake ? 'packet-fake-sha' : 'packet-rules-sha',
      provider,
      model: fake ? 'fixture-fake-v1' : 'none',
      prompt_version: 'inventory-v1',
      schema_version: '1.0',
      cache_key: fake ? 'cache-fake-1' : 'cache-rules-1',
      status: fake ? 'succeeded' : 'not_called',
      provider_calls: fake ? 1 : 0,
      network_calls: 0,
      input_tokens: fake ? 120 : 0,
      cached_input_tokens: 0,
      output_tokens: fake ? 40 : 0,
      estimated_cost: 0,
      latency_ms: fake ? 8 : 0,
      error_code: null,
    },
  }
}

function syntheticAnalysisResult() {
  const result = analysisResult('fake')
  return {
    ...result,
    analysis: {
      ...result.analysis,
      analysis_id: 'analysis_synthetic_1',
      packet_id: 'packet_synthetic_1',
      model: 'fixture-analyst-v1',
      summary: '离线受控 synthetic 分析摘要',
    },
    receipt: {
      ...result.receipt,
      receipt_id: 'model_receipt_synthetic_1',
      packet_sha256: 'packet-synthetic-sha',
      model: 'fixture-analyst-v1',
      prompt_version: 'report-analysis-v1',
      schema_version: 'ai-analysis-v1',
      cache_key: 'cache-synthetic-1',
      synthetic: true,
      consent_receipt_id: syntheticConsentReceiptId,
      cost_basis: 'synthetic_zero_external_cost',
    },
    consent_receipt: {
      consent_receipt_id: syntheticConsentReceiptId,
      client_action_id: syntheticClientActionId,
      status: 'consumed',
      confirmed: true,
      synthetic: true,
      snapshot_id: 'snapshot_1',
      snapshot_sha256: 'snapshot-sha-1',
      packet_id: 'packet_synthetic_1',
      packet_sha256: 'packet-synthetic-sha',
      packet_bytes: 800,
      artifact_privacy_mode: 'share_safe',
      analysis_execution_mode: 'cloud_metadata_minimized',
      provider: 'fake',
      model: 'fixture-analyst-v1',
      prompt_version: 'report-analysis-v1',
      analysis_schema_version: 'ai-analysis-v1',
      disclosure_version: 'synthetic-disclosure-v1',
      budget: syntheticBudget,
      cost_basis: 'synthetic_zero_external_cost',
      provider_calls: 1,
      network_calls: 0,
      input_tokens: 200,
      cached_input_tokens: 0,
      output_tokens: 80,
      estimated_cost: 0,
      latency_ms: 8,
      fallback: false,
      created_at: '2026-07-27T09:01:30Z',
      consumed_at: '2026-07-27T09:01:31Z',
      error_code: null,
    },
  }
}

function reportResult(provider: 'none' | 'fake') {
  const fake = provider === 'fake'
  return {
    report_id: fake ? 'report_fake_1' : 'report_rules_1',
    status: fake ? 'ai_complete' : 'deterministic_only',
    manifest: {
      schema_version: '1.0',
      report_schema_version: '1.0',
      report_id: fake ? 'report_fake_1' : 'report_rules_1',
      artifact_id: fake ? 'artifact_fake_1' : 'artifact_rules_1',
      snapshot_id: 'snapshot_1',
      packet_id: fake ? 'packet_fake_1' : 'packet_rules_1',
      analysis_id: fake ? 'analysis_fake_1' : 'analysis_rules_1',
      generated_at: '2026-07-27T09:02:00Z',
      artifact_privacy_mode: fake ? 'share_safe' : 'local_full',
      provider,
      analysis_status: fake ? 'ai_complete' : 'deterministic_only',
      filename: '空间透视盘点报告.xlsx',
      workbook_sha256: fake ? 'workbook-fake-sha' : 'workbook-rules-sha',
      sheets: [
        '空间体检概览',
        '空间明细清单',
        '建议优先查看',
        '可能重复与安装包',
        '报告说明与记录',
      ],
      zip_integrity: true,
      reopen_validated: true,
    },
    download_url: `/v1/inventory/reports/${fake ? 'report_fake_1' : 'report_rules_1'}/download`,
  }
}

function syntheticReportResult() {
  const result = reportResult('fake')
  return {
    ...result,
    report_id: 'report_synthetic_1',
    manifest: {
      ...result.manifest,
      report_id: 'report_synthetic_1',
      artifact_id: 'artifact_synthetic_1',
      packet_id: 'packet_synthetic_1',
      analysis_id: 'analysis_synthetic_1',
      workbook_sha256: 'workbook-synthetic-sha',
    },
    download_url: '/v1/inventory/reports/report_synthetic_1/download',
  }
}

function inventoryBaseResponses(fetchMock: ReturnType<typeof vi.fn>) {
  fetchMock
    .mockResolvedValueOnce(jsonResponse(scan))
    .mockResolvedValueOnce(jsonResponse(scan))
    .mockResolvedValueOnce(jsonResponse(snapshot))
    .mockResolvedValueOnce(jsonResponse(snapshot))
}

function renderConnected() {
  return render(
    <InventoryReportView
      connection="connected"
      onRetryHealth={vi.fn(async () => undefined)}
      onCoreFailure={vi.fn()}
    />,
  )
}

async function runInventory() {
  fireEvent.click(screen.getByRole('button', { name: '运行受控盘点' }))
  await screen.findByRole('heading', { name: '这份盘点看到了什么' })
}

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('fixture-only inventory report view', () => {
  it('starts with the fixed fixture, pending counters, and no real-scope or action controls', () => {
    renderConnected()

    expect(screen.getByRole('heading', { name: '先得到报告，再决定要不要整理' })).toBeInTheDocument()
    const fixtureStamp = within(screen.getByLabelText('固定执行范围'))
    expect(fixtureStamp.getByText('standard')).toBeInTheDocument()
    expect(fixtureStamp.getByText('inventory_metadata')).toBeInTheDocument()
    expect(fixtureStamp.getByText('compute_hash=false')).toBeInTheDocument()

    const boundary = within(
      screen.getByRole('heading', { name: '四项产品副作用保持为零' }).closest('section')!,
    )
    expect(boundary.getAllByText('—')).toHaveLength(4)
    expect(boundary.getByText('内容读取')).toBeInTheDocument()
    expect(boundary.getByText('文件 hash')).toBeInTheDocument()
    expect(boundary.getByText('网络调用')).toBeInTheDocument()
    expect(boundary.getByText('源文件动作')).toBeInTheDocument()

    expect(document.querySelector('input[type="file"]')).toBeNull()
    expect(document.querySelector('input[type="text"], input[type="search"]')).toBeNull()
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
    expect(screen.queryByRole('radio')).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', {
        name: /删除|隔离|执行|卸载|清理|授权|同意|上传|选择目录|选择文件/,
      }),
    ).not.toBeInTheDocument()
  })

  it('runs the complete none + local_full ten-operation lineage with exact payloads and truthful nulls', async () => {
    const fetchMock = vi.fn()
    inventoryBaseResponses(fetchMock)
    fetchMock
      .mockResolvedValueOnce(jsonResponse(packetPreview('local_full', null)))
      .mockResolvedValueOnce(jsonResponse(analysisResult('none')))
      .mockResolvedValueOnce(jsonResponse(analysisResult('none')))
      .mockResolvedValueOnce(jsonResponse(reportResult('none')))
      .mockResolvedValueOnce(jsonResponse(reportResult('none')))
      .mockResolvedValueOnce(new Response('fixture workbook', {
        status: 200,
        headers: {
          'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
          'Content-Disposition': "attachment; filename*=UTF-8''%E7%A9%BA%E9%97%B4%E9%80%8F%E8%A7%86%E7%9B%98%E7%82%B9%E6%8A%A5%E5%91%8A.xlsx",
        },
      }))

    const createObjectURL = vi.fn().mockReturnValue('blob:fixture-report')
    const revokeObjectURL = vi.fn()
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined)
    class DownloadURL extends URL {}
    Object.assign(DownloadURL, { createObjectURL, revokeObjectURL })
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('URL', DownloadURL)

    renderConnected()
    await runInventory()

    const boundary = within(
      screen.getByRole('heading', { name: '四项产品副作用保持为零' }).closest('section')!,
    )
    expect(boundary.getAllByText('0')).toHaveLength(4)
    expect(screen.getByText('fixture/restricted')).toBeInTheDocument()
    expect(screen.getByText('受控 fixture 仅用于验证')).toBeInTheDocument()
    expect(screen.getByText('未获取')).toBeInTheDocument()
    expect(screen.getByText('未评估')).toBeInTheDocument()
    expect(screen.getByText('是否取消')).toBeInTheDocument()
    expect(screen.getAllByText('否')).toHaveLength(2)
    expect(screen.getByText('none')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: '生成证据预览' }))
    expect(await screen.findByText('packet-rules-sha')).toBeInTheDocument()
    expect(screen.getByText('local_full')).toBeInTheDocument()
    expect(screen.getByText('仅本机')).toBeInTheDocument()
    expect(screen.getByText('仅含受控元数据')).toBeInTheDocument()
    expect(screen.getByText('前 1 / 共 1')).toBeInTheDocument()
    expect(screen.queryByText('无位置字段')).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: '生成 XLSX 报告' }))
    expect(await screen.findByRole('heading', { name: '空间透视盘点报告已就绪' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '规则版已完成' })).toBeInTheDocument()
    expect(screen.getByText('未调用 Provider')).toBeInTheDocument()
    expect(screen.getByText('workbook-rules-sha')).toBeInTheDocument()
    expect(screen.getAllByText('通过')).toHaveLength(2)

    fireEvent.click(screen.getByRole('button', { name: '下载 XLSX 报告' }))
    expect(await screen.findByText(/XLSX 下载已启动/)).toBeInTheDocument()

    const expectedUrls = [
      '/v1/inventory/scans',
      '/v1/inventory/scans/scan_1',
      '/v1/inventory/snapshots',
      '/v1/inventory/snapshots/snapshot_1',
      '/v1/inventory/analysis-packets/preview',
      '/v1/inventory/analyses',
      '/v1/inventory/analyses/analysis_rules_1',
      '/v1/inventory/reports',
      '/v1/inventory/reports/report_rules_1',
      '/v1/inventory/reports/report_rules_1/download',
    ].map((path) => `${CORE_API_URL}${path}`)
    expect(fetchMock.mock.calls.map(([input]) => String(input))).toEqual(expectedUrls)

    const requests = fetchMock.mock.calls.map(([, init]) => ({
      method: init?.method ?? 'GET',
      body: init?.body ? JSON.parse(String(init.body)) : null,
    }))
    expect(requests).toEqual([
      {
        method: 'POST',
        body: { fixture_id: 'standard', profile: 'inventory_metadata', compute_hash: false },
      },
      { method: 'GET', body: null },
      { method: 'POST', body: { scan_id: 'scan_1' } },
      { method: 'GET', body: null },
      {
        method: 'POST',
        body: {
          snapshot_id: 'snapshot_1',
          artifact_privacy_mode: 'local_full',
          analysis_execution_mode: 'none',
          top_k: 200,
        },
      },
      { method: 'POST', body: { packet_id: 'packet_rules_1', provider: 'none' } },
      { method: 'GET', body: null },
      {
        method: 'POST',
        body: {
          snapshot_id: 'snapshot_1',
          packet_id: 'packet_rules_1',
          analysis_id: 'analysis_rules_1',
        },
      },
      { method: 'GET', body: null },
      { method: 'GET', body: null },
    ])
    expect(createObjectURL).toHaveBeenCalledWith(expect.objectContaining({
      size: 16,
      type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    }))
    expect(click).toHaveBeenCalledTimes(1)
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:fixture-report')
  })

  it('uses fake + share_safe only as a local simulation and invalidates the old lineage on mode switch', async () => {
    const fetchMock = vi.fn()
    inventoryBaseResponses(fetchMock)
    fetchMock
      .mockResolvedValueOnce(jsonResponse(packetPreview('share_safe', {
        passed: true,
        issue_codes: [],
        packet_bytes: 800,
        max_packet_bytes: 100_000,
      })))
      .mockResolvedValueOnce(jsonResponse(analysisResult('fake')))
      .mockResolvedValueOnce(jsonResponse(analysisResult('fake')))
      .mockResolvedValueOnce(jsonResponse(reportResult('fake')))
      .mockResolvedValueOnce(jsonResponse(reportResult('fake')))
    vi.stubGlobal('fetch', fetchMock)

    renderConnected()
    await runInventory()

    fireEvent.click(screen.getByRole('radio', { name: /受控 fake/ }))
    expect(screen.getByText(/不是真实 AI 或云服务/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '生成证据预览' }))

    expect(await screen.findByText('packet-fake-sha')).toBeInTheDocument()
    expect(screen.getByText('share_safe')).toBeInTheDocument()
    expect(screen.getByText('local_only')).toBeInTheDocument()
    expect(screen.getByText('通过')).toBeInTheDocument()
    expect(screen.getByText('无位置字段')).toBeInTheDocument()
    expect(JSON.parse(String(fetchMock.mock.calls[4][1]?.body))).toEqual({
      snapshot_id: 'snapshot_1',
      artifact_privacy_mode: 'share_safe',
      analysis_execution_mode: 'local_only',
      top_k: 200,
    })

    fireEvent.click(screen.getByRole('button', { name: '生成 XLSX 报告' }))
    expect(await screen.findByRole('heading', { name: '空间透视盘点报告已就绪' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '受控模拟分析已完成' })).toBeInTheDocument()
    expect(screen.getByText('调用成功')).toBeInTheDocument()
    expect(JSON.parse(String(fetchMock.mock.calls[5][1]?.body))).toEqual({
      packet_id: 'packet_fake_1',
      provider: 'fake',
    })

    fireEvent.click(screen.getByRole('radio', { name: /规则版/ }))

    expect(screen.queryByText('packet-fake-sha')).not.toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: '受控模拟分析已完成' })).not.toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: '空间透视盘点报告已就绪' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '生成证据预览' })).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(9)
  })

  it('requires explicit one-report consent and sends the complete server-declared synthetic binding', async () => {
    const fetchMock = vi.fn()
    inventoryBaseResponses(fetchMock)
    fetchMock
      .mockResolvedValueOnce(jsonResponse(syntheticPacketPreview()))
      .mockResolvedValueOnce(jsonResponse(syntheticAnalysisResult()))
      .mockResolvedValueOnce(jsonResponse(syntheticAnalysisResult()))
      .mockResolvedValueOnce(jsonResponse(syntheticReportResult()))
      .mockResolvedValueOnce(jsonResponse(syntheticReportResult()))
    vi.stubGlobal('fetch', fetchMock)
    vi.spyOn(globalThis.crypto, 'randomUUID')
      .mockReturnValueOnce('00000000-0000-4000-8000-000000000001')
      .mockReturnValueOnce('00000000-0000-4000-8000-000000000002')

    renderConnected()
    await runInventory()

    fireEvent.click(screen.getByRole('radio', { name: /逐报告 consent/ }))
    expect(screen.getByText(/真实云能力仍关闭/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '生成证据预览' }))

    expect(await screen.findAllByText('packet-synthetic-sha')).toHaveLength(2)
    expect(screen.getByText('cloud_metadata_minimized')).toBeInTheDocument()
    const disclosure = within(
      screen.getByRole('heading', { name: '本次 synthetic 分析会使用什么' }).closest('section')!,
    )
    expect(disclosure.getByText('fixture-analyst-v1')).toBeInTheDocument()
    expect(disclosure.getByText('800 B')).toBeInTheDocument()
    expect(disclosure.getByText('对象类型与 evidence/object 引用')).toBeInTheDocument()
    expect(disclosure.getByText('文件内容与绝对路径')).toBeInTheDocument()
    expect(disclosure.getByText('12,000')).toBeInTheDocument()
    expect(disclosure.getByText('2,500')).toBeInTheDocument()
    expect(disclosure.getByText('90 秒')).toBeInTheDocument()
    expect(disclosure.getByText(/本轮不发送、不读取 key、不产生外部计费/)).toBeInTheDocument()

    const consent = disclosure.getByRole('checkbox', {
      name: /我已核对本次证据包并同意仅用于这一份报告/,
    })
    const generate = disclosure.getByRole('button', {
      name: '同意本次 synthetic 分析并生成 XLSX',
    })
    expect(consent).not.toBeChecked()
    expect(generate).toBeDisabled()

    fireEvent.click(consent)
    expect(generate).toBeEnabled()
    fireEvent.click(generate)

    expect(await screen.findByRole('heading', { name: '空间透视盘点报告已就绪' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '离线受控 synthetic 分析已完成' })).toBeInTheDocument()
    expect(screen.getByText(syntheticConsentReceiptId)).toBeInTheDocument()
    expect(screen.getByText('已一次性消费')).toBeInTheDocument()
    expect(screen.getAllByText(/外部计费为 0/)).toHaveLength(2)
    expect(screen.getByText(/不证明真实价格或币种/)).toBeInTheDocument()

    expect(JSON.parse(String(fetchMock.mock.calls[4][1]?.body))).toEqual({
      snapshot_id: 'snapshot_1',
      artifact_privacy_mode: 'share_safe',
      analysis_execution_mode: 'cloud_metadata_minimized',
      budget: syntheticBudget,
      top_k: 200,
    })
    expect(JSON.parse(String(fetchMock.mock.calls[5][1]?.body))).toEqual({
      packet_id: 'packet_synthetic_1',
      provider: 'fake',
      consent: {
        consent_schema_version: '1.0',
        consent_receipt_id: syntheticConsentReceiptId,
        client_action_id: syntheticClientActionId,
        confirmed: true,
        snapshot_id: 'snapshot_1',
        snapshot_sha256: 'snapshot-sha-1',
        packet_id: 'packet_synthetic_1',
        packet_sha256: 'packet-synthetic-sha',
        packet_bytes: 800,
        artifact_privacy_mode: 'share_safe',
        analysis_execution_mode: 'cloud_metadata_minimized',
        provider: 'fake',
        model: 'fixture-analyst-v1',
        prompt_version: 'report-analysis-v1',
        analysis_schema_version: 'ai-analysis-v1',
        disclosure_version: 'synthetic-disclosure-v1',
        budget: syntheticBudget,
        cost_basis: 'synthetic_zero_external_cost',
      },
    })
  })

  it('clears synthetic consent on packet regeneration and always exposes the rules fallback', async () => {
    const renewedPreview = syntheticPacketPreview()
    renewedPreview.packet.packet_id = 'packet_synthetic_2'
    renewedPreview.packet.packet_sha256 = 'packet-synthetic-sha-2'
    renewedPreview.analysis_offer.packet_id = 'packet_synthetic_2'
    renewedPreview.analysis_offer.packet_sha256 = 'packet-synthetic-sha-2'

    const fetchMock = vi.fn()
    inventoryBaseResponses(fetchMock)
    fetchMock
      .mockResolvedValueOnce(jsonResponse(syntheticPacketPreview()))
      .mockResolvedValueOnce(jsonResponse(renewedPreview))
    vi.stubGlobal('fetch', fetchMock)

    renderConnected()
    await runInventory()
    fireEvent.click(screen.getByRole('radio', { name: /逐报告 consent/ }))
    fireEvent.click(screen.getByRole('button', { name: '生成证据预览' }))
    const firstConsent = await screen.findByRole('checkbox', {
      name: /我已核对本次证据包并同意仅用于这一份报告/,
    })
    fireEvent.click(firstConsent)
    expect(firstConsent).toBeChecked()

    fireEvent.click(screen.getByRole('button', { name: '重新生成证据预览' }))
    expect(await screen.findAllByText('packet-synthetic-sha-2')).toHaveLength(2)
    expect(screen.getByRole('checkbox', {
      name: /我已核对本次证据包并同意仅用于这一份报告/,
    })).not.toBeChecked()

    fireEvent.click(screen.getByRole('button', { name: '改用规则版' }))
    expect(screen.getByRole('radio', { name: /规则版/ })).toBeChecked()
    expect(screen.queryByText('packet-synthetic-sha-2')).not.toBeInTheDocument()
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
  })

  it('blocks synthetic consent when privacy lint fails and keeps the rules fallback available', async () => {
    const blocked = syntheticPacketPreview({
      passed: false,
      issue_codes: ['ABSOLUTE_PATH_DETECTED'],
      packet_bytes: 900,
      max_packet_bytes: 256_000,
    })
    const fetchMock = vi.fn()
    inventoryBaseResponses(fetchMock)
    fetchMock.mockResolvedValueOnce(jsonResponse(blocked))
    vi.stubGlobal('fetch', fetchMock)

    renderConnected()
    await runInventory()
    fireEvent.click(screen.getByRole('radio', { name: /逐报告 consent/ }))
    fireEvent.click(screen.getByRole('button', { name: '生成证据预览' }))

    expect(await screen.findByText('隐私门禁已阻断后续分析')).toBeInTheDocument()
    expect(screen.getByRole('checkbox', {
      name: /我已核对本次证据包并同意仅用于这一份报告/,
    })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: '改用规则版' }))
    expect(screen.getByRole('radio', { name: /规则版/ })).toBeChecked()
    expect(fetchMock).toHaveBeenCalledTimes(5)
  })

  it('locks preset controls while a packet is pending and ignores its stale response', async () => {
    let resolvePacket!: (response: Response) => void
    const pendingPacket = new Promise<Response>((resolve) => {
      resolvePacket = resolve
    })
    const fetchMock = vi.fn()
    inventoryBaseResponses(fetchMock)
    fetchMock.mockReturnValueOnce(pendingPacket)
    vi.stubGlobal('fetch', fetchMock)

    renderConnected()
    await runInventory()

    fireEvent.click(screen.getByRole('button', { name: '生成证据预览' }))
    const rulesRadio = screen.getByRole('radio', { name: /规则版/ })
    const fakeRadio = screen.getByRole('radio', { name: /受控 fake/ })
    const syntheticRadio = screen.getByRole('radio', { name: /逐报告 consent/ })
    expect(rulesRadio).toBeDisabled()
    expect(fakeRadio).toBeDisabled()
    expect(syntheticRadio).toBeDisabled()

    fakeRadio.removeAttribute('disabled')
    fireEvent.click(fakeRadio)
    expect(screen.getByRole('radio', { name: /受控 fake/ })).toBeChecked()

    await act(async () => {
      resolvePacket(jsonResponse(packetPreview('local_full', null)))
      await pendingPacket
    })

    expect(screen.queryByText('packet-rules-sha')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '生成证据预览' })).toBeEnabled()
    expect(fetchMock).toHaveBeenCalledTimes(5)
  })

  it('blocks analysis when the share_safe privacy lint fails', async () => {
    const fetchMock = vi.fn()
    inventoryBaseResponses(fetchMock)
    fetchMock.mockResolvedValueOnce(jsonResponse(packetPreview('share_safe', {
      passed: false,
      issue_codes: ['ABSOLUTE_PATH_DETECTED', 'RAW_NAME_DETECTED'],
      packet_bytes: 900,
      max_packet_bytes: 100_000,
    })))
    vi.stubGlobal('fetch', fetchMock)

    renderConnected()
    await runInventory()
    fireEvent.click(screen.getByRole('radio', { name: /受控 fake/ }))
    fireEvent.click(screen.getByRole('button', { name: '生成证据预览' }))

    await waitFor(() => {
      expect(screen.getAllByRole('alert').some((alert) => (
        alert.textContent?.includes('ABSOLUTE_PATH_DETECTED')
        && alert.textContent.includes('RAW_NAME_DETECTED')
      ))).toBe(true)
    })
    expect(screen.getByText('隐私门禁已阻断后续分析')).toBeInTheDocument()
    const generateButton = screen.getByRole('button', { name: '生成 XLSX 报告' })
    expect(generateButton).toBeDisabled()
    fireEvent.click(generateButton)
    expect(fetchMock).toHaveBeenCalledTimes(5)
    expect(fetchMock.mock.calls.map(([input]) => String(input))).not.toContain(
      `${CORE_API_URL}/v1/inventory/analyses`,
    )
  })

  it('shows the structured API message and code to the user', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse({
      code: 'FIXTURE_NOT_FOUND',
      message: '受控 fixture 不存在',
      details: { fixture_id: 'standard' },
      request_id: 'req_fixture_1',
    }, 404))
    vi.stubGlobal('fetch', fetchMock)

    renderConnected()
    fireEvent.click(screen.getByRole('button', { name: '运行受控盘点' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(
      '受控 fixture 不存在（FIXTURE_NOT_FOUND）',
    )
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('reports a transport failure so the parent can expose Core recovery', async () => {
    const onCoreFailure = vi.fn()
    const onRetryHealth = vi.fn(async () => undefined)
    vi.stubGlobal('fetch', vi.fn().mockRejectedValueOnce(new TypeError('Failed to fetch')))

    function RecoveryHarness() {
      const [connection, setConnection] = useState<'connected' | 'offline'>('connected')
      return (
        <InventoryReportView
          connection={connection}
          onRetryHealth={async () => {
            await onRetryHealth()
            setConnection('connected')
          }}
          onCoreFailure={() => {
            onCoreFailure()
            setConnection('offline')
          }}
        />
      )
    }

    render(<RecoveryHarness />)
    fireEvent.click(screen.getByRole('button', { name: '运行受控盘点' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Failed to fetch')
    expect(onCoreFailure).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: '重新检查 Core' }))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: '运行受控盘点' })).toBeEnabled()
    })
    expect(onRetryHealth).toHaveBeenCalledTimes(1)
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
})
