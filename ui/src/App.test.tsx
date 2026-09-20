import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import App from './App'

const healthyResponse = {
  status: 'ok',
  version: '0.1.0',
  db_status: 'ok',
  capabilities: {
    real_upload_enabled: false,
    mock_provider_enabled: true,
    file_upload_enabled: false,
    cloud_metadata_analysis_available: false,
    cloud_metadata_analysis_enabled: false,
  },
  current_time: '2026-07-17T10:00:00Z',
}

function response(payload: unknown, ok = true, status = 200) {
  return { ok, status, json: async () => payload }
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('App', () => {
  it('shows a truthful connected workspace with a local-path scan entry', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(healthyResponse)))

    render(<App />)

    expect(await screen.findByText('Core 已连接')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '体检总览' }))
    expect(screen.getByRole('button', { name: '开始只读体检' })).toBeEnabled()
    expect(screen.getByLabelText('本机绝对路径')).toBeInTheDocument()
    expect(screen.getByText(/真实上传：始终关闭/)).toBeInTheDocument()
    expect(document.querySelector('input[type="file"]')).toBeNull()
  })

  it('shows an actionable offline state and retries', async () => {
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce(response(healthyResponse))
    vi.stubGlobal('fetch', fetchMock)

    render(<App />)

    expect(await screen.findByText('Core 未连接')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '体检总览' }))
    fireEvent.click(screen.getByRole('button', { name: '重新检查连接' }))

    await waitFor(() => expect(screen.getByText('Core 已连接')).toBeInTheDocument())
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('loads real scan results, protects high risk, and gates execution behind preview', async () => {
    const session = {
      id: 'scan_1', status: 'completed', requested_paths: ['/tmp/demo'],
      started_at: '2026-07-17T10:00:00Z', finished_at: '2026-07-17T10:00:01Z',
      current_path: '/tmp/demo/repeat-b.txt', files_seen: 3, files_indexed: 3,
      files_skipped: 0, bytes_seen: 100, error_summary: [],
    }
    const assets = [
      { id: 'a1', abs_path: '/tmp/demo/repeat-a.txt', size_bytes: 40, category: 'document', source_hint: 'downloads', status: 'active', scan_session_id: 'scan_1', risk_flags: [], path_hash: '1', file_hash: 'h', partial_hash: 'p', hash_status: 'full', ext: '.txt', mime: 'text/plain', created_at: null, modified_at: null, accessed_at: null },
      { id: 'a2', abs_path: '/tmp/demo/repeat-b.txt', size_bytes: 40, category: 'document', source_hint: 'downloads', status: 'active', scan_session_id: 'scan_1', risk_flags: ['exact_duplicate'], path_hash: '2', file_hash: 'h', partial_hash: 'p', hash_status: 'full', ext: '.txt', mime: 'text/plain', created_at: null, modified_at: null, accessed_at: null },
      { id: 'a3', abs_path: '/tmp/demo/合同-样本.txt', size_bytes: 20, category: 'document', source_hint: 'documents', status: 'active', scan_session_id: 'scan_1', risk_flags: ['sensitive_keyword:合同'], path_hash: '3', file_hash: null, partial_hash: null, hash_status: 'not_started', ext: '.txt', mime: 'text/plain', created_at: null, modified_at: null, accessed_at: null },
    ]
    const suggestions = [
      { id: 's1', asset_id: 'a2', dup_group_id: 'd1', category: 'safe_to_process', risk_level: 'low', proposed_action: 'quarantine', reason: 'SHA-256 完全一致', evidence: { items: [{ type: 'path', label: '路径', value: '/tmp/demo/repeat-b.txt' }] }, reversible: true, default_selected: true, status: 'active', created_at: null },
      { id: 's2', asset_id: 'a3', dup_group_id: null, category: 'sensitive_protected', risk_level: 'high', proposed_action: 'protect', reason: '命中合同关键词', evidence: { items: [{ type: 'path', label: '路径', value: '/tmp/demo/合同-样本.txt' }] }, reversible: true, default_selected: false, status: 'active', created_at: null },
    ]
    const plan = {
      id: 'plan_1', action_type: 'quarantine', status: 'previewed', reversible: true,
      summary: { file_count: 1, total_size_bytes: 40, target_policy: 'app_quarantine' },
      risk_summary: [{ risk_level: 'low', file_count: 1, size_bytes: 40 }],
      items: [{ asset_id: 'a2', suggestion_id: 's1', display_path: '/tmp/demo/repeat-b.txt', size_bytes: 40, risk_level: 'low', reversible: true, warnings: [] }],
      warnings: [], version: 'v1', created_at: '2026-07-17T10:00:02Z', expires_at: '2026-07-17T10:15:02Z',
    }
    const receipt = {
      id: 'receipt_1', operation_plan_id: 'plan_1', action_type: 'quarantine',
      status: 'succeeded', reversible: true, file_count: 1, total_size_bytes: 40,
      started_at: '2026-07-17T10:00:03Z', finished_at: '2026-07-17T10:00:04Z',
      affects_cloud_sync: false, rule_version: null, provider_version: null,
      file_results: [],
    }

    const fetchMock = vi.fn().mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.endsWith('/health')) return Promise.resolve(response(healthyResponse))
      if (url.endsWith('/scan') && init?.method === 'POST') return Promise.resolve(response({ ...session, status: 'pending', finished_at: null, files_seen: 0, files_indexed: 0, bytes_seen: 0 }))
      if (url.includes('/scan/scan_1')) return Promise.resolve(response(session))
      if (url.includes('/assets')) return Promise.resolve(response({ items: assets }))
      if (url.includes('/fileintel/overview')) return Promise.resolve(response({ scan_session_id: 'scan_1', total_files: 3, total_size_bytes: 100, by_category: [{ key: 'document', file_count: 3, size_bytes: 100 }], by_source: [{ key: 'downloads', file_count: 2, size_bytes: 80 }], by_directory: [], top_large_files: assets, risk_summary: [{ risk_level: 'high', file_count: 1, size_bytes: 20 }], generated_at: '2026-07-17T10:00:02Z' }))
      if (url.includes('/dups')) return Promise.resolve(response({ items: [] }))
      if (url.includes('/suggestions')) return Promise.resolve(response({ items: suggestions }))
      if (url.includes('/quarantine')) return Promise.resolve(response({ items: [] }))
      if (url.includes('/operations/preview')) return Promise.resolve(response(plan))
      if (url.includes('/operations/execute')) return Promise.resolve(response(receipt))
      if (url.includes('/operations')) return Promise.resolve(response({ items: [] }))
      throw new Error(`unexpected request: ${url}`)
    })
    vi.stubGlobal('fetch', fetchMock)

    class FakeEventSource {
      onerror: (() => void) | null = null
      constructor(_url: string) {}
      addEventListener(_name: string, listener: EventListener) {
        queueMicrotask(() => listener({ data: JSON.stringify({
          event_id: 'e1', scan_session_id: 'scan_1', type: 'completed', occurred_at: '2026-07-17T10:00:01Z',
          current_path: '/tmp/demo/repeat-b.txt', files_seen: 3, files_indexed: 3, files_skipped: 0, bytes_seen: 100, message: '完成',
        }) } as unknown as Event))
      }
      close() {}
    }
    vi.stubGlobal('EventSource', FakeEventSource)

    render(<App />)
    await screen.findByText('Core 已连接')
    fireEvent.click(screen.getByRole('button', { name: '体检总览' }))
    fireEvent.change(screen.getByLabelText('本机绝对路径'), { target: { value: '/tmp/demo' } })
    fireEvent.click(screen.getByRole('button', { name: '开始只读体检' }))

    expect(await screen.findByText(/已在本机索引 3 个文件/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /^整理建议/ }))
    expect(await screen.findByText('合同-样本.txt')).toBeInTheDocument()
    const checkboxes = screen.getAllByRole('checkbox') as HTMLInputElement[]
    expect(checkboxes).toHaveLength(2)
    expect(checkboxes[0]).toBeChecked()
    expect(checkboxes[1]).toBeDisabled()

    fireEvent.click(screen.getByRole('button', { name: '生成操作预览' }))
    expect(await screen.findByRole('dialog', { name: '操作预览' })).toBeInTheDocument()
    expect(screen.getByText('不会永久删除')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '确认移入隔离区' }))
    expect(await screen.findByRole('button', { name: '立即撤销' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: '空间报告' }))
    expect(await screen.findByRole('heading', { name: '先得到报告，再决定要不要整理' })).toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: '操作预览' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '立即撤销' })).not.toBeInTheDocument()
    expect(screen.queryByText(/文件已进入应用级隔离区/)).not.toBeInTheDocument()
  })
})
