import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  ApiError,
  CORE_API_URL,
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
} from './api'

function jsonResponse(payload: unknown, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('fixture-only inventory API client', () => {
  it('uses the ten frozen endpoints and projects exact request payloads', async () => {
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(jsonResponse({})))
    vi.stubGlobal('fetch', fetchMock)

    await createInventoryScan()
    await getInventoryScan('scan/1')
    await createInventorySnapshot('scan_1')
    await getInventorySnapshot('snapshot/1')
    await previewInventoryPacket({
      snapshot_id: 'snapshot_1',
      artifact_privacy_mode: 'share_safe',
      analysis_execution_mode: 'local_only',
      top_k: 50,
      path: '/must-not-leak',
    } as Parameters<typeof previewInventoryPacket>[0] & { path: string })
    await createInventoryAnalysis('packet_1', 'fake')
    await getInventoryAnalysis('analysis/1')
    await createInventoryReport({
      snapshot_id: 'snapshot_1',
      packet_id: 'packet_1',
      analysis_id: 'analysis_1',
      path: '/must-not-leak',
    } as Parameters<typeof createInventoryReport>[0] & { path: string })
    await getInventoryReport('report/1')

    expect(fetchMock).toHaveBeenCalledTimes(9)
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual([
      `${CORE_API_URL}/v1/inventory/scans`,
      `${CORE_API_URL}/v1/inventory/scans/scan%2F1`,
      `${CORE_API_URL}/v1/inventory/snapshots`,
      `${CORE_API_URL}/v1/inventory/snapshots/snapshot%2F1`,
      `${CORE_API_URL}/v1/inventory/analysis-packets/preview`,
      `${CORE_API_URL}/v1/inventory/analyses`,
      `${CORE_API_URL}/v1/inventory/analyses/analysis%2F1`,
      `${CORE_API_URL}/v1/inventory/reports`,
      `${CORE_API_URL}/v1/inventory/reports/report%2F1`,
    ])
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({
      fixture_id: 'standard',
      profile: 'inventory_metadata',
      compute_hash: false,
    })
    expect(JSON.parse(String(fetchMock.mock.calls[2][1]?.body))).toEqual({ scan_id: 'scan_1' })
    expect(JSON.parse(String(fetchMock.mock.calls[4][1]?.body))).toEqual({
      snapshot_id: 'snapshot_1',
      artifact_privacy_mode: 'share_safe',
      analysis_execution_mode: 'local_only',
      top_k: 50,
    })
    expect(JSON.parse(String(fetchMock.mock.calls[5][1]?.body))).toEqual({
      packet_id: 'packet_1',
      provider: 'fake',
    })
    expect(JSON.parse(String(fetchMock.mock.calls[7][1]?.body))).toEqual({
      snapshot_id: 'snapshot_1',
      packet_id: 'packet_1',
      analysis_id: 'analysis_1',
    })
  })

  it('rejects providers outside none and fake before making a request', () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)

    expect(() => createInventoryAnalysis('packet_1', 'cloud' as 'fake')).toThrowError(
      expect.objectContaining({ code: 'INVALID_INVENTORY_PROVIDER' }),
    )
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('projects the complete synthetic consent binding as one nested object', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({}))
    vi.stubGlobal('fetch', fetchMock)

    const consent = {
      consent_schema_version: '1.0' as const,
      consent_receipt_id: 'consent_receipt_00000000-0000-4000-8000-000000000001',
      client_action_id: 'client_action_00000000-0000-4000-8000-000000000002',
      confirmed: true as const,
      snapshot_id: 'snapshot_1',
      snapshot_sha256: 'snapshot-sha-1',
      packet_id: 'packet_synthetic_1',
      packet_sha256: 'packet-synthetic-sha',
      packet_bytes: 800,
      artifact_privacy_mode: 'share_safe' as const,
      analysis_execution_mode: 'cloud_metadata_minimized' as const,
      provider: 'fake' as const,
      model: 'fixture-analyst-v1',
      prompt_version: 'report-analysis-v1',
      analysis_schema_version: 'ai-analysis-v1',
      disclosure_version: 'synthetic-disclosure-v1',
      budget: {
        max_provider_calls: 1 as const,
        max_schema_retries: 1 as const,
        max_input_tokens: 12_000,
        max_output_tokens: 2_500,
        max_packet_bytes: 256_000,
        timeout_ms: 90_000,
        max_estimated_cost: 0 as const,
      },
      cost_basis: 'synthetic_zero_external_cost' as const,
    }

    await createInventoryAnalysis('packet_synthetic_1', 'fake', consent)

    expect(fetchMock).toHaveBeenCalledWith(
      `${CORE_API_URL}/v1/inventory/analyses`,
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          packet_id: 'packet_synthetic_1',
          provider: 'fake',
          consent,
        }),
      }),
    )
  })
})

describe('inventory XLSX download', () => {
  it('uses the attachment filename and always revokes the object URL', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('fixture workbook', {
      status: 200,
      headers: {
        'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'Content-Disposition': "attachment; filename*=UTF-8''%E7%A9%BA%E9%97%B4%E9%80%8F%E8%A7%86.xlsx",
      },
    }))
    const createObjectURL = vi.fn().mockReturnValue('blob:fixture-report')
    const revokeObjectURL = vi.fn()
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined)
    class DownloadURL extends URL {}
    Object.assign(DownloadURL, { createObjectURL, revokeObjectURL })
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('URL', DownloadURL)

    const filename = await downloadInventoryReport(
      '/v1/inventory/reports/report_123/download',
      'fallback.xlsx',
    )

    expect(filename).toBe('空间透视.xlsx')
    expect(fetchMock).toHaveBeenCalledWith(
      `${CORE_API_URL}/v1/inventory/reports/report_123/download`,
      { headers: { Accept: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' } },
    )
    expect(createObjectURL).toHaveBeenCalledWith(expect.objectContaining({
      size: 16,
      type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    }))
    expect(click).toHaveBeenCalledTimes(1)
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:fixture-report')
  })

  it('surfaces a structured JSON ErrorResponse without creating a Blob URL', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({
      code: 'REPORT_NOT_FOUND',
      message: '报告不存在',
      details: { report_id: 'report_missing' },
      request_id: 'req_1',
    }, 404))
    const createObjectURL = vi.fn()
    class DownloadURL extends URL {}
    Object.assign(DownloadURL, { createObjectURL, revokeObjectURL: vi.fn() })
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('URL', DownloadURL)

    const error = await downloadInventoryReport(
      '/v1/inventory/reports/report_missing/download',
    ).catch((caught: unknown) => caught)

    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({
      status: 404,
      code: 'REPORT_NOT_FOUND',
      message: '报告不存在',
      details: { report_id: 'report_missing' },
      requestId: 'req_1',
    })
    expect(createObjectURL).not.toHaveBeenCalled()
  })

  it('rejects a successful response with a non-XLSX media type', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('<html>not a workbook</html>', {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    }))
    const createObjectURL = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('URL', Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() }))

    await expect(downloadInventoryReport(
      '/v1/inventory/reports/report_123/download',
    )).rejects.toMatchObject({
      code: 'INVALID_INVENTORY_REPORT_MEDIA_TYPE',
    })
    expect(createObjectURL).not.toHaveBeenCalled()
  })

  it('rejects arbitrary or cross-origin download locations', async () => {
    await expect(downloadInventoryReport('/Users/demo/private.xlsx')).rejects.toMatchObject({
      code: 'INVALID_INVENTORY_DOWNLOAD_URL',
    })
    await expect(downloadInventoryReport('https://example.com/report.xlsx')).rejects.toMatchObject({
      code: 'INVALID_INVENTORY_DOWNLOAD_URL',
    })
  })
})
