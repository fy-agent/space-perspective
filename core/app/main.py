from __future__ import annotations

import asyncio
from collections.abc import AsyncIterable
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated

from fastapi import FastAPI, Header, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.sse import EventSourceResponse, ServerSentEvent
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from core.app.config import Settings, load_settings
from core.app.errors import (
    DomainError,
    domain_exception_handler,
    http_exception_handler,
    validation_exception_handler,
)
from core.app.models import (
    AssetCategory,
    AssetDetail,
    AssetList,
    AssetStatus,
    Capabilities,
    DuplicateGroupList,
    ErrorResponse,
    FileIntelOverview,
    HealthResponse,
    InventoryAnalysisCreateRequest,
    InventoryAnalysisResponse,
    InventoryPacketPreviewRequest,
    InventoryPacketPreviewResponse,
    InventoryReportCreateRequest,
    InventoryReportResponse,
    InventoryScanCreateRequest,
    InventoryScanResponse,
    InventorySnapshotCreateRequest,
    MockAnalyzeRequest,
    MockAnalyzeResponse,
    OperationExecuteRequest,
    OperationPlan,
    OperationPreviewRequest,
    OperationReceipt,
    OperationReceiptList,
    OperationStatus,
    OperationUndoRequest,
    ProviderInfo,
    ProviderList,
    QuarantineItemList,
    QuarantineStatus,
    RiskLevel,
    ScanRequest,
    ScanSession,
    SourceHint,
    SuggestionCategory,
    SuggestionList,
)
from core.inventory.models import ReportSnapshotV1
from core.db.connection import EXPECTED_SCHEMA_VERSION, get_schema_version, initialize_database
from core.db.repository import Repository, utc_now
from core.services.inventory import InventoryService
from core.services.operations import OperationService
from core.services.scans import ScanInputError, ScanService


TERMINAL_SCAN_STATES = {"completed", "partial", "cancelled", "failed"}
XLSX_MEDIA_TYPE = (
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
)
INVENTORY_ERROR_RESPONSES = {
    "default": {
        "model": ErrorResponse,
        "description": "Error response",
    }
}
INVENTORY_DOWNLOAD_RESPONSES = {
    200: {
        "description": "Verified XLSX attachment",
        "headers": {
            "Cache-Control": {
                "schema": {
                    "type": "string",
                    "enum": ["no-store"],
                }
            }
        },
        "content": {
            XLSX_MEDIA_TYPE: {
                "schema": {
                    "type": "string",
                    "format": "binary",
                }
            }
        },
    },
    **INVENTORY_ERROR_RESPONSES,
}


def create_app(settings: Settings | None = None) -> FastAPI:
    app_settings = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        initialize_database(app_settings.database_path)
        repository = Repository(app_settings.database_path)
        app.state.repository = repository
        app.state.scan_service = ScanService(repository, app_settings)
        app.state.operation_service = OperationService(repository, app_settings)
        app.state.inventory_service = InventoryService(repository, app_settings)
        app.state.scan_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="local-scan")
        yield
        app.state.scan_executor.shutdown(wait=True, cancel_futures=True)

    app = FastAPI(
        title="Local AI Data Butler MVP API",
        version=app_settings.version,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url=None,
    )
    app.state.settings = app_settings
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"])
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(app_settings.allowed_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Accept", "Content-Type", "Last-Event-ID", "X-Request-ID"],
    )
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(DomainError, domain_exception_handler)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return response

    def repository() -> Repository:
        return app.state.repository

    @app.get("/health", response_model=HealthResponse, tags=["health"])
    def get_health() -> HealthResponse:
        schema_version = get_schema_version(app_settings.database_path)
        db_status = "ok" if schema_version == EXPECTED_SCHEMA_VERSION else "migration_required"
        return HealthResponse(
            status="ok" if db_status == "ok" else "degraded",
            version=app_settings.version,
            db_status=db_status,
            capabilities=Capabilities(
                real_upload_enabled=False,
                mock_provider_enabled=True,
                file_upload_enabled=False,
                cloud_metadata_analysis_available=False,
                cloud_metadata_analysis_enabled=False,
                controlled_synthetic_consent_available=True,
            ),
            current_time=datetime.now(timezone.utc),
        )

    @app.post("/scan", response_model=ScanSession, status_code=status.HTTP_202_ACCEPTED, tags=["scan"])
    def create_scan(request: ScanRequest) -> ScanSession:
        try:
            session, normalized = app.state.scan_service.create(request)
        except ScanInputError as exc:
            raise DomainError("SCAN_PATH_INVALID", str(exc), status_code=422) from exc
        app.state.scan_executor.submit(app.state.scan_service.run, session.id, normalized)
        return session

    @app.get("/scan/{scan_session_id}", response_model=ScanSession, tags=["scan"])
    def get_scan(scan_session_id: str) -> ScanSession:
        session = repository().get_scan(scan_session_id)
        if session is None:
            raise DomainError("SCAN_NOT_FOUND", "扫描任务不存在", status_code=404)
        return session

    @app.get(
        "/scan/{scan_session_id}/stream",
        response_class=EventSourceResponse,
        tags=["scan"],
    )
    async def stream_scan(
        scan_session_id: str,
        last_event_id: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
    ) -> AsyncIterable[ServerSentEvent]:
        if repository().get_scan(scan_session_id) is None:
            raise DomainError("SCAN_NOT_FOUND", "扫描任务不存在", status_code=404)
        cursor = last_event_id
        while True:
            pending = repository().list_scan_events(scan_session_id, cursor)
            for event in pending:
                cursor = event.event_id
                yield ServerSentEvent(
                    data=event, event="scan_event", id=event.event_id, retry=1000
                )
            session = repository().get_scan(scan_session_id)
            if session is None or (session.status in TERMINAL_SCAN_STATES and not pending):
                return
            await asyncio.sleep(0.1)

    @app.post("/scan/{scan_session_id}/cancel", response_model=ScanSession, tags=["scan"])
    def cancel_scan(scan_session_id: str) -> ScanSession:
        session = app.state.scan_service.cancel(scan_session_id)
        if session is None:
            raise DomainError("SCAN_NOT_FOUND", "扫描任务不存在", status_code=404)
        return session

    @app.get("/assets", response_model=AssetList, tags=["assets"])
    def list_assets(
        scan_session_id: str | None = None,
        category: AssetCategory | None = None,
        source_hint: SourceHint | None = None,
        asset_status: Annotated[AssetStatus | None, Query(alias="status")] = None,
        min_size_bytes: Annotated[int | None, Query(ge=0)] = None,
        page: Annotated[int, Query(ge=1)] = 1,
        page_size: Annotated[int, Query(ge=1, le=500)] = 50,
    ) -> AssetList:
        return repository().list_assets(
            scan_id=scan_session_id, category=category, source_hint=source_hint,
            status=asset_status, min_size_bytes=min_size_bytes, page=page, page_size=page_size,
        )

    @app.get("/assets/{asset_id}", response_model=AssetDetail, tags=["assets"])
    def get_asset(asset_id: str) -> AssetDetail:
        detail = repository().get_asset_detail(asset_id)
        if detail is None:
            raise DomainError("ASSET_NOT_FOUND", "资产不存在", status_code=404)
        return detail

    @app.get("/fileintel/overview", response_model=FileIntelOverview, tags=["fileintel"])
    def get_overview(scan_session_id: str | None = None) -> FileIntelOverview:
        resolved = scan_session_id or repository().latest_scan_id()
        if resolved is None or repository().get_scan(resolved) is None:
            raise DomainError("SCAN_NOT_FOUND", "还没有可用扫描记录", status_code=404)
        return repository().get_overview(resolved)

    @app.get("/dups", response_model=DuplicateGroupList, tags=["dups"])
    def list_dups(
        scan_session_id: str | None = None,
        min_reclaimable_bytes: Annotated[int, Query(ge=0)] = 0,
        page: Annotated[int, Query(ge=1)] = 1,
        page_size: Annotated[int, Query(ge=1, le=500)] = 50,
    ) -> DuplicateGroupList:
        return repository().list_duplicate_groups(
            scan_session_id, min_reclaimable_bytes, page, page_size
        )

    @app.get("/suggestions", response_model=SuggestionList, tags=["suggestions"])
    def list_suggestions(
        scan_session_id: str | None = None,
        category: SuggestionCategory | None = None,
        risk_level: RiskLevel | None = None,
        default_selected: bool | None = None,
        page: Annotated[int, Query(ge=1)] = 1,
        page_size: Annotated[int, Query(ge=1, le=500)] = 50,
    ) -> SuggestionList:
        return repository().list_suggestions(
            scan_id=scan_session_id, category=category, risk_level=risk_level,
            default_selected=default_selected, page=page, page_size=page_size,
        )

    @app.post("/operations/preview", response_model=OperationPlan, tags=["operations"])
    def create_preview(request: OperationPreviewRequest) -> OperationPlan:
        return app.state.operation_service.preview(request)

    @app.post("/operations/execute", response_model=OperationReceipt, tags=["operations"])
    def execute_operation(request: OperationExecuteRequest) -> OperationReceipt:
        return app.state.operation_service.execute(request)

    @app.get("/operations", response_model=OperationReceiptList, tags=["operations"])
    def list_operations(
        operation_status: Annotated[OperationStatus | None, Query(alias="status")] = None,
        page: Annotated[int, Query(ge=1)] = 1,
        page_size: Annotated[int, Query(ge=1, le=500)] = 50,
    ) -> OperationReceiptList:
        return repository().list_receipts(operation_status, page, page_size)

    @app.get("/operations/{operation_id}", response_model=OperationReceipt, tags=["operations"])
    def get_operation(operation_id: str) -> OperationReceipt:
        receipt = repository().get_receipt(operation_id)
        if receipt is None:
            raise DomainError("OPERATION_NOT_FOUND", "操作收据不存在", status_code=404)
        return receipt

    @app.post(
        "/operations/{operation_id}/undo", response_model=OperationReceipt, tags=["operations"]
    )
    def undo_operation(operation_id: str, request: OperationUndoRequest) -> OperationReceipt:
        return app.state.operation_service.undo(operation_id, request)

    @app.get("/quarantine", response_model=QuarantineItemList, tags=["quarantine"])
    def list_quarantine(
        operation_id: str | None = None,
        quarantine_status: Annotated[QuarantineStatus | None, Query(alias="status")] = None,
        page: Annotated[int, Query(ge=1)] = 1,
        page_size: Annotated[int, Query(ge=1, le=500)] = 50,
    ) -> QuarantineItemList:
        return repository().list_quarantine(operation_id, quarantine_status, page, page_size)

    @app.get("/providers", response_model=ProviderList, tags=["providers"])
    def list_providers() -> ProviderList:
        return ProviderList(items=[
            ProviderInfo(
                name="local-rules", kind="rules", enabled=True, is_stub=False,
                capabilities=["category", "source_hint", "risk", "suggestions"],
            ),
            ProviderInfo(
                name="mock", kind="mock", enabled=True, is_stub=True,
                capabilities=["frontend_integration"],
            ),
        ])

    @app.post("/providers/mock/analyze", response_model=MockAnalyzeResponse, tags=["providers"])
    def mock_analyze(request: MockAnalyzeRequest) -> MockAnalyzeResponse:
        scope = f"{len(request.asset_ids)} 个资产" if request.asset_ids else "当前本地统计"
        return MockAnalyzeResponse(
            summary=f"本地 mock 已接收{scope}；未读取文件内容，也未发起网络请求。",
            generated_at=utc_now(),
        )

    @app.post(
        "/v1/inventory/scans",
        response_model=InventoryScanResponse,
        status_code=status.HTTP_201_CREATED,
        operation_id="createInventoryScan",
        responses=INVENTORY_ERROR_RESPONSES,
        tags=["inventory"],
    )
    def create_inventory_scan(
        request: InventoryScanCreateRequest,
    ) -> InventoryScanResponse:
        return app.state.inventory_service.create_scan(request)

    @app.get(
        "/v1/inventory/scans/{scan_id}",
        response_model=InventoryScanResponse,
        operation_id="getInventoryScan",
        responses=INVENTORY_ERROR_RESPONSES,
        tags=["inventory"],
    )
    def get_inventory_scan(scan_id: str) -> InventoryScanResponse:
        return app.state.inventory_service.get_scan(scan_id)

    @app.post(
        "/v1/inventory/snapshots",
        response_model=ReportSnapshotV1,
        status_code=status.HTTP_201_CREATED,
        operation_id="createInventorySnapshot",
        responses=INVENTORY_ERROR_RESPONSES,
        tags=["inventory"],
    )
    def create_inventory_snapshot(
        request: InventorySnapshotCreateRequest,
    ) -> ReportSnapshotV1:
        return app.state.inventory_service.create_snapshot(request.scan_id)

    @app.get(
        "/v1/inventory/snapshots/{snapshot_id}",
        response_model=ReportSnapshotV1,
        operation_id="getInventorySnapshot",
        responses=INVENTORY_ERROR_RESPONSES,
        tags=["inventory"],
    )
    def get_inventory_snapshot(snapshot_id: str) -> ReportSnapshotV1:
        return app.state.inventory_service.get_snapshot(snapshot_id)

    @app.post(
        "/v1/inventory/analysis-packets/preview",
        response_model=InventoryPacketPreviewResponse,
        operation_id="previewInventoryAnalysisPacket",
        responses=INVENTORY_ERROR_RESPONSES,
        tags=["inventory"],
    )
    def preview_inventory_packet(
        request: InventoryPacketPreviewRequest,
    ) -> InventoryPacketPreviewResponse:
        return app.state.inventory_service.preview_packet(request)

    @app.post(
        "/v1/inventory/analyses",
        response_model=InventoryAnalysisResponse,
        status_code=status.HTTP_201_CREATED,
        operation_id="createInventoryAnalysis",
        responses=INVENTORY_ERROR_RESPONSES,
        tags=["inventory"],
    )
    def create_inventory_analysis(
        request: InventoryAnalysisCreateRequest,
    ) -> InventoryAnalysisResponse:
        return app.state.inventory_service.create_analysis(request)

    @app.get(
        "/v1/inventory/analyses/{analysis_id}",
        response_model=InventoryAnalysisResponse,
        operation_id="getInventoryAnalysis",
        responses=INVENTORY_ERROR_RESPONSES,
        tags=["inventory"],
    )
    def get_inventory_analysis(analysis_id: str) -> InventoryAnalysisResponse:
        return app.state.inventory_service.get_analysis(analysis_id)

    @app.post(
        "/v1/inventory/reports",
        response_model=InventoryReportResponse,
        status_code=status.HTTP_201_CREATED,
        operation_id="createInventoryReport",
        responses=INVENTORY_ERROR_RESPONSES,
        tags=["inventory"],
    )
    def create_inventory_report(
        request: InventoryReportCreateRequest,
    ) -> InventoryReportResponse:
        return app.state.inventory_service.create_report(request)

    @app.get(
        "/v1/inventory/reports/{report_id}",
        response_model=InventoryReportResponse,
        operation_id="getInventoryReport",
        responses=INVENTORY_ERROR_RESPONSES,
        tags=["inventory"],
    )
    def get_inventory_report(report_id: str) -> InventoryReportResponse:
        return app.state.inventory_service.get_report(report_id)

    @app.get(
        "/v1/inventory/reports/{report_id}/download",
        response_class=FileResponse,
        operation_id="downloadInventoryReport",
        responses=INVENTORY_DOWNLOAD_RESPONSES,
        tags=["inventory"],
    )
    def download_inventory_report(report_id: str) -> FileResponse:
        path, manifest = app.state.inventory_service.report_download(report_id)
        return FileResponse(
            path,
            media_type=XLSX_MEDIA_TYPE,
            filename=manifest.filename,
            headers={"Cache-Control": "no-store"},
        )

    return app


app = create_app()
