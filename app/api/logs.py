import logging
from typing import Optional

from fastapi import APIRouter, File, HTTPException, Query, UploadFile, status

from app.schemas.log_analysis import LogAnalysisRequest, LogAnalysisResponse
from app.services.agent_service import analyze_logs

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Log Analysis"])


@router.post(
    "/analyze",
    response_model=LogAnalysisResponse,
    summary="Analyze log entries with AI agent",
    description=(
        "Analyzes application logs to detect incidents, determine probable root causes, "
        "and suggest immediate mitigations. Can analyze logs from a file path or direct raw content."
    ),
)
async def analyze_logs_endpoint(
    request: Optional[LogAnalysisRequest] = None,
) -> LogAnalysisResponse:
    try:
        log_path = request.log_path if request else None
        log_content = request.log_content if request else None
        trigger_email = request.trigger_email if request else True

        result = await analyze_logs(
            log_path=log_path,
            log_content=log_content,
            trigger_email=trigger_email,
        )

        if result.get("status") == "error":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get("message", "Log analysis failed"),
            )

        return LogAnalysisResponse(**result)

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Error executing analyze_logs: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal error during log analysis: {exc}",
        )


@router.get(
    "/analyze",
    response_model=LogAnalysisResponse,
    summary="Quickly analyze default log file",
    description="Convenience GET endpoint to trigger analysis on the default server log file (app/Temp/app.log).",
)
async def analyze_default_logs_endpoint(
    trigger_email: bool = Query(
        default=True,
        description="Whether to send an alert if critical severity is detected.",
    ),
) -> LogAnalysisResponse:
    try:
        result = await analyze_logs(trigger_email=trigger_email)
        if result.get("status") == "error":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get("message", "Log analysis failed"),
            )
        return LogAnalysisResponse(**result)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Error executing analyze_logs: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal error during log analysis: {exc}",
        )


@router.post(
    "/upload-and-analyze",
    response_model=LogAnalysisResponse,
    summary="Upload a log file and analyze it",
    description="Upload a .log or text file to be parsed, masked, and analyzed by the AI agent.",
)
async def upload_and_analyze_logs_endpoint(
    file: UploadFile = File(..., description="Log file to upload and inspect"),
    trigger_email: bool = Query(
        default=True,
        description="Whether to send an alert if critical severity is detected.",
    ),
) -> LogAnalysisResponse:
    try:
        content_bytes = await file.read()
        log_content = content_bytes.decode("utf-8", errors="replace")

        result = await analyze_logs(
            log_content=log_content,
            trigger_email=trigger_email,
        )

        if result.get("status") == "error":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get("message", "Log analysis failed"),
            )

        return LogAnalysisResponse(**result)

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Error during uploaded log analysis: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal error analyzing uploaded log: {exc}",
        )
