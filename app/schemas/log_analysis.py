from typing import Any, Optional
from pydantic import BaseModel, Field


class LogAnalysisRequest(BaseModel):
    """Request payload for analyzing logs."""
    log_path: Optional[str] = Field(
        default=None,
        description="Optional file path to the log file to analyze. Defaults to app/Temp/app.log if not provided.",
        examples=["app/Temp/app.log"],
    )
    log_content: Optional[str] = Field(
        default=None,
        description="Optional raw text content of log entries to analyze directly. Takes precedence over log_path.",
    )
    trigger_email: bool = Field(
        default=True,
        description="Whether to automatically send an alert email if an incident is evaluated as critical.",
    )


class IncidentAnalysisData(BaseModel):
    """Structured incident investigation result produced by the agent."""
    incident_id: Optional[str] = Field(default=None, description="Identifier for the incident.")
    service_name: Optional[str] = Field(default=None, description="Affected service component.")
    severity: Optional[str] = Field(default=None, description="Severity: CRITICAL, HIGH, MEDIUM, or LOW.")
    incident_summary: Optional[str] = Field(default=None, description="Concise summary of the incident.")
    root_cause: Optional[str] = Field(default=None, description="Determined or probable root cause.")
    cause_status: Optional[str] = Field(default=None, description="CONFIRMED, PROBABLE, or UNKNOWN.")
    evidence: list[Any] = Field(default_factory=list, description="Evidence lines and logs supporting root cause.")
    historical_matches: list[Any] = Field(default_factory=list, description="Similar past incidents.")
    recommended_fixes: list[str] = Field(default_factory=list, description="Immediate mitigations and permanent fixes.")
    verification_steps: list[str] = Field(default_factory=list, description="Steps to verify resolution.")
    confidence_score: Optional[float] = Field(default=None, description="Confidence score between 0.0 and 1.0.")
    notification_required: Optional[bool] = Field(default=False, description="True if alert notification is required.")


class LogAnalysisResponse(BaseModel):
    """Response returned by the log analysis endpoint."""
    status: str = Field(description="Execution status: 'success', 'partial_success', or 'error'.")
    message: Optional[str] = Field(default=None, description="Informational message or error description.")
    incident_count: Optional[int] = Field(default=0, description="Total incident groups identified in logs.")
    analysis: Optional[IncidentAnalysisData | dict[str, Any]] = Field(
        default=None,
        description="Detailed agent analysis output.",
    )
    notification: Optional[dict[str, Any]] = Field(
        default=None,
        description="Status of any dispatched notifications (e.g. email alert).",
    )
    raw_output: Optional[str] = Field(
        default=None,
        description="Raw agent response if structured parsing failed.",
    )
