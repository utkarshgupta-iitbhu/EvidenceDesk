from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class FindingItem(BaseModel):
    title: str
    detail: str
    severity: str = "INFO"  # HIGH | MEDIUM | LOW | INFO
    caveat: str

class AttachmentItem(BaseModel):
    filename: str
    extension: str
    sizeKb: float
    sha256: str
    flagged: bool

class StandardErrorDetail(BaseModel):
    code: str
    message: str
    requestId: Optional[str] = None

class ErrorResponse(BaseModel):
    error: StandardErrorDetail

class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
