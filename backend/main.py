import os
import uuid
import logging
import asyncio
from typing import Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request, Header, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, JSONResponse

from config import settings
from scan_store import scan_store
from email_analyzer import EmailThreatAnalyzer
from image_analyzer import ImageForensicAnalyzer
from text_analyzer import TextLinguisticAnalyzer
from report_generator import ForensicPDFReporter
from models import HealthResponse, ErrorResponse, StandardErrorDetail

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("EvidenceDesk")

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Digital Evidence Triage — Preliminary Forensics & Indicator Analysis Engine",
    version=settings.VERSION
)

# Global Concurrency Limiter (prevents CPU/RAM exhaustion on free cloud instances)
concurrency_limiter = asyncio.Semaphore(settings.MAX_CONCURRENT_SCANS)

# CORS: Strict explicit origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers_and_request_id(request: Request, call_next):
    req_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    response = await call_next(request)
    response.headers["X-Request-ID"] = req_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response

async def read_bounded_upload(file: UploadFile, max_bytes: int = settings.MAX_FILE_BYTES) -> bytes:
    """Reads uploaded stream in bounded chunks. Rejects uploads exceeding max_bytes before consuming memory."""
    buffer = bytearray()
    while True:
        chunk = await file.read(settings.CHUNK_SIZE)
        if not chunk:
            break
        buffer.extend(chunk)
        if len(buffer) > max_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Upload exceeded maximum allowable triage threshold of {max_bytes // (1024*1024)}MB."
            )
    return bytes(buffer)

def get_session_id(x_session_token: Optional[str] = Header(None)) -> str:
    """Extracts or assigns an analyst session identifier for scan authorization."""
    return x_session_token or "anonymous_session"

@app.get("/", tags=["System"])
def home():
    return {
        "system": "EvidenceDesk",
        "subtitle": "Digital Evidence Triage",
        "status": "online",
        "version": settings.VERSION,
        "notice": "Automated preliminary triage engine. Indicators require independent forensic verification.",
        "docs": "/docs"
    }

@app.get("/api/health", response_model=HealthResponse, tags=["System"])
def health_check():
    return HealthResponse(
        status="healthy", 
        service=settings.PROJECT_NAME, 
        version=settings.VERSION
    )

@app.post("/api/scan/email", tags=["Triage"])
async def scan_email(
    request: Request,
    file: UploadFile = File(...),
    x_session_token: Optional[str] = Header(None)
):
    """Upload an .eml email message for preliminary header, authentication, and phishing triage."""
    req_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    session_id = get_session_id(x_session_token)

    if not file or not file.filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No email file provided.")

    ext = os.path.splitext(file.filename)[1].lower()
    if ext != ".eml":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, 
            detail=f"Invalid format '{ext}'. Email triage requires standard RFC 5322 (.eml) files."
        )

    contents = await read_bounded_upload(file)
    if len(contents) == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty (0 bytes).")

    async with concurrency_limiter:
        try:
            analyzer = EmailThreatAnalyzer(raw_bytes=contents, file_name=file.filename)
            result = analyzer.analyze()
            
            # Save to server-authoritative scan store tagged with session_id
            scan_id = scan_store.save_scan("email", result, session_id=session_id)
            result["scanId"] = scan_id
            return result
        except ValueError as val_err:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(val_err))
        except Exception as exc:
            logger.error(f"[{req_id}] Unexpected error during email scan: {str(exc)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                detail="The email message could not be parsed due to an internal analyzer error."
            )

@app.post("/api/scan/image", tags=["Triage"])
async def scan_image(
    request: Request,
    file: UploadFile = File(...),
    x_session_token: Optional[str] = Header(None)
):
    """Upload a JPEG, PNG, or WEBP image to inspect EXIF metadata, ELA recompression differences, and trailing payloads."""
    req_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    session_id = get_session_id(x_session_token)

    if not file or not file.filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No image file provided.")

    contents = await read_bounded_upload(file)
    if len(contents) == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty (0 bytes).")

    async with concurrency_limiter:
        try:
            analyzer = ImageForensicAnalyzer(raw_bytes=contents, file_name=file.filename)
            result = analyzer.analyze()
            
            scan_id = scan_store.save_scan("image", result, session_id=session_id)
            result["scanId"] = scan_id
            return result
        except ValueError as val_err:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(val_err))
        except Exception as exc:
            logger.error(f"[{req_id}] Unexpected error during image scan: {str(exc)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                detail="The image asset could not be processed due to an internal analyzer error."
            )

@app.post("/api/scan/text", tags=["Triage"])
async def scan_text(
    request: Request,
    file: Optional[UploadFile] = File(None),
    raw_text: Optional[str] = Form(None),
    x_session_token: Optional[str] = Header(None)
):
    """Scan raw text or upload a .txt/.docx/.pdf document for stylistic indicators and sentence burstiness."""
    req_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    session_id = get_session_id(x_session_token)
    text_content = ""
    source_name = "Direct Input"
    file_bytes = None

    if file and file.filename:
        source_name = file.filename
        ext = os.path.splitext(file.filename)[1].lower()
        if ext not in settings.SUPPORTED_DOCUMENT_EXTENSIONS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Unsupported document format '{ext}'. Document triage only accepts: {', '.join(sorted(settings.SUPPORTED_DOCUMENT_EXTENSIONS))}."
            )

        file_bytes = await read_bounded_upload(file)
        try:
            text_content = TextLinguisticAnalyzer.extract_from_file(file_bytes, file.filename)
        except ValueError as ex_err:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(ex_err))
    elif raw_text and raw_text.strip():
        text_content = raw_text.strip()
        if len(text_content) > settings.MAX_TEXT_CHARS:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, 
                detail=f"Pasted text exceeds maximum triage threshold of {settings.MAX_TEXT_CHARS:,} characters."
            )
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No document or text content was provided for analysis.")

    async with concurrency_limiter:
        try:
            analyzer = TextLinguisticAnalyzer(text=text_content, source_name=source_name, file_bytes=file_bytes)
            result = analyzer.analyze()
            
            scan_id = scan_store.save_scan("text", result, session_id=session_id)
            result["scanId"] = scan_id
            return result
        except Exception as exc:
            logger.error(f"[{req_id}] Unexpected error during text scan: {str(exc)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                detail="The document content could not be analyzed due to an internal processing error."
            )

@app.get("/api/scan/{scan_id}", tags=["Triage"])
def get_scan_record(scan_id: str, x_session_token: Optional[str] = Header(None)):
    """Retrieve an authenticated server-side analysis record by scan ID (session-authorized)."""
    session_id = get_session_id(x_session_token)
    record = scan_store.get_scan(scan_id, session_id=session_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan record not found or expired.")
    return record

@app.delete("/api/scan/{scan_id}", tags=["Triage"])
def delete_scan_record(scan_id: str, x_session_token: Optional[str] = Header(None)):
    """Explicitly purges an evidence scan record from server memory."""
    session_id = get_session_id(x_session_token)
    success = scan_store.delete_scan(scan_id, session_id=session_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan record not found or expired.")
    return {"status": "deleted", "scanId": scan_id}

@app.get("/api/export/report/{scan_id}", tags=["Reports"])
def export_verified_report(scan_id: str, x_session_token: Optional[str] = Header(None)):
    """Generates an unforgeable PDF triage report strictly from an existing server-side scan record."""
    session_id = get_session_id(x_session_token)
    record = scan_store.get_scan(scan_id, session_id=session_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cannot generate report: Scan record not found or expired.")

    try:
        pdf_bytes = ForensicPDFReporter.generate(record)
        module_name = record.get("module", "triage").capitalize()
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=EvidenceDesk_{module_name}_Report_{scan_id[:8]}.pdf"}
        )
    except Exception as pdf_err:
        logger.error(f"PDF report generation failed for scan {scan_id}: {str(pdf_err)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="PDF report generation failed.")

@app.get("/api/export/manifest/{scan_id}", tags=["Reports"])
def export_verified_manifest(scan_id: str, x_session_token: Optional[str] = Header(None)):
    """Exports an authenticated JSON evidence manifest strictly from the server-side scan record."""
    session_id = get_session_id(x_session_token)
    record = scan_store.get_scan(scan_id, session_id=session_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cannot export manifest: Scan record not found or expired.")

    import json
    manifest_bytes = json.dumps(record, indent=2, default=str).encode("utf-8")
    return Response(
        content=manifest_bytes,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=EvidenceDesk_Manifest_{scan_id[:8]}.json"}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
