import os
from typing import List, Set

class Settings:
    PROJECT_NAME: str = "EvidenceDesk API"
    PROJECT_SUBTITLE: str = "Digital Evidence Triage"
    VERSION: str = "1.2.0"
    
    # Upload limits
    MAX_FILE_BYTES: int = int(os.getenv("EVIDENCE_DESK_MAX_BYTES", 25 * 1024 * 1024))  # 25 MB
    CHUNK_SIZE: int = 1024 * 1024  # 1 MB chunk reading
    
    # Processing & Expansion bounds (Defense against resource exhaustion)
    MAX_PIXELS: int = int(os.getenv("EVIDENCE_DESK_MAX_PIXELS", 40_000_000))  # 40 Megapixels
    MAX_PDF_PAGES: int = int(os.getenv("EVIDENCE_DESK_MAX_PDF_PAGES", 50))
    MAX_TEXT_CHARS: int = int(os.getenv("EVIDENCE_DESK_MAX_TEXT_CHARS", 500_000))
    MAX_ATTACHMENTS: int = int(os.getenv("EVIDENCE_DESK_MAX_ATTACHMENTS", 30))
    MAX_CONCURRENT_SCANS: int = int(os.getenv("EVIDENCE_DESK_CONCURRENCY", 5))
    
    # Scan store memory controls (TTL auto-wipe & FIFO eviction)
    SCAN_STORE_MAX_ITEMS: int = int(os.getenv("EVIDENCE_DESK_SCAN_STORE_MAX_ITEMS", 200))
    SCAN_STORE_TTL_HOURS: int = int(os.getenv("EVIDENCE_DESK_SCAN_STORE_TTL_HOURS", 2))
    
    # Supported format allowlists (validated strictly on backend)
    SUPPORTED_DOCUMENT_EXTENSIONS: Set[str] = {".pdf", ".docx", ".txt"}
    SUPPORTED_IMAGE_FORMATS: Set[str] = {"JPEG", "PNG", "WEBP", "GIF"}
    
    # CORS Origins: Default to local Vite servers, configurable for production
    ALLOWED_ORIGINS: List[str] = [
        origin.strip() for origin in os.getenv(
            "EVIDENCE_DESK_ALLOWED_ORIGINS", 
            "https://evidence-desk-ten.vercel.app,http://localhost:5173,http://127.0.0.1:5173"
        ).split(",") if origin.strip()
    ]

settings = Settings()
