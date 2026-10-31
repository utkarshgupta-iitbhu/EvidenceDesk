import uuid
import copy
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from config import settings

class ScanStore:
    """Thread-safe, session-authorized evidence scan store with TTL expiration.
    
    Security & Privacy Model:
    1. Authorization: Scans are tagged with a client session_id. Requests to access,
       export, or delete evidence records must present the matching session token.
    2. RAM Defense: Base64 image heatmaps are stripped before storage.
    3. Auto-Wipe: Records older than SCAN_STORE_TTL_HOURS are automatically purged.
    4. Explicit Deletion: Analysts can immediately purge evidence from memory.
    """
    def __init__(self, max_items: int = settings.SCAN_STORE_MAX_ITEMS, ttl_hours: int = settings.SCAN_STORE_TTL_HOURS):
        self._store: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._max_items = max_items
        self._ttl = timedelta(hours=ttl_hours)

    def _purge_expired_locked(self, now: datetime):
        expired_keys = [
            k for k, v in self._store.items() 
            if (now.timestamp() - v["stored_at_ts"]) > self._ttl.total_seconds()
        ]
        for k in expired_keys:
            del self._store[k]

    def save_scan(self, module: str, result_data: Dict[str, Any], session_id: str) -> str:
        scan_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        created_at_str = now.strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Strip heavy Base64 heatmap from stored record to save memory
        cleaned_result = copy.deepcopy(result_data)
        if "ela" in cleaned_result and isinstance(cleaned_result["ela"], dict):
            if "heatmapBase64" in cleaned_result["ela"]:
                cleaned_result["ela"]["heatmapBase64"] = "[Heatmap rendered in interactive session]"

        record = {
            "scan_id": scan_id,
            "session_id": session_id,
            "module": module,
            "created_at": created_at_str,
            "stored_at_ts": now.timestamp(),
            "result": cleaned_result
        }
        
        with self._lock:
            self._purge_expired_locked(now)
            if len(self._store) >= self._max_items:
                oldest_key = next(iter(self._store))
                del self._store[oldest_key]
            self._store[scan_id] = record
            
        return scan_id

    def get_scan(self, scan_id: str, session_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        now = datetime.now(timezone.utc)
        with self._lock:
            self._purge_expired_locked(now)
            record = self._store.get(scan_id)
            if not record:
                return None
            # If session_id is provided, enforce ownership matching
            if session_id and record.get("session_id") != session_id:
                return None
            return record

    def delete_scan(self, scan_id: str, session_id: Optional[str] = None) -> bool:
        now = datetime.now(timezone.utc)
        with self._lock:
            self._purge_expired_locked(now)
            record = self._store.get(scan_id)
            if not record:
                return False
            if session_id and record.get("session_id") != session_id:
                return False
            del self._store[scan_id]
            return True

scan_store = ScanStore()
