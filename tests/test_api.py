import unittest
import os
import sys
import io

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend'))
sys.path.insert(0, backend_dir)

from fastapi.testclient import TestClient
from main import app
from scan_store import scan_store

client = TestClient(app)

class TestEvidenceDeskAPI(unittest.TestCase):
    
    def setUp(self):
        self.evidence_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'evidence'))
        self.suspicious_email_path = os.path.join(self.evidence_dir, 'suspicious_email.eml')
        self.clean_image_path = os.path.join(self.evidence_dir, 'clean_evidence.jpg')
        self.session_token = "analyst_session_abc123"

    def test_health_endpoint(self):
        resp = client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "healthy")

    def test_email_scan_session_auth_and_deletion(self):
        # 1. Upload email with session token
        with open(self.suspicious_email_path, "rb") as f:
            resp = client.post(
                "/api/scan/email", 
                files={"file": ("suspicious_email.eml", f, "message/rfc822")},
                headers={"X-Session-Token": self.session_token}
            )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("scanId", data)
        scan_id = data["scanId"]

        # 2. Fetch server record with matching session token
        rec_resp = client.get(f"/api/scan/{scan_id}", headers={"X-Session-Token": self.session_token})
        self.assertEqual(rec_resp.status_code, 200)
        self.assertEqual(rec_resp.json()["module"], "email")

        # 3. Requesting with wrong session token must return 404 (Session ownership defense!)
        wrong_session_resp = client.get(f"/api/scan/{scan_id}", headers={"X-Session-Token": "unauthorized_attacker_token"})
        self.assertEqual(wrong_session_resp.status_code, 404)

        # 4. Download verified PDF report with matching token
        pdf_resp = client.get(f"/api/export/report/{scan_id}", headers={"X-Session-Token": self.session_token})
        self.assertEqual(pdf_resp.status_code, 200)
        self.assertEqual(pdf_resp.headers["content-type"], "application/pdf")
        self.assertTrue(pdf_resp.content.startswith(b"%PDF"))

        # 5. Download verified JSON manifest
        manifest_resp = client.get(f"/api/export/manifest/{scan_id}", headers={"X-Session-Token": self.session_token})
        self.assertEqual(manifest_resp.status_code, 200)
        self.assertEqual(manifest_resp.json()["scan_id"], scan_id)

        # 6. Explicitly delete evidence scan from memory
        del_resp = client.delete(f"/api/scan/{scan_id}", headers={"X-Session-Token": self.session_token})
        self.assertEqual(del_resp.status_code, 200)
        self.assertEqual(del_resp.json()["status"], "deleted")

        # Verify scan is now gone
        check_gone = client.get(f"/api/scan/{scan_id}", headers={"X-Session-Token": self.session_token})
        self.assertEqual(check_gone.status_code, 404)

    def test_image_scan_and_store_memory_safety(self):
        with open(self.clean_image_path, "rb") as f:
            resp = client.post(
                "/api/scan/image", 
                files={"file": ("clean.jpg", f, "image/jpeg")},
                headers={"X-Session-Token": self.session_token}
            )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        scan_id = data["scanId"]
        self.assertIn("heatmapBase64", data["ela"])

        # Check server-stored record: Base64 heatmap should be stripped to protect memory!
        stored_rec = scan_store.get_scan(scan_id, session_id=self.session_token)
        self.assertIsNotNone(stored_rec)
        self.assertIn("[Heatmap rendered in interactive session]", stored_rec["result"]["ela"]["heatmapBase64"])

    def test_corrupt_image_upload_returns_422(self):
        corrupt_data = b"\xff\xd8\xff\xe0" + b"GARBAGE_PAYLOAD" * 20
        resp = client.post("/api/scan/image", files={"file": ("bad.jpg", io.BytesIO(corrupt_data), "image/jpeg")})
        self.assertEqual(resp.status_code, 422)
        self.assertIn("corrupted or unreadable", resp.json()["detail"])

    def test_unsupported_document_format_returns_422(self):
        resp = client.post("/api/scan/text", files={"file": ("malware.exe", io.BytesIO(b"MZ..."), "application/octet-stream")})
        self.assertEqual(resp.status_code, 422)
        self.assertIn("Unsupported document format", resp.json()["detail"])

    def test_text_scan_flow(self):
        sample = "Furthermore, in summary it is crucial to delve into the intricate tapestry of modern technology."
        resp = client.post("/api/scan/text", data={"raw_text": sample}, headers={"X-Session-Token": self.session_token})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("scanId", data)
        self.assertIn("heuristicScore", data)

if __name__ == '__main__':
    unittest.main()
