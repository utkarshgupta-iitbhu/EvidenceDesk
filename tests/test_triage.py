import unittest
import os
import sys

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend'))
sys.path.insert(0, backend_dir)

from email_analyzer import EmailThreatAnalyzer
from image_analyzer import ImageForensicAnalyzer
from text_analyzer import TextLinguisticAnalyzer
from report_generator import ForensicPDFReporter

class TestEvidenceDeskAnalyzers(unittest.TestCase):
    
    def setUp(self):
        self.evidence_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'evidence'))
        self.suspicious_email_path = os.path.join(self.evidence_dir, 'suspicious_email.eml')
        self.clean_image_path = os.path.join(self.evidence_dir, 'clean_evidence.jpg')
        self.tampered_image_path = os.path.join(self.evidence_dir, 'tampered_evidence.jpg')

    def test_email_triage_suspicious_and_attachment_inventory(self):
        with open(self.suspicious_email_path, 'rb') as f:
            data = f.read()
        analyzer = EmailThreatAnalyzer(data, 'suspicious_email.eml')
        result = analyzer.analyze()

        self.assertIn('sha256', result)
        self.assertIn('md5', result)
        self.assertGreaterEqual(result['triageScore'], 60)
        self.assertIn('Elevated', result['status'])
        
        # Verify attachment inventory has individual sha256 hashes
        self.assertTrue(len(result['attachments']) > 0)
        for att in result['attachments']:
            self.assertIn('sha256', att)
            self.assertEqual(len(att['sha256']), 64)

    def test_html_only_email_extracts_href_and_detects_link_divergence(self):
        # Anchor-only link where visible text says legitimate bank but href goes to malicious IP
        raw_html_email = (
            b"From: security@trusted.example\r\n"
            b"Reply-To: attacker@diverted.example\r\n"
            b"To: victim@example.org\r\n"
            b"Subject: Security Alert\r\n"
            b"Content-Type: text/html\r\n\r\n"
            b"<html><body><p>Please update details at <a href=\"http://192.168.1.200/verify\">https://mybank.com</a> immediately.</p></body></html>"
        )
        res = EmailThreatAnalyzer(raw_html_email, 'html_test.eml').analyze()
        self.assertTrue(res['bodyIsHtmlReconstructed'])
        # Reply-To divergence should be flagged
        self.assertTrue(any("Reply-To" in f['title'] for f in res['findings']))
        # Anchor text link divergence (mybank.com -> 192.168.1.200) must be flagged!
        self.assertTrue(any("Link Divergence" in f['title'] for f in res['findings']))
        self.assertIn('192.168.1.200', str(res['flaggedLinks']))

    def test_image_clean_vs_tampered_ela_variance(self):
        with open(self.clean_image_path, 'rb') as f:
            clean_bytes = f.read()
        clean_res = ImageForensicAnalyzer(clean_bytes, 'clean_evidence.jpg').analyze()
        self.assertEqual(clean_res['format'], 'JPEG')

        with open(self.tampered_image_path, 'rb') as f:
            tampered_bytes = f.read()
        tampered_res = ImageForensicAnalyzer(tampered_bytes, 'tampered_evidence.jpg').analyze()
        self.assertGreater(tampered_res['triageScore'], clean_res['triageScore'])

    def test_corrupt_image_fails_with_explicit_error(self):
        # Corrupt header/payload must fail rather than returning baseline score
        corrupt_bytes = b"\xff\xd8\xff\xe0" + b"CORRUPTED_NON_IMAGE_DATA_PADDING" * 15
        with self.assertRaises(ValueError):
            ImageForensicAnalyzer(corrupt_bytes, 'corrupt.jpg').analyze()

    def test_text_dual_hashes_and_phrase_matching(self):
        sample = (
            "Furthermore, in summary it is crucial to delve into the intricate tapestry of modern technology. "
            "Moreover, the system meticulously showcases the essential benefits of digital transformation. "
            "Consequently, this underpins the pivotal framework that is continuously developed."
        )
        fake_file_bytes = b"RAW_ORIGINAL_DOCUMENT_FILE_BYTES"
        res = TextLinguisticAnalyzer(sample, source_name="doc.pdf", file_bytes=fake_file_bytes).analyze()
        
        # Original file SHA-256 must NOT equal extracted text SHA-256
        self.assertNotEqual(res['fileSha256'], res['textSha256'])
        self.assertEqual(len(res['fileSha256']), 64)
        self.assertEqual(len(res['textSha256']), 64)
        # Verify multi-word phrase 'in summary' matched
        self.assertTrue(any('in summary' in w for w in res['flaggedBuzzwords']))

    def test_unsupported_document_extension_rejected(self):
        with self.assertRaises(ValueError):
            TextLinguisticAnalyzer.extract_from_file(b"EXECUTABLE_BYTES", "payload.exe")

    def test_pdf_report_with_xml_entities_and_module_tables(self):
        with open(self.suspicious_email_path, 'rb') as f:
            data = f.read()
        eml_res = EmailThreatAnalyzer(data, 'suspicious_email.eml').analyze()
        eml_res['fileName'] = "Evidence <Test> & 'Special'.eml"
        eml_res['findings'].append({
            "title": "<Script> & Injection Test", 
            "detail": "Data with <unclosed tag & unescaped entity>", 
            "severity": "HIGH", 
            "caveat": "Special <chars>"
        })
        
        scan_record = {
            "scan_id": "test-scan-uuid-1234",
            "module": "email",
            "created_at": "2026-10-31 12:00:00 UTC",
            "result": eml_res
        }
        
        pdf_bytes = ForensicPDFReporter.generate(scan_record)
        self.assertTrue(pdf_bytes.startswith(b'%PDF'))
        self.assertGreater(len(pdf_bytes), 1000)

if __name__ == '__main__':
    unittest.main()
