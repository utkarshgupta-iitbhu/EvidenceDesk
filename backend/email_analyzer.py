import re
import hashlib
import ipaddress
import html
from email import policy
from email.parser import BytesParser
from urllib.parse import urlsplit
from typing import Dict, Any, List, Set, Tuple

from config import settings
from text_analyzer import TextLinguisticAnalyzer

class EmailThreatAnalyzer:
    """Defensible preliminary triage analyzer for raw RFC 5322 (.eml) email messages.
    
    LIMITATION NOTICE: This analyzer performs static, read-only pattern checks on
    the provided message headers and body. It does NOT perform live DNS lookups,
    cryptographic DKIM validation, or SPF verification. Headers can be spoofed
    if the message was not received directly by a trusted mail transfer agent (MTA).
    """

    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".ps1", 
        ".iso", ".hta", ".zip", ".rar", ".7z", ".docm", ".xlsm"
    }

    URGENT_KEYWORDS = [
        "urgent", "immediately", "account suspended", "verify your account",
        "action required", "password reset", "unauthorized login", "wire transfer",
        "billing dispute", "invoice overdue"
    ]

    SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "ow.ly", "buff.ly"}

    def __init__(self, raw_bytes: bytes, file_name: str = "email.eml"):
        if not raw_bytes:
            raise ValueError("Email payload is empty (0 bytes).")
        if len(raw_bytes) > settings.MAX_FILE_BYTES:
            raise ValueError(f"File size exceeds maximum triage limit of {settings.MAX_FILE_BYTES // (1024 * 1024)}MB.")

        self.raw_bytes = raw_bytes
        self.file_name = file_name
        self.findings: List[Dict[str, str]] = []
        self.triage_score = 0

        try:
            self.msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        except Exception as e:
            raise ValueError(f"Malformed RFC 5322 email structure: {str(e)}")

    def _clean_url(self, url: str) -> str:
        """Strip trailing punctuation from URLs."""
        return re.sub(r'[.,;:!?)\]>]+$', '', url.strip())

    def _extract_html_links_and_text(self, html_content: str):
        all_urls = set()
        divergent_links = []

        anchor_pattern = re.compile(r'<a\s+[^>]*href=[\'\"](https?://[^\'\"]+)[\'\"][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
        for href_url, anchor_raw in anchor_pattern.findall(html_content):
            clean_href = self._clean_url(html.unescape(href_url))
            all_urls.add(clean_href)
            
            anchor_text = re.sub(r'<[^>]+>', '', anchor_raw).strip()
            anchor_text_clean = html.unescape(anchor_text)
            
            if re.search(r'^(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}', anchor_text_clean):
                try:
                    href_domain = urlsplit(clean_href).netloc.lower()
                    anchor_domain = urlsplit(
                        anchor_text_clean if anchor_text_clean.startswith(('http://', 'https://')) else f"https://{anchor_text_clean}"
                    ).netloc.lower()
                    
                    if anchor_domain and href_domain and anchor_domain != href_domain:
                        divergent_links.append({
                            "visibleText": anchor_text_clean[:60],
                            "actualDestination": clean_href[:100],
                            "hrefDomain": href_domain,
                            "displayedDomain": anchor_domain
                        })
                except Exception:
                    pass

        src_pattern = re.compile(r'src=[\'\"](https?://[^\'\"]+)[\'\"]', re.IGNORECASE)
        for src_url in src_pattern.findall(html_content):
            all_urls.add(self._clean_url(html.unescape(src_url)))

        clean = re.sub(r'<style.*?</style>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        clean = re.sub(r'<script.*?</script>', '', clean, flags=re.DOTALL | re.IGNORECASE)
        clean = re.sub(r'<[^>]+>', ' ', clean)
        clean = html.unescape(clean)
        clean_text = re.sub(r'\s+', ' ', clean).strip()

        return all_urls, divergent_links, clean_text

    def analyze(self) -> Dict[str, Any]:
        sha256_hash = hashlib.sha256(self.raw_bytes).hexdigest()
        md5_hash = hashlib.md5(self.raw_bytes).hexdigest()

        subject = str(self.msg.get("Subject", "(No Subject)"))
        from_hdr = str(self.msg.get("From", "(Unknown Sender)"))
        to_hdr = str(self.msg.get("To", "(Unknown Recipient)"))
        date_hdr = str(self.msg.get("Date", "(No Date Header)"))
        return_path = str(self.msg.get("Return-Path", "")).strip()
        reply_to = str(self.msg.get("Reply-To", "")).strip()

        # 1. Check Return-Path Sender Discrepancy
        if return_path and from_hdr:
            clean_rp = return_path.strip("<>").lower()
            if clean_rp and clean_rp not in from_hdr.lower():
                self.findings.append({
                    "title": "Return-Path / From Header Discrepancy",
                    "detail": f"Return-Path '{return_path}' differs from sender '{from_hdr}'.",
                    "severity": "MEDIUM",
                    "caveat": "Legitimate mailing lists and transactional services sometimes route through different return paths."
                })
                self.triage_score += 20

        # 2. Check Reply-To Divergence
        if reply_to and from_hdr:
            clean_rt = reply_to.strip("<>").lower()
            if clean_rt and clean_rt not in from_hdr.lower():
                self.findings.append({
                    "title": "Reply-To Divergence Detected",
                    "detail": f"Replies will be routed to '{reply_to}' instead of the visible sender '{from_hdr}'.",
                    "severity": "HIGH",
                    "caveat": "Divergent Reply-To addresses are a standard technique in spear-phishing and BEC attacks."
                })
                self.triage_score += 25

        # 3. Parse Reported Authentication-Results
        auth_results = str(self.msg.get("Authentication-Results", "")).lower()
        received_spf = str(self.msg.get("Received-SPF", "")).lower()

        spf_failed = bool(re.search(r'\bspf=(?:fail|softfail|permerror|temperror)\b', auth_results)) or ("fail" in received_spf)
        dkim_failed = bool(re.search(r'\bdkim=(?:fail|permerror|temperror)\b', auth_results))
        dmarc_failed = bool(re.search(r'\bdmarc=(?:fail|reject)\b', auth_results))

        if spf_failed or dkim_failed or dmarc_failed:
            details = []
            if spf_failed: details.append("SPF reported fail/softfail")
            if dkim_failed: details.append("DKIM reported fail")
            if dmarc_failed: details.append("DMARC reported fail")
            self.findings.append({
                "title": "Reported Authentication Failures in Header",
                "detail": f"Headers record authentication failures: {', '.join(details)}.",
                "severity": "HIGH",
                "caveat": "Note: Parsed from message text. This tool does not perform live cryptographic DNS or key checks."
            })
            self.triage_score += 35
        elif not auth_results and not received_spf:
            self.findings.append({
                "title": "No Authentication-Results Header Found",
                "detail": "Message lacks internal MTA authentication assessment.",
                "severity": "INFO",
                "caveat": "Common in offline exports, drafts, or internal relay paths."
            })

        # 4. Relay Server Hops
        received_hdrs = self.msg.get_all("Received", [])
        relay_hops = []
        for hop in received_hdrs[:50]:  # Bound relay hop inspection
            hop_str = str(hop).strip()
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', hop_str)
            public_ips = []
            for ip in ips:
                try:
                    if not ipaddress.ip_address(ip).is_private:
                        public_ips.append(ip)
                except ValueError:
                    pass
            relay_hops.append({
                "raw": hop_str[:200] + ("..." if len(hop_str) > 200 else ""),
                "public_ips": public_ips
            })

        # 5. Extract Body & All URLs (Plain-text + HTML attributes)
        body_text = ""
        is_html_source = False
        all_extracted_urls = set()
        divergent_anchors = []

        if self.msg.is_multipart():
            for part in self.msg.walk():
                ctype = part.get_content_type()
                if ctype == "text/plain" and not body_text:
                    try:
                        content = part.get_content()
                        if isinstance(content, str):
                            body_text = content
                    except Exception:
                        pass
                elif ctype == "text/html":
                    try:
                        raw_html = part.get_content()
                        if isinstance(raw_html, str):
                            html_urls, div_links, html_txt = self._extract_html_links_and_text(raw_html)
                            all_extracted_urls.update(html_urls)
                            divergent_anchors.extend(div_links)
                            if not body_text:
                                body_text = html_txt
                                is_html_source = True
                    except Exception:
                        pass
        else:
            try:
                content = self.msg.get_content()
                if isinstance(content, str):
                    if self.msg.get_content_type() == "text/html":
                        html_urls, div_links, html_txt = self._extract_html_links_and_text(content)
                        all_extracted_urls.update(html_urls)
                        divergent_anchors.extend(div_links)
                        body_text = html_txt
                        is_html_source = True
                    else:
                        body_text = content
            except Exception:
                pass

        # Raw plaintext URLs
        raw_text_urls = re.findall(r'https?://[^\s<>"\']+', body_text)
        for u in raw_text_urls:
            all_extracted_urls.add(self._clean_url(u))

        # Flag Divergent Anchor Links (Text says Domain A, link goes to Domain B)
        if divergent_anchors:
            for da in divergent_anchors:
                self.findings.append({
                    "title": "Phishing Link Divergence Detected",
                    "detail": f"Visible link text displays '{da['displayedDomain']}', but actual destination points to '{da['hrefDomain']}'.",
                    "severity": "HIGH",
                    "caveat": "Classic spear-phishing technique designed to deceive users regarding link destinations."
                })
                self.triage_score += 35

        # 6. AI Spear-Phishing Linguistic Check on Body
        ai_body_analysis = None
        if body_text and len(body_text.split()) >= 15:
            text_engine = TextLinguisticAnalyzer(text=body_text, source_name="Email Body Text")
            ai_body_analysis = text_engine.analyze()
            
            if ai_body_analysis.get("heuristicScore", 0) >= 60:
                self.findings.append({
                    "title": "Elevated Synthetic Writing Markers in Body",
                    "detail": f"Body text scored {ai_body_analysis['heuristicScore']}/100 on stylistic uniformity markers.",
                    "severity": "LOW",
                    "caveat": "Experimental heuristic. Does not prove automated or AI origin; professional templates often exhibit high uniformity."
                })
                self.triage_score += 15

        # 7. Urgency Keywords
        found_urgency = [w for w in self.URGENT_KEYWORDS if w in body_text.lower()]
        if found_urgency:
            self.findings.append({
                "title": "Urgency & Coercion Triggers",
                "detail": f"Detected urgency patterns: {', '.join(found_urgency[:3])}.",
                "severity": "MEDIUM",
                "caveat": "Urgency language is used in phishing lures, but also appears in standard billing notices."
            })
            self.triage_score += 15

        # 8. Analyze Flagged URLs
        flagged_urls = []
        for url in sorted(all_extracted_urls):
            try:
                domain = urlsplit(url).netloc.lower()
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                    flagged_urls.append({"url": url, "reason": "Uses raw numeric IP address instead of domain hostname"})
                    self.triage_score += 25
                elif domain in self.SHORTENER_DOMAINS:
                    flagged_urls.append({"url": url, "reason": "Uses URL shortener (obfuscates destination)"})
                    self.triage_score += 15
            except Exception:
                pass

        if flagged_urls:
            self.findings.append({
                "title": "Suspicious URL Structure Detected",
                "detail": f"Flagged {len(flagged_urls)} link(s) using numeric IPs or shortening services.",
                "severity": "HIGH",
                "caveat": "Legitimate services rarely require numeric IP links in consumer correspondence."
            })

        # 9. Attachment Inventory with Individual SHA-256 Hashes
        attachment_inventory = []
        dangerous_attachments = []
        raw_attachments = list(self.msg.iter_attachments())[:settings.MAX_ATTACHMENTS]
        
        for part in raw_attachments:
            fname = part.get_filename() or "unnamed_attachment"
            ext = "." + fname.split(".")[-1].lower() if "." in fname else ""
            is_risky = ext in self.SUSPICIOUS_EXTENSIONS
            
            att_payload = part.get_payload(decode=True) or b""
            att_hash = hashlib.sha256(att_payload).hexdigest()
            att_size_kb = round(len(att_payload) / 1024, 2)

            if is_risky:
                dangerous_attachments.append(fname)

            attachment_inventory.append({
                "filename": fname,
                "extension": ext or "(none)",
                "sizeKb": att_size_kb,
                "sha256": att_hash,
                "flagged": is_risky
            })

        if dangerous_attachments:
            self.findings.append({
                "title": "Executable / Risky Attachment Extension",
                "detail": f"Detected high-risk extension(s): {', '.join(dangerous_attachments)}.",
                "severity": "HIGH",
                "caveat": "Scripts, archives, and macro-enabled documents should be inspected in an isolated sandbox."
            })
            self.triage_score += 35

        self.triage_score = min(100, max(0, self.triage_score))
        if self.triage_score >= 60:
            status = "Elevated Risk (Active Review Required)"
        elif self.triage_score >= 30:
            status = "Moderate Risk (Investigate Flags)"
        else:
            status = "Baseline Indicators (No High-Risk Patterns Flagged)"

        return {
            "fileName": self.file_name,
            "sha256": sha256_hash,
            "md5": md5_hash,
            "fileSize": len(self.raw_bytes),
            "triageScore": self.triage_score,
            "status": status,
            "scoreLabel": "Email Threat Triage Score",
            "scoreDisclaimer": "Heuristic risk indicator based on static header and body checks. Does not verify external DNS, mail server reputation, or cryptographic authenticity.",
            "headers": {
                "subject": subject,
                "from": from_hdr,
                "replyTo": reply_to or "Same as From",
                "to": to_hdr,
                "date": date_hdr,
                "returnPath": return_path or "Not specified",
                "authReported": auth_results or "Not reported in message"
            },
            "findings": self.findings,
            "aiBodyAnalysis": ai_body_analysis,
            "relayHopsCount": len(relay_hops),
            "relayHops": relay_hops[:5],
            "linksFound": len(all_extracted_urls),
            "flaggedLinks": flagged_urls,
            "attachments": attachment_inventory,
            "bodyIsHtmlReconstructed": is_html_source,
            "bodyPreview": body_text[:350] + ("..." if len(body_text) > 350 else "")
        }
