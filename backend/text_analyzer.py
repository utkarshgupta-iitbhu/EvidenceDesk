import os
import re
import math
import hashlib
import io
from typing import List, Dict, Any
from pypdf import PdfReader
from docx import Document
from config import settings

class TextLinguisticAnalyzer:
    """Experimental linguistic heuristic analyzer.
    
    IMPORTANT DEFICIENCY & METHODOLOGY NOTICE:
    This tool measures stylistic uniformity markers (sentence length variance,
    transition phrase density, passive voice frequency, and pronoun presence).
    These metrics are UNCALIBRATED HEURISTICS and DO NOT constitute a statistical
    probability or proof of AI vs. human authorship. Standard business correspondence,
    academic writing, legal contracts, and non-native English frequently exhibit
    high uniformity without AI involvement.
    """

    AI_TRANSITION_TERMS = [
        "furthermore", "moreover", "additionally", "consequently", "therefore",
        "in summary", "notably", "foster", "delve", "testament", "tapestry",
        "meticulously", "revolutionize", "crucial", "essential", "showcase",
        "pivotal", "beacon", "underpins", "intertwined"
    ]

    HUMAN_PRONOUNS = {"i", "me", "my", "myself", "we", "our", "us", "ourselves"}

    def __init__(self, text: str, source_name: str = "Direct Input", file_bytes: bytes = None):
        self.raw_text = text.strip()
        self.source_name = source_name
        self.file_bytes = file_bytes
        self.findings: List[Dict[str, str]] = []
        self.heuristic_score = 0

    @staticmethod
    def extract_from_file(raw_bytes: bytes, file_name: str) -> str:
        if not raw_bytes:
            raise ValueError("Uploaded document contains no data (0 bytes).")
        if len(raw_bytes) > settings.MAX_FILE_BYTES:
            raise ValueError(f"Document exceeds 25MB limit ({round(len(raw_bytes)/(1024*1024), 2)}MB).")

        name_lower = file_name.lower()
        ext = os.path.splitext(name_lower)[1]
        if ext not in settings.SUPPORTED_DOCUMENT_EXTENSIONS:
            raise ValueError(f"Unsupported document format '{ext}'. Document triage only accepts: {', '.join(sorted(settings.SUPPORTED_DOCUMENT_EXTENSIONS))}.")

        try:
            if ext == ".pdf":
                reader = PdfReader(io.BytesIO(raw_bytes))
                total_pages = len(reader.pages)
                if total_pages > settings.MAX_PDF_PAGES:
                    raise ValueError(f"PDF exceeds maximum page limit of {settings.MAX_PDF_PAGES} pages (uploaded: {total_pages} pages).")
                
                extracted = []
                for idx, page in enumerate(reader.pages):
                    txt = page.extract_text()
                    if txt and txt.strip():
                        extracted.append(txt.strip())
                if not extracted:
                    raise ValueError(
                        "No digital text layer found in PDF. This appears to be a scanned document or image container. "
                        "Digital text extraction requires an embedded text stream."
                    )
                full_text = "\n".join(extracted)
                if len(full_text) > settings.MAX_TEXT_CHARS:
                    raise ValueError(f"Extracted document text exceeds limit of {settings.MAX_TEXT_CHARS:,} characters.")
                return full_text

            elif ext == ".docx":
                doc = Document(io.BytesIO(raw_bytes))
                extracted = [para.text.strip() for para in doc.paragraphs if para.text and para.text.strip()]
                if not extracted:
                    raise ValueError("No extractable paragraph text found in DOCX file.")
                full_text = "\n".join(extracted)
                if len(full_text) > settings.MAX_TEXT_CHARS:
                    raise ValueError(f"Extracted document text exceeds limit of {settings.MAX_TEXT_CHARS:,} characters.")
                return full_text

            else:
                try:
                    full_text = raw_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    full_text = raw_bytes.decode("latin-1")
                if len(full_text) > settings.MAX_TEXT_CHARS:
                    raise ValueError(f"Document text exceeds limit of {settings.MAX_TEXT_CHARS:,} characters.")
                return full_text

        except Exception as e:
            if isinstance(e, ValueError):
                raise e
            raise ValueError(f"Document extraction failure: {str(e)}")

    def _split_sentences(self) -> List[str]:
        sentences = re.split(r'[.!?]+(?:\s+|$)', self.raw_text)
        return [s.strip() for s in sentences if len(s.strip()) > 3]

    def _calculate_burstiness(self, sentences: List[str]) -> float:
        if len(sentences) < 2:
            return 0.5
        lengths = [len(s.split()) for s in sentences]
        mean = sum(lengths) / len(lengths)
        if mean == 0:
            return 0.5
        variance = sum((l - mean) ** 2 for l in lengths) / len(lengths)
        std_dev = math.sqrt(variance)
        return round(std_dev / mean, 3)

    def analyze(self) -> Dict[str, Any]:
        file_sha256 = hashlib.sha256(self.file_bytes).hexdigest() if self.file_bytes else "N/A (Direct Text Input)"
        file_md5 = hashlib.md5(self.file_bytes).hexdigest() if self.file_bytes else "N/A"
        
        text_encoded = self.raw_text.encode("utf-8", errors="replace")
        text_sha256 = hashlib.sha256(text_encoded).hexdigest()

        # Word tokens using word boundary pattern
        words = [w.lower() for w in re.findall(r'\b[a-zA-Z]+\b', self.raw_text)]
        total_words = len(words)
        sentences = self._split_sentences()
        total_sentences = len(sentences)

        if total_words < 15:
            return {
                "sourceName": self.source_name,
                "fileSha256": file_sha256,
                "textSha256": text_sha256,
                "fileMd5": file_md5,
                "heuristicScore": 0,
                "status": "Inconclusive Sample (Under 15 words)",
                "scoreLabel": "Linguistic Heuristic Score",
                "scoreDisclaimer": "Sample size is insufficient for statistical analysis (minimum 15 words required).",
                "totalWords": total_words,
                "totalSentences": total_sentences,
                "findings": [{
                    "title": "Insufficient Text Length",
                    "detail": f"Sample contains only {total_words} word(s). Reliable stylistic analysis requires longer discourse.",
                    "severity": "INFO",
                    "caveat": "Cannot draw even preliminary conclusions on short phrases."
                }],
                "metrics": {
                    "burstiness": 0.0,
                    "lexicalDiversityTtr": "N/A",
                    "aiBuzzwordDensity": "0.0%",
                    "passiveClausesCount": 0
                },
                "flaggedBuzzwords": [],
                "flaggedSentences": []
            }

        # 1. Burstiness (Sentence Length Variance)
        burstiness = self._calculate_burstiness(sentences)
        if burstiness < 0.30:
            self.findings.append({
                "title": "Low Sentence Burstiness (Uniform Lengths)",
                "detail": f"Sentence length coefficient of variation is {burstiness}. Sentences follow a rigid length rhythm.",
                "severity": "MEDIUM",
                "caveat": "Academic, legal, and translated texts often follow structured, uniform pacing naturally."
            })
            self.heuristic_score += 30
        elif burstiness > 0.55:
            self.findings.append({
                "title": "High Sentence Burstiness (Varied Pacing)",
                "detail": f"Sentence length variation score is {burstiness}. Contains a dynamic blend of short and compound clauses.",
                "severity": "INFO",
                "caveat": "Characteristic of informal or expressive human writing."
            })

        # 2. AI Transition & Phrase Matching
        found_markers = []
        lowered_text = self.raw_text.lower()
        for marker in self.AI_TRANSITION_TERMS:
            pattern = r'\b' + re.escape(marker) + r'\b'
            matches = re.findall(pattern, lowered_text)
            if matches:
                found_markers.extend(matches)

        marker_density = round((len(found_markers) / max(total_words, 1)) * 100, 2)
        if marker_density >= 2.0:
            self.findings.append({
                "title": "Elevated Transition & Marker Density",
                "detail": f"Flagged marker density: {marker_density}%. Commonly over-represented words: {list(set(found_markers))[:4]}.",
                "severity": "MEDIUM",
                "caveat": "Formal professional templates and grant proposals naturally rely on cohesive markers."
            })
            self.heuristic_score += 25

        # 3. First-Person Pronouns
        found_pronouns = [w for w in words if w in self.HUMAN_PRONOUNS]
        pronoun_density = round((len(found_pronouns) / max(total_words, 1)) * 100, 2)
        if pronoun_density == 0 and total_words > 60:
            self.findings.append({
                "title": "Impersonal Narrative (Absence of First-Person Pronouns)",
                "detail": "Zero first-person pronouns (I, we, our, me) detected in sample.",
                "severity": "LOW",
                "caveat": "Standard requirement for encyclopedic, technical, and third-person journalism writing."
            })
            self.heuristic_score += 15

        # 4. Passive Voice Index
        passive_matches = re.findall(
            r'\b(is|am|are|was|were|be|been|being)\b\s+\b([a-z]+ed|written|taken|seen|done|given|chosen|known|made|built)\b', 
            self.raw_text, re.IGNORECASE
        )
        passive_ratio = round((len(passive_matches) / max(total_sentences, 1)), 2)
        if passive_ratio > 0.45:
            self.findings.append({
                "title": "Frequent Passive Constructions",
                "detail": f"Identified {len(passive_matches)} passive voice clauses ({passive_ratio} per sentence).",
                "severity": "LOW",
                "caveat": "Standard in scientific and institutional reports."
            })
            self.heuristic_score += 15

        # 5. Lexical Diversity (Type-Token Ratio)
        unique_words = len(set(words))
        ttr = round((unique_words / total_words) * 100, 2) if total_words else 0

        self.heuristic_score = min(100, max(0, self.heuristic_score))
        if self.heuristic_score >= 60:
            status = "Elevated Stylistic Uniformity (Requires Review)"
        elif self.heuristic_score >= 35:
            status = "Moderate Stylistic Markers"
        else:
            status = "Typical Stylistic Variance"

        # Flagged sentences for transparency
        flagged_sentences = []
        for s in sentences:
            s_lower = s.lower()
            contained = [m for m in self.AI_TRANSITION_TERMS if re.search(r'\b' + re.escape(m) + r'\b', s_lower)]
            if len(contained) >= 2 or any(k in contained for k in ["delve", "tapestry", "testament"]):
                flagged_sentences.append({
                    "sentence": s,
                    "markers": contained
                })

        return {
            "sourceName": self.source_name,
            "fileSha256": file_sha256,
            "textSha256": text_sha256,
            "fileMd5": file_md5,
            "heuristicScore": self.heuristic_score,
            "status": status,
            "scoreLabel": "Linguistic Heuristic Score",
            "scoreDisclaimer": "Uncalibrated experimental indicator. Measures stylistic uniformity and transition frequency. NOT a calibrated probability and cannot prove or disprove AI authorship.",
            "totalWords": total_words,
            "totalSentences": total_sentences,
            "metrics": {
                "burstiness": burstiness,
                "lexicalDiversityTtr": f"{ttr}%",
                "aiBuzzwordDensity": f"{marker_density}%",
                "passiveClausesCount": len(passive_matches)
            },
            "findings": self.findings,
            "flaggedBuzzwords": list(set(found_markers)),
            "flaggedSentences": flagged_sentences[:5]
        }
