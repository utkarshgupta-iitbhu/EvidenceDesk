import io
import base64
import hashlib
from typing import Dict, Any, List, Optional
from PIL import Image, ImageChops
from PIL.ExifTags import TAGS, GPSTAGS
from config import settings

class ImageForensicAnalyzer:
    """Preliminary image metadata and tamper-indicator triage engine.
    
    LIMITATION NOTICE:
    1. Error Level Analysis (ELA) visualizes JPEG recompression residuals. Differences
       occur naturally around sharp high-frequency edges, text, or after routine resaving.
       ELA DOES NOT definitively prove image splicing or tampering.
    2. Missing EXIF metadata is standard for web uploads, social media platforms,
       and privacy-aware editors. It is INCONCLUSIVE and does not indicate synthetic origins.
    3. The payload check scans for trailing data appended past format end-markers and
       embedded ZIP headers. It is NOT an exhaustive steganography detector.
    """

    KNOWN_EDITING_SIGNATURES = [
        "photoshop", "gimp", "canva", "lightroom", "pixelmator", 
        "midjourney", "stable diffusion", "dall-e", "firefly"
    ]

    def __init__(self, raw_bytes: bytes, file_name: str = "image.jpg"):
        if not raw_bytes:
            raise ValueError("Uploaded image payload is empty (0 bytes).")
        if len(raw_bytes) > settings.MAX_FILE_BYTES:
            raise ValueError(f"Image exceeds maximum size limit of {settings.MAX_FILE_BYTES // (1024*1024)}MB.")

        self.raw_bytes = raw_bytes
        self.file_name = file_name
        self.findings: List[Dict[str, str]] = []
        self.anomaly_score = 0

        self.detected_format = self._validate_magic_bytes(raw_bytes)
        if not self.detected_format or self.detected_format not in settings.SUPPORTED_IMAGE_FORMATS:
            raise ValueError(f"File content does not match supported image signatures ({', '.join(sorted(settings.SUPPORTED_IMAGE_FORMATS))}).")

    def _validate_magic_bytes(self, data: bytes) -> Optional[str]:
        if data.startswith(b"\xff\xd8\xff"):
            return "JPEG"
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            return "PNG"
        if data.startswith(b"RIFF") and len(data) > 12 and data[8:12] == b"WEBP":
            return "WEBP"
        if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
            return "GIF"
        return None

    def _convert_gps(self, dms, ref):
        try:
            degrees = float(dms[0])
            minutes = float(dms[1])
            seconds = float(dms[2])
            decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
            if ref in ['S', 'W']:
                decimal = -decimal
            return round(decimal, 6)
        except Exception:
            return None

    def analyze(self) -> Dict[str, Any]:
        sha256 = hashlib.sha256(self.raw_bytes).hexdigest()
        md5 = hashlib.md5(self.raw_bytes).hexdigest()
        file_size_kb = round(len(self.raw_bytes) / 1024, 2)

        # 1. Trailing Appended Data & ZIP Signature Checks
        stego_found = False
        payload_details = None

        if self.detected_format == "JPEG":
            eof_index = self.raw_bytes.rfind(b"\xff\xd9")
            if eof_index != -1 and (eof_index + 2) < len(self.raw_bytes):
                trailing_bytes = len(self.raw_bytes) - (eof_index + 2)
                if trailing_bytes > 32:
                    stego_found = True
                    payload_details = f"Detected {trailing_bytes} byte(s) appended past standard JPEG EOF marker (FF D9)."
        elif self.detected_format == "PNG":
            iend_index = self.raw_bytes.rfind(b"IEND\xae\x42\x60\x82")
            if iend_index != -1 and (iend_index + 8) < len(self.raw_bytes):
                trailing_bytes = len(self.raw_bytes) - (iend_index + 8)
                if trailing_bytes > 32:
                    stego_found = True
                    payload_details = f"Detected {trailing_bytes} byte(s) appended past PNG IEND chunk."

        if b"PK\x03\x04" in self.raw_bytes:
            stego_found = True
            payload_details = (payload_details or "") + " Embedded ZIP archive header located within file bytes."

        if stego_found:
            self.findings.append({
                "title": "Appended Trailing Data / Archive Signature",
                "detail": payload_details,
                "severity": "HIGH",
                "caveat": "Some camera vendors write custom diagnostic metadata after EOF; however, this is frequently used for payload delivery."
            })
            self.anomaly_score += 40

        # 2. Strict Pillow Decoding Validation (Never return Baseline if corrupt!)
        metadata = {}
        gps_coords = None
        has_camera_hardware = False
        width, height = 0, 0

        try:
            pil_img = Image.open(io.BytesIO(self.raw_bytes))
            width, height = pil_img.size
            if (width * height) > settings.MAX_PIXELS:
                raise ValueError(f"Image dimensions ({width}x{height}) exceed maximum decompression limit of {settings.MAX_PIXELS:,} pixels.")
            
            # Force verification of actual image raster data
            pil_img.verify()
            
            # Reopen after verify() (Pillow requirement)
            pil_img = Image.open(io.BytesIO(self.raw_bytes))
            
            # Public EXIF extraction API
            exif_dict = pil_img.getexif()
            if exif_dict:
                gps_raw = {}
                for tag_id, value in exif_dict.items():
                    tag_name = TAGS.get(tag_id, str(tag_id))
                    if tag_name == "GPSInfo":
                        for g_id, g_val in value.items():
                            gps_raw[GPSTAGS.get(g_id, str(g_id))] = g_val
                    elif tag_name in ["Make", "Model", "Software", "DateTimeOriginal", "ExposureTime", "FNumber", "ISOSpeedRatings"]:
                        if isinstance(value, bytes):
                            value = value.decode("utf-8", errors="ignore").strip("\x00")
                        metadata[tag_name] = str(value).strip()

                if "Make" in metadata or "Model" in metadata:
                    has_camera_hardware = True
                    self.findings.append({
                        "title": "Camera Hardware Metadata Recorded",
                        "detail": f"Device: {metadata.get('Make', '')} {metadata.get('Model', '')}".strip(),
                        "severity": "INFO",
                        "caveat": "EXIF tags can be modified or injected by metadata editing tools."
                    })

                software_val = metadata.get("Software", "").lower()
                for sig in self.KNOWN_EDITING_SIGNATURES:
                    if sig in software_val:
                        self.findings.append({
                            "title": "Editing / Generation Software Marker",
                            "detail": f"EXIF Software field identifies '{metadata['Software']}'.",
                            "severity": "MEDIUM",
                            "caveat": "Indicates the image was saved through editing software; does not prove deceptive alteration."
                        })
                        self.anomaly_score += 25
                        break

                if "GPSLatitude" in gps_raw and "GPSLongitude" in gps_raw:
                    lat = self._convert_gps(gps_raw["GPSLatitude"], gps_raw.get("GPSLatitudeRef", "N"))
                    lon = self._convert_gps(gps_raw["GPSLongitude"], gps_raw.get("GPSLongitudeRef", "E"))
                    if lat is not None and lon is not None:
                        # Privacy by default: coordinates returned without external mapsUrl
                        gps_coords = {
                            "latitude": lat,
                            "longitude": lon,
                            "masked": True
                        }
                        self.findings.append({
                            "title": "Geolocation Coordinates Embedded",
                            "detail": "Embedded latitude and longitude records detected. Coordinates are masked by default to protect evidence privacy.",
                            "severity": "INFO",
                            "caveat": "GPS coordinates pinpoint device location at exposure."
                        })
            else:
                self.findings.append({
                    "title": "No EXIF Metadata Present",
                    "detail": "File contains no camera hardware, lens, or exposure records.",
                    "severity": "INFO",
                    "caveat": "Standard for web-compressed images, screenshots, social media platforms, or privacy scrubbers. Inconclusive for authenticity."
                })

        except Exception as e:
            raise ValueError(f"Image parsing failed: file appears corrupted or unreadable ({str(e)}).")

        # 3. Error Level Analysis (ELA) Heatmap
        ela_base64 = None
        ela_variance_score = 0

        try:
            original = Image.open(io.BytesIO(self.raw_bytes)).convert("RGB")
            temp_buffer = io.BytesIO()
            original.save(temp_buffer, "JPEG", quality=95)
            temp_buffer.seek(0)
            resaved = Image.open(temp_buffer)

            diff = ImageChops.difference(original, resaved)
            extrema = diff.getextrema()
            max_diff = max([ex[1] for ex in extrema]) or 1

            scale = min(255.0 / max_diff, 10.0)
            enhanced = diff.point(lambda p: int(p * scale))

            ela_out = io.BytesIO()
            enhanced.save(ela_out, format="PNG")
            ela_base64 = "data:image/png;base64," + base64.b64encode(ela_out.getvalue()).decode("utf-8")

            if max_diff >= 25:
                ela_variance_score = min(100, int(max_diff * 1.3))
                self.findings.append({
                    "title": "Elevated Error Level Analysis (ELA) Variance",
                    "detail": f"Peak recompression difference index: {max_diff}. Non-uniform compression response observed.",
                    "severity": "MEDIUM",
                    "caveat": "High-contrast geometric lines, text overlays, or natural textures also create high ELA differences. Manual examination of heatmap required."
                })
                self.anomaly_score += 25

        except Exception as err:
            self.findings.append({
                "title": "ELA Processing Warning",
                "detail": f"Could not compute ELA comparison: {str(err)}",
                "severity": "LOW",
                "caveat": "Non-fatal processing notice."
            })

        self.anomaly_score = min(100, max(0, self.anomaly_score))
        if self.anomaly_score >= 60:
            status = "Elevated Anomaly Indicators (Requires Manual Review)"
        elif self.anomaly_score >= 30:
            status = "Moderate Anomaly Indicators"
        else:
            status = "Baseline Indicators (No Discrepancies Flagged)"

        return {
            "fileName": self.file_name,
            "sha256": sha256,
            "md5": md5,
            "fileSizeKb": file_size_kb,
            "dimensions": f"{width}x{height}",
            "format": self.detected_format,
            "triageScore": self.anomaly_score,
            "status": status,
            "scoreLabel": "Image Anomaly Triage Score",
            "scoreDisclaimer": "Heuristic anomaly score. ELA differences and omitted EXIF tags do not constitute legal or technical proof of manipulation.",
            "hasCameraHardware": has_camera_hardware,
            "metadata": metadata,
            "gps": gps_coords,
            "steganography": {
                "detected": stego_found,
                "details": payload_details
            },
            "ela": {
                "varianceScore": ela_variance_score,
                "heatmapBase64": ela_base64
            },
            "findings": self.findings
        }
