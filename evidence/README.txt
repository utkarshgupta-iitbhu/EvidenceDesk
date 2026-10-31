EvidenceDesk sample inputs

These are fictional, synthetic inputs for local UI demonstrations. The email domains use reserved example domains. The images are generated graphics. The suspicious email attachment contains plain explanatory text only. The appended image archive contains one plain-text README and no executable content.

Suggested walkthrough

EMAIL
- email_baseline.eml: should show a baseline/low indicator result, with reported SPF/DKIM/DMARC pass values.
- email_review_indicators.eml: designed to show Reply-To and Return-Path discrepancies, reported authentication failures, urgency wording, a numeric-IP URL, and a risky extension. Its .xlsm attachment is inert text, not a macro.
- email_html_only.eml: exercises HTML-only body extraction, Reply-To divergence, urgency wording, and a numeric-IP URL.

IMAGE
- image_clean_with_demo_metadata.jpg: includes fabricated camera make/model tags; it is a generated graphic, not a camera photograph.
- image_overlay_edit.jpg: has a visible synthetic overlay and a different JPEG save quality for ELA viewing. ELA is only a visual heuristic.
- image_appended_safe_archive.jpg: a valid JPEG followed by a harmless ZIP containing README_SAFE.txt, to demonstrate the appended-data/archive indicator.
- image_clean.png and image_clean.webp: clean-format compatibility examples.

TEXT / DOCUMENT
- text_varied_baseline.txt: longer neutral writing with varied sentence lengths.
- text_repeated_markers_and_passive_voice.txt: includes repeated transition markers and passive constructions to demonstrate the displayed heuristics.
- text_short_inconclusive.txt: intentionally short to demonstrate the minimum sample-length message.

Paste any .txt contents into the text box, or upload the files. Exact scores depend on the current rules and should be read as heuristic indicators only. These files are not real evidence and must not be used to make security or authorship decisions.
