import React, { useState } from 'react';

export default function TriageSummary({ 
  result, 
  activeModule, 
  onDownloadReport, 
  onDownloadManifest, 
  onPurgeServerEvidence, 
  onReset 
}) {
  const [copiedHash, setCopiedHash] = useState(false);
  const [copiedScanId, setCopiedScanId] = useState(false);

  const getPriorityStyle = (score, mod) => {
    if (score >= 60) {
      return { 
        label: mod === 'text' ? 'Elevated Stylistic Uniformity (Review Required)' : 'Elevated Risk (Active Review Required)', 
        class: 'priority-high' 
      };
    }
    if (score >= 30) {
      return { 
        label: mod === 'text' ? 'Moderate Stylistic Markers' : 'Moderate Risk (Investigate Flags)', 
        class: 'priority-medium' 
      };
    }
    return { 
      label: mod === 'text' ? 'Typical Stylistic Variance' : 'Baseline Indicators (No Discrepancies Flagged)', 
      class: 'priority-low' 
    };
  };

  const score = result?.triageScore ?? result?.heuristicScore ?? 0;
  const priority = getPriorityStyle(score, activeModule);
  
  const hasFile = Boolean(result?.fileSha256 || (result?.sha256 && !result?.textSha256));
  const primaryHash = result?.fileSha256 || result?.sha256 || 'N/A';
  const textHash = result?.textSha256;

  const copyVal = (val, setFunc) => {
    if (val && val !== 'N/A') {
      navigator.clipboard.writeText(val);
      setFunc(true);
      setTimeout(() => setFunc(false), 2000);
    }
  };

  return (
    <section className="triage-summary-card" aria-label="Triage summary and provenance">
      <div className="summary-main">
        <div className={`priority-badge ${priority.class}`}>
          <span className="priority-label">{priority.label}</span>
          <span className="priority-score">{score} / 100</span>
        </div>

        <div className="summary-metadata">
          <div className="meta-row">
            <span className="meta-label">Evidence Target:</span>
            <span className="meta-val bold">{result?.fileName || result?.sourceName || 'Uploaded Asset'}</span>
          </div>

          {hasFile && primaryHash !== 'N/A' && (
            <div className="meta-row">
              <span className="meta-label">Computed File SHA-256:</span>
              <span className="meta-val hash-val">
                {primaryHash}
                <button 
                  type="button" 
                  className="btn-icon-copy" 
                  onClick={() => copyVal(primaryHash, setCopiedHash)} 
                  title="Copy full SHA-256 hash"
                  aria-label="Copy file SHA-256 hash"
                >
                  {copiedHash ? '✓ Copied' : 'Copy'}
                </button>
              </span>
            </div>
          )}

          {textHash && (
            <div className="meta-row">
              <span className="meta-label">Computed Text Stream SHA-256:</span>
              <span className="meta-val hash-val">{textHash}</span>
            </div>
          )}

          {result?.scanId && (
            <div className="meta-row">
              <span className="meta-label">Server Scan ID:</span>
              <span className="meta-val mono">
                {result.scanId}
                <button 
                  type="button" 
                  className="btn-icon-copy" 
                  onClick={() => copyVal(result.scanId, setCopiedScanId)} 
                  title="Copy server scan ID"
                  aria-label="Copy server scan ID"
                >
                  {copiedScanId ? '✓ Copied' : 'Copy'}
                </button>
              </span>
            </div>
          )}
        </div>

        <p className="summary-disclaimer">
          <strong>Methodology Note:</strong> {result?.scoreDisclaimer || 'Triage indicator score based on heuristic rules. Findings require independent forensic validation.'}
        </p>
      </div>

      <div className="summary-actions">
        <button type="button" className="btn-action-primary" onClick={onDownloadReport}>
          Download Verified PDF
        </button>
        <button type="button" className="btn-action-outline" onClick={onDownloadManifest}>
          Export JSON Manifest
        </button>
        <button type="button" className="btn-action-danger-outline" onClick={onPurgeServerEvidence}>
          Purge from Server
        </button>
        <button type="button" className="btn-action-ghost" onClick={onReset}>
          New Review
        </button>
      </div>
    </section>
  );
}
