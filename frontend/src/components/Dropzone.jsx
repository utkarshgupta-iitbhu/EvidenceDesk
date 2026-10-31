import React, { useState, useRef } from 'react';

export default function Dropzone({ 
  activeModule, 
  stagedFile, 
  rawText, 
  onStageFile, 
  onClearFile, 
  onTextChange, 
  onExecuteScan, 
  loading 
}) {
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef(null);

  const getAcceptTypes = () => {
    if (activeModule === 'email') return '.eml,message/rfc822';
    if (activeModule === 'image') return 'image/jpeg,image/png,image/webp,.jpg,.jpeg,.png,.webp';
    return '.pdf,.docx,.txt,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document,text/plain';
  };

  const getFormatLabel = () => {
    if (activeModule === 'email') return 'Accepted: .eml (RFC 5322 messages)';
    if (activeModule === 'image') return 'Accepted: JPEG, PNG, WEBP';
    return 'Accepted: PDF (with digital text stream), DOCX, TXT';
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (!loading) setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    if (loading) return;

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      onStageFile(e.dataTransfer.files[0]);
    }
  };

  const formatBytes = (bytes) => {
    if (!bytes) return '0 B';
    const mb = bytes / (1024 * 1024);
    if (mb >= 1) return `${mb.toFixed(2)} MB`;
    return `${(bytes / 1024).toFixed(1)} KB`;
  };

  return (
    <section className="dropzone-section" aria-label="Evidence intake workspace">
      <div className="section-title-wrap">
        <h2 className="workspace-title">
          {activeModule === 'email' && 'Email Threat Triage'}
          {activeModule === 'image' && 'Image Metadata & Tamper Indicators'}
          {activeModule === 'text' && 'Document & Stylistic Review'}
        </h2>
        <p className="workspace-desc">
          {activeModule === 'email' && 'Examines unverified authentication headers, Reply-To discrepancies, server relay hops, and attachment hashes.'}
          {activeModule === 'image' && 'Extracts camera hardware EXIF data, trailing payload bytes, and computes Error Level Analysis (ELA) variance.'}
          {activeModule === 'text' && 'Computes sentence length burstiness, transition phrase density, and passive voice patterns. Uncalibrated indicator.'}
        </p>
      </div>

      {!stagedFile ? (
        <div
          className={`dropzone-box ${isDragging ? 'dragging' : ''}`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current && fileInputRef.current.click()}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              fileInputRef.current && fileInputRef.current.click();
            }
          }}
          aria-label="Upload evidence file"
        >
          <div className="dropzone-icon">📥</div>
          <div className="dropzone-prompt">
            <span className="prompt-action">Select or drag evidence file here</span>
            <span className="prompt-limits">{getFormatLabel()} • 25 MB Max Threshold</span>
          </div>
          <input
            ref={fileInputRef}
            type="file"
            className="hidden-file-input"
            accept={getAcceptTypes()}
            onChange={(e) => {
              if (e.target.files && e.target.files[0]) {
                onStageFile(e.target.files[0]);
              }
              // Reset input value so re-selecting same file triggers onChange
              e.target.value = '';
            }}
          />
        </div>
      ) : (
        <div className="staged-file-card">
          <div className="file-info-group">
            <div className="file-type-icon">
              {activeModule === 'email' && '✉️'}
              {activeModule === 'image' && '🖼️'}
              {activeModule === 'text' && '📄'}
            </div>
            <div className="file-name-meta">
              <span className="staged-filename">{stagedFile.name}</span>
              <span className="staged-meta">
                {formatBytes(stagedFile.size)} • {stagedFile.type || 'Binary Stream'}
              </span>
            </div>
          </div>

          <div className="staged-actions">
            <button
              type="button"
              className="btn-text-danger"
              onClick={onClearFile}
              disabled={loading}
              aria-label="Remove staged file"
            >
              Clear
            </button>
            <button
              type="button"
              className="btn-action-primary"
              onClick={onExecuteScan}
              disabled={loading}
            >
              {loading ? 'Processing...' : 'Run Triage Analysis'}
            </button>
          </div>
        </div>
      )}

      {activeModule === 'text' && !stagedFile && (
        <div className="text-paste-container">
          <div className="divider-label">
            <span>OR PASTE TEXT EXCERPT DIRECTLY</span>
          </div>
          <textarea
            className="text-input-field"
            value={rawText}
            onChange={(e) => onTextChange(e.target.value)}
            placeholder="Paste text excerpt (minimum 15 words for stylistic evaluation)..."
            rows={4}
            disabled={loading}
            aria-label="Pasted text excerpt"
          />
          <button
            type="button"
            className="btn-action-primary align-end"
            onClick={onExecuteScan}
            disabled={loading || !rawText.trim()}
          >
            {loading ? 'Analyzing...' : 'Analyze Excerpt'}
          </button>
        </div>
      )}
    </section>
  );
}
