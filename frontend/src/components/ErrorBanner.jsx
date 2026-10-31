import React from 'react';

export default function ErrorBanner({ error, onDismiss }) {
  if (!error) return null;

  return (
    <div className="error-banner" role="alert">
      <div className="error-content">
        <h4 className="error-title">{error.title || 'Analysis Error'}</h4>
        <p className="error-detail">{error.detail || error.message || String(error)}</p>
      </div>
      <button type="button" className="error-dismiss-btn" onClick={onDismiss} aria-label="Dismiss error">
        Dismiss
      </button>
    </div>
  );
}
