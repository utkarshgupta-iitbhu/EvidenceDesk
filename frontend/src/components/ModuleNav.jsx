import React from 'react';

const MODULES = [
  { id: 'email', name: 'Email Threat Triage', tag: 'RFC 5322 & Phishing' },
  { id: 'image', name: 'Image Forensics', tag: 'EXIF & ELA Variance' },
  { id: 'text', name: 'Document Analysis', tag: 'Stylistic Uniformity' },
];

export default function ModuleNav({ activeModule, onSelectModule, disabled }) {
  return (
    <nav className="module-nav" role="tablist" aria-label="Forensic Investigation Modules">
      {MODULES.map((m) => {
        const isActive = activeModule === m.id;
        return (
          <button
            key={m.id}
            id={`tab-${m.id}`}
            type="button"
            role="tab"
            disabled={disabled}
            className={`nav-tab-btn ${isActive ? 'active' : ''}`}
            onClick={() => onSelectModule(m.id)}
            aria-selected={isActive}
            aria-controls={`panel-${m.id}`}
            tabIndex={isActive ? 0 : -1}
          >
            <span className="tab-title">{m.name}</span>
            <span className="tab-tag">{m.tag}</span>
          </button>
        );
      })}
    </nav>
  );
}
