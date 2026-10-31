import React from 'react';

export default function FindingsTable({ findings = [] }) {
  const getSevClass = (sev) => {
    const s = String(sev || '').toUpperCase();
    if (s === 'HIGH') return 'sev-high';
    if (s === 'MEDIUM') return 'sev-medium';
    if (s === 'LOW') return 'sev-low';
    return 'sev-info';
  };

  return (
    <section className="evidence-section">
      <h3 className="section-subheading">Recorded Indicators ({findings.length})</h3>
      {findings.length === 0 ? (
        <div className="empty-findings">
          No anomalous indicators were flagged by the automated rules in this sample.
        </div>
      ) : (
        <div className="findings-grid">
          {findings.map((f, i) => (
            <div key={i} className={`finding-card ${getSevClass(f.severity)}`}>
              <div className="finding-header">
                <span className="finding-title">{f.title}</span>
                <span className={`finding-pill ${getSevClass(f.severity)}`}>{f.severity}</span>
              </div>
              <p className="finding-detail">{f.detail}</p>
              {f.caveat && (
                <p className="finding-caveat">
                  <strong>Technical Context:</strong> {f.caveat}
                </p>
              )}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
