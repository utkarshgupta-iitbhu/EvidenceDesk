import React from 'react';

export default function TextEvidenceView({ result }) {
  const metrics = result?.metrics || {};
  const buzzwords = result?.flaggedBuzzwords || [];
  const sentences = result?.flaggedSentences || [];

  return (
    <div className="evidence-subpanel">
      <h3 className="section-subheading">Stylistic Uniformity Indicators</h3>
      <div className="metrics-grid">
        <div className="metric-box">
          <span className="metric-label">Sentence Burstiness</span>
          <span className="metric-value">{metrics.burstiness ?? 'N/A'}</span>
          <span className="metric-hint">Low (&lt;0.30) indicates flat pacing</span>
        </div>
        <div className="metric-box">
          <span className="metric-label">Transition Marker Density</span>
          <span className="metric-value">{metrics.aiBuzzwordDensity ?? '0.0%'}</span>
          <span className="metric-hint">Cohesive marker frequency</span>
        </div>
        <div className="metric-box">
          <span className="metric-label">Total Words / Sentences</span>
          <span className="metric-value">{result?.totalWords} / {result?.totalSentences}</span>
          <span className="metric-hint">Discourse volume</span>
        </div>
        <div className="metric-box">
          <span className="metric-label">Passive Voice Clauses</span>
          <span className="metric-value">{metrics.passiveClausesCount ?? 0}</span>
          <span className="metric-hint">Passive phrasing constructions</span>
        </div>
      </div>

      {buzzwords.length > 0 && (
        <>
          <h3 className="section-subheading" style={{ marginTop: '20px' }}>Matched Transition Phrases & Markers</h3>
          <div className="marker-pills-wrap">
            {buzzwords.map((w, idx) => (
              <span key={idx} className="marker-pill">{w}</span>
            ))}
          </div>
        </>
      )}

      {sentences.length > 0 && (
        <>
          <h3 className="section-subheading" style={{ marginTop: '20px' }}>Sample Sentences with High Marker Frequency</h3>
          <div className="flagged-sentences-wrap">
            {sentences.slice(0, 3).map((item, idx) => (
              <div key={idx} className="sentence-card">
                <p className="sentence-text">"{item.sentence}"</p>
                <div className="sentence-markers">
                  <span className="marker-note">Markers: {item.markers.join(', ')}</span>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
