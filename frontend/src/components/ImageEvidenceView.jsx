import React, { useState } from 'react';

export default function ImageEvidenceView({ result, selectedImageUrl }) {
  const [elaOpacity, setElaOpacity] = useState(0.5);
  const [showGps, setShowGps] = useState(false);
  const [copiedGps, setCopiedGps] = useState(false);

  const metadata = result?.metadata || {};
  const gps = result?.gps;

  const copyCoordinates = () => {
    if (gps) {
      navigator.clipboard.writeText(`${gps.latitude}, ${gps.longitude}`);
      setCopiedGps(true);
      setTimeout(() => setCopiedGps(false), 2000);
    }
  };

  return (
    <div className="evidence-subpanel">
      <div className="inspector-header">
        <h3 className="section-subheading">Error Level Analysis (ELA) Recompression</h3>
        <div className="slider-control">
          <label htmlFor="ela-slider" className="control-label">Heatmap Overlay:</label>
          <input
            id="ela-slider"
            type="range"
            min="0"
            max="1"
            step="0.05"
            value={elaOpacity}
            onChange={(e) => setElaOpacity(parseFloat(e.target.value))}
            className="range-input"
          />
        </div>
      </div>

      <div className="image-viewport-container">
        {selectedImageUrl && (
          <img src={selectedImageUrl} alt="Original uploaded asset" className="base-img" />
        )}
        {result?.ela?.heatmapBase64 && (
          <img
            src={result.ela.heatmapBase64}
            alt="Error Level Analysis heatmap"
            className="ela-overlay"
            style={{ opacity: elaOpacity }}
          />
        )}
      </div>

      <p className="image-caption">
        *ELA highlights compression delta against a 95% re-saved baseline. High-contrast edges and fine text naturally show elevated variance.
      </p>

      <h3 className="section-subheading" style={{ marginTop: '20px' }}>Recorded File & Camera Metadata</h3>
      <div className="evidence-table-card">
        <table className="evidence-table">
          <tbody>
            <tr>
              <th>Detected Format</th>
              <td>{result?.format || 'Unknown'} ({result?.dimensions || 'N/A'})</td>
            </tr>
            <tr>
              <th>Camera Hardware Tags</th>
              <td>{result?.hasCameraHardware ? 'Hardware Make/Model found' : 'None recorded (Metadata omitted or stripped)'}</td>
            </tr>
            {metadata.Make && (
              <tr>
                <th>Camera Make</th>
                <td>{metadata.Make}</td>
              </tr>
            )}
            {metadata.Model && (
              <tr>
                <th>Camera Model</th>
                <td>{metadata.Model}</td>
              </tr>
            )}
            {metadata.Software && (
              <tr>
                <th>Software Identifier</th>
                <td>{metadata.Software}</td>
              </tr>
            )}
            {metadata.DateTimeOriginal && (
              <tr>
                <th>Date/Time Original</th>
                <td>{metadata.DateTimeOriginal}</td>
              </tr>
            )}
            <tr>
              <th>Geolocation Coordinates</th>
              <td>
                {gps ? (
                  <div className="gps-privacy-box">
                    {!showGps ? (
                      <button type="button" className="btn-action-outline btn-sm" onClick={() => setShowGps(true)}>
                        Reveal Coordinates (Private by default)
                      </button>
                    ) : (
                      <div className="gps-revealed">
                        <span className="mono">{gps.latitude}, {gps.longitude}</span>
                        <button type="button" className="btn-action-ghost btn-sm" onClick={copyCoordinates}>
                          {copiedGps ? '✓ Copied' : 'Copy Lat/Long'}
                        </button>
                      </div>
                    )}
                  </div>
                ) : (
                  'No GPS coordinates recorded'
                )}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}
