import React from 'react';

export default function EmailEvidenceView({ result }) {
  const headers = result?.headers || {};
  const attachments = result?.attachments || [];
  const flaggedLinks = result?.flaggedLinks || [];

  return (
    <div className="evidence-subpanel">
      <h3 className="section-subheading">Header & Transport Authentication</h3>
      <div className="evidence-table-card">
        <table className="evidence-table">
          <tbody>
            <tr>
              <th>From (Visible Sender)</th>
              <td>{headers.from || '(None)'}</td>
            </tr>
            <tr>
              <th>Reply-To</th>
              <td>
                {headers.replyTo || 'Same as From'}
                {headers.replyTo && headers.replyTo !== 'Same as From' && (
                  <span className="badge-warning">Divergent Address</span>
                )}
              </td>
            </tr>
            <tr>
              <th>Return-Path</th>
              <td>{headers.returnPath || '(None)'}</td>
            </tr>
            <tr>
              <th>Subject</th>
              <td>{headers.subject || '(No Subject)'}</td>
            </tr>
            <tr>
              <th>Reported Authentication</th>
              <td className="mono-cell">{headers.authReported || 'None reported in header'}</td>
            </tr>
            <tr>
              <th>Recorded Relay Hops</th>
              <td>{result?.relayHopsCount || 0} public hop(s) recorded</td>
            </tr>
          </tbody>
        </table>
      </div>

      {attachments.length > 0 && (
        <>
          <h3 className="section-subheading" style={{ marginTop: '20px' }}>Attachment Inventory ({attachments.length})</h3>
          <div className="evidence-table-card">
            <table className="evidence-table">
              <thead>
                <tr>
                  <th>Filename</th>
                  <th>Size</th>
                  <th>Individual SHA-256 Hash</th>
                  <th>Flag</th>
                </tr>
              </thead>
              <tbody>
                {attachments.map((att, idx) => (
                  <tr key={idx}>
                    <td className="bold">{att.filename}</td>
                    <td>{att.sizeKb} KB</td>
                    <td className="mono-cell">{att.sha256}</td>
                    <td>
                      {att.flagged ? (
                        <span className="badge-danger">High-Risk Extension</span>
                      ) : (
                        <span className="badge-neutral">Standard</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {flaggedLinks.length > 0 && (
        <>
          <h3 className="section-subheading" style={{ marginTop: '20px' }}>Flagged URL Structures</h3>
          <div className="evidence-table-card">
            <table className="evidence-table">
              <thead>
                <tr>
                  <th>Target URL</th>
                  <th>Risk Reason</th>
                </tr>
              </thead>
              <tbody>
                {flaggedLinks.map((link, idx) => (
                  <tr key={idx}>
                    <td className="mono-cell break-all">{link.url}</td>
                    <td>{link.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
