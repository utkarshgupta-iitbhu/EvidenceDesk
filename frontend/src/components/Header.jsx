import React, { useState, useEffect } from 'react';
import { checkBackendHealth } from '../api/client';

export default function Header() {
  const [healthStatus, setHealthStatus] = useState({ online: null, version: '1.2.0' });

  useEffect(() => {
    let mounted = true;
    const verifyHealth = async () => {
      const res = await checkBackendHealth();
      if (mounted) {
        setHealthStatus(res);
      }
    };

    verifyHealth();
    const interval = setInterval(verifyHealth, 30000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  return (
    <header className="workstation-header">
      <div className="header-brand">
        <div className="brand-badge">
          <span className="brand-logo">ED</span>
        </div>
        <div>
          <h1 className="brand-title">EvidenceDesk</h1>
          <p className="brand-subtitle">Digital Evidence Triage Workstation</p>
        </div>
      </div>

      <div className="header-meta">
        <div className="status-indicator">
          <span className={`pulse-dot ${healthStatus.online === false ? 'offline' : (healthStatus.online === true ? 'online' : 'checking')}`}></span>
          <span className="status-text">
            {healthStatus.online === true && `Connected (API v${healthStatus.version})`}
            {healthStatus.online === false && 'API Offline'}
            {healthStatus.online === null && 'Connecting...'}
          </span>
        </div>
        <div className="version-pill">v1.2.0</div>
      </div>
    </header>
  );
}
