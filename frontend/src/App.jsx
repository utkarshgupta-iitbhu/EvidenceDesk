import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import ModuleNav from './components/ModuleNav';
import Dropzone from './components/Dropzone';
import TriageSummary from './components/TriageSummary';
import FindingsTable from './components/FindingsTable';
import EmailEvidenceView from './components/EmailEvidenceView';
import ImageEvidenceView from './components/ImageEvidenceView';
import TextEvidenceView from './components/TextEvidenceView';
import ErrorBanner from './components/ErrorBanner';
import { 
  postScan, 
  downloadReportFile, 
  downloadManifestFile, 
  deleteServerScan 
} from './api/client';

export default function App() {
  const [activeModule, setActiveModule] = useState('email');
  
  // Staged input
  const [stagedFile, setStagedFile] = useState(null);
  const [selectedImageUrl, setSelectedImageUrl] = useState(null);
  const [rawText, setRawText] = useState('');
  
  // Execution & Results
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [resultModule, setResultModule] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const [notification, setNotification] = useState(null);

  // Manage image preview without memory leaks
  useEffect(() => {
    if (!stagedFile || activeModule !== 'image') {
      setSelectedImageUrl(null);
      return;
    }
    const url = URL.createObjectURL(stagedFile);
    setSelectedImageUrl(url);
    return () => URL.revokeObjectURL(url);
  }, [stagedFile, activeModule]);

  const handleStageFile = (file) => {
    setErrorMessage(null);
    setScanResult(null);
    setResultModule(null);

    // If file is oversized, clear any previously staged file immediately!
    if (file.size > 25 * 1024 * 1024) {
      setStagedFile(null);
      setErrorMessage({
        title: 'File Exceeds Triage Threshold',
        detail: `The selected file '${file.name}' is ${(file.size / (1024 * 1024)).toFixed(2)} MB. EvidenceDesk imposes a strict 25 MB limit for safe in-memory analysis.`
      });
      return;
    }
    setStagedFile(file);
  };

  const handleClearFile = () => {
    setStagedFile(null);
    setScanResult(null);
    setResultModule(null);
    setErrorMessage(null);
  };

  const handleExecuteScan = async () => {
    setLoading(true);
    setErrorMessage(null);
    setNotification(null);

    const formData = new FormData();
    const currentModule = activeModule;

    if (stagedFile) {
      formData.append('file', stagedFile);
    } else if (currentModule === 'text' && rawText.trim()) {
      formData.append('raw_text', rawText.trim());
    } else {
      setLoading(false);
      return;
    }

    try {
      const endpoint = `/api/scan/${currentModule}`;
      const data = await postScan(endpoint, formData);
      setScanResult(data);
      setResultModule(currentModule);
    } catch (err) {
      setErrorMessage({
        title: 'Triage Execution Failed',
        detail: err.message
      });
      setScanResult(null);
      setResultModule(null);
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadReport = async () => {
    if (!scanResult || !scanResult.scanId) return;
    try {
      await downloadReportFile(scanResult.scanId, resultModule || activeModule);
    } catch (err) {
      setErrorMessage({
        title: 'Report Download Failed',
        detail: err.message
      });
    }
  };

  const handleDownloadManifest = async () => {
    if (!scanResult || !scanResult.scanId) return;
    try {
      await downloadManifestFile(scanResult.scanId, resultModule || activeModule);
    } catch (err) {
      setErrorMessage({
        title: 'Manifest Export Failed',
        detail: err.message
      });
    }
  };

  const handlePurgeEvidence = async () => {
    if (!scanResult || !scanResult.scanId) return;
    try {
      await deleteServerScan(scanResult.scanId);
      setNotification('Evidence record successfully purged from server memory.');
      handleReset();
    } catch (err) {
      setErrorMessage({
        title: 'Evidence Purge Failed',
        detail: err.message
      });
    }
  };

  const handleReset = () => {
    setScanResult(null);
    setResultModule(null);
    setStagedFile(null);
    setRawText('');
    setErrorMessage(null);
  };

  return (
    <div className="app-shell">
      <Header />
      
      <main className="main-content">
        <ModuleNav
          activeModule={activeModule}
          onSelectModule={(mod) => {
            setActiveModule(mod);
            handleReset();
          }}
          disabled={loading}
        />

        {notification && (
          <div className="notification-banner" role="status">
            <span>✓ {notification}</span>
            <button type="button" className="btn-sm-dismiss" onClick={() => setNotification(null)}>Dismiss</button>
          </div>
        )}

        <ErrorBanner error={errorMessage} onDismiss={() => setErrorMessage(null)} />

        {!scanResult && (
          <div id={`panel-${activeModule}`} role="tabpanel" aria-labelledby={`tab-${activeModule}`}>
            <Dropzone
              activeModule={activeModule}
              stagedFile={stagedFile}
              rawText={rawText}
              onStageFile={handleStageFile}
              onClearFile={handleClearFile}
              onTextChange={setRawText}
              onExecuteScan={handleExecuteScan}
              loading={loading}
            />
          </div>
        )}

        {loading && (
          <div className="processing-indicator" aria-live="polite">
            <div className="spinner-element"></div>
            <p className="processing-title">Running Triage Analysis...</p>
            <p className="processing-sub">Evaluating file structure, computing cryptographic hashes, and validating rules.</p>
          </div>
        )}

        {!loading && scanResult && (
          <div className="results-container" id={`panel-${resultModule || activeModule}`} role="tabpanel">
            <TriageSummary
              result={scanResult}
              activeModule={resultModule || activeModule}
              onDownloadReport={handleDownloadReport}
              onDownloadManifest={handleDownloadManifest}
              onPurgeServerEvidence={handlePurgeEvidence}
              onReset={handleReset}
            />

            <div className="results-split-layout">
              <FindingsTable findings={scanResult.findings || []} />

              {(resultModule || activeModule) === 'email' && (
                <EmailEvidenceView result={scanResult} />
              )}
              {(resultModule || activeModule) === 'image' && (
                <ImageEvidenceView result={scanResult} selectedImageUrl={selectedImageUrl} />
              )}
              {(resultModule || activeModule) === 'text' && (
                <TextEvidenceView result={scanResult} />
              )}
            </div>
          </div>
        )}
      </main>

      <footer className="workstation-footer">
        <div className="footer-author-card">
          <div className="author-meta">
            <span className="author-badge-pill">Creator & Maintainer</span>
            <h3 className="author-name">Utkarsh Gupta</h3>
            <p className="author-tagline">Student & Aspiring SDE • IIT (BHU) Varanasi</p>
          </div>

          <div className="author-links">
            <a 
              href="mailto:gupta.utkarsh.iitbhu@gmail.com" 
              className="author-btn"
              title="Email Developer"
            >
              <span className="btn-icon">✉️</span>
              <span>gupta.utkarsh.iitbhu@gmail.com</span>
            </a>
            <a 
              href="https://github.com/utkarshgupta-iitbhu" 
              target="_blank" 
              rel="noopener noreferrer" 
              className="author-btn"
              title="GitHub Profile"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
              </svg>
              <span>GitHub</span>
            </a>
            <a 
              href="https://github.com/utkarshgupta-iitbhu/EvidenceDesk" 
              target="_blank" 
              rel="noopener noreferrer" 
              className="author-btn primary"
              title="View Repository"
            >
              <span>⭐ Star Repository</span>
            </a>
          </div>
        </div>

        <div className="footer-bottom-line">
          <span>EvidenceDesk v1.2.0 • Digital Evidence Triage Workstation</span>
          <span>•</span>
          <span>Designed & Built by Utkarsh Gupta</span>
        </div>
      </footer>
    </div>
  );
}
