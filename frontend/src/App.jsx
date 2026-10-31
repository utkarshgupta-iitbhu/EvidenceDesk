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
        EvidenceDesk v1.2.0 • Digital Evidence Triage Workstation • Indicators are heuristic and require independent verification.
      </footer>
    </div>
  );
}
