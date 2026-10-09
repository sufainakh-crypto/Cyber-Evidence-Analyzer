import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { analyzeInput } from '../services/api';

function Analyze() {
  const [inputVal, setInputVal] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const [copied, setCopied] = useState(false);
  const navigate = useNavigate();

  const handleAnalyze = async (e) => {
    e.preventDefault();
    const cleanInput = inputVal.trim();
    if (!cleanInput) {
      setError("Please enter a valid URL, IP address, or domain.");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);
    setCopied(false);

    try {
      const data = await analyzeInput(cleanInput);
      setResult(data);
    } catch (err) {
      console.error("Error analyzing input:", err);
      const backendMsg = err.response?.data?.detail;
      if (backendMsg) {
        setError(backendMsg);
      } else {
        setError("Unable to complete analysis. Please make sure the FastAPI backend is running at http://127.0.0.1:8000.");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleCopyId = () => {
    if (result?.evidence_id) {
      navigator.clipboard.writeText(result.evidence_id);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const getBadgeClass = (level) => {
    switch (level?.toUpperCase()) {
      case 'LOW': return 'badge-low';
      case 'MEDIUM': return 'badge-medium';
      case 'HIGH': return 'badge-high';
      default: return 'badge-neutral';
    }
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">Analyze a Threat</h1>
          <p className="page-subtitle">
            Enter a suspicious URL, IP address, or domain for basic threat analysis.
          </p>
        </div>
      </div>

      <div className="section-card">
        <form onSubmit={handleAnalyze} className="analyze-form">
          <div className="form-group">
            <label htmlFor="threatInput" className="form-label">
              Artifact to Analyze
            </label>
            <div className="input-group">
              <input
                id="threatInput"
                type="text"
                className="input-field"
                placeholder="Enter URL, IP address, or domain..."
                value={inputVal}
                onChange={(e) => {
                  setInputVal(e.target.value);
                  if (error) setError(null);
                }}
                disabled={loading}
              />
              <button type="submit" className="btn btn-primary btn-analyze" disabled={loading}>
                {loading ? '⏳ Analyzing...' : 'Analyze Threat'}
              </button>
            </div>
            <small className="form-hint">
              Examples: <code>https://example.com</code>, <code>8.8.8.8</code>, <code>example.com</code>
            </small>
          </div>
        </form>

        {error && (
          <div className="state-message error-box" style={{ marginTop: '0.75rem', padding: '1rem' }}>
            <span className="error-icon" style={{ fontSize: '1.25rem' }}>⚠️</span>
            <p className="error-text">{error}</p>
          </div>
        )}
      </div>

      {/* Result Section */}
      <div className="section-card">
        <div className="section-header">
          <h2>Analysis Results</h2>
          <span className={`badge ${result ? getBadgeClass(result.risk_level) : 'badge-neutral'}`}>
            {result ? result.risk_level : 'Waiting for Input'}
          </span>
        </div>

        {loading ? (
          <div className="state-message">
            <span className="spinner">⏳</span>
            <p className="loading-text">Analyzing...</p>
          </div>
        ) : result ? (
          <div className="result-container">
            <div className="detail-grid">
              <div className="detail-item full-width">
                <span className="detail-label">Evidence ID</span>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
                  <code className="detail-code">{result.evidence_id}</code>
                  <button className="btn btn-secondary btn-sm" onClick={handleCopyId}>
                    {copied ? '✓ Copied!' : '📋 Copy ID'}
                  </button>
                  <button
                    className="btn btn-primary btn-sm"
                    onClick={() => navigate('/reports', { state: { evidence_id: result.evidence_id } })}
                  >
                    📄 Generate Report
                  </button>
                </div>
              </div>

              <div className="detail-item">
                <span className="detail-label">Input</span>
                <span className="detail-value highlight">{result.input}</span>
              </div>

              <div className="detail-item">
                <span className="detail-label">Input Type</span>
                <span className="type-tag">{result.input_type}</span>
              </div>

              <div className="detail-item">
                <span className="detail-label">Risk Score</span>
                <span className="detail-value" style={{ fontWeight: 700, fontSize: '1.2rem' }}>
                  {result.risk_score} / 100
                </span>
              </div>

              <div className="detail-item">
                <span className="detail-label">Risk Level</span>
                <span className={`badge ${getBadgeClass(result.risk_level)}`}>
                  {result.risk_level}
                </span>
              </div>

              <div className="detail-item">
                <span className="detail-label">Timestamp</span>
                <span className="detail-value">{new Date(result.timestamp).toLocaleString()}</span>
              </div>

              {result.url && (
                <div className="detail-item">
                  <span className="detail-label">URL</span>
                  <span className="detail-value">{result.url}</span>
                </div>
              )}

              {result.domain && (
                <div className="detail-item">
                  <span className="detail-label">Domain</span>
                  <span className="detail-value">{result.domain}</span>
                </div>
              )}

              {result.ip_address && (
                <div className="detail-item">
                  <span className="detail-label">IP Address</span>
                  <span className="detail-value">{result.ip_address}</span>
                </div>
              )}
            </div>

            {result.findings && (
              <div className="detail-section" style={{ marginTop: '1.25rem' }}>
                <span className="detail-label">Findings</span>
                <p className="detail-text-box">{result.findings}</p>
              </div>
            )}

            {result.threat_intelligence_sources && result.threat_intelligence_sources.length > 0 && (
              <div className="detail-section" style={{ marginTop: '1rem' }}>
                <span className="detail-label">Threat Intelligence Sources</span>
                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.25rem' }}>
                  {result.threat_intelligence_sources.map((src) => (
                    <span key={src} className="badge badge-info">{src}</span>
                  ))}
                </div>
              </div>
            )}

            {result.threat_intelligence_summary && (
              <div className="detail-section" style={{ marginTop: '1rem' }}>
                <span className="detail-label">Threat Intelligence Summary</span>
                <p className="detail-text-box intel-summary">{result.threat_intelligence_summary}</p>
              </div>
            )}

            <div className="disclaimer-note" style={{ marginTop: '1.25rem' }}>
              ℹ️ Note: Risk assessment is based on heuristic signals and external threat intelligence indicators. Does not guarantee malware detection.
            </div>
          </div>
        ) : (
          <div className="empty-state">
            <span className="empty-icon">🔍</span>
            <p className="empty-title">Ready for Threat Analysis</p>
            <p className="empty-text">Enter a URL, IP address, or domain above and click "Analyze Threat" to generate an evidence report.</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default Analyze;
