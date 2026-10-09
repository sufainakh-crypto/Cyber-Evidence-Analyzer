import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { analyzeInput, getCases } from '../services/api';

function Analyze() {
  const navigate = useNavigate();
  const location = useLocation();

  const [inputVal, setInputVal] = useState('');
  const [selectedCaseId, setSelectedCaseId] = useState('');
  const [availableCases, setAvailableCases] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const [copiedId, setCopiedId] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);

  useEffect(() => {
    // If navigated from Cases page with a specific case
    if (location.state?.case_id) {
      setSelectedCaseId(location.state.case_id);
    }
    // Load cases for selection dropdown
    const loadCasesList = async () => {
      try {
        const cases = await getCases();
        setAvailableCases(cases || []);
      } catch (err) {
        console.warn("Could not load cases list for analyze dropdown:", err);
      }
    };
    loadCasesList();
  }, [location.state]);

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
    setCopiedId(false);
    setCopiedHash(false);

    try {
      const data = await analyzeInput(cleanInput, selectedCaseId.trim() || null);
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
      setCopiedId(true);
      setTimeout(() => setCopiedId(false), 2000);
    }
  };

  const handleCopyHash = () => {
    if (result?.sha256_hash) {
      navigator.clipboard.writeText(result.sha256_hash);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
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

  const getSourceStatusBadge = (item) => {
    if (item.status === 'success') {
      return <span className="badge badge-verified">LIVE / RESPONDED</span>;
    }
    if (item.status === 'key_missing') {
      return <span className="badge badge-neutral">NOT CONFIGURED (.env)</span>;
    }
    if (item.status === 'not_applicable') {
      return <span className="badge badge-neutral">N/A FOR TYPE</span>;
    }
    return <span className="badge badge-mismatch">UNAVAILABLE / TIMEOUT</span>;
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">Analyze a Threat Artifact</h1>
          <p className="page-subtitle">
            Forensic heuristic evaluation, transparent risk scoring, cryptographic hashing, and threat intelligence ingestion.
          </p>
        </div>
      </div>

      <div className="section-card">
        <form onSubmit={handleAnalyze} className="analyze-form">
          <div className="form-group">
            <label htmlFor="threatInput" className="form-label">
              Artifact to Analyze <span style={{ color: 'var(--high-color)' }}>*</span>
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
              Examples: <code>https://malicious-example.xyz/login</code>, <code>198.51.100.22</code>, <code>phish-portal.top</code>
            </small>
          </div>

          {/* Optional Investigation Case Selection */}
          <div className="form-group" style={{ marginTop: '0.75rem' }}>
            <label htmlFor="caseSelect" className="form-label">
              Associate with Investigation Case (Optional)
            </label>
            <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
              <select
                id="caseSelect"
                className="input-field"
                style={{ maxWidth: '350px' }}
                value={selectedCaseId}
                onChange={(e) => setSelectedCaseId(e.target.value)}
                disabled={loading}
              >
                <option value="">-- Standalone (No Case) --</option>
                {availableCases.map((c) => (
                  <option key={c.case_id} value={c.case_id}>
                    {c.case_id}: {c.title.substring(0, 28)}
                  </option>
                ))}
              </select>
              {selectedCaseId && (
                <span className="badge badge-info">
                  Will attach to: {selectedCaseId}
                </span>
              )}
            </div>
            <small className="form-hint">
              Associating evidence with a case aggregates it into the case investigation timeline and cross-evidence map.
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
          <h2>Analysis &amp; Explainable Risk Assessment</h2>
          <span className={`badge ${result ? getBadgeClass(result.risk_level) : 'badge-neutral'}`}>
            {result ? `${result.risk_level} RISK (${result.risk_score}/100)` : 'Waiting for Input'}
          </span>
        </div>

        {loading ? (
          <div className="state-message">
            <span className="spinner">⏳</span>
            <p className="loading-text">Executing heuristic rule matrix and threat intelligence queries...</p>
          </div>
        ) : result ? (
          <div className="result-container">
            {/* Top Evidence Identity & Action Bar */}
            <div className="detail-grid">
              <div className="detail-item full-width">
                <span className="detail-label">Evidence ID (Unique Forensic Identifier)</span>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
                  <code className="detail-code">{result.evidence_id}</code>
                  <button className="btn btn-secondary btn-sm" onClick={handleCopyId}>
                    {copiedId ? '✓ Copied ID' : '📋 Copy ID'}
                  </button>
                  {result.case_id && (
                    <button
                      className="btn btn-secondary btn-sm"
                      onClick={() => navigate('/cases', { state: { case_id: result.case_id } })}
                    >
                      📁 View in Case ({result.case_id})
                    </button>
                  )}
                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => navigate('/correlation', { state: { evidence_id: result.evidence_id } })}
                  >
                    🔗 Check Correlations
                  </button>
                  <button
                    className="btn btn-primary btn-sm"
                    onClick={() => navigate('/reports', { state: { evidence_id: result.evidence_id } })}
                  >
                    📄 Generate Incident Report
                  </button>
                </div>
              </div>

              {result.sha256_hash && (
                <div className="detail-item full-width">
                  <span className="detail-label">Cryptographic Integrity Hash (SHA-256 Canonical Signature)</span>
                  <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
                    <code className="detail-code" style={{ fontSize: '0.82rem', wordBreak: 'break-all' }}>
                      {result.sha256_hash}
                    </code>
                    <button className="btn btn-secondary btn-sm" onClick={handleCopyHash}>
                      {copiedHash ? '✓ Copied Hash' : '📋 Copy Hash'}
                    </button>
                    <span className="badge badge-verified">PROTECTED FIELD HASH</span>
                  </div>
                  <small style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                    Canonical SHA-256 hash calculated over protected evidence fields to provide verifiable tamper-detection.
                  </small>
                </div>
              )}

              <div className="detail-item">
                <span className="detail-label">Analyzed Input</span>
                <span className="detail-value highlight">{result.input}</span>
              </div>

              <div className="detail-item">
                <span className="detail-label">Input Type</span>
                <span className="type-tag">{result.input_type}</span>
              </div>

              <div className="detail-item">
                <span className="detail-label">Final Risk Score</span>
                <span className="detail-value" style={{ fontWeight: 700, fontSize: '1.25rem' }}>
                  {result.risk_score} / 100
                </span>
              </div>

              <div className="detail-item">
                <span className="detail-label">Risk Classification</span>
                <span className={`badge ${getBadgeClass(result.risk_level)}`}>
                  {result.risk_level}
                </span>
              </div>

              <div className="detail-item">
                <span className="detail-label">Ingestion Timestamp</span>
                <span className="detail-value">{new Date(result.timestamp).toLocaleString()}</span>
              </div>

              {result.url && (
                <div className="detail-item">
                  <span className="detail-label">Extracted URL</span>
                  <span className="detail-value">{result.url}</span>
                </div>
              )}

              {result.domain && (
                <div className="detail-item">
                  <span className="detail-label">Extracted Domain</span>
                  <span className="detail-value">{result.domain}</span>
                </div>
              )}

              {result.ip_address && (
                <div className="detail-item">
                  <span className="detail-label">Extracted IP Address</span>
                  <span className="detail-value">{result.ip_address}</span>
                </div>
              )}
            </div>

            {/* FEATURE 2: EXPLAINABLE RISK BREAKDOWN */}
            <div style={{ marginTop: '1.5rem', paddingTop: '1.25rem', borderTop: '1px solid var(--border-color)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                <h3 style={{ fontSize: '1.1rem', margin: 0, color: 'var(--text-main)' }}>
                  🔍 Explainable Risk Assessment &amp; Rule Matrix
                </h3>
                <span className="badge badge-info">Documented Scoring Method</span>
              </div>

              {/* 1. Local Heuristics Breakdown */}
              <div style={{ marginBottom: '1.25rem' }}>
                <h4 style={{ fontSize: '0.92rem', color: 'var(--text-muted)', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  A. Local Static &amp; Structural Heuristics
                </h4>
                {result.heuristic_breakdown && result.heuristic_breakdown.length > 0 ? (
                  <div className="heuristic-rule-grid">
                    {result.heuristic_breakdown.map((rule, idx) => (
                      <div key={idx} className="heuristic-rule-card">
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                          <strong style={{ fontSize: '0.88rem' }}>{rule.rule}</strong>
                          <span className={`badge ${rule.delta > 0 ? 'badge-high' : 'badge-neutral'}`} style={{ fontSize: '0.75rem' }}>
                            {rule.delta > 0 ? `+${rule.delta} pts` : '0 pts'}
                          </span>
                        </div>
                        <p style={{ margin: 0, fontSize: '0.8rem', color: 'var(--text-main)', lineHeight: 1.35 }}>
                          {rule.detail}
                        </p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="detail-text-box">{result.findings}</p>
                )}
              </div>

              {/* 2. External Threat Intelligence Status & Breakdown */}
              <div style={{ marginBottom: '1.25rem' }}>
                <h4 style={{ fontSize: '0.92rem', color: 'var(--text-muted)', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  B. External Threat Intelligence Sources &amp; Verification Status
                </h4>
                {result.threat_intel_breakdown && result.threat_intel_breakdown.length > 0 ? (
                  <div className="ti-sources-grid">
                    {result.threat_intel_breakdown.map((src, idx) => (
                      <div key={idx} className="ti-source-card">
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                          <strong style={{ fontSize: '0.92rem' }}>{src.source}</strong>
                          {getSourceStatusBadge(src)}
                        </div>
                        <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--text-main)', lineHeight: 1.4 }}>
                          {src.explanation}
                        </p>
                        {src.score_delta > 0 && (
                          <div style={{ marginTop: '0.4rem', fontSize: '0.8rem', color: 'var(--high-color)', fontWeight: 600 }}>
                            Score adjustment: +{src.score_delta} pts
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="detail-text-box">{result.threat_intelligence_summary || "No external threat intelligence feeds queried."}</p>
                )}
              </div>

              {/* 3. Transparent Forensic Disclaimers & Methodology */}
              <div className="caveat-box" style={{ marginTop: '1rem', lineHeight: 1.5 }}>
                <div style={{ fontWeight: 600, marginBottom: '0.25rem' }}>
                  ⚖️ Transparent Forensic Methodology &amp; Disclaimers:
                </div>
                <ul style={{ margin: 0, paddingLeft: '1.25rem', fontSize: '0.82rem' }}>
                  <li>
                    <strong>Preliminary Assessment:</strong> Risk score is a preliminary heuristic triage assessment; it does not guarantee malware detection or absence of malicious intent.
                  </li>
                  <li>
                    <strong>Threat Intelligence Coverage:</strong> Unconfigured or missing external API responses (e.g., missing API keys) are <em>never</em> treated as proof that an artifact is benign. Absence of evidence is not evidence of absence.
                  </li>
                  <li>
                    <strong>HTTPS Transport Limitation:</strong> Valid HTTPS/TLS certificates merely indicate transport encryption; threat actors and phishing campaigns frequently deploy HTTPS certificates.
                  </li>
                </ul>
              </div>
            </div>
          </div>
        ) : (
          <div className="empty-state">
            <span className="empty-icon">🔍</span>
            <p className="empty-title">Ready for Threat Analysis</p>
            <p className="empty-text">Enter a URL, IP address, or domain above and click "Analyze Threat" to run heuristic rule inspection and cryptographic integrity hashing.</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default Analyze;
