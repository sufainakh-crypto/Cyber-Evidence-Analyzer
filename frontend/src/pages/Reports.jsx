import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { createReport, getEvidence, getCases } from '../services/api';

function Reports() {
  const location = useLocation();
  const [reportScope, setReportScope] = useState('case'); // 'case' | 'evidence'
  const [selectedCaseId, setSelectedCaseId] = useState('');
  const [selectedEvidenceId, setSelectedEvidenceId] = useState('');
  const [reportTitle, setReportTitle] = useState('Digital Forensics & Threat Incident Report');
  const [investigatorNotes, setInvestigatorNotes] = useState('');

  const [availableCases, setAvailableCases] = useState([]);
  const [availableEvidence, setAvailableEvidence] = useState([]);
  const [loading, setLoading] = useState(false);
  const [dataLoading, setDataLoading] = useState(true);
  const [error, setError] = useState(null);
  const [reportResult, setReportResult] = useState(null);

  useEffect(() => {
    // If navigated with state from Case or Evidence or Analyze page
    if (location.state?.case_id) {
      setReportScope('case');
      setSelectedCaseId(location.state.case_id);
    } else if (location.state?.evidence_id) {
      setReportScope('evidence');
      setSelectedEvidenceId(location.state.evidence_id);
    }

    const loadSelectionData = async () => {
      setDataLoading(true);
      try {
        const [casesData, evData] = await Promise.all([
          getCases().catch(() => []),
          getEvidence().catch(() => []),
        ]);
        setAvailableCases(casesData || []);
        setAvailableEvidence(evData || []);

        // Default selection if available
        if (!location.state?.case_id && casesData?.length > 0) {
          setSelectedCaseId(casesData[0].case_id);
        } else if (!location.state?.case_id && casesData?.length === 0 && evData?.length > 0) {
          setReportScope('evidence');
          setSelectedEvidenceId(evData[0].evidence_id);
        }
      } catch (err) {
        console.error("Could not load selection options:", err);
      } finally {
        setDataLoading(false);
      }
    };
    loadSelectionData();
  }, [location.state]);

  const handleGenerateReport = async (e) => {
    e.preventDefault();
    setError(null);
    setReportResult(null);

    let payload = {
      title: reportTitle.trim() || "Digital Forensics & Threat Incident Report",
      description: investigatorNotes.trim() || undefined,
    };

    if (reportScope === 'case') {
      const cid = selectedCaseId.trim();
      if (!cid) {
        setError("Please select or enter an Investigation Case ID.");
        return;
      }
      payload.case_id = cid;
    } else {
      const eid = selectedEvidenceId.trim();
      if (!eid) {
        setError("Please select or enter an Evidence ID.");
        return;
      }
      payload.evidence_ids = [eid];
    }

    setLoading(true);
    try {
      const res = await createReport(payload);
      if (res && res.data) {
        setReportResult(res.data);
      } else {
        throw new Error("Invalid response format received from backend.");
      }
    } catch (err) {
      console.error("Error generating incident report:", err);
      const detail = err.response?.data?.detail;
      setError(detail || "Failed to generate report. Please verify your selection and backend connectivity.");
    } finally {
      setLoading(false);
    }
  };

  const handlePrint = () => {
    window.print();
  };

  const handleDownloadJson = () => {
    if (!reportResult) return;
    const blob = new Blob([JSON.stringify(reportResult, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${reportResult.report_id || 'incident-report'}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const getBadgeClass = (level) => {
    switch (level?.toUpperCase()) {
      case 'LOW': return 'badge-low';
      case 'MEDIUM': return 'badge-medium';
      case 'HIGH': return 'badge-high';
      default: return 'badge-neutral';
    }
  };

  const getIntegrityBadge = (status) => {
    switch (status?.toUpperCase()) {
      case 'VERIFIED':
        return <span className="badge badge-verified">🛡️ VERIFIED (SHA-256)</span>;
      case 'INTEGRITY_MISMATCH':
        return <span className="badge badge-mismatch">⚠️ INTEGRITY MISMATCH</span>;
      case 'UNHASHED_LEGACY':
        return <span className="badge badge-neutral">ℹ️ LEGACY RECORD</span>;
      default:
        return <span className="badge badge-neutral">UNVERIFIED</span>;
    }
  };

  return (
    <div className="page-container report-page-root">
      {/* Configuration Header - hidden during print */}
      <div className="page-header no-print">
        <div>
          <h1 className="page-title">Incident Reports</h1>
          <p className="page-subtitle">
            Generate formal, verifiable digital forensics and cyber threat intelligence incident reports with cryptographic audit trails.
          </p>
        </div>
        {reportResult && (
          <div style={{ display: 'flex', gap: '0.75rem' }}>
            <button className="btn btn-primary" onClick={handlePrint}>
              🖨️ Print / Save as PDF
            </button>
            <button className="btn btn-secondary" onClick={handleDownloadJson}>
              📥 Export JSON
            </button>
          </div>
        )}
      </div>

      {/* Generator Configuration Card - hidden during print */}
      <div className="section-card no-print">
        <div className="section-header">
          <h2>Report Configuration</h2>
          <span className="badge badge-info">Evidence &amp; Case Generator</span>
        </div>

        <form onSubmit={handleGenerateReport} className="report-form">
          <div className="form-group">
            <label className="form-label">Report Target Scope</label>
            <div style={{ display: 'flex', gap: '1rem', marginTop: '0.25rem' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', color: 'var(--text-main)' }}>
                <input
                  type="radio"
                  name="reportScope"
                  value="case"
                  checked={reportScope === 'case'}
                  onChange={() => setReportScope('case')}
                />
                <strong>Investigation Case</strong> (Full case evidence + timeline)
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', color: 'var(--text-main)' }}>
                <input
                  type="radio"
                  name="reportScope"
                  value="evidence"
                  checked={reportScope === 'evidence'}
                  onChange={() => setReportScope('evidence')}
                />
                <strong>Single Evidence Item</strong> (Standalone artifact analysis)
              </label>
            </div>
          </div>

          {reportScope === 'case' ? (
            <div className="form-group">
              <label htmlFor="caseSelectInput" className="form-label">
                Investigation Case <span style={{ color: 'var(--high-color)' }}>*</span>
              </label>
              <div className="input-group">
                <input
                  id="caseSelectInput"
                  type="text"
                  className="input-field"
                  placeholder="Enter or select Case ID (e.g. CASE-001)"
                  value={selectedCaseId}
                  onChange={(e) => setSelectedCaseId(e.target.value)}
                  disabled={loading}
                />
                {availableCases.length > 0 && (
                  <select
                    className="input-field"
                    style={{ maxWidth: '300px', cursor: 'pointer' }}
                    value={selectedCaseId}
                    onChange={(e) => setSelectedCaseId(e.target.value)}
                    disabled={loading}
                  >
                    <option value="">-- Select Case --</option>
                    {availableCases.map((c) => (
                      <option key={c.case_id} value={c.case_id}>
                        {c.case_id}: {c.title.substring(0, 24)} ({c.evidence_count} items)
                      </option>
                    ))}
                  </select>
                )}
              </div>
              <small className="form-hint">
                Select an open or reviewed case to aggregate all associated evidence records and chronological timeline.
              </small>
            </div>
          ) : (
            <div className="form-group">
              <label htmlFor="evidenceSelectInput" className="form-label">
                Evidence ID <span style={{ color: 'var(--high-color)' }}>*</span>
              </label>
              <div className="input-group">
                <input
                  id="evidenceSelectInput"
                  type="text"
                  className="input-field"
                  placeholder="Enter or select Evidence ID (UUID or EV-001)"
                  value={selectedEvidenceId}
                  onChange={(e) => setSelectedEvidenceId(e.target.value)}
                  disabled={loading}
                />
                {availableEvidence.length > 0 && (
                  <select
                    className="input-field"
                    style={{ maxWidth: '300px', cursor: 'pointer' }}
                    value={selectedEvidenceId}
                    onChange={(e) => setSelectedEvidenceId(e.target.value)}
                    disabled={loading}
                  >
                    <option value="">-- Select Evidence --</option>
                    {availableEvidence.map((ev) => (
                      <option key={ev.evidence_id} value={ev.evidence_id}>
                        {ev.evidence_id.substring(0, 8)}: {(ev.input_value || ev.input).substring(0, 20)} ({ev.risk_level})
                      </option>
                    ))}
                  </select>
                )}
              </div>
            </div>
          )}

          <div className="form-group">
            <label htmlFor="reportTitleInput" className="form-label">Report Title</label>
            <input
              id="reportTitleInput"
              type="text"
              className="input-field"
              value={reportTitle}
              onChange={(e) => setReportTitle(e.target.value)}
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label htmlFor="notesInput" className="form-label">Investigator Notes &amp; Observations</label>
            <textarea
              id="notesInput"
              className="input-field textarea-field"
              rows="3"
              placeholder="Document chain-of-custody context, investigative hypothesis, or incident response actions taken..."
              value={investigatorNotes}
              onChange={(e) => setInvestigatorNotes(e.target.value)}
              disabled={loading}
            />
          </div>

          <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.5rem' }}>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? '⏳ Generating Forensic Report...' : '📄 Generate Incident Report'}
            </button>
          </div>
        </form>

        {error && (
          <div className="state-message error-box" style={{ marginTop: '1rem', padding: '1rem' }}>
            <span className="error-icon">⚠️</span>
            <p className="error-text">{error}</p>
          </div>
        )}
      </div>

      {/* Formal Printable Incident Report Sheet */}
      {reportResult ? (
        <div className="report-paper-container">
          <div className="printable-report-sheet">
            {/* Report Header */}
            <div className="report-doc-header">
              <div className="report-brand">
                <div className="report-logo">🛡️</div>
                <div>
                  <h1 className="report-main-title">CYBER INCIDENT FORENSIC REPORT</h1>
                  <span className="report-sub-title">OPCODE IMPACT 2026 — DIGITAL FORENSICS &amp; THREAT INTELLIGENCE</span>
                </div>
              </div>
              <div className="report-meta-box">
                <div><strong>Report ID:</strong> <code>{reportResult.report_id}</code></div>
                <div><strong>Generated:</strong> {new Date(reportResult.generated_at).toLocaleString()}</div>
                <div><strong>Classification:</strong> OFFICIAL INVESTIGATION RECORD</div>
              </div>
            </div>

            {/* Title & Case Banner */}
            <div className="report-section-title-banner">
              <h2>{reportResult.title}</h2>
              {reportResult.case && (
                <div className="report-case-pill">
                  <span>Case: <strong>{reportResult.case.case_id}</strong> — {reportResult.case.title}</span>
                  <span className="badge badge-info">Status: {reportResult.case.status}</span>
                </div>
              )}
            </div>

            {/* Investigator Notes */}
            {reportResult.description && (
              <div className="report-doc-section">
                <h3 className="report-section-heading">1. Investigator Observations &amp; Incident Scope</h3>
                <div className="report-notes-box">
                  <p>{reportResult.description}</p>
                </div>
              </div>
            )}

            {/* Executive Risk Summary */}
            <div className="report-doc-section">
              <h3 className="report-section-heading">2. Executive Risk &amp; Threat Summary</h3>
              <div className="report-stats-grid">
                <div className="report-stat-card">
                  <span className="report-stat-label">Total Artifacts Analyzed</span>
                  <span className="report-stat-value">{reportResult.summary.total_artifacts}</span>
                </div>
                <div className="report-stat-card">
                  <span className="report-stat-label">Overall Risk Rating</span>
                  <span className={`report-stat-value ${getBadgeClass(reportResult.summary.overall_risk_level)}`} style={{ padding: '0.2rem 0.6rem', borderRadius: '4px' }}>
                    {reportResult.summary.overall_risk_level}
                  </span>
                </div>
                <div className="report-stat-card">
                  <span className="report-stat-label">Average Risk Score</span>
                  <span className="report-stat-value">{reportResult.summary.average_risk_score} / 100</span>
                </div>
                <div className="report-stat-card">
                  <span className="report-stat-label">Risk Distribution</span>
                  <span style={{ fontSize: '0.9rem', color: 'var(--text-main)', marginTop: '0.25rem' }}>
                    🟢 {reportResult.summary.low_count} Low &nbsp;|&nbsp; 
                    🟡 {reportResult.summary.medium_count} Med &nbsp;|&nbsp; 
                    🔴 {reportResult.summary.high_count} High
                  </span>
                </div>
              </div>
            </div>

            {/* Evidence Inventory with Cryptographic Integrity */}
            <div className="report-doc-section">
              <h3 className="report-section-heading">3. Evidence Item Inventory &amp; Cryptographic Integrity Verification</h3>
              <div className="table-container">
                <table className="evidence-table" style={{ fontSize: '0.85rem' }}>
                  <thead>
                    <tr>
                      <th>Evidence ID</th>
                      <th>Artifact Input</th>
                      <th>Type</th>
                      <th>Risk</th>
                      <th>Cryptographic Integrity Status</th>
                      <th>Timestamp</th>
                    </tr>
                  </thead>
                  <tbody>
                    {reportResult.evidence_records.map((ev) => (
                      <tr key={ev.evidence_id}>
                        <td><code>{ev.evidence_id.substring(0, 10)}...</code></td>
                        <td className="input-cell" title={ev.input_value}><strong>{ev.input_value}</strong></td>
                        <td><span className="type-tag">{ev.input_type}</span></td>
                        <td>
                          <span className={`badge ${getBadgeClass(ev.risk_level)}`}>
                            {ev.risk_level} ({ev.risk_score})
                          </span>
                        </td>
                        <td>
                          {getIntegrityBadge(ev.integrity_verification?.status)}
                        </td>
                        <td className="time-cell">{ev.timestamp ? new Date(ev.timestamp).toLocaleString() : 'N/A'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Integrity detail per evidence */}
              <div style={{ marginTop: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {reportResult.evidence_records.map((ev) => (
                  <div key={ev.evidence_id} className="integrity-detail-line">
                    <span style={{ minWidth: '100px' }}><code>{ev.evidence_id.substring(0, 8)}</code>:</span>
                    <span style={{ color: 'var(--text-muted)' }}>SHA-256 Hash:</span>
                    <code style={{ wordBreak: 'break-all', fontSize: '0.8rem', color: 'var(--accent-color)' }}>
                      {ev.sha256_hash || 'No hash recorded'}
                    </code>
                  </div>
                ))}
              </div>
            </div>

            {/* Detailed Findings per Artifact */}
            <div className="report-doc-section">
              <h3 className="report-section-heading">4. Forensic Analysis &amp; Threat Intelligence Details</h3>
              {reportResult.evidence_records.map((ev, index) => (
                <div key={ev.evidence_id} className="report-evidence-deep-card">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                    <h4 style={{ margin: 0, fontSize: '0.95rem' }}>
                      Artifact #{index + 1}: <code>{ev.input_value}</code> ({ev.input_type.toUpperCase()})
                    </h4>
                    <span className={`badge ${getBadgeClass(ev.risk_level)}`}>
                      Score: {ev.risk_score} / 100 — {ev.risk_level}
                    </span>
                  </div>

                  {ev.findings && (
                    <div style={{ marginBottom: '0.5rem' }}>
                      <strong style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Heuristic Findings:</strong>
                      <p style={{ margin: '0.2rem 0', fontSize: '0.85rem', color: 'var(--text-main)', lineHeight: 1.4 }}>
                        {ev.findings}
                      </p>
                    </div>
                  )}

                  {ev.threat_intelligence_summary && (
                    <div style={{ marginBottom: '0.5rem' }}>
                      <strong style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Threat Intelligence Summary:</strong>
                      <p style={{ margin: '0.2rem 0', fontSize: '0.85rem', color: 'var(--text-main)', lineHeight: 1.4 }}>
                        {ev.threat_intelligence_summary}
                      </p>
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* Investigation Timeline */}
            {reportResult.timeline && reportResult.timeline.length > 0 && (
              <div className="report-doc-section">
                <h3 className="report-section-heading">5. Chronological Investigation Timeline</h3>
                <div className="timeline-container">
                  {reportResult.timeline.map((evt, idx) => (
                    <div key={idx} className="timeline-item">
                      <div className="timeline-marker"></div>
                      <div className="timeline-content">
                        <div className="timeline-header">
                          <strong className="timeline-title">{evt.title}</strong>
                          <span className="timeline-time">
                            {evt.timestamp ? new Date(evt.timestamp).toLocaleString() : 'N/A'}
                          </span>
                        </div>
                        <p className="timeline-details">{evt.details}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Cross-Evidence Correlations if present */}
            {reportResult.correlations && reportResult.correlations.length > 0 && (
              <div className="report-doc-section">
                <h3 className="report-section-heading">6. Cross-Evidence Correlation Findings</h3>
                <div className="correlation-list">
                  {reportResult.correlations.map((rel) => (
                    <div key={rel.relationship_id} className="correlation-card" style={{ padding: '0.75rem' }}>
                      <div className="correlation-header">
                        <span style={{ fontSize: '0.85rem' }}>
                          <code>{rel.source_input}</code> ⇄ <code>{rel.target_input}</code>
                        </span>
                        <span className="badge badge-info">{rel.relationship_type} ({rel.confidence_level} Confidence)</span>
                      </div>
                      <p style={{ fontSize: '0.82rem', margin: '0.35rem 0' }}>{rel.explanation}</p>
                      <div className="caveat-box" style={{ fontSize: '0.75rem', padding: '0.4rem 0.6rem' }}>
                        ⚖️ {rel.forensic_caveat}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Forensic Limitations & Methodological Disclaimers */}
            <div className="report-doc-section">
              <h3 className="report-section-heading">7. Methodological Limitations &amp; Disclaimers</h3>
              <div className="report-limitations-list">
                {reportResult.limitations.map((lim, i) => (
                  <div key={i} className="limitation-item">
                    <strong>⚠️ {lim.title}:</strong>
                    <p>{lim.content}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Sign-off footer */}
            <div className="report-sign-off">
              <div className="sign-block">
                <div className="sign-line"></div>
                <span>Lead Forensic Investigator</span>
              </div>
              <div className="sign-block">
                <div className="sign-line"></div>
                <span>Incident Response Supervisor</span>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="section-card no-print">
          <div className="empty-state">
            <span className="empty-icon">📋</span>
            <p className="empty-title">Ready to Generate Incident Report</p>
            <p className="empty-text">Select a Case or Evidence Item above and click "Generate Incident Report" to build a verifiable forensic report.</p>
          </div>
        </div>
      )}
    </div>
  );
}

export default Reports;
