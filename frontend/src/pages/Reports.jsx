import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { createReport, getEvidence, getEvidenceById } from '../services/api';

function Reports() {
  const location = useLocation();
  const [evidenceId, setEvidenceId] = useState('');
  const [reportTitle, setReportTitle] = useState('Cyber Incident Evidence Report');
  const [reportDesc, setReportDesc] = useState('');
  const [availableEvidence, setAvailableEvidence] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [reportResult, setReportResult] = useState(null);
  const [evidenceDetail, setEvidenceDetail] = useState(null);

  useEffect(() => {
    // If navigated from Analyze page with state
    if (location.state?.evidence_id) {
      setEvidenceId(location.state.evidence_id);
    }

    // Load available evidence list for easy selection
    const loadEvidenceList = async () => {
      try {
        const data = await getEvidence();
        setAvailableEvidence(data || []);
      } catch (err) {
        console.error("Could not load evidence list for selection:", err);
      }
    };
    loadEvidenceList();
  }, [location.state]);

  const handleGenerateReport = async (e) => {
    e.preventDefault();
    const cleanId = evidenceId.trim();
    if (!cleanId) {
      setError("Please provide a valid Evidence ID.");
      return;
    }

    setLoading(true);
    setError(null);
    setReportResult(null);
    setEvidenceDetail(null);

    const payload = {
      title: reportTitle.trim() || "Cyber Incident Evidence Report",
      description: reportDesc.trim() || undefined,
      evidence_ids: [cleanId],
    };

    try {
      // Call POST /reports
      const reportResponse = await createReport(payload);
      setReportResult(reportResponse);

      // Attempt to load the associated evidence details for enriched report preview
      try {
        const detail = await getEvidenceById(cleanId);
        setEvidenceDetail(detail);
      } catch (detailErr) {
        console.warn("Could not fetch associated evidence details:", detailErr);
      }
    } catch (err) {
      console.error("Error generating report:", err);
      setError("Unable to generate the report. Please check the Evidence ID and make sure the FastAPI backend is running.");
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setEvidenceId('');
    setReportTitle('Cyber Incident Evidence Report');
    setReportDesc('');
    setError(null);
    setReportResult(null);
    setEvidenceDetail(null);
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
          <h1 className="page-title">Incident Reports</h1>
          <p className="page-subtitle">
            Generate formal cyber threat intelligence and incident analysis reports from analyzed evidence items.
          </p>
        </div>
      </div>

      <div className="section-card">
        <div className="section-header">
          <h2>Generate Incident Report</h2>
          <span className="badge badge-info">Report Builder</span>
        </div>

        <form onSubmit={handleGenerateReport} className="report-form">
          <div className="form-group">
            <label htmlFor="evidenceIdInput" className="form-label">
              Evidence ID <span style={{ color: 'var(--high-color)' }}>*</span>
            </label>
            <div className="input-group">
              <input
                id="evidenceIdInput"
                type="text"
                className="input-field"
                placeholder="Enter or paste an Evidence ID (UUID)"
                value={evidenceId}
                onChange={(e) => setEvidenceId(e.target.value)}
                disabled={loading}
              />
              {availableEvidence.length > 0 && (
                <select
                  className="input-field"
                  style={{ maxWidth: '280px', cursor: 'pointer' }}
                  onChange={(e) => {
                    if (e.target.value) setEvidenceId(e.target.value);
                  }}
                  value={evidenceId}
                  disabled={loading}
                >
                  <option value="">-- Or Select Existing --</option>
                  {availableEvidence.map((ev) => (
                    <option key={ev.evidence_id || ev.id} value={ev.evidence_id}>
                      {(ev.input_value || ev.input || '').substring(0, 22)} ({ev.risk_level})
                    </option>
                  ))}
                </select>
              )}
            </div>
            <small className="form-hint">
              Select from previously analyzed evidence records or paste an Evidence ID.
            </small>
          </div>

          <div className="form-group">
            <label htmlFor="reportTitleInput" className="form-label">
              Report Title
            </label>
            <input
              id="reportTitleInput"
              type="text"
              className="input-field"
              placeholder="e.g., Cyber Incident Analysis Report"
              value={reportTitle}
              onChange={(e) => setReportTitle(e.target.value)}
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label htmlFor="reportDescInput" className="form-label">
              Incident Description / Notes (Optional)
            </label>
            <textarea
              id="reportDescInput"
              className="input-field textarea-field"
              rows="3"
              placeholder="Brief description or investigation findings..."
              value={reportDesc}
              onChange={(e) => setReportDesc(e.target.value)}
              disabled={loading}
            ></textarea>
          </div>

          <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.5rem' }}>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? '⏳ Generating report...' : '📄 Generate Incident Report'}
            </button>
            <button type="button" className="btn btn-secondary" onClick={handleClear} disabled={loading}>
              ✕ Clear
            </button>
          </div>
        </form>
      </div>

      {/* Generated Report Section */}
      <div className="section-card">
        <div className="section-header">
          <h2>Report Preview</h2>
          <span className={`badge ${reportResult ? 'badge-info' : 'badge-neutral'}`}>
            {reportResult ? 'Report Output' : 'No Report Generated'}
          </span>
        </div>

        {loading ? (
          <div className="state-message">
            <span className="spinner">⏳</span>
            <p className="loading-text">Generating report...</p>
          </div>
        ) : error ? (
          <div className="state-message error-box">
            <span className="error-icon">⚠️</span>
            <p className="error-text">{error}</p>
          </div>
        ) : reportResult ? (
          <div className="modal-body" style={{ padding: 0 }}>
            {/* Backend Response Details */}
            <div className="detail-grid">
              {reportResult.message && (
                <div className="detail-item full-width">
                  <span className="detail-label">Backend Status</span>
                  <span className="detail-value highlight">{reportResult.message}</span>
                </div>
              )}

              {reportResult.data?.title && (
                <div className="detail-item">
                  <span className="detail-label">Report Title</span>
                  <span className="detail-value" style={{ fontWeight: 600 }}>{reportResult.data.title}</span>
                </div>
              )}

              {reportResult.data?.evidence_ids && (
                <div className="detail-item">
                  <span className="detail-label">Included Evidence IDs</span>
                  <span className="detail-value">
                    {reportResult.data.evidence_ids.map((id) => (
                      <code key={id} className="evidence-code" style={{ marginRight: '0.5rem' }}>{id}</code>
                    ))}
                  </span>
                </div>
              )}

              {reportResult.data?.description && (
                <div className="detail-item full-width">
                  <span className="detail-label">Description / Summary</span>
                  <p className="detail-text-box">{reportResult.data.description}</p>
                </div>
              )}
            </div>

            {/* Associated Evidence Details if retrieved */}
            {evidenceDetail && (
              <div style={{ marginTop: '1.25rem', paddingTop: '1.25rem', borderTop: '1px solid var(--border-color)' }}>
                <h3 style={{ fontSize: '1.1rem', marginBottom: '1rem', color: 'var(--text-main)' }}>
                  Associated Evidence Information
                </h3>
                <div className="detail-grid">
                  <div className="detail-item">
                    <span className="detail-label">Input Target</span>
                    <span className="detail-value highlight">{evidenceDetail.input_value || evidenceDetail.input}</span>
                  </div>

                  <div className="detail-item">
                    <span className="detail-label">Input Type</span>
                    <span className="type-tag">{evidenceDetail.input_type}</span>
                  </div>

                  <div className="detail-item">
                    <span className="detail-label">Risk Score</span>
                    <span className="detail-value">{evidenceDetail.risk_score} / 100</span>
                  </div>

                  <div className="detail-item">
                    <span className="detail-label">Risk Level</span>
                    <span className={`badge ${getBadgeClass(evidenceDetail.risk_level)}`}>
                      {evidenceDetail.risk_level}
                    </span>
                  </div>

                  {evidenceDetail.timestamp && (
                    <div className="detail-item">
                      <span className="detail-label">Timestamp</span>
                      <span className="detail-value">{new Date(evidenceDetail.timestamp).toLocaleString()}</span>
                    </div>
                  )}

                  {evidenceDetail.url && (
                    <div className="detail-item">
                      <span className="detail-label">URL</span>
                      <span className="detail-value">{evidenceDetail.url}</span>
                    </div>
                  )}

                  {evidenceDetail.domain && (
                    <div className="detail-item">
                      <span className="detail-label">Domain</span>
                      <span className="detail-value">{evidenceDetail.domain}</span>
                    </div>
                  )}

                  {evidenceDetail.ip_address && (
                    <div className="detail-item">
                      <span className="detail-label">IP Address</span>
                      <span className="detail-value">{evidenceDetail.ip_address}</span>
                    </div>
                  )}
                </div>

                {evidenceDetail.findings && (
                  <div className="detail-section" style={{ marginTop: '1rem' }}>
                    <span className="detail-label">Findings</span>
                    <p className="detail-text-box">{evidenceDetail.findings}</p>
                  </div>
                )}

                {evidenceDetail.threat_intelligence_sources && (
                  <div className="detail-section">
                    <span className="detail-label">Threat Intelligence Sources</span>
                    <span className="detail-value">{evidenceDetail.threat_intelligence_sources}</span>
                  </div>
                )}

                {evidenceDetail.threat_intelligence_summary && (
                  <div className="detail-section">
                    <span className="detail-label">Threat Intelligence Summary</span>
                    <p className="detail-text-box intel-summary">{evidenceDetail.threat_intelligence_summary}</p>
                  </div>
                )}
              </div>
            )}
          </div>
        ) : (
          <div className="empty-state">
            <span className="empty-icon">📋</span>
            <p className="empty-title">No Report Generated Yet</p>
            <p className="empty-text">Provide an Evidence ID and click "Generate Incident Report" to create and preview an incident report.</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default Reports;
