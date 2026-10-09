import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  getEvidence,
  getEvidenceById,
  deleteEvidence,
  getCorrelations,
  verifyEvidenceIntegrity,
} from '../services/api';

function Evidence() {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('evidence'); // 'evidence' | 'correlations'
  const [evidenceList, setEvidenceList] = useState([]);
  const [correlationsData, setCorrelationsData] = useState(null);
  const [corrFilter, setCorrFilter] = useState('ALL');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedEvidence, setSelectedEvidence] = useState(null);
  const [modalCorrelations, setModalCorrelations] = useState([]);
  const [modalLoading, setModalLoading] = useState(false);
  const [deletingId, setDeletingId] = useState(null);

  // Integrity verification status map { evidence_id: verifyResult }
  const [integrityMap, setIntegrityMap] = useState({});
  const [verifyingId, setVerifyingId] = useState(null);

  const fetchEvidenceData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [evData, corrData] = await Promise.all([
        getEvidence(),
        getCorrelations().catch((err) => {
          console.warn("Could not load correlations:", err);
          return null;
        }),
      ]);
      setEvidenceList(evData || []);
      setCorrelationsData(corrData);
    } catch (err) {
      console.error("Error fetching evidence:", err);
      setError("Unable to load evidence. Please make sure the FastAPI backend is running.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvidenceData();
  }, []);

  const handleVerify = async (evidence_id, e) => {
    if (e) e.stopPropagation();
    setVerifyingId(evidence_id);
    try {
      const res = await verifyEvidenceIntegrity(evidence_id);
      setIntegrityMap((prev) => ({ ...prev, [evidence_id]: res }));
    } catch (err) {
      console.error("Error verifying integrity:", err);
      alert("Failed to perform cryptographic verification.");
    } finally {
      setVerifyingId(null);
    }
  };

  const handleViewDetails = async (evidence_id) => {
    setModalLoading(true);
    setSelectedEvidence({ evidence_id });
    setModalCorrelations([]);
    try {
      const details = await getEvidenceById(evidence_id);
      setSelectedEvidence(details);

      // Trigger integrity verification in modal if not yet checked
      if (!integrityMap[evidence_id]) {
        try {
          const vRes = await verifyEvidenceIntegrity(evidence_id);
          setIntegrityMap((prev) => ({ ...prev, [evidence_id]: vRes }));
        } catch (vErr) {
          console.warn("Could not verify in modal:", vErr);
        }
      }

      try {
        const corrRes = await getCorrelations(evidence_id);
        setModalCorrelations(corrRes?.correlations || []);
      } catch (cErr) {
        console.warn("Could not fetch evidence correlations:", cErr);
      }
    } catch (err) {
      console.error("Error fetching evidence details:", err);
      alert("Failed to load details for this evidence record.");
      setSelectedEvidence(null);
    } finally {
      setModalLoading(false);
    }
  };

  const handleDelete = async (evidence_id) => {
    const confirmed = window.confirm("Are you sure you want to delete this evidence record?");
    if (!confirmed) return;

    setDeletingId(evidence_id);
    try {
      await deleteEvidence(evidence_id);
      await fetchEvidenceData();
    } catch (err) {
      console.error("Error deleting evidence:", err);
      alert("Failed to delete the evidence record.");
    } finally {
      setDeletingId(null);
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

  const getRelBadgeClass = (type) => {
    switch (type) {
      case 'MULTI_INDICATOR': return 'badge-rel-multi';
      case 'EXACT_MATCH': return 'badge-rel-exact';
      case 'TEMPORAL_RELATIONSHIP': return 'badge-rel-temp';
      case 'UNCONFIRMED_HYPOTHESIS': return 'badge-rel-hypo';
      default: return 'badge-neutral';
    }
  };

  const getConfBadgeClass = (conf) => {
    switch (conf?.toUpperCase()) {
      case 'HIGH': return 'badge-conf-high';
      case 'MEDIUM': return 'badge-conf-med';
      case 'LOW':
      case 'INFORMATIONAL':
      default: return 'badge-conf-low';
    }
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return 'N/A';
    try {
      return new Date(dateStr).toLocaleString();
    } catch {
      return dateStr;
    }
  };

  const allCorrelations = correlationsData?.correlations || [];
  const filteredCorrelations = allCorrelations.filter((c) => {
    if (corrFilter === 'ALL') return true;
    return c.relationship_type === corrFilter;
  });

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">Evidence &amp; Correlation Hub</h1>
          <p className="page-subtitle">
            Forensic repository of analyzed cyber artifacts with cryptographic SHA-256 integrity verification and automated correlation engine.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button className="btn btn-secondary" onClick={fetchEvidenceData} disabled={loading}>
            🔄 Refresh Repository
          </button>
          <button className="btn btn-primary" onClick={() => navigate('/analyze')}>
            ➕ Analyze Artifact
          </button>
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="tabs-nav">
        <button
          className={`tab-btn ${activeTab === 'evidence' ? 'active' : ''}`}
          onClick={() => setActiveTab('evidence')}
        >
          📁 Evidence Records ({evidenceList.length})
        </button>
        <button
          className={`tab-btn ${activeTab === 'correlations' ? 'active' : ''}`}
          onClick={() => setActiveTab('correlations')}
        >
          🔗 Cross-Evidence Correlations ({correlationsData?.total_correlations_found || 0})
        </button>
      </div>

      {loading ? (
        <div className="section-card">
          <div className="state-message">
            <span className="spinner">⏳</span>
            <p className="loading-text">Loading evidence and correlations...</p>
          </div>
        </div>
      ) : error ? (
        <div className="section-card">
          <div className="state-message error-box">
            <span className="error-icon">⚠️</span>
            <p className="error-text">{error}</p>
            <button className="btn btn-primary btn-sm" onClick={fetchEvidenceData}>
              Retry Connection
            </button>
          </div>
        </div>
      ) : activeTab === 'evidence' ? (
        /* Tab 1: Evidence Table */
        <div className="section-card">
          {evidenceList.length === 0 ? (
            <div className="empty-state">
              <span className="empty-icon">📁</span>
              <p className="empty-title">No evidence records found.</p>
              <p className="empty-text">Submit a URL, IP, or Domain on the Analyze page to store evidence items.</p>
              <button className="btn btn-primary btn-sm" onClick={() => navigate('/analyze')}>
                Analyze First Artifact
              </button>
            </div>
          ) : (
            <div className="table-container">
              <table className="evidence-table">
                <thead>
                  <tr>
                    <th>Evidence ID</th>
                    <th>Target Input</th>
                    <th>Type</th>
                    <th>Risk Score</th>
                    <th>Risk Level</th>
                    <th>Case Association</th>
                    <th>SHA-256 Integrity</th>
                    <th>Timestamp</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {evidenceList.map((item) => {
                    const vStatus = integrityMap[item.evidence_id];
                    return (
                      <tr key={item.evidence_id || item.id}>
                        <td>
                          <code className="evidence-code">
                            {(item.evidence_id || '').substring(0, 8)}...
                          </code>
                        </td>
                        <td className="input-cell" title={item.input_value || item.input}>
                          {item.input_value || item.input}
                        </td>
                        <td>
                          <span className="type-tag">{item.input_type}</span>
                        </td>
                        <td>
                          <span className="score-value">{item.risk_score}</span>
                        </td>
                        <td>
                          <span className={`badge ${getBadgeClass(item.risk_level)}`}>
                            {item.risk_level}
                          </span>
                        </td>
                        <td>
                          {item.cases && item.cases.length > 0 ? (
                            <span
                              className="badge badge-info"
                              style={{ cursor: 'pointer' }}
                              onClick={() => navigate('/cases', { state: { case_id: item.cases[0] } })}
                              title={`Associated with case ${item.cases.join(', ')}`}
                            >
                              📁 {item.cases[0]}
                            </span>
                          ) : (
                            <span className="badge badge-neutral" style={{ opacity: 0.6 }}>Standalone</span>
                          )}
                        </td>
                        <td>
                          {vStatus ? (
                            <span
                              className={`badge ${vStatus.matches ? 'badge-verified' : 'badge-mismatch'}`}
                              title={vStatus.message}
                            >
                              {vStatus.status}
                            </span>
                          ) : item.sha256_hash ? (
                            <button
                              className="btn btn-secondary btn-sm"
                              style={{ fontSize: '0.75rem', padding: '0.2rem 0.5rem' }}
                              onClick={(e) => handleVerify(item.evidence_id, e)}
                              disabled={verifyingId === item.evidence_id}
                            >
                              {verifyingId === item.evidence_id ? '⏳ Checking...' : '🛡️ Check Hash'}
                            </button>
                          ) : (
                            <span className="badge badge-neutral">LEGACY</span>
                          )}
                        </td>
                        <td className="time-cell">{formatDate(item.timestamp)}</td>
                        <td style={{ textAlign: 'right' }}>
                          <div className="action-buttons">
                            <button
                              className="btn btn-secondary btn-sm"
                              onClick={() => navigate('/correlation', { state: { evidence_id: item.evidence_id } })}
                              title="Correlate this artifact across the repository"
                            >
                              🔗 Correlate
                            </button>
                            <button
                              className="btn btn-secondary btn-sm"
                              onClick={() => handleViewDetails(item.evidence_id)}
                            >
                              👁️ Details
                            </button>
                            <button
                              className="btn btn-danger btn-sm"
                              onClick={() => handleDelete(item.evidence_id)}
                              disabled={deletingId === item.evidence_id}
                            >
                              {deletingId === item.evidence_id ? 'Deleting...' : '🗑️ Delete'}
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      ) : (
        /* Tab 2: Cross-Evidence Correlations View */
        <div className="section-card">
          <div className="section-header" style={{ flexWrap: 'wrap', gap: '0.75rem' }}>
            <div>
              <h2>Automated Correlation Analysis</h2>
              <p className="stat-desc" style={{ marginTop: '0.25rem' }}>
                Evaluated {correlationsData?.total_records_analyzed || 0} artifacts for technical indicator convergence, temporal proximity, and infrastructure overlap.
              </p>
            </div>

            {/* Filter buttons */}
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              <button
                className={`btn btn-sm ${corrFilter === 'ALL' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setCorrFilter('ALL')}
              >
                All ({allCorrelations.length})
              </button>
              <button
                className={`btn btn-sm ${corrFilter === 'MULTI_INDICATOR' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setCorrFilter('MULTI_INDICATOR')}
              >
                Multi-Indicator ({correlationsData?.relationship_type_counts?.MULTI_INDICATOR || 0})
              </button>
              <button
                className={`btn btn-sm ${corrFilter === 'EXACT_MATCH' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setCorrFilter('EXACT_MATCH')}
              >
                Exact Match ({correlationsData?.relationship_type_counts?.EXACT_MATCH || 0})
              </button>
              <button
                className={`btn btn-sm ${corrFilter === 'TEMPORAL_RELATIONSHIP' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setCorrFilter('TEMPORAL_RELATIONSHIP')}
              >
                Temporal ({correlationsData?.relationship_type_counts?.TEMPORAL_RELATIONSHIP || 0})
              </button>
              <button
                className={`btn btn-sm ${corrFilter === 'UNCONFIRMED_HYPOTHESIS' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setCorrFilter('UNCONFIRMED_HYPOTHESIS')}
              >
                Hypothesis ({correlationsData?.relationship_type_counts?.UNCONFIRMED_HYPOTHESIS || 0})
              </button>
              <button
                className="btn btn-primary btn-sm"
                onClick={() => navigate('/correlation')}
              >
                🚀 Full Correlation Engine &rarr;
              </button>
            </div>
          </div>

          {filteredCorrelations.length === 0 ? (
            <div className="empty-state">
              <span className="empty-icon">🔗</span>
              <p className="empty-title">No correlations match this filter</p>
              <p className="empty-text">Select another category or analyze additional indicators to discover convergence.</p>
            </div>
          ) : (
            <div className="correlation-list">
              {filteredCorrelations.map((rel) => (
                <div key={rel.relationship_id} className="correlation-card">
                  <div className="correlation-header">
                    <div className="correlation-nodes">
                      <div className={`node-chip ${rel.source_risk_level === 'HIGH' ? 'high' : ''}`} title={rel.source_input}>
                        <code>{rel.source_evidence_id.substring(0, 8)}</code>: {rel.source_input}
                      </div>
                      <span className="rel-arrow">⇄</span>
                      <div className={`node-chip ${rel.target_risk_level === 'HIGH' ? 'high' : ''}`} title={rel.target_input}>
                        <code>{rel.target_evidence_id.substring(0, 8)}</code>: {rel.target_input}
                      </div>
                    </div>

                    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                      <span className={`badge ${getRelBadgeClass(rel.relationship_type)}`}>
                        {rel.relationship_type.replace('_', ' ')}
                      </span>
                      <span className={`badge ${getConfBadgeClass(rel.confidence_level)}`}>
                        Confidence: {rel.confidence_level}
                      </span>
                      {rel.time_delta_human && (
                        <span className="badge badge-neutral">⏱️ {rel.time_delta_human}</span>
                      )}
                    </div>
                  </div>

                  {/* Matched Indicators */}
                  {rel.matched_indicators && rel.matched_indicators.length > 0 && (
                    <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
                      <span className="detail-label" style={{ marginRight: '0.25rem' }}>Matched Indicators:</span>
                      {rel.matched_indicators.map((ind, i) => (
                        <span key={i} className="matched-pill" title={ind.details}>
                          <strong>{ind.indicator_type.toUpperCase()}:</strong> {ind.matched_value}
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Explanation */}
                  <p style={{ fontSize: '0.88rem', color: 'var(--text-main)', margin: 0, lineHeight: 1.45 }}>
                    {rel.explanation}
                  </p>

                  {/* Forensic Caveat Box */}
                  {rel.forensic_caveat && (
                    <div className="caveat-box">
                      ⚖️ <strong>Forensic Rigor Note:</strong> {rel.forensic_caveat}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Details Modal */}
      {selectedEvidence && (
        <div className="modal-backdrop" onClick={() => setSelectedEvidence(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '850px' }}>
            <div className="modal-header">
              <h2>Evidence Record Forensic Details</h2>
              <button className="modal-close" onClick={() => setSelectedEvidence(null)}>✕</button>
            </div>

            {modalLoading ? (
              <div className="state-message">
                <span className="spinner">⏳</span>
                <p className="loading-text">Loading details and verifying integrity...</p>
              </div>
            ) : (
              <div className="modal-body">
                {/* Cryptographic SHA-256 Integrity Verification Box */}
                <div className="integrity-card" style={{ marginBottom: '1.25rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span style={{ fontSize: '1.1rem' }}>🛡️</span>
                      <strong>Cryptographic Evidence Integrity (SHA-256)</strong>
                    </div>
                    {integrityMap[selectedEvidence.evidence_id] ? (
                      <span className={`badge ${integrityMap[selectedEvidence.evidence_id].matches ? 'badge-verified' : 'badge-mismatch'}`}>
                        {integrityMap[selectedEvidence.evidence_id].status}
                      </span>
                    ) : (
                      <button
                        className="btn btn-secondary btn-sm"
                        onClick={() => handleVerify(selectedEvidence.evidence_id)}
                        disabled={verifyingId === selectedEvidence.evidence_id}
                      >
                        {verifyingId === selectedEvidence.evidence_id ? 'Verifying...' : 'Verify Now'}
                      </button>
                    )}
                  </div>

                  <div style={{ fontSize: '0.82rem', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Stored Signature: </span>
                      <code style={{ wordBreak: 'break-all', color: 'var(--accent-color)' }}>
                        {selectedEvidence.sha256_hash || 'No hash recorded (Legacy record)'}
                      </code>
                    </div>
                    {integrityMap[selectedEvidence.evidence_id]?.calculated_hash && (
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Recalculated Signature: </span>
                        <code style={{ wordBreak: 'break-all' }}>
                          {integrityMap[selectedEvidence.evidence_id].calculated_hash}
                        </code>
                      </div>
                    )}
                  </div>

                  <div className="caveat-box" style={{ marginTop: '0.6rem', fontSize: '0.78rem', padding: '0.45rem 0.65rem' }}>
                    ⚖️ <strong>Integrity Scope:</strong> Cryptographic integrity verification confirms whether the protected evidence record matches its exact state at creation time. It does NOT verify external truthfulness of data or guarantee legal admissibility.
                  </div>
                </div>

                <div className="detail-grid">
                  <div className="detail-item full-width">
                    <span className="detail-label">Evidence ID</span>
                    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
                      <code className="detail-code">{selectedEvidence.evidence_id}</code>
                      <button
                        className="btn btn-primary btn-sm"
                        onClick={() => {
                          setSelectedEvidence(null);
                          navigate('/reports', { state: { evidence_id: selectedEvidence.evidence_id } });
                        }}
                      >
                        📄 Generate Report
                      </button>
                    </div>
                  </div>

                  <div className="detail-item">
                    <span className="detail-label">Target Artifact</span>
                    <span className="detail-value highlight">{selectedEvidence.input_value || selectedEvidence.input}</span>
                  </div>

                  <div className="detail-item">
                    <span className="detail-label">Input Type</span>
                    <span className="type-tag">{selectedEvidence.input_type}</span>
                  </div>

                  <div className="detail-item">
                    <span className="detail-label">Risk Score</span>
                    <span className="detail-value" style={{ fontWeight: 700 }}>{selectedEvidence.risk_score} / 100</span>
                  </div>

                  <div className="detail-item">
                    <span className="detail-label">Risk Classification</span>
                    <span className={`badge ${getBadgeClass(selectedEvidence.risk_level)}`}>
                      {selectedEvidence.risk_level}
                    </span>
                  </div>

                  <div className="detail-item">
                    <span className="detail-label">Ingested At</span>
                    <span className="detail-value">{formatDate(selectedEvidence.timestamp)}</span>
                  </div>

                  <div className="detail-item">
                    <span className="detail-label">Case Association</span>
                    <span className="detail-value">
                      {selectedEvidence.cases && selectedEvidence.cases.length > 0 ? (
                        <code className="case-id-badge">{selectedEvidence.cases.join(', ')}</code>
                      ) : (
                        'None (Standalone)'
                      )}
                    </span>
                  </div>

                  {selectedEvidence.url && (
                    <div className="detail-item">
                      <span className="detail-label">URL</span>
                      <span className="detail-value">{selectedEvidence.url}</span>
                    </div>
                  )}

                  {selectedEvidence.domain && (
                    <div className="detail-item">
                      <span className="detail-label">Domain</span>
                      <span className="detail-value">{selectedEvidence.domain}</span>
                    </div>
                  )}

                  {selectedEvidence.ip_address && (
                    <div className="detail-item">
                      <span className="detail-label">IP Address</span>
                      <span className="detail-value">{selectedEvidence.ip_address}</span>
                    </div>
                  )}
                </div>

                {selectedEvidence.findings && (
                  <div className="detail-section" style={{ marginTop: '1rem' }}>
                    <span className="detail-label">Heuristic Findings</span>
                    <p className="detail-text-box">{selectedEvidence.findings}</p>
                  </div>
                )}

                {selectedEvidence.threat_intelligence_sources && (
                  <div className="detail-section" style={{ marginTop: '1rem' }}>
                    <span className="detail-label">Threat Intelligence Sources</span>
                    <span className="detail-value">{selectedEvidence.threat_intelligence_sources}</span>
                  </div>
                )}

                {selectedEvidence.threat_intelligence_summary && (
                  <div className="detail-section" style={{ marginTop: '1rem' }}>
                    <span className="detail-label">Threat Intelligence Summary</span>
                    <p className="detail-text-box intel-summary">{selectedEvidence.threat_intelligence_summary}</p>
                  </div>
                )}

                {/* Cross-Evidence Correlations for this Record */}
                <div style={{ marginTop: '1.5rem', paddingTop: '1.25rem', borderTop: '1px solid var(--border-color)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                    <h3 style={{ fontSize: '1.05rem', color: 'var(--text-main)', margin: 0 }}>
                      🔗 Correlated Records ({modalCorrelations.length})
                    </h3>
                    <span className="badge badge-info">Automated Forensic Graph</span>
                  </div>

                  {modalCorrelations.length === 0 ? (
                    <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                      No other evidence records currently share indicators with this artifact.
                    </p>
                  ) : (
                    <div className="correlation-list">
                      {modalCorrelations.map((rel) => {
                        const otherId = rel.source_evidence_id === selectedEvidence.evidence_id
                          ? rel.target_evidence_id
                          : rel.source_evidence_id;
                        const otherInput = rel.source_evidence_id === selectedEvidence.evidence_id
                          ? rel.target_input
                          : rel.source_input;
                        const otherRisk = rel.source_evidence_id === selectedEvidence.evidence_id
                          ? rel.target_risk_level
                          : rel.source_risk_level;

                        return (
                          <div key={rel.relationship_id} className="correlation-card" style={{ padding: '0.85rem' }}>
                            <div className="correlation-header">
                              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
                                <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Related Item:</span>
                                <code className="node-chip" style={{ fontSize: '0.8rem' }}>{otherId.substring(0, 8)}</code>
                                <strong style={{ fontSize: '0.85rem' }}>{otherInput}</strong>
                                <span className={`badge ${getBadgeClass(otherRisk)}`}>{otherRisk}</span>
                              </div>
                              <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
                                <span className={`badge ${getRelBadgeClass(rel.relationship_type)}`}>
                                  {rel.relationship_type}
                                </span>
                                <span className={`badge ${getConfBadgeClass(rel.confidence_level)}`}>
                                  {rel.confidence_level}
                                </span>
                              </div>
                            </div>

                            <p style={{ fontSize: '0.82rem', color: 'var(--text-main)', margin: 0 }}>
                              {rel.explanation}
                            </p>

                            <div className="caveat-box" style={{ fontSize: '0.75rem', padding: '0.5rem 0.75rem' }}>
                              ⚖️ {rel.forensic_caveat}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>
            )}

            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setSelectedEvidence(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default Evidence;
