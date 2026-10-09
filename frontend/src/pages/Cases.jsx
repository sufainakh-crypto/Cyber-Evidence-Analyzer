import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  getCases,
  getCaseById,
  createCase,
  deleteCase,
  getEvidence,
  addEvidenceToCase,
  removeEvidenceFromCase,
  verifyEvidenceIntegrity,
  correlateSelected,
} from '../services/api';

function Cases() {
  const navigate = useNavigate();
  const location = useLocation();

  const [casesList, setCasesList] = useState([]);
  const [selectedCase, setSelectedCase] = useState(null);
  const [loading, setLoading] = useState(true);
  const [caseLoading, setCaseLoading] = useState(false);
  const [error, setError] = useState(null);

  // Modal / Form state for new Case
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [createSubmitting, setCreateSubmitting] = useState(false);

  // Link Evidence state
  const [allEvidence, setAllEvidence] = useState([]);
  const [selectedEvidenceToLink, setSelectedEvidenceToLink] = useState('');
  const [linkNotes, setLinkNotes] = useState('');
  const [linking, setLinking] = useState(false);

  // Integrity verification status cache
  const [integrityMap, setIntegrityMap] = useState({});
  const [verifyingId, setVerifyingId] = useState(null);

  // Threat relationship map data for current case
  const [caseCorrelations, setCaseCorrelations] = useState([]);

  const fetchCases = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getCases();
      setCasesList(data || []);
    } catch (err) {
      console.error("Error loading cases:", err);
      setError("Unable to load investigation cases. Ensure the FastAPI backend is running.");
    } finally {
      setLoading(false);
    }
  };

  const fetchCaseDetails = async (caseId) => {
    setCaseLoading(true);
    try {
      const details = await getCaseById(caseId);
      setSelectedCase(details);

      // Also fetch cross-evidence correlations for this case's evidence
      if (details?.evidence_records?.length > 1) {
        const eids = details.evidence_records.map((e) => e.evidence_id);
        try {
          const corrRes = await correlateSelected(eids);
          setCaseCorrelations(corrRes?.correlations || []);
        } catch (cErr) {
          console.warn("Could not load case correlations:", cErr);
          setCaseCorrelations([]);
        }
      } else {
        setCaseCorrelations([]);
      }
    } catch (err) {
      console.error("Error fetching case details:", err);
      alert(`Could not load details for case ${caseId}.`);
    } finally {
      setCaseLoading(false);
    }
  };

  const loadAllEvidence = async () => {
    try {
      const evs = await getEvidence();
      setAllEvidence(evs || []);
    } catch (err) {
      console.warn("Could not load evidence for dropdown:", err);
    }
  };

  useEffect(() => {
    fetchCases();
    loadAllEvidence();
  }, []);

  // Check if routed with a specific case
  useEffect(() => {
    if (location.state?.case_id) {
      fetchCaseDetails(location.state.case_id);
    }
  }, [location.state]);

  const handleCreateCase = async (e) => {
    e.preventDefault();
    if (!newTitle.trim()) {
      alert("Please provide a case title.");
      return;
    }
    setCreateSubmitting(true);
    try {
      const created = await createCase({
        title: newTitle.trim(),
        description: newDesc.trim() || undefined,
      });
      setShowCreateModal(false);
      setNewTitle('');
      setNewDesc('');
      await fetchCases();
      // Open the newly created case
      if (created?.case_id) {
        await fetchCaseDetails(created.case_id);
      }
    } catch (err) {
      console.error("Error creating case:", err);
      alert("Failed to create case. Please try again.");
    } finally {
      setCreateSubmitting(false);
    }
  };

  const handleDeleteCase = async (caseId) => {
    const confirm = window.confirm(`Are you sure you want to delete case ${caseId}? Standalone evidence records will NOT be deleted.`);
    if (!confirm) return;
    try {
      await deleteCase(caseId);
      if (selectedCase?.case_id === caseId) {
        setSelectedCase(null);
      }
      await fetchCases();
    } catch (err) {
      console.error("Error deleting case:", err);
      alert("Failed to delete case.");
    }
  };

  const handleLinkEvidence = async (e) => {
    e.preventDefault();
    if (!selectedEvidenceToLink || !selectedCase) return;
    setLinking(true);
    try {
      await addEvidenceToCase(selectedCase.case_id, selectedEvidenceToLink, linkNotes);
      setSelectedEvidenceToLink('');
      setLinkNotes('');
      await fetchCaseDetails(selectedCase.case_id);
      await fetchCases();
    } catch (err) {
      console.error("Error associating evidence:", err);
      alert("Failed to associate evidence to case.");
    } finally {
      setLinking(false);
    }
  };

  const handleUnlinkEvidence = async (evidenceId) => {
    if (!selectedCase) return;
    const confirm = window.confirm(`Unlink evidence ${evidenceId.substring(0, 8)} from case ${selectedCase.case_id}?`);
    if (!confirm) return;
    try {
      await removeEvidenceFromCase(selectedCase.case_id, evidenceId);
      await fetchCaseDetails(selectedCase.case_id);
      await fetchCases();
    } catch (err) {
      console.error("Error unlinking evidence:", err);
      alert("Failed to unlink evidence.");
    }
  };

  const handleVerifyIntegrity = async (evidenceId) => {
    setVerifyingId(evidenceId);
    try {
      const res = await verifyEvidenceIntegrity(evidenceId);
      setIntegrityMap((prev) => ({ ...prev, [evidenceId]: res }));
    } catch (err) {
      console.error("Error verifying integrity:", err);
      alert("Failed to verify cryptographic integrity.");
    } finally {
      setVerifyingId(null);
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

  // Find evidence not yet in selectedCase
  const unlinkedEvidence = allEvidence.filter((ev) => {
    if (!selectedCase?.evidence_records) return true;
    return !selectedCase.evidence_records.some((e) => e.evidence_id === ev.evidence_id);
  });

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">Digital Evidence Cases</h1>
          <p className="page-subtitle">
            Case-based incident management, chronological investigation timelines, and multi-artifact forensic tracking.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button className="btn btn-secondary" onClick={fetchCases} disabled={loading}>
            🔄 Refresh
          </button>
          <button className="btn btn-primary" onClick={() => setShowCreateModal(true)}>
            📁 New Investigation Case
          </button>
        </div>
      </div>

      {/* Main Layout: Left = Case List, Right = Case Details */}
      <div className="cases-layout-grid">
        {/* Cases Sidebar List */}
        <div className="section-card cases-sidebar">
          <div className="section-header">
            <h2>Active Cases</h2>
            <span className="badge badge-info">{casesList.length} Total</span>
          </div>

          {loading ? (
            <div className="state-message">
              <span className="spinner">⏳</span>
              <p className="loading-text">Loading cases...</p>
            </div>
          ) : error ? (
            <div className="state-message error-box">
              <span className="error-icon">⚠️</span>
              <p className="error-text">{error}</p>
            </div>
          ) : casesList.length === 0 ? (
            <div className="empty-state">
              <span className="empty-icon">📁</span>
              <p className="empty-title">No Investigation Cases</p>
              <p className="empty-text">Create your first case to organize and track digital evidence items together.</p>
              <button className="btn btn-primary btn-sm" onClick={() => setShowCreateModal(true)}>
                + Create First Case
              </button>
            </div>
          ) : (
            <div className="case-card-list">
              {casesList.map((c) => {
                const isSelected = selectedCase?.case_id === c.case_id;
                return (
                  <div
                    key={c.case_id}
                    className={`case-summary-card ${isSelected ? 'selected' : ''}`}
                    onClick={() => fetchCaseDetails(c.case_id)}
                  >
                    <div className="case-summary-header">
                      <code className="case-id-badge">{c.case_id}</code>
                      <span className="badge badge-info">{c.status}</span>
                    </div>
                    <h3 className="case-card-title">{c.title}</h3>
                    {c.description && (
                      <p className="case-card-desc">{c.description.substring(0, 75)}...</p>
                    )}
                    <div className="case-card-footer">
                      <span>🔗 {c.evidence_count} evidence item{c.evidence_count === 1 ? '' : 's'}</span>
                      <span>{new Date(c.created_at).toLocaleDateString()}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Selected Case Workspace Details */}
        <div className="section-card cases-detail-view">
          {caseLoading ? (
            <div className="state-message">
              <span className="spinner">⏳</span>
              <p className="loading-text">Loading case workspace...</p>
            </div>
          ) : !selectedCase ? (
            <div className="empty-state" style={{ padding: '3rem 1rem' }}>
              <span className="empty-icon">📂</span>
              <p className="empty-title">No Case Selected</p>
              <p className="empty-text">Select a case from the list on the left or create a new investigation case to view evidence details, investigation timeline, and reports.</p>
            </div>
          ) : (
            <div className="case-detail-content">
              {/* Case Action Bar */}
              <div className="case-header-banner">
                <div>
                  <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center', marginBottom: '0.35rem' }}>
                    <code className="case-id-badge large">{selectedCase.case_id}</code>
                    <span className="badge badge-info">Status: {selectedCase.status}</span>
                    <span className="timeline-time">
                      Registered: {new Date(selectedCase.created_at).toLocaleString()}
                    </span>
                  </div>
                  <h2 style={{ margin: 0, fontSize: '1.35rem', color: 'var(--text-main)' }}>
                    {selectedCase.title}
                  </h2>
                  {selectedCase.description && (
                    <p style={{ margin: '0.4rem 0 0 0', color: 'var(--text-muted)', fontSize: '0.9rem', lineHeight: 1.4 }}>
                      {selectedCase.description}
                    </p>
                  )}
                </div>

                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <button
                    className="btn btn-primary btn-sm"
                    onClick={() => navigate('/analyze', { state: { case_id: selectedCase.case_id } })}
                  >
                    ➕ Analyze New Artifact
                  </button>
                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => navigate('/reports', { state: { case_id: selectedCase.case_id } })}
                  >
                    📄 Generate Report
                  </button>
                  <button
                    className="btn btn-danger btn-sm"
                    onClick={() => handleDeleteCase(selectedCase.case_id)}
                  >
                    🗑️ Delete Case
                  </button>
                </div>
              </div>

              {/* Sub-section: Associated Evidence Records */}
              <div className="case-section-block">
                <div className="section-header" style={{ padding: '0 0 0.75rem 0' }}>
                  <div>
                    <h3 style={{ margin: 0, fontSize: '1.1rem' }}>
                      Associated Evidence Records ({selectedCase.evidence_records?.length || 0})
                    </h3>
                    <p style={{ margin: '0.2rem 0 0 0', fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                      Digital forensic artifacts logged under this investigation case.
                    </p>
                  </div>
                </div>

                {selectedCase.evidence_records?.length === 0 ? (
                  <div className="empty-state" style={{ padding: '1.5rem 1rem' }}>
                    <p className="empty-title">No evidence linked to this case yet.</p>
                    <p className="empty-text">Link an existing evidence artifact below, or analyze a new threat artifact directly into this case.</p>
                  </div>
                ) : (
                  <div className="table-container">
                    <table className="evidence-table" style={{ fontSize: '0.88rem' }}>
                      <thead>
                        <tr>
                          <th>Evidence ID</th>
                          <th>Target Input</th>
                          <th>Type</th>
                          <th>Risk Score</th>
                          <th>Risk Level</th>
                          <th>Integrity Status</th>
                          <th style={{ textAlign: 'right' }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {selectedCase.evidence_records.map((ev) => {
                          const vStatus = integrityMap[ev.evidence_id];
                          return (
                            <tr key={ev.evidence_id}>
                              <td>
                                <code className="evidence-code">
                                  {ev.evidence_id.substring(0, 8)}...
                                </code>
                              </td>
                              <td className="input-cell" title={ev.input_value || ev.input}>
                                <strong>{ev.input_value || ev.input}</strong>
                              </td>
                              <td><span className="type-tag">{ev.input_type}</span></td>
                              <td><span className="score-value">{ev.risk_score}</span></td>
                              <td>
                                <span className={`badge ${getBadgeClass(ev.risk_level)}`}>
                                  {ev.risk_level}
                                </span>
                              </td>
                              <td>
                                {vStatus ? (
                                  <span className={`badge ${vStatus.matches ? 'badge-verified' : 'badge-mismatch'}`}>
                                    {vStatus.status}
                                  </span>
                                ) : ev.sha256_hash ? (
                                  <span className="badge badge-info" title={ev.sha256_hash}>
                                    SHA-256 HASHED
                                  </span>
                                ) : (
                                  <span className="badge badge-neutral">UNHASHED</span>
                                )}
                              </td>
                              <td style={{ textAlign: 'right' }}>
                                <div className="action-buttons" style={{ justifyContent: 'flex-end' }}>
                                  <button
                                    className="btn btn-secondary btn-sm"
                                    onClick={() => handleVerifyIntegrity(ev.evidence_id)}
                                    disabled={verifyingId === ev.evidence_id}
                                    title="Cryptographically verify SHA-256 integrity"
                                  >
                                    {verifyingId === ev.evidence_id ? '⏳' : '🛡️ Verify'}
                                  </button>
                                  <button
                                    className="btn btn-secondary btn-sm"
                                    onClick={() => handleUnlinkEvidence(ev.evidence_id)}
                                    title="Unlink from this case"
                                  >
                                    ✕ Unlink
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

                {/* Form to Link Existing Evidence */}
                {unlinkedEvidence.length > 0 && (
                  <form onSubmit={handleLinkEvidence} className="link-evidence-inline-form">
                    <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-main)' }}>
                      Link Existing Evidence:
                    </span>
                    <select
                      className="input-field"
                      style={{ maxWidth: '280px' }}
                      value={selectedEvidenceToLink}
                      onChange={(e) => setSelectedEvidenceToLink(e.target.value)}
                      disabled={linking}
                    >
                      <option value="">-- Select Unlinked Evidence --</option>
                      {unlinkedEvidence.map((e) => (
                        <option key={e.evidence_id} value={e.evidence_id}>
                          {e.evidence_id.substring(0, 8)}: {(e.input_value || e.input).substring(0, 24)} ({e.risk_level})
                        </option>
                      ))}
                    </select>
                    <input
                      type="text"
                      className="input-field"
                      placeholder="Investigative context notes (optional)..."
                      style={{ flex: 1 }}
                      value={linkNotes}
                      onChange={(e) => setLinkNotes(e.target.value)}
                      disabled={linking}
                    />
                    <button
                      type="submit"
                      className="btn btn-primary btn-sm"
                      disabled={!selectedEvidenceToLink || linking}
                    >
                      {linking ? 'Linking...' : '➕ Link to Case'}
                    </button>
                  </form>
                )}
              </div>

              {/* Sub-section: Chronological Investigation Timeline */}
              <div className="case-section-block">
                <div className="section-header" style={{ padding: '0 0 0.75rem 0' }}>
                  <div>
                    <h3 style={{ margin: 0, fontSize: '1.1rem' }}>Chronological Investigation Timeline</h3>
                    <p style={{ margin: '0.2rem 0 0 0', fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                      Audit-ready event log sorted strictly by real timestamps.
                    </p>
                  </div>
                </div>

                <div className="timeline-container">
                  {selectedCase.timeline?.map((evt, idx) => (
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

              {/* Sub-section (FEATURE 5): Threat Relationship Map */}
              <div className="case-section-block">
                <div className="section-header" style={{ padding: '0 0 0.75rem 0' }}>
                  <div>
                    <h3 style={{ margin: 0, fontSize: '1.1rem' }}>Threat Relationship Map</h3>
                    <p style={{ margin: '0.2rem 0 0 0', fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                      Nodes and edges generated strictly from genuine shared technical indicators between evidence items in this case.
                    </p>
                  </div>
                </div>

                {caseCorrelations.length === 0 ? (
                  <div className="empty-state" style={{ padding: '1.25rem' }}>
                    <p className="empty-title">No Shared Technical Indicators Found</p>
                    <p className="empty-text">
                      {selectedCase.evidence_records?.length < 2
                        ? "Associate at least two evidence items to evaluate technical convergence."
                        : "The artifacts in this case do not currently share confirmed IP, domain, URL, or hash overlap."}
                    </p>
                  </div>
                ) : (
                  <div>
                    {/* Visual SVG Relationship Map */}
                    <div className="relationship-graph-container">
                      <svg className="relationship-svg" viewBox="0 0 700 240" style={{ width: '100%', height: '240px' }}>
                        {/* Render nodes and links */}
                        {caseCorrelations.slice(0, 4).map((rel, idx) => {
                          const yPos = 60 + idx * 45;
                          return (
                            <g key={rel.relationship_id}>
                              {/* Edge line */}
                              <line
                                x1="180"
                                y1={yPos}
                                x2="520"
                                y2={yPos}
                                stroke="var(--primary-color)"
                                strokeWidth="2"
                                strokeDasharray="4"
                              />
                              {/* Edge Label badge */}
                              <rect
                                x="300"
                                y={yPos - 12}
                                width="100"
                                height="22"
                                rx="4"
                                fill="var(--bg-card)"
                                stroke="var(--border-color)"
                              />
                              <text
                                x="350"
                                y={yPos + 3}
                                textAnchor="middle"
                                fontSize="10"
                                fill="var(--accent-color)"
                                fontWeight="bold"
                              >
                                {rel.relationship_type}
                              </text>

                              {/* Source Node */}
                              <circle cx="180" cy={yPos} r="18" fill="#1e293b" stroke="#3b82f6" strokeWidth="2" />
                              <text x="180" y={yPos + 4} textAnchor="middle" fontSize="10" fill="#fff" fontWeight="bold">
                                {rel.source_evidence_id.substring(0, 4)}
                              </text>
                              <text x="155" y={yPos + 4} textAnchor="end" fontSize="11" fill="var(--text-main)">
                                {rel.source_input.substring(0, 18)}
                              </text>

                              {/* Target Node */}
                              <circle cx="520" cy={yPos} r="18" fill="#1e293b" stroke="#ef4444" strokeWidth="2" />
                              <text x="520" y={yPos + 4} textAnchor="middle" fontSize="10" fill="#fff" fontWeight="bold">
                                {rel.target_evidence_id.substring(0, 4)}
                              </text>
                              <text x="545" y={yPos + 4} textAnchor="start" fontSize="11" fill="var(--text-main)">
                                {rel.target_input.substring(0, 18)}
                              </text>
                            </g>
                          );
                        })}
                      </svg>
                    </div>

                    {/* Detailed relationship list */}
                    <div className="correlation-list" style={{ marginTop: '0.75rem' }}>
                      {caseCorrelations.map((rel) => (
                        <div key={rel.relationship_id} className="correlation-card" style={{ padding: '0.75rem' }}>
                          <div className="correlation-header">
                            <div>
                              <code>{rel.source_input}</code> ⇄ <code>{rel.target_input}</code>
                            </div>
                            <span className="badge badge-info">{rel.relationship_type}</span>
                          </div>
                          <p style={{ fontSize: '0.82rem', margin: '0.25rem 0' }}>{rel.explanation}</p>
                          <div className="caveat-box" style={{ fontSize: '0.75rem', padding: '0.35rem 0.5rem' }}>
                            ⚖️ {rel.forensic_caveat}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Modal to Create New Case */}
      {showCreateModal && (
        <div className="modal-backdrop" onClick={() => setShowCreateModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '520px' }}>
            <div className="modal-header">
              <h2>Open New Investigation Case</h2>
              <button className="modal-close" onClick={() => setShowCreateModal(false)}>✕</button>
            </div>
            <form onSubmit={handleCreateCase}>
              <div className="modal-body">
                <div className="form-group">
                  <label htmlFor="modalTitle" className="form-label">
                    Case Title <span style={{ color: 'var(--high-color)' }}>*</span>
                  </label>
                  <input
                    id="modalTitle"
                    type="text"
                    className="input-field"
                    placeholder="e.g., Phishing Campaign Q4 - Financial Spearphish"
                    value={newTitle}
                    onChange={(e) => setNewTitle(e.target.value)}
                    required
                    disabled={createSubmitting}
                  />
                </div>
                <div className="form-group">
                  <label htmlFor="modalDesc" className="form-label">Investigation Scope &amp; Context</label>
                  <textarea
                    id="modalDesc"
                    className="input-field textarea-field"
                    rows="3"
                    placeholder="Describe incident source, affected assets, or initial threat actor hypotheses..."
                    value={newDesc}
                    onChange={(e) => setNewDesc(e.target.value)}
                    disabled={createSubmitting}
                  />
                </div>
              </div>
              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setShowCreateModal(false)}
                  disabled={createSubmitting}
                >
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" disabled={createSubmitting}>
                  {createSubmitting ? 'Opening Case...' : '📁 Create Case'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default Cases;
