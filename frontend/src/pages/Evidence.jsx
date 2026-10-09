import React, { useState, useEffect } from 'react';
import { getEvidence, getEvidenceById, deleteEvidence } from '../services/api';

function Evidence() {
  const [evidenceList, setEvidenceList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedEvidence, setSelectedEvidence] = useState(null);
  const [modalLoading, setModalLoading] = useState(false);
  const [deletingId, setDeletingId] = useState(null);

  const fetchEvidenceData = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getEvidence();
      setEvidenceList(data);
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

  const handleViewDetails = async (evidence_id) => {
    setModalLoading(true);
    setSelectedEvidence({ evidence_id }); // open modal in loading state
    try {
      const details = await getEvidenceById(evidence_id);
      setSelectedEvidence(details);
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

  const formatDate = (dateStr) => {
    if (!dateStr) return 'N/A';
    try {
      return new Date(dateStr).toLocaleString();
    } catch {
      return dateStr;
    }
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">Evidence Repository</h1>
          <p className="page-subtitle">
            Historical log of all analyzed cyber evidence records stored securely in SQLite database.
          </p>
        </div>
        <button className="btn btn-secondary" onClick={fetchEvidenceData} disabled={loading}>
          🔄 Refresh Evidence
        </button>
      </div>

      <div className="section-card">
        {loading ? (
          <div className="state-message">
            <span className="spinner">⏳</span>
            <p className="loading-text">Loading evidence...</p>
          </div>
        ) : error ? (
          <div className="state-message error-box">
            <span className="error-icon">⚠️</span>
            <p className="error-text">{error}</p>
            <button className="btn btn-primary btn-sm" onClick={fetchEvidenceData}>
              Retry Connection
            </button>
          </div>
        ) : evidenceList.length === 0 ? (
          <div className="empty-state">
            <span className="empty-icon">📁</span>
            <p className="empty-title">No evidence records found.</p>
            <p className="empty-text">Submit a URL, IP, or Domain on the Analyze page to store evidence items.</p>
          </div>
        ) : (
          <div className="table-container">
            <table className="evidence-table">
              <thead>
                <tr>
                  <th>Evidence ID</th>
                  <th>Input</th>
                  <th>Type</th>
                  <th>Risk Score</th>
                  <th>Risk Level</th>
                  <th>Timestamp</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {evidenceList.map((item) => (
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
                    <td className="time-cell">{formatDate(item.timestamp)}</td>
                    <td style={{ textAlign: 'right' }}>
                      <div className="action-buttons">
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => handleViewDetails(item.evidence_id)}
                        >
                          👁️ View Details
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
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Details Modal */}
      {selectedEvidence && (
        <div className="modal-backdrop" onClick={() => setSelectedEvidence(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Evidence Record Details</h2>
              <button className="modal-close" onClick={() => setSelectedEvidence(null)}>✕</button>
            </div>

            {modalLoading ? (
              <div className="state-message">
                <span className="spinner">⏳</span>
                <p className="loading-text">Loading details...</p>
              </div>
            ) : (
              <div className="modal-body">
                <div className="detail-grid">
                  <div className="detail-item full-width">
                    <span className="detail-label">Evidence ID</span>
                    <code className="detail-code">{selectedEvidence.evidence_id}</code>
                  </div>

                  <div className="detail-item">
                    <span className="detail-label">Input Target</span>
                    <span className="detail-value highlight">{selectedEvidence.input_value || selectedEvidence.input}</span>
                  </div>

                  <div className="detail-item">
                    <span className="detail-label">Input Type</span>
                    <span className="type-tag">{selectedEvidence.input_type}</span>
                  </div>

                  <div className="detail-item">
                    <span className="detail-label">Risk Score</span>
                    <span className="detail-value">{selectedEvidence.risk_score} / 100</span>
                  </div>

                  <div className="detail-item">
                    <span className="detail-label">Risk Level</span>
                    <span className={`badge ${getBadgeClass(selectedEvidence.risk_level)}`}>
                      {selectedEvidence.risk_level}
                    </span>
                  </div>

                  <div className="detail-item">
                    <span className="detail-label">Timestamp</span>
                    <span className="detail-value">{formatDate(selectedEvidence.timestamp)}</span>
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
                  <div className="detail-section">
                    <span className="detail-label">Heuristic Findings</span>
                    <p className="detail-text-box">{selectedEvidence.findings}</p>
                  </div>
                )}

                {selectedEvidence.threat_intelligence_sources && (
                  <div className="detail-section">
                    <span className="detail-label">Threat Intelligence Sources</span>
                    <span className="detail-value">{selectedEvidence.threat_intelligence_sources}</span>
                  </div>
                )}

                {selectedEvidence.threat_intelligence_summary && (
                  <div className="detail-section">
                    <span className="detail-label">Threat Intelligence Summary</span>
                    <p className="detail-text-box intel-summary">{selectedEvidence.threat_intelligence_summary}</p>
                  </div>
                )}
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
