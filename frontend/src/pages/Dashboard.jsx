import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getEvidence, getCases, getCorrelations } from '../services/api';

function Dashboard() {
  const navigate = useNavigate();
  const [evidenceList, setEvidenceList] = useState([]);
  const [casesList, setCasesList] = useState([]);
  const [correlationsData, setCorrelationsData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchDashboardData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [evData, casesData, corrData] = await Promise.all([
        getEvidence().catch(() => []),
        getCases().catch(() => []),
        getCorrelations().catch(() => null),
      ]);
      setEvidenceList(evData || []);
      setCasesList(casesData || []);
      setCorrelationsData(corrData);
    } catch (err) {
      console.error("Dashboard failed to load evidence:", err);
      setError("Unable to load dashboard statistics. Please make sure the FastAPI backend is running.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  // Compute dynamic statistics strictly from actual backend evidence records
  const total = evidenceList.length;
  const casesCount = casesList.length;
  const lowRisk = evidenceList.filter(
    (e) => (e.risk_level || '').trim().toUpperCase() === 'LOW'
  ).length;
  const mediumRisk = evidenceList.filter(
    (e) => (e.risk_level || '').trim().toUpperCase() === 'MEDIUM'
  ).length;
  const highRisk = evidenceList.filter(
    (e) => (e.risk_level || '').trim().toUpperCase() === 'HIGH'
  ).length;

  // Sort most recent records first by timestamp
  const recentItems = [...evidenceList]
    .sort((a, b) => {
      const timeA = new Date(a.timestamp || 0).getTime();
      const timeB = new Date(b.timestamp || 0).getTime();
      return timeB - timeA;
    })
    .slice(0, 6);

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
          <h1 className="page-title">Cyber Evidence Analyzer</h1>
          <p className="page-subtitle">
            Digital Forensics &amp; Threat Intelligence Platform — OPCODE IMPACT 2026.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
          <button className="btn btn-secondary" onClick={fetchDashboardData} disabled={loading}>
            🔄 Refresh
          </button>
          <button className="btn btn-secondary" onClick={() => navigate('/correlation')}>
            🔗 Correlations Hub
          </button>
          <button className="btn btn-secondary" onClick={() => navigate('/cases')}>
            📁 Cases Hub
          </button>
          <button className="btn btn-primary" onClick={() => navigate('/analyze')}>
            ➕ Analyze Threat
          </button>
        </div>
      </div>

      {loading ? (
        <div className="section-card">
          <div className="state-message">
            <span className="spinner">⏳</span>
            <p className="loading-text">Loading statistics from SQLite repository...</p>
          </div>
        </div>
      ) : error ? (
        <div className="section-card">
          <div className="state-message error-box">
            <span className="error-icon">⚠️</span>
            <p className="error-text">{error}</p>
            <button className="btn btn-primary btn-sm" onClick={fetchDashboardData}>
              Retry Connection
            </button>
          </div>
        </div>
      ) : (
        <>
          {/* Dynamic Overview Stats Cards */}
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-header">
                <span className="stat-title">Total Evidence</span>
                <span className="stat-icon">📊</span>
              </div>
              <div className="stat-value">{total}</div>
              <p className="stat-desc">Stored analysis records</p>
            </div>

            <div className="stat-card" style={{ borderLeft: '3px solid #c084fc', cursor: 'pointer' }} onClick={() => navigate('/correlation')}>
              <div className="stat-header">
                <span className="stat-title">Correlated Links</span>
                <span className="stat-icon">🔗</span>
              </div>
              <div className="stat-value" style={{ color: '#c084fc' }}>
                {correlationsData?.total_correlations_found || 0}
              </div>
              <p className="stat-desc">Identified relationships &rarr;</p>
            </div>

            <div className="stat-card" style={{ borderLeft: '3px solid var(--primary-accent)' }}>
              <div className="stat-header">
                <span className="stat-title">Investigation Cases</span>
                <span className="stat-icon">📁</span>
              </div>
              <div className="stat-value" style={{ color: 'var(--primary-accent)' }}>{casesCount}</div>
              <p className="stat-desc">Active cases open</p>
            </div>

            <div className="stat-card border-low">
              <div className="stat-header">
                <span className="stat-title">Low Risk</span>
                <span className="stat-icon green">🟢</span>
              </div>
              <div className="stat-value text-low">{lowRisk}</div>
              <p className="stat-desc">Score &lt; 35</p>
            </div>

            <div className="stat-card border-medium">
              <div className="stat-header">
                <span className="stat-title">Medium Risk</span>
                <span className="stat-icon yellow">🟡</span>
              </div>
              <div className="stat-value text-medium">{mediumRisk}</div>
              <p className="stat-desc">Score 35 - 69</p>
            </div>

            <div className="stat-card border-high">
              <div className="stat-header">
                <span className="stat-title">High Risk</span>
                <span className="stat-icon red">🔴</span>
              </div>
              <div className="stat-value text-high">{highRisk}</div>
              <p className="stat-desc">Score &ge; 70</p>
            </div>
          </div>

          {/* Quick Workflow Action Shortcuts */}
          <div className="section-card" style={{ padding: '1rem 1.5rem', marginBottom: '1.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
              <div>
                <strong style={{ fontSize: '0.95rem' }}>⚡ Quick Forensic Workflows:</strong>
                <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                  Rapidly transition from artifact ingestion to case tracking and official report delivery.
                </p>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                <button className="btn btn-secondary btn-sm" onClick={() => navigate('/cases')}>
                  📁 Open Investigation Case
                </button>
                <button className="btn btn-secondary btn-sm" onClick={() => navigate('/evidence')}>
                  🛡️ Verify Cryptographic Integrity
                </button>
                <button className="btn btn-secondary btn-sm" onClick={() => navigate('/reports')}>
                  📄 Generate Incident Report
                </button>
              </div>
            </div>
          </div>

          {/* Recent Analysis Section */}
          <div className="section-card">
            <div className="section-header">
              <h2>Recent Evidence Ingestions</h2>
              <span className="badge badge-info">
                {total > 0 ? `${recentItems.length} Recent Records` : 'Latest Activity'}
              </span>
            </div>

            {recentItems.length === 0 ? (
              <div className="empty-state">
                <p className="empty-title">No recent analysis activity</p>
                <p className="empty-text">Submit a URL, IP address, or Domain on the Analyze page to view real-time evidence here.</p>
                <button className="btn btn-primary" onClick={() => navigate('/analyze')}>
                  Start First Analysis
                </button>
              </div>
            ) : (
              <div className="table-container">
                <table className="evidence-table">
                  <thead>
                    <tr>
                      <th>Artifact Input</th>
                      <th>Type</th>
                      <th>Risk Level</th>
                      <th>Risk Score</th>
                      <th>Case</th>
                      <th>Timestamp</th>
                      <th style={{ textAlign: 'right' }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentItems.map((item) => (
                      <tr key={item.evidence_id || item.id}>
                        <td className="input-cell" title={item.input_value || item.input}>
                          {item.input_value || item.input}
                        </td>
                        <td>
                          <span className="type-tag">{item.input_type}</span>
                        </td>
                        <td>
                          <span className={`badge ${getBadgeClass(item.risk_level)}`}>
                            {item.risk_level}
                          </span>
                        </td>
                        <td>
                          <span className="score-value">{item.risk_score}</span>
                        </td>
                        <td>
                          {item.cases && item.cases.length > 0 ? (
                            <span
                              className="badge badge-info"
                              style={{ cursor: 'pointer' }}
                              onClick={() => navigate('/cases', { state: { case_id: item.cases[0] } })}
                            >
                              📁 {item.cases[0]}
                            </span>
                          ) : (
                            <span className="badge badge-neutral" style={{ opacity: 0.6 }}>Standalone</span>
                          )}
                        </td>
                        <td className="time-cell">
                          {item.timestamp ? new Date(item.timestamp).toLocaleString() : 'N/A'}
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <div className="action-buttons" style={{ justifyContent: 'flex-end' }}>
                            <button
                              className="btn btn-secondary btn-sm"
                              onClick={() => navigate('/correlation', { state: { evidence_id: item.evidence_id } })}
                              title="Correlate this artifact across the repository"
                            >
                              🔗 Correlate
                            </button>
                            <button
                              className="btn btn-secondary btn-sm"
                              onClick={() => navigate('/evidence')}
                            >
                              View
                            </button>
                            <button
                              className="btn btn-primary btn-sm"
                              onClick={() => navigate('/reports', { state: { evidence_id: item.evidence_id } })}
                            >
                              Report
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
        </>
      )}
    </div>
  );
}

export default Dashboard;
