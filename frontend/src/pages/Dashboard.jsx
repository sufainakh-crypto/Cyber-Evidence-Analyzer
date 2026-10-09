import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getEvidence } from '../services/api';

function Dashboard() {
  const navigate = useNavigate();
  const [evidenceList, setEvidenceList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchDashboardData = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getEvidence();
      setEvidenceList(data || []);
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
    .slice(0, 5);

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
            Real-time Threat Intelligence and Heuristic Evidence Analysis for URLs, IP Addresses, and Domains.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button className="btn btn-secondary" onClick={fetchDashboardData} disabled={loading}>
            🔄 Refresh
          </button>
          <button className="btn btn-primary" onClick={() => navigate('/analyze')}>
            ➕ Analyze New Threat
          </button>
        </div>
      </div>

      {loading ? (
        <div className="section-card">
          <div className="state-message">
            <span className="spinner">⏳</span>
            <p className="loading-text">Loading statistics...</p>
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

          {/* Recent Analysis Section */}
          <div className="section-card">
            <div className="section-header">
              <h2>Recent Analysis</h2>
              <span className="badge badge-info">
                {total > 0 ? `${recentItems.length} Recent Records` : 'Latest Activity'}
              </span>
            </div>

            {recentItems.length === 0 ? (
              <div className="empty-state">
                <p className="empty-title">No recent analysis activity</p>
                <p className="empty-text">Submit a URL, IP address, or Domain on the Analyze page to view real-time evidence here.</p>
                <button className="btn btn-secondary" onClick={() => navigate('/analyze')}>
                  Start First Analysis
                </button>
              </div>
            ) : (
              <div className="table-container">
                <table className="evidence-table">
                  <thead>
                    <tr>
                      <th>Input</th>
                      <th>Type</th>
                      <th>Risk Level</th>
                      <th>Risk Score</th>
                      <th>Timestamp</th>
                      <th style={{ textAlign: 'right' }}>Action</th>
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
                        <td className="time-cell">
                          {item.timestamp ? new Date(item.timestamp).toLocaleString() : 'N/A'}
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={() => navigate('/evidence')}
                          >
                            View in Repository
                          </button>
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
