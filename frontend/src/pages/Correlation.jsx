import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  getEvidence,
  getCases,
  getCorrelations,
  correlateSelected,
} from '../services/api';

function Correlation() {
  const navigate = useNavigate();
  const location = useLocation();

  // State
  const [evidenceList, setEvidenceList] = useState([]);
  const [casesList, setCasesList] = useState([]);
  const [correlationsData, setCorrelationsData] = useState(null);
  const [selectedCaseId, setSelectedCaseId] = useState('');
  const [selectedEvidenceIds, setSelectedEvidenceIds] = useState([]);
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [confidenceFilter, setConfidenceFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [viewMode, setViewMode] = useState('cards'); // 'cards' | 'matrix'
  const [loading, setLoading] = useState(true);
  const [correlating, setCorrelating] = useState(false);
  const [error, setError] = useState(null);
  const [showSelectorModal, setShowSelectorModal] = useState(false);

  // Initialize data
  const fetchData = async (caseId = null) => {
    setLoading(true);
    setError(null);
    try {
      const [evData, casesData, corrData] = await Promise.all([
        getEvidence().catch(() => []),
        getCases().catch(() => []),
        getCorrelations(null, caseId || undefined).catch((err) => {
          console.warn("Could not load correlations:", err);
          return null;
        }),
      ]);
      setEvidenceList(evData || []);
      setCasesList(casesData || []);
      setCorrelationsData(corrData);

      // If location.state provided an evidence_id, pre-filter
      if (location.state?.evidence_id) {
        setSelectedEvidenceIds([location.state.evidence_id]);
      }
    } catch (err) {
      console.error("Error loading correlation data:", err);
      setError("Unable to load correlation data. Please verify that the FastAPI backend is running.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const initialCase = location.state?.case_id || '';
    if (initialCase) {
      setSelectedCaseId(initialCase);
    }
    fetchData(initialCase);
  }, [location.state]);

  const handleCaseFilterChange = async (e) => {
    const cId = e.target.value;
    setSelectedCaseId(cId);
    setCorrelating(true);
    try {
      const corrData = await getCorrelations(null, cId || null);
      setCorrelationsData(corrData);
    } catch (err) {
      console.error("Error fetching case correlations:", err);
      setError("Failed to filter correlations by case.");
    } finally {
      setCorrelating(false);
    }
  };

  const handleRunManualSelection = async () => {
    if (selectedEvidenceIds.length < 2) {
      alert("Please select at least 2 evidence records to run pairwise cross-correlation.");
      return;
    }
    setCorrelating(true);
    setShowSelectorModal(false);
    try {
      const corrData = await correlateSelected(selectedEvidenceIds);
      setCorrelationsData(corrData);
    } catch (err) {
      console.error("Error running selected correlation:", err);
      setError("Failed to run correlation on selected artifacts.");
    } finally {
      setCorrelating(false);
    }
  };

  const handleResetFilters = () => {
    setSelectedCaseId('');
    setSelectedEvidenceIds([]);
    setTypeFilter('ALL');
    setConfidenceFilter('ALL');
    setSearchQuery('');
    fetchData(null);
  };

  const toggleSelectEvidenceId = (id) => {
    setSelectedEvidenceIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  // Badges and formatting
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

  const getRuleIcon = (rule) => {
    if (!rule) return '🔗';
    if (rule.includes('CRYPTOGRAPHIC')) return '🔒';
    if (rule.includes('MULTI_INDICATOR')) return '⚡';
    if (rule.includes('URL') || rule.includes('DOMAIN')) return '🌐';
    if (rule.includes('IP') || rule.includes('SUBNET')) return '🖥️';
    if (rule.includes('USER') || rule.includes('DEVICE')) return '👤';
    if (rule.includes('TEMPORAL')) return '⏱️';
    if (rule.includes('EVENT_RECORD') || rule.includes('CASE')) return '📁';
    return '🔗';
  };

  // Filter correlations
  const allCorrelations = correlationsData?.correlations || [];
  const filteredCorrelations = allCorrelations.filter((c) => {
    // Type Filter
    if (typeFilter !== 'ALL' && c.relationship_type !== typeFilter) {
      return false;
    }
    // Confidence Filter
    if (confidenceFilter !== 'ALL' && c.confidence_level !== confidenceFilter) {
      return false;
    }
    // Search Query (source, target, explanation, matched values)
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchSource = (c.source_input || '').toLowerCase().includes(q);
      const matchTarget = (c.target_input || '').toLowerCase().includes(q);
      const matchExplanation = (c.explanation || '').toLowerCase().includes(q);
      const matchSimple = (c.simple_explanation || '').toLowerCase().includes(q);
      const matchIndicators = (c.matched_indicators || []).some(
        (m) => (m.matched_value || '').toLowerCase().includes(q) || (m.indicator_type || '').toLowerCase().includes(q)
      );
      if (!matchSource && !matchTarget && !matchExplanation && !matchSimple && !matchIndicators) {
        return false;
      }
    }
    return true;
  });

  const typeCounts = correlationsData?.relationship_type_counts || {};

  return (
    <div className="page-container">
      {/* Page Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Evidence Correlation Engine</h1>
          <p className="page-subtitle">
            Forensic multi-attribute relationship analysis across technical indicators, time windows, infrastructure, and event records.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
          <button
            className="btn btn-secondary"
            onClick={() => fetchData(selectedCaseId)}
            disabled={loading || correlating}
          >
            🔄 {correlating ? 'Analyzing...' : 'Re-run Correlation'}
          </button>
          <button
            className="btn btn-secondary"
            onClick={() => setShowSelectorModal(true)}
            disabled={loading || evidenceList.length < 2}
          >
            🎯 Pairwise Artifact Selector {selectedEvidenceIds.length > 0 ? `(${selectedEvidenceIds.length})` : ''}
          </button>
          <button
            className="btn btn-primary"
            onClick={() => navigate('/reports', { state: { case_id: selectedCaseId || undefined } })}
          >
            📄 Generate Incident Report
          </button>
        </div>
      </div>

      {/* Scope & Control Bar */}
      <div className="section-card" style={{ marginBottom: '1.5rem', padding: '1rem 1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
          {/* Scope Dropdown */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.88rem', fontWeight: '600', color: 'var(--text-main)' }}>
              Investigation Scope:
            </span>
            <select
              className="form-input"
              style={{ width: 'auto', minWidth: '220px', padding: '0.45rem 0.75rem', fontSize: '0.88rem' }}
              value={selectedCaseId}
              onChange={handleCaseFilterChange}
              disabled={loading || correlating}
            >
              <option value="">🌐 Entire Evidence Repository ({evidenceList.length} items)</option>
              {casesList.map((c) => (
                <option key={c.case_id} value={c.case_id}>
                  📁 Case {c.case_id}: {c.title} ({c.evidence_count} items)
                </option>
              ))}
            </select>

            {selectedEvidenceIds.length > 0 && (
              <span className="badge badge-info" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}>
                🎯 Selected {selectedEvidenceIds.length} manual artifacts
                <button
                  onClick={() => {
                    setSelectedEvidenceIds([]);
                    fetchData(selectedCaseId);
                  }}
                  style={{ background: 'transparent', border: 'none', color: 'inherit', cursor: 'pointer', padding: 0 }}
                  title="Clear manual selection"
                >
                  ✕
                </button>
              </span>
            )}
          </div>

          {/* View Mode Toggle */}
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Display:</span>
            <button
              className={`btn btn-sm ${viewMode === 'cards' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setViewMode('cards')}
            >
              🗂️ Cards View
            </button>
            <button
              className={`btn btn-sm ${viewMode === 'matrix' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setViewMode('matrix')}
            >
              📊 Matrix Table
            </button>
          </div>
        </div>
      </div>

      {/* KPI Overview Cards */}
      <div className="stats-grid" style={{ marginBottom: '1.5rem' }}>
        <div className="stat-card">
          <div className="stat-header">
            <span className="stat-label">Evaluated Artifacts</span>
            <span className="stat-icon">📁</span>
          </div>
          <span className="stat-value">{correlationsData?.total_records_analyzed || 0}</span>
          <span className="stat-desc">Parsed technical indicator records</span>
        </div>

        <div className="stat-card">
          <div className="stat-header">
            <span className="stat-label">Correlated Links</span>
            <span className="stat-icon">🔗</span>
          </div>
          <span className="stat-value">{correlationsData?.total_correlations_found || 0}</span>
          <span className="stat-desc">Pairwise relationships identified</span>
        </div>

        <div className="stat-card">
          <div className="stat-header">
            <span className="stat-label">Multi-Indicator Convergence</span>
            <span className="stat-icon">⚡</span>
          </div>
          <span className="stat-value" style={{ color: '#c084fc' }}>
            {typeCounts.MULTI_INDICATOR || 0}
          </span>
          <span className="stat-desc">High-confidence shared vectors</span>
        </div>

        <div className="stat-card">
          <div className="stat-header">
            <span className="stat-label">Exact Technical Matches</span>
            <span className="stat-icon">🎯</span>
          </div>
          <span className="stat-value" style={{ color: '#38bdf8' }}>
            {typeCounts.EXACT_MATCH || 0}
          </span>
          <span className="stat-desc">Identical Hash, IP, Domain, or URL</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="section-card" style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
            {/* Type Filters */}
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              <button
                className={`btn btn-sm ${typeFilter === 'ALL' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setTypeFilter('ALL')}
              >
                All ({allCorrelations.length})
              </button>
              <button
                className={`btn btn-sm ${typeFilter === 'MULTI_INDICATOR' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setTypeFilter('MULTI_INDICATOR')}
              >
                ⚡ Multi-Indicator ({typeCounts.MULTI_INDICATOR || 0})
              </button>
              <button
                className={`btn btn-sm ${typeFilter === 'EXACT_MATCH' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setTypeFilter('EXACT_MATCH')}
              >
                🎯 Exact Match ({typeCounts.EXACT_MATCH || 0})
              </button>
              <button
                className={`btn btn-sm ${typeFilter === 'TEMPORAL_RELATIONSHIP' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setTypeFilter('TEMPORAL_RELATIONSHIP')}
              >
                ⏱️ Temporal ({typeCounts.TEMPORAL_RELATIONSHIP || 0})
              </button>
              <button
                className={`btn btn-sm ${typeFilter === 'UNCONFIRMED_HYPOTHESIS' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setTypeFilter('UNCONFIRMED_HYPOTHESIS')}
              >
                💡 Hypotheses ({typeCounts.UNCONFIRMED_HYPOTHESIS || 0})
              </button>
            </div>

            {/* Confidence Filter */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Confidence:</span>
              <select
                className="form-input"
                style={{ width: 'auto', padding: '0.35rem 0.65rem', fontSize: '0.82rem' }}
                value={confidenceFilter}
                onChange={(e) => setConfidenceFilter(e.target.value)}
              >
                <option value="ALL">All Confidence Levels</option>
                <option value="HIGH">High Confidence</option>
                <option value="MEDIUM">Medium Confidence</option>
                <option value="LOW">Low Confidence</option>
                <option value="INFORMATIONAL">Informational</option>
              </select>
            </div>
          </div>

          {/* Search Input */}
          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
            <input
              type="text"
              className="form-input"
              placeholder="🔍 Search correlation items by IP, domain, hash, rule, or explanation..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{ fontSize: '0.88rem' }}
            />
            {(searchQuery || typeFilter !== 'ALL' || confidenceFilter !== 'ALL' || selectedCaseId) && (
              <button className="btn btn-secondary btn-sm" onClick={handleResetFilters}>
                Clear Filters
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      {loading ? (
        <div className="section-card">
          <div className="state-message">
            <span className="spinner">⏳</span>
            <p className="loading-text">Extracting indicators and executing forensic correlation algorithms...</p>
          </div>
        </div>
      ) : error ? (
        <div className="section-card">
          <div className="state-message error-box">
            <span className="error-icon">⚠️</span>
            <p className="error-text">{error}</p>
            <button className="btn btn-primary btn-sm" onClick={() => fetchData(selectedCaseId)}>
              Retry Connection
            </button>
          </div>
        </div>
      ) : filteredCorrelations.length === 0 ? (
        <div className="section-card">
          <div className="empty-state">
            <span className="empty-icon">🔗</span>
            <p className="empty-title">No correlations found matching current filters</p>
            <p className="empty-text">
              {evidenceList.length < 2
                ? "You need at least 2 analyzed evidence records in the database for the engine to evaluate relationships."
                : "None of the records currently share IP addresses, file hashes, domains, user/device accounts, or temporal proximity under these filter criteria."}
            </p>
            <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem' }}>
              <button className="btn btn-secondary btn-sm" onClick={handleResetFilters}>
                Reset All Filters
              </button>
              <button className="btn btn-primary btn-sm" onClick={() => navigate('/analyze')}>
                Analyze More Artifacts
              </button>
            </div>
          </div>
        </div>
      ) : viewMode === 'cards' ? (
        /* Cards View */
        <div className="correlation-list">
          {filteredCorrelations.map((rel) => (
            <div key={rel.relationship_id} className="correlation-card">
              {/* Header: Nodes & Badges */}
              <div className="correlation-header">
                <div className="correlation-nodes">
                  {/* Source Node */}
                  <div
                    className={`node-chip ${rel.source_risk_level === 'HIGH' ? 'high' : ''}`}
                    title={`Source: ${rel.source_input} (${rel.source_evidence_id})`}
                  >
                    <code>{rel.source_evidence_id.substring(0, 8)}</code>: {rel.source_input}
                    {rel.source_risk_level && (
                      <span className={`badge ${getBadgeClass(rel.source_risk_level)}`} style={{ marginLeft: '0.4rem', fontSize: '0.72rem', padding: '0.1rem 0.4rem' }}>
                        {rel.source_risk_level}
                      </span>
                    )}
                  </div>

                  <span className="rel-arrow">⇄</span>

                  {/* Target Node */}
                  <div
                    className={`node-chip ${rel.target_risk_level === 'HIGH' ? 'high' : ''}`}
                    title={`Target: ${rel.target_input} (${rel.target_evidence_id})`}
                  >
                    <code>{rel.target_evidence_id.substring(0, 8)}</code>: {rel.target_input}
                    {rel.target_risk_level && (
                      <span className={`badge ${getBadgeClass(rel.target_risk_level)}`} style={{ marginLeft: '0.4rem', fontSize: '0.72rem', padding: '0.1rem 0.4rem' }}>
                        {rel.target_risk_level}
                      </span>
                    )}
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
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

              {/* Rule & Matched Indicators */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {rel.rule_applied && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.82rem', color: 'var(--primary-accent)' }}>
                    <span>{getRuleIcon(rel.rule_applied)} <strong>Rule Applied:</strong> <code>{rel.rule_applied}</code></span>
                  </div>
                )}

                {rel.matched_indicators && rel.matched_indicators.length > 0 && (
                  <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
                    <span className="detail-label" style={{ marginRight: '0.25rem', fontSize: '0.78rem' }}>Matched Indicators:</span>
                    {rel.matched_indicators.map((ind, i) => (
                      <span key={i} className="matched-pill" title={ind.details}>
                        <strong>{ind.indicator_type.toUpperCase()}:</strong> {ind.matched_value}
                        {ind.is_private_or_shared && <span style={{ color: '#f59e0b', marginLeft: '0.25rem' }}>(Private/Shared)</span>}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* Simple Plain-English Explanation */}
              {rel.simple_explanation ? (
                <div style={{ background: 'rgba(56, 189, 248, 0.05)', borderLeft: '3px solid var(--primary-accent)', padding: '0.65rem 0.85rem', borderRadius: '4px' }}>
                  <strong style={{ fontSize: '0.82rem', color: 'var(--primary-accent)', display: 'block', marginBottom: '0.2rem' }}>
                    💡 Plain-English Summary:
                  </strong>
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-main)', margin: 0, lineHeight: 1.45 }}>
                    {rel.simple_explanation}
                  </p>
                </div>
              ) : (
                <p style={{ fontSize: '0.88rem', color: 'var(--text-main)', margin: 0, lineHeight: 1.45 }}>
                  {rel.explanation}
                </p>
              )}

              {/* Recommended Investigator Action */}
              {rel.investigator_action && (
                <div style={{ background: 'rgba(16, 185, 129, 0.06)', borderLeft: '3px solid var(--low-color)', padding: '0.55rem 0.75rem', borderRadius: '4px' }}>
                  <strong style={{ fontSize: '0.8rem', color: 'var(--low-color)', display: 'block', marginBottom: '0.15rem' }}>
                    🎯 Recommended Investigator Next Step:
                  </strong>
                  <p style={{ fontSize: '0.83rem', color: 'var(--text-main)', margin: 0, lineHeight: 1.4 }}>
                    {rel.investigator_action}
                  </p>
                </div>
              )}

              {/* Forensic Rigor Caveat Box */}
              {rel.forensic_caveat && (
                <div className="caveat-box">
                  ⚖️ <strong>Forensic Rigor Note:</strong> {rel.forensic_caveat}
                </div>
              )}

              {/* Action Bar */}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.25rem' }}>
                <button
                  className="btn btn-secondary btn-sm"
                  onClick={() => navigate('/reports', { state: { evidence_id: rel.source_evidence_id } })}
                >
                  📄 Report on Pair
                </button>
              </div>
            </div>
          ))}
        </div>
      ) : (
        /* Matrix Table View */
        <div className="section-card">
          <div className="table-container">
            <table className="evidence-table" style={{ fontSize: '0.85rem' }}>
              <thead>
                <tr>
                  <th>Rel ID</th>
                  <th>Source Artifact</th>
                  <th>Target Artifact</th>
                  <th>Relationship Category</th>
                  <th>Confidence</th>
                  <th>Matched Vector</th>
                  <th>Time Delta</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredCorrelations.map((rel) => {
                  const firstMatch = rel.matched_indicators?.[0];
                  return (
                    <tr key={rel.relationship_id}>
                      <td><code>{rel.relationship_id}</code></td>
                      <td className="input-cell" title={rel.source_input}>
                        <strong>{rel.source_input}</strong>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          ID: {rel.source_evidence_id.substring(0, 8)}
                        </div>
                      </td>
                      <td className="input-cell" title={rel.target_input}>
                        <strong>{rel.target_input}</strong>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          ID: {rel.target_evidence_id.substring(0, 8)}
                        </div>
                      </td>
                      <td>
                        <span className={`badge ${getRelBadgeClass(rel.relationship_type)}`}>
                          {rel.relationship_type.replace('_', ' ')}
                        </span>
                      </td>
                      <td>
                        <span className={`badge ${getConfBadgeClass(rel.confidence_level)}`}>
                          {rel.confidence_level}
                        </span>
                      </td>
                      <td>
                        {firstMatch ? (
                          <span className="matched-pill" title={firstMatch.details}>
                            {firstMatch.indicator_type}: {firstMatch.matched_value}
                          </span>
                        ) : (
                          'Temporal'
                        )}
                      </td>
                      <td className="time-cell">{rel.time_delta_human || 'N/A'}</td>
                      <td>
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => navigate('/reports', { state: { evidence_id: rel.source_evidence_id } })}
                        >
                          📄 Report
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Manual Selection Modal */}
      {showSelectorModal && (
        <div className="modal-backdrop" onClick={() => setShowSelectorModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '750px' }}>
            <div className="modal-header">
              <h2>Select Artifacts for Pairwise Cross-Correlation</h2>
              <button className="modal-close" onClick={() => setShowSelectorModal(false)}>✕</button>
            </div>
            <div className="modal-body">
              <p style={{ fontSize: '0.88rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
                Select two or more stored digital artifacts to evaluate specific technical overlap and co-occurrence.
              </p>

              <div style={{ maxHeight: '350px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {evidenceList.map((item) => {
                  const isChecked = selectedEvidenceIds.includes(item.evidence_id);
                  return (
                    <label
                      key={item.evidence_id}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.75rem',
                        padding: '0.6rem 0.85rem',
                        background: isChecked ? 'rgba(56, 189, 248, 0.1)' : 'var(--bg-dark)',
                        border: `1px solid ${isChecked ? 'var(--primary-accent)' : 'var(--border-color)'}`,
                        borderRadius: '6px',
                        cursor: 'pointer',
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => toggleSelectEvidenceId(item.evidence_id)}
                      />
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <strong style={{ fontSize: '0.88rem', color: 'var(--text-main)', wordBreak: 'break-all' }}>
                            {item.input_value || item.input}
                          </strong>
                          <span className={`badge ${getBadgeClass(item.risk_level)}`} style={{ fontSize: '0.72rem' }}>
                            {item.risk_level} ({item.risk_score})
                          </span>
                        </div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                          ID: <code>{item.evidence_id.substring(0, 10)}...</code> &bull; Type: {item.input_type.toUpperCase()}
                        </div>
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>
            <div className="modal-footer" style={{ display: 'flex', justifyContent: 'space-between' }}>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => setSelectedEvidenceIds([])}
              >
                Clear Selection
              </button>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button className="btn btn-secondary btn-sm" onClick={() => setShowSelectorModal(false)}>
                  Cancel
                </button>
                <button
                  className="btn btn-primary btn-sm"
                  onClick={handleRunManualSelection}
                  disabled={selectedEvidenceIds.length < 2}
                >
                  ⚡ Correlate Selected ({selectedEvidenceIds.length})
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default Correlation;
