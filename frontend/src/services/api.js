import axios from 'axios';

const api = axios.create({
  baseURL: 'http://127.0.0.1:8000',
  headers: {
    'Content-Type': 'application/json',
  },
});

export const analyzeInput = async (inputValue, caseId = null) => {
  const payload = { input: inputValue };
  if (caseId) payload.case_id = caseId;
  const response = await api.post('/analyze', payload);
  return response.data;
};

export const getEvidence = async () => {
  const response = await api.get('/evidence');
  return response.data;
};

export const getEvidenceById = async (evidence_id) => {
  const response = await api.get(`/evidence/${evidence_id}`);
  return response.data;
};

export const verifyEvidenceIntegrity = async (evidence_id) => {
  const response = await api.get(`/evidence/${evidence_id}/verify`);
  return response.data;
};

export const deleteEvidence = async (evidence_id) => {
  const response = await api.delete(`/evidence/${evidence_id}`);
  return response.data;
};

// Case Management APIs
export const getCases = async () => {
  const response = await api.get('/cases');
  return response.data;
};

export const getCaseById = async (case_id) => {
  const response = await api.get(`/cases/${case_id}`);
  return response.data;
};

export const createCase = async (caseData) => {
  const response = await api.post('/cases', caseData);
  return response.data;
};

export const deleteCase = async (case_id) => {
  const response = await api.delete(`/cases/${case_id}`);
  return response.data;
};

export const addEvidenceToCase = async (case_id, evidence_id, notes = '') => {
  const response = await api.post(`/cases/${case_id}/evidence`, {
    evidence_id,
    notes,
  });
  return response.data;
};

export const removeEvidenceFromCase = async (case_id, evidence_id) => {
  const response = await api.delete(`/cases/${case_id}/evidence/${evidence_id}`);
  return response.data;
};

// Incident Report API
export const createReport = async (reportData) => {
  const response = await api.post('/reports', reportData);
  return response.data;
};

export const getCorrelations = async (evidence_id = null, case_id = null) => {
  const params = {};
  if (evidence_id) params.evidence_id = evidence_id;
  if (case_id) params.case_id = case_id;
  const response = await api.get('/correlate', { params });
  return response.data;
};

export const correlateSelected = async (evidence_ids = null, case_id = null) => {
  const payload = {};
  if (evidence_ids) payload.evidence_ids = evidence_ids;
  if (case_id) payload.case_id = case_id;
  const response = await api.post('/correlate', payload);
  return response.data;
};

export default api;
