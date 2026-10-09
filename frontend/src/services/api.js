import axios from 'axios';

const api = axios.create({
  baseURL: 'http://127.0.0.1:8000',
  headers: {
    'Content-Type': 'application/json',
  },
});

export const analyzeInput = async (inputValue) => {
  const response = await api.post('/analyze', { input: inputValue });
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

export const deleteEvidence = async (evidence_id) => {
  const response = await api.delete(`/evidence/${evidence_id}`);
  return response.data;
};

export const createReport = async (reportData) => {
  const response = await api.post('/reports', reportData);
  return response.data;
};

export default api;
