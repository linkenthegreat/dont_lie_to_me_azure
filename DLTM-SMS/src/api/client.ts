const BASE = '/api';

export async function analyzeMessage(messageText: string, phoneNumber?: string) {
  const res = await fetch(`${BASE}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ messageText, phoneNumber }),
  });
  if (!res.ok) throw new Error('Analysis failed');
  return res.json();
}

export async function getTemplates() {
  const res = await fetch(`${BASE}/numbers/templates`);
  if (!res.ok) throw new Error('Failed to fetch templates');
  return res.json();
}

export async function getNumbers(label?: string) {
  const params = new URLSearchParams();
  if (label) params.set('label', label);
  const res = await fetch(`${BASE}/numbers?${params}`);
  if (!res.ok) throw new Error('Failed to fetch numbers');
  return res.json();
}

export async function getStats() {
  const res = await fetch(`${BASE}/numbers/stats`);
  if (!res.ok) throw new Error('Failed to fetch stats');
  return res.json();
}

export async function reportNumber(phoneNumber: string, category: string, description: string) {
  const res = await fetch(`${BASE}/report`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ phoneNumber, category, description }),
  });
  if (!res.ok) throw new Error('Failed to report number');
  return res.json();
}
