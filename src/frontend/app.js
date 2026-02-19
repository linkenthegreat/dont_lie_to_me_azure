/**
 * Don't Lie To Me – Frontend JavaScript
 *
 * Handles tab switching, file upload (drag & drop + click), and API calls
 * to the Azure Functions backend.
 *
 * API base URL is resolved automatically:
 *   - In production: same origin (/api/...)
 *   - In local dev:  set window.API_BASE_URL before loading this script,
 *                    or rely on the default http://localhost:7071/api
 */

(function () {
  'use strict';

  // ── Configuration ─────────────────────────────────────────────────────
  const API_BASE = window.API_BASE_URL || 'http://localhost:7071/api';

  // ── DOM References ────────────────────────────────────────────────────
  const tabs          = document.querySelectorAll('.tab');
  const tabPanels     = document.querySelectorAll('.tab-panel');
  const analyzeBtn    = document.getElementById('analyze-btn');
  const messageInput  = document.getElementById('message-input');
  const imageInput    = document.getElementById('image-input');
  const dropZone      = document.getElementById('drop-zone');
  const dropZoneText  = document.getElementById('drop-zone-text');
  const analysisMode  = document.getElementById('analysis-mode');
  const loadingEl     = document.getElementById('loading');
  const resultsSection = document.getElementById('results-section');

  // Result blocks
  const resultClassify  = document.getElementById('result-classify');
  const resultAnalyze   = document.getElementById('result-analyze');
  const resultGuidance  = document.getElementById('result-guidance');
  const resultError     = document.getElementById('result-error');

  let activeTab = 'text';
  let selectedFile = null;

  // ── Tab switching ─────────────────────────────────────────────────────
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => { t.classList.remove('active'); t.setAttribute('aria-selected', 'false'); });
      tabPanels.forEach(p => p.classList.remove('active'));

      tab.classList.add('active');
      tab.setAttribute('aria-selected', 'true');
      activeTab = tab.dataset.tab;
      document.getElementById(`tab-${activeTab}`).classList.add('active');
    });
  });

  // ── File upload ───────────────────────────────────────────────────────
  imageInput.addEventListener('change', () => {
    if (imageInput.files.length) {
      selectedFile = imageInput.files[0];
      dropZoneText.textContent = `✅ ${selectedFile.name}`;
    }
  });

  dropZone.addEventListener('dragover', e => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('drag-over');
  });

  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const files = e.dataTransfer.files;
    if (files.length && files[0].type.startsWith('image/')) {
      selectedFile = files[0];
      dropZoneText.textContent = `✅ ${selectedFile.name}`;
    }
  });

  // ── Analyse button ─────────────────────────────────────────────────────
  analyzeBtn.addEventListener('click', async () => {
    let text = '';

    if (activeTab === 'text') {
      text = messageInput.value.trim();
      if (!text) {
        alert('Please paste a message to analyse.');
        return;
      }
    } else {
      if (!selectedFile) {
        alert('Please select or drop an image file.');
        return;
      }
      try {
        text = await extractTextFromImage(selectedFile);
      } catch {
        showError('Failed to process the image. Please try pasting the text instead.');
        return;
      }
    }

    const mode = analysisMode.value;
    setLoading(true);
    hideAllResults();

    try {
      const data = await callApi(mode, text);
      renderResult(mode, data);
    } catch (err) {
      showError(err.message || 'An unexpected error occurred. Please try again.');
    } finally {
      setLoading(false);
    }
  });

  // ── API calls ─────────────────────────────────────────────────────────
  async function callApi(endpoint, text) {
    const url = `${API_BASE}/${endpoint}`;
    const body = { text };

    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      let detail = '';
      try {
        const errBody = await response.json();
        detail = errBody.error || errBody.detail || '';
      } catch { /* ignore */ }
      throw new Error(`API error ${response.status}${detail ? ': ' + detail : ''}.`);
    }

    return response.json();
  }

  // ── Image text extraction (client-side placeholder) ────────────────────
  /**
   * Converts the image to a base64 data URI and returns it as the "text"
   * payload. The backend is responsible for OCR or multi-modal analysis.
   *
   * Replace this with a real OCR call (e.g. Azure AI Vision Read API) if
   * you need client-side text extraction.
   */
  function extractTextFromImage(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result); // base64 data URI
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  }

  // ── Render results ─────────────────────────────────────────────────────
  function renderResult(mode, data) {
    resultsSection.classList.remove('hidden');

    if (mode === 'classify') {
      const classification = data.classification || 'UNKNOWN';
      const badge = document.getElementById('classification-badge');
      badge.textContent = classification.replace(/_/g, ' ');
      badge.className = `badge badge-${classification}`;
      document.getElementById('confidence-value').textContent =
        data.confidence != null ? `${Math.round(data.confidence * 100)}%` : 'N/A';
      document.getElementById('reasoning-value').textContent = data.reasoning || '';
      resultClassify.classList.remove('hidden');

    } else if (mode === 'analyze') {
      populateList('red-flags-list', data.red_flags);
      populateList('persuasion-list', data.persuasion_techniques);
      populateList('impersonation-list', data.impersonation_indicators);
      document.getElementById('analysis-summary').textContent = data.summary || '';
      resultAnalyze.classList.remove('hidden');

    } else if (mode === 'guidance') {
      populateList('immediate-actions-list', data.immediate_actions, 'ol');
      populateList('reporting-steps-list', data.reporting_steps, 'ol');
      populateList('prevention-tips-list', data.prevention_tips);
      populateResourcesList('resources-list', data.resources);
      resultGuidance.classList.remove('hidden');
    }
  }

  function populateList(elementId, items, _type = 'ul') {
    const el = document.getElementById(elementId);
    el.innerHTML = '';
    if (!items || items.length === 0) {
      const li = document.createElement('li');
      li.textContent = 'None identified.';
      li.style.color = 'var(--color-muted)';
      el.appendChild(li);
      return;
    }
    items.forEach(item => {
      const li = document.createElement('li');
      li.textContent = item;
      el.appendChild(li);
    });
  }

  function populateResourcesList(elementId, items) {
    const el = document.getElementById(elementId);
    el.innerHTML = '';
    if (!items || items.length === 0) {
      const li = document.createElement('li');
      li.textContent = 'No specific resources provided.';
      li.style.color = 'var(--color-muted)';
      el.appendChild(li);
      return;
    }
    items.forEach(item => {
      const li = document.createElement('li');
      // If the item looks like a URL, render it as a link
      if (/^https?:\/\//i.test(item)) {
        const a = document.createElement('a');
        a.href = item;
        a.textContent = item;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        li.appendChild(a);
      } else {
        li.textContent = item;
      }
      el.appendChild(li);
    });
  }

  // ── UI helpers ─────────────────────────────────────────────────────────
  function setLoading(isLoading) {
    loadingEl.classList.toggle('hidden', !isLoading);
    analyzeBtn.disabled = isLoading;
  }

  function hideAllResults() {
    resultsSection.classList.add('hidden');
    [resultClassify, resultAnalyze, resultGuidance, resultError].forEach(el => {
      el.classList.add('hidden');
    });
  }

  function showError(message) {
    resultsSection.classList.remove('hidden');
    resultError.classList.remove('hidden');
    document.getElementById('error-message').textContent = `⚠️ ${message}`;
  }

})();
