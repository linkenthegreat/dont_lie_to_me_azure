/**
 * Don't Lie To Me -- Frontend JavaScript
 *
 * Handles tab switching, file upload, API calls, i18n, session management,
 * history, export, and feedback.
 */

(function () {
  'use strict';

  // -- Configuration --------------------------------------------------------
  const API_BASE = window.API_BASE_URL || 'http://localhost:7071/api';

  // -- Session management ---------------------------------------------------
  function getSessionId() {
    let sid = localStorage.getItem('dltm_session_id');
    if (!sid) {
      sid = crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + Math.random().toString(36).slice(2);
      localStorage.setItem('dltm_session_id', sid);
    }
    return sid;
  }

  const SESSION_ID = getSessionId();

  // -- DOM References -------------------------------------------------------
  const tabs           = document.querySelectorAll('.tab');
  const tabPanels      = document.querySelectorAll('.tab-panel');
  const analyzeBtn     = document.getElementById('analyze-btn');
  const messageInput   = document.getElementById('message-input');
  const imageInput     = document.getElementById('image-input');
  const dropZone       = document.getElementById('drop-zone');
  const dropZoneText   = document.getElementById('drop-zone-text');
  const analysisMode   = document.getElementById('analysis-mode');
  const loadingEl      = document.getElementById('loading');
  const resultsSection = document.getElementById('results-section');
  const langSelect     = document.getElementById('lang-select');

  // Result blocks
  const resultClassify  = document.getElementById('result-classify');
  const resultAnalyze   = document.getElementById('result-analyze');
  const resultGuidance  = document.getElementById('result-guidance');
  const resultSentiment = document.getElementById('result-sentiment');
  const resultError     = document.getElementById('result-error');
  const feedbackWidget  = document.getElementById('feedback-widget');

  let activeTab = 'text';
  let selectedFile = null;
  let currentTranslations = {};

  // -- Tab switching --------------------------------------------------------
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => { t.classList.remove('active'); t.setAttribute('aria-selected', 'false'); });
      tabPanels.forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      tab.setAttribute('aria-selected', 'true');
      activeTab = tab.dataset.tab;
      document.getElementById('tab-' + activeTab).classList.add('active');
    });
  });

  // -- File upload ----------------------------------------------------------
  imageInput.addEventListener('change', () => {
    if (imageInput.files.length) {
      selectedFile = imageInput.files[0];
      dropZoneText.textContent = selectedFile.name;
    }
  });

  dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
  dropZone.addEventListener('dragleave', () => { dropZone.classList.remove('drag-over'); });
  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const files = e.dataTransfer.files;
    if (files.length && files[0].type.startsWith('image/')) {
      selectedFile = files[0];
      dropZoneText.textContent = selectedFile.name;
    }
  });

  // -- Analyse button -------------------------------------------------------
  analyzeBtn.addEventListener('click', async () => {
    let text = '';

    if (activeTab === 'text') {
      text = messageInput.value.trim();
      if (!text) { alert('Please paste a message to analyse.'); return; }
    } else {
      if (!selectedFile) { alert('Please select or drop an image file.'); return; }
      try { text = await extractTextFromImage(selectedFile); } catch {
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
      feedbackWidget.classList.remove('hidden');
    } catch (err) {
      showError(err.message || 'An unexpected error occurred. Please try again.');
    } finally {
      setLoading(false);
    }
  });

  // -- API calls ------------------------------------------------------------
  async function callApi(endpoint, text) {
    const url = API_BASE + '/' + endpoint;
    const body = { text: text, session_id: SESSION_ID };

    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      let detail = '';
      try { const errBody = await response.json(); detail = errBody.error || errBody.detail || ''; } catch {}
      throw new Error('API error ' + response.status + (detail ? ': ' + detail : '') + '.');
    }
    return response.json();
  }

  // -- Image text extraction ------------------------------------------------
  function extractTextFromImage(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  }

  // -- Render results -------------------------------------------------------
  function renderResult(mode, data) {
    resultsSection.classList.remove('hidden');

    if (mode === 'classify') {
      const classification = data.classification || 'UNKNOWN';
      const badge = document.getElementById('classification-badge');
      badge.textContent = classification.replace(/_/g, ' ');
      badge.className = 'badge badge-' + classification;
      document.getElementById('confidence-value').textContent =
        data.confidence != null ? Math.round(data.confidence * 100) + '%' : 'N/A';
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

    } else if (mode === 'sentiment') {
      renderSentimentResult(data);
      resultSentiment.classList.remove('hidden');
    }
  }

  function renderSentimentResult(data) {
    var overview = document.getElementById('sentiment-overview');
    var s = data.sentiment || {};
    overview.innerHTML =
      '<p><strong>Primary Emotion:</strong> ' + (s.primary_emotion || 'N/A') + '</p>' +
      '<p><strong>Overall Tone:</strong> ' + (s.overall_tone || 'N/A') + '</p>' +
      renderEmotionScores(s.emotion_scores || {});

    var manip = document.getElementById('manipulation-details');
    var m = data.manipulation || {};
    manip.innerHTML =
      '<p><strong>Pressure Score:</strong> ' + renderPressureBar(m.pressure_score || 0) + '</p>' +
      '<p><strong>Techniques:</strong> ' + (m.techniques_detected || []).join(', ') + '</p>' +
      '<p><strong>Urgency Indicators:</strong> ' + (m.urgency_indicators || []).join(', ') + '</p>' +
      '<p><strong>Authority Claims:</strong> ' + (m.authority_claims || []).join(', ') + '</p>';

    var lang = document.getElementById('language-analysis');
    var la = data.language_analysis || {};
    lang.innerHTML =
      '<p><strong>Formality:</strong> ' + (la.formality_level || 'N/A') + '</p>' +
      '<p><strong>Grammar Quality:</strong> ' + (la.grammar_quality || 'N/A') + '</p>' +
      '<p><strong>Suspicious Phrases:</strong> ' + (la.suspicious_phrases || []).join(', ') + '</p>';

    var risk = document.getElementById('risk-assessment');
    var riskLevel = data.risk_assessment || 'UNKNOWN';
    risk.textContent = riskLevel;
    risk.className = 'badge badge-risk-' + riskLevel;

    document.getElementById('sentiment-summary').textContent = data.summary || '';
  }

  function renderEmotionScores(scores) {
    if (!scores || Object.keys(scores).length === 0) return '';
    var html = '<div class="emotion-scores">';
    for (var emotion in scores) {
      var pct = Math.round((scores[emotion] || 0) * 100);
      html += '<div class="emotion-bar"><span class="emotion-label">' + emotion + '</span>' +
        '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%"></div></div>' +
        '<span class="emotion-pct">' + pct + '%</span></div>';
    }
    html += '</div>';
    return html;
  }

  function renderPressureBar(score) {
    var pct = Math.round((score || 0) * 100);
    return '<span class="pressure-score">' + pct + '%</span>' +
      ' <div class="bar-track inline-bar"><div class="bar-fill pressure-fill" style="width:' + pct + '%"></div></div>';
  }

  function populateList(elementId, items, _type) {
    var el = document.getElementById(elementId);
    el.innerHTML = '';
    if (!items || items.length === 0) {
      var li = document.createElement('li');
      li.textContent = 'None identified.';
      li.style.color = 'var(--color-muted)';
      el.appendChild(li);
      return;
    }
    items.forEach(function (item) {
      var li = document.createElement('li');
      li.textContent = item;
      el.appendChild(li);
    });
  }

  function populateResourcesList(elementId, items) {
    var el = document.getElementById(elementId);
    el.innerHTML = '';
    if (!items || items.length === 0) {
      var li = document.createElement('li');
      li.textContent = 'No specific resources provided.';
      li.style.color = 'var(--color-muted)';
      el.appendChild(li);
      return;
    }
    items.forEach(function (item) {
      var li = document.createElement('li');
      if (/^https?:\/\//i.test(item)) {
        var a = document.createElement('a');
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

  // -- UI helpers -----------------------------------------------------------
  function setLoading(isLoading) {
    loadingEl.classList.toggle('hidden', !isLoading);
    analyzeBtn.disabled = isLoading;
  }

  function hideAllResults() {
    resultsSection.classList.add('hidden');
    [resultClassify, resultAnalyze, resultGuidance, resultSentiment, resultError].forEach(function (el) {
      if (el) el.classList.add('hidden');
    });
    feedbackWidget.classList.add('hidden');
  }

  function showError(message) {
    resultsSection.classList.remove('hidden');
    resultError.classList.remove('hidden');
    document.getElementById('error-message').textContent = message;
  }

  // -- i18n -----------------------------------------------------------------
  async function loadTranslations(lang) {
    try {
      var resp = await fetch(API_BASE + '/i18n?lang=' + lang);
      if (!resp.ok) return;
      var bundle = await resp.json();
      currentTranslations = bundle.translations || {};
      applyTranslations();
    } catch (e) {
      // Silently fail
    }
  }

  function applyTranslations() {
    document.querySelectorAll('[data-i18n]').forEach(function (el) {
      var key = el.getAttribute('data-i18n');
      if (currentTranslations[key]) {
        el.textContent = currentTranslations[key];
      }
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(function (el) {
      var key = el.getAttribute('data-i18n-placeholder');
      if (currentTranslations[key]) {
        el.placeholder = currentTranslations[key];
      }
    });
  }

  langSelect.addEventListener('change', function () {
    var lang = langSelect.value;
    localStorage.setItem('dltm_lang', lang);
    loadTranslations(lang);
  });

  // Restore language preference
  var savedLang = localStorage.getItem('dltm_lang');
  if (savedLang && savedLang !== 'en') {
    langSelect.value = savedLang;
    loadTranslations(savedLang);
  }

  // -- Feedback -------------------------------------------------------------
  document.querySelectorAll('.btn-feedback').forEach(function (btn) {
    btn.addEventListener('click', async function () {
      var rating = btn.dataset.rating === 'up' ? 5 : 1;
      try {
        await fetch(API_BASE + '/feedback', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ rating: rating, session_id: SESSION_ID }),
        });
        feedbackWidget.innerHTML = '<p>Thank you for your feedback!</p>';
      } catch (e) {
        // Silently fail
      }
    });
  });

  // -- Export ---------------------------------------------------------------
  var exportCsvBtn = document.getElementById('export-csv-btn');
  var exportPdfBtn = document.getElementById('export-pdf-btn');

  if (exportCsvBtn) {
    exportCsvBtn.addEventListener('click', function () {
      window.open(API_BASE + '/export?session_id=' + SESSION_ID + '&format=csv', '_blank');
    });
  }

  if (exportPdfBtn) {
    exportPdfBtn.addEventListener('click', function () {
      window.open(API_BASE + '/export?session_id=' + SESSION_ID + '&format=pdf', '_blank');
    });
  }

  // -- History --------------------------------------------------------------
  async function loadHistory() {
    var historySection = document.getElementById('history-section');
    var historyList = document.getElementById('history-list');
    try {
      var resp = await fetch(API_BASE + '/history?session_id=' + SESSION_ID + '&limit=10');
      if (!resp.ok) return;
      var items = await resp.json();
      if (items.length === 0) return;

      historySection.classList.remove('hidden');
      historyList.innerHTML = '';
      items.forEach(function (item) {
        var div = document.createElement('div');
        div.className = 'history-item';
        var r = item.result || {};
        var classification = r.classification || r.overall_verdict || item.endpoint || '';
        div.innerHTML =
          '<span class="history-time">' + (item.timestamp || '').substring(0, 19) + '</span> ' +
          '<span class="badge badge-sm badge-' + classification + '">' + classification + '</span> ' +
          '<span class="history-text">' + (item.inputText || '').substring(0, 80) + '...</span>';
        historyList.appendChild(div);
      });
    } catch (e) {
      // History unavailable
    }
  }

  // Load history on page load
  loadHistory();

})();
