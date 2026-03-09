/**
 * Unified Chat Interface - Phase B.5
 * 
 * Handles conversational interaction with agent orchestration backend.
 * Supports multimodal input (text, images, URLs) via drag-and-drop and paste.
 */

(function () {
  'use strict';

  // DOM elements
  let chatMessages, chatInput, chatSendBtn, dropOverlay;
  let modeTabs, chatMode, advancedMode;

  // Session state
  let sessionId = generateSessionId();
  let conversationHistory = [];
  let currentImages = [];

  // API endpoint
  const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:7071/api'
    : '/api';

  /**
   * Initialize chat interface
   */
  function init() {
    // Get DOM elements
    chatMessages = document.getElementById('chat-messages');
    chatInput = document.getElementById('chat-input');
    chatSendBtn = document.getElementById('chat-send-btn');
    dropOverlay = document.getElementById('drop-overlay');
    modeTabs = document.querySelectorAll('.mode-tab');
    chatMode = document.getElementById('chat-mode');
    advancedMode = document.getElementById('advanced-mode');

    if (!chatMessages || !chatInput || !chatSendBtn) {
      console.warn('Chat UI elements not found - chat interface disabled');
      return;
    }

    // Setup event listeners
    setupModeTabListeners();
    setupChatListeners();
    setupDragAndDrop();
    setupPasteHandler();
  }

  /**
   * Setup mode tab switching (Chat vs Advanced)
   */
  function setupModeTabListeners() {
    modeTabs.forEach(tab => {
      tab.addEventListener('click', () => {
        const targetMode = tab.dataset.mode;

        // Update tab states
        modeTabs.forEach(t => {
          t.classList.remove('active');
          t.setAttribute('aria-selected', 'false');
        });
        tab.classList.add('active');
        tab.setAttribute('aria-selected', 'true');

        // Show/hide mode sections
        if (targetMode === 'chat') {
          chatMode.classList.remove('hidden');
          advancedMode.classList.add('hidden');
        } else {
          chatMode.classList.add('hidden');
          advancedMode.classList.remove('hidden');
        }
      });
    });
  }

  /**
   * Setup chat input and send button listeners
   */
  function setupChatListeners() {
    // Send on button click
    chatSendBtn.addEventListener('click', handleSendMessage);

    // Send on Enter (but allow Shift+Enter for newlines)
    chatInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        handleSendMessage();
      }
    });
  }

  /**
   * Setup drag-and-drop for images
   */
  function setupDragAndDrop() {
    const chatContainer = document.querySelector('.chat-container');
    if (!chatContainer) return;

    // Prevent default drag behaviors
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
      chatContainer.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
      e.preventDefault();
      e.stopPropagation();
    }

    // Show overlay on drag enter
    ['dragenter', 'dragover'].forEach(eventName => {
      chatContainer.addEventListener(eventName, () => {
        dropOverlay.classList.remove('hidden');
      });
    });

    // Hide overlay on drag leave
    ['dragleave', 'drop'].forEach(eventName => {
      chatContainer.addEventListener(eventName, () => {
        dropOverlay.classList.add('hidden');
      });
    });

    // Handle drop
    chatContainer.addEventListener('drop', handleDrop);
  }

  /**
   * Handle file drop
   */
  function handleDrop(e) {
    const dt = e.dataTransfer;
    const files = dt.files;

    if (files.length > 0) {
      const file = files[0];
      if (file.type.startsWith('image/')) {
        processImageFile(file);
      } else {
        showError('Please drop an image file (PNG, JPG, etc.)');
      }
    }
  }

  /**
   * Setup paste handler for images
   */
  function setupPasteHandler() {
    chatInput.addEventListener('paste', (e) => {
      const items = e.clipboardData.items;

      for (let i = 0; i < items.length; i++) {
        if (items[i].type.indexOf('image') !== -1) {
          e.preventDefault();
          const file = items[i].getAsFile();
          processImageFile(file);
          return;
        }
      }
    });
  }

  /**
   * Process image file and convert to base64
   */
  function processImageFile(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      const base64 = e.target.result;
      currentImages.push(base64);
      showImagePreview(base64);
    };
    reader.readAsDataURL(file);
  }

  /**
   * Show image preview in chat input area
   */
  function showImagePreview(base64) {
    const preview = document.createElement('div');
    preview.className = 'image-preview';
    preview.innerHTML = `
      <img src="${base64}" alt="Uploaded image preview" />
      <button class="remove-image" aria-label="Remove image">&times;</button>
    `;

    const removeBtn = preview.querySelector('.remove-image');
    removeBtn.addEventListener('click', () => {
      currentImages = currentImages.filter(img => img !== base64);
      preview.remove();
    });

    const inputWrapper = document.querySelector('.chat-input-wrapper');
    inputWrapper.insertBefore(preview, chatInput);
  }

  /**
   * Handle send message
   */
  async function handleSendMessage() {
    const message = chatInput.value.trim();

    if (!message && currentImages.length === 0) {
      return; // Nothing to send
    }

    // Disable input while processing
    chatInput.disabled = true;
    chatSendBtn.disabled = true;

    // Append user message to chat
    appendUserMessage(message, currentImages);

    // Clear input
    chatInput.value = '';
    const imagePreviews = document.querySelectorAll('.image-preview');
    imagePreviews.forEach(preview => preview.remove());

    // Prepare request
    const requestBody = {
      message: message || '(Image attached)',
      images: currentImages,
      session_id: sessionId,
      context: {
        conversation_history: conversationHistory.slice(-6), // Last 6 messages
      },
    };

    // Clear current images
    const sentImages = [...currentImages];
    currentImages = [];

    // Add to conversation history
    conversationHistory.push({
      role: 'user',
      content: message,
    });

    // Show typing indicator
    const typingIndicator = appendTypingIndicator();

    try {
      const response = await fetch(`${API_BASE}/chat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();

      // Remove typing indicator
      typingIndicator.remove();

      // Append assistant response
      appendAssistantMessage(data);

      // Add to conversation history
      conversationHistory.push({
        role: 'assistant',
        content: data.message,
      });

    } catch (error) {
      console.error('Chat error:', error);
      typingIndicator.remove();
      appendErrorMessage('Sorry, I encountered an error. Please try again.');
    } finally {
      // Re-enable input
      chatInput.disabled = false;
      chatSendBtn.disabled = false;
      chatInput.focus();
    }
  }

  /**
   * Append user message to chat
   */
  function appendUserMessage(text, images) {
    const messageDiv = document.createElement('div');
    messageDiv.className = 'chat-message user-message';

    let content = '';

    if (images.length > 0) {
      content += '<div class="message-images">';
      images.forEach(img => {
        content += `<img src="${img}" alt="User uploaded image" class="message-image" />`;
      });
      content += '</div>';
    }

    if (text) {
      content += `<div class="message-text">${escapeHtml(text)}</div>`;
    }

    messageDiv.innerHTML = content;
    chatMessages.appendChild(messageDiv);
    scrollToBottom();
  }

  /**
   * Append assistant message to chat
   */
  function appendAssistantMessage(data) {
    const messageDiv = document.createElement('div');
    messageDiv.className = 'chat-message assistant-message';

    // Convert markdown-style formatting to HTML
    let messageHtml = formatMessage(data.message);

    // Add structured data as inline cards if present
    if (data.data && Object.keys(data.data).length > 0) {
      messageHtml += renderDataCard(data.data);
    }

    // Add trace info (collapsible)
    if (data.trace) {
      messageHtml += `
        <details class="trace-details">
          <summary>🔍 Trace Info</summary>
          <div class="trace-content">
            <p><strong>Agent:</strong> ${data.agent_used}</p>
            <p><strong>Route:</strong> ${data.trace.route_path.join(' → ')}</p>
            <p><strong>Duration:</strong> ${Math.round(data.trace.duration_ms)}ms</p>
            <p><strong>Decision:</strong> ${data.trace.routing_decision}</p>
          </div>
        </details>
      `;
    }

    messageDiv.innerHTML = messageHtml;
    chatMessages.appendChild(messageDiv);
    scrollToBottom();
  }

  /**
   * Format message text (basic markdown-style formatting)
   */
  function formatMessage(text) {
    // Escape HTML first
    let html = escapeHtml(text);

    // Convert **bold** to <strong>
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');

    // Convert line breaks
    html = html.replace(/\n/g, '<br>');

    // Convert emojis at start of lines to styled elements
    html = html.replace(/^([⚠️✅🟡❌🔍👋]+)/gm, '<span class="message-emoji">$1</span>');

    return html;
  }

  /**
   * Render structured data as inline card
   */
  function renderDataCard(data) {
    let html = '<div class="data-card">';

    // Classification
    if (data.classification) {
      html += `
        <div class="data-item">
          <span class="badge badge-${data.classification.toLowerCase().replace('_', '-')}">
            ${data.classification}
          </span>
          ${data.confidence ? `<span class="confidence">${Math.round(data.confidence * 100)}% confidence</span>` : ''}
        </div>
      `;
    }

    // Red flags
    if (data.analysis && data.analysis.red_flags && data.analysis.red_flags.length > 0) {
      html += '<div class="data-item"><strong>Red Flags:</strong><ul>';
      data.analysis.red_flags.forEach(flag => {
        html += `<li>${escapeHtml(flag)}</li>`;
      });
      html += '</ul></div>';
    }

    // URL verdict
    if (data.verdict) {
      html += `
        <div class="data-item">
          <strong>URL Status:</strong> 
          <span class="badge badge-${data.verdict.toLowerCase().replace('_', '-')}">
            ${data.verdict}
          </span>
        </div>
      `;
    }

    html += '</div>';
    return html;
  }

  /**
   * Append typing indicator
   */
  function appendTypingIndicator() {
    const indicator = document.createElement('div');
    indicator.className = 'chat-message assistant-message typing-indicator';
    indicator.innerHTML = `
      <div class="typing-dots">
        <span></span>
        <span></span>
        <span></span>
      </div>
    `;
    chatMessages.appendChild(indicator);
    scrollToBottom();
    return indicator;
  }

  /**
   * Append error message
   */
  function appendErrorMessage(text) {
    const messageDiv = document.createElement('div');
    messageDiv.className = 'chat-message error-message';
    messageDiv.innerHTML = `<div class="message-text">❌ ${escapeHtml(text)}</div>`;
    chatMessages.appendChild(messageDiv);
    scrollToBottom();
  }

  /**
   * Show error toast
   */
  function showError(message) {
    // TODO: Implement toast notification
    alert(message);
  }

  /**
   * Scroll chat to bottom
   */
  function scrollToBottom() {
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }

  /**
   * Escape HTML to prevent XSS
   */
  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  /**
   * Generate session ID
   */
  function generateSessionId() {
    return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }

  // Initialize on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
