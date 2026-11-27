/**
 * RedactIQ - Application Controller (app.js)
 * Manages UI state, events, debounced scanning, synchronized diff scrolling,
 * file reading, tooltips, theme toggling, and data exports.
 * Adopts the BizLink-inspired modern SaaS aesthetic.
 */

(function () {
  'use strict';

  // =========================================================================
  // Application State
  // =========================================================================
  const state = {
    rawText: '',
    fileType: 'txt', // 'txt' or 'csv'
    fileName: '',
    currentMode: 'full', // 'full' | 'partial' | 'pseudo'
    includeTypeTag: false,
    enabledTypes: {
      EMAIL: true,
      PHONE: true,
      IP: true,
      PAN: true,
      AADHAAR: true,
      CREDIT_CARD: true
    },
    detectionResult: null,
    redactionResult: null,
    debounceTimer: null,
    isSyncScrolling: false
  };

  // =========================================================================
  // DOM Elements Cache
  // =========================================================================
  const DOM = {};

  function initDOMElements() {
    DOM.themeToggleBtn = document.getElementById('themeToggleBtn');
    DOM.themeToggleIcon = document.getElementById('themeToggleIcon');
    DOM.themeToggleLabel = document.getElementById('themeToggleLabel');

    DOM.modeFullBtn = document.getElementById('modeFullBtn');
    DOM.modePartialBtn = document.getElementById('modePartialBtn');
    DOM.modePseudoBtn = document.getElementById('modePseudoBtn');
    DOM.modeTabs = document.querySelectorAll('.mode-tab-btn');
    DOM.includeTypeTagCheckbox = document.getElementById('includeTypeTagCheckbox');
    DOM.typeTagToggleLabel = document.getElementById('typeTagToggleLabel');

    DOM.filterCheckboxes = {
      EMAIL: document.getElementById('filterEmail'),
      PHONE: document.getElementById('filterPhone'),
      IP: document.getElementById('filterIp'),
      PAN: document.getElementById('filterPan'),
      AADHAAR: document.getElementById('filterAadhaar'),
      CREDIT_CARD: document.getElementById('filterCard')
    };

    DOM.sidebarCounts = {
      EMAIL: document.getElementById('sidebarCountEmail'),
      PHONE: document.getElementById('sidebarCountPhone'),
      IP: document.getElementById('sidebarCountIp'),
      PAN: document.getElementById('sidebarCountPan'),
      AADHAAR: document.getElementById('sidebarCountAadhaar'),
      CREDIT_CARD: document.getElementById('sidebarCountCard')
    };

    DOM.chartBars = {
      EMAIL: document.getElementById('barEmail'),
      PHONE: document.getElementById('barPhone'),
      IP: document.getElementById('barIp'),
      PAN: document.getElementById('barPan'),
      AADHAAR: document.getElementById('barAadhaar'),
      CREDIT_CARD: document.getElementById('barCard')
    };

    DOM.gaugePercentVal = document.getElementById('gaugePercentVal');
    DOM.gaugePath = document.getElementById('gaugePath');

    DOM.statTotalCount = document.getElementById('statTotalCount');
    DOM.statRejectedCount = document.getElementById('statRejectedCount');
    DOM.statRejectedCard = document.getElementById('statRejectedCard');
    DOM.navTotalBadge = document.getElementById('navTotalBadge');
    DOM.navMappingBadge = document.getElementById('navMappingBadge');
    DOM.navStudioBtn = document.getElementById('navStudioBtn');
    DOM.navMappingBtn = document.getElementById('navMappingBtn');

    DOM.loadSampleBtn = document.getElementById('loadSampleBtn');
    DOM.loadResumeBtn = document.getElementById('loadResumeBtn');
    DOM.loadCsvSampleBtn = document.getElementById('loadCsvSampleBtn');
    DOM.toggleInputExpandBtn = document.getElementById('toggleInputExpandBtn');
    DOM.inputExpandText = document.getElementById('inputExpandText');
    DOM.rawTextareaWrapper = document.getElementById('rawTextareaWrapper');
    DOM.clearBtn = document.getElementById('clearBtn');
    DOM.fileInfoChip = document.getElementById('fileInfoChip');
    DOM.fileInfoText = document.getElementById('fileInfoText');
    DOM.removeFileBtn = document.getElementById('removeFileBtn');

    DOM.dropzone = document.getElementById('dropzone');
    DOM.fileInput = document.getElementById('fileInput');
    DOM.rawInputText = document.getElementById('rawInputText');

    DOM.originalCharCount = document.getElementById('originalCharCount');
    DOM.sanitizedCharCount = document.getElementById('sanitizedCharCount');
    DOM.originalContentPane = document.getElementById('originalContentPane');
    DOM.sanitizedContentPane = document.getElementById('sanitizedContentPane');

    DOM.mappingSection = document.getElementById('mappingSection');
    DOM.mappingCountBadge = document.getElementById('mappingCountBadge');
    DOM.mappingTableBody = document.getElementById('mappingTableBody');
    DOM.downloadMappingBtn = document.getElementById('downloadMappingBtn');

    DOM.downloadSanitizedBtn = document.getElementById('downloadSanitizedBtn');
    DOM.downloadFileTypeLabel = document.getElementById('downloadFileTypeLabel');
    DOM.copyClipboardBtn = document.getElementById('copyClipboardBtn');
    DOM.copyBtnIcon = document.getElementById('copyBtnIcon');
    DOM.copyBtnText = document.getElementById('copyBtnText');
    DOM.downloadAuditBtn = document.getElementById('downloadAuditBtn');

    DOM.floatingTooltip = document.getElementById('floatingTooltip');
    DOM.toastContainer = document.getElementById('toastContainer');

    DOM.rejectedModalBackdrop = document.getElementById('rejectedModalBackdrop');
    DOM.modalRejectedCountBadge = document.getElementById('modalRejectedCountBadge');
    DOM.modalRejectedList = document.getElementById('modalRejectedList');
    DOM.modalCloseBtn = document.getElementById('modalCloseBtn');
  }

  // =========================================================================
  // Theme Management
  // =========================================================================
  function initTheme() {
    const savedTheme = localStorage.getItem('redactiq_theme') || 'light';
    setTheme(savedTheme);

    DOM.themeToggleBtn.addEventListener('click', () => {
      const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
      setTheme(newTheme);
    });
  }

  function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('redactiq_theme', theme);
    if (DOM.themeToggleIcon) {
      DOM.themeToggleIcon.textContent = theme === 'dark' ? '☀️' : '🌙';
    }
    if (DOM.themeToggleLabel) {
      DOM.themeToggleLabel.textContent = theme === 'dark' ? 'Theme: Dark' : 'Theme: Light';
    }
  }

  // =========================================================================
  // Toast Notifications
  // =========================================================================
  function showToast(message, type = 'info', duration = 3000) {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    let icon = 'ℹ️';
    if (type === 'error') icon = '⚠️';
    if (type === 'success') icon = '✓';

    toast.innerHTML = `<span>${icon}</span><span>${window.RedactIQRedactor.escapeHtml(message)}</span>`;
    DOM.toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px) scale(0.96)';
      toast.style.transition = 'all 0.2s ease';
      setTimeout(() => toast.remove(), 200);
    }, duration);
  }

  // =========================================================================
  // Core Processing Pipeline
  // =========================================================================
  function process(immediate = false) {
    if (state.debounceTimer) {
      clearTimeout(state.debounceTimer);
      state.debounceTimer = null;
    }

    if (immediate) {
      runPipeline();
    } else {
      state.debounceTimer = setTimeout(runPipeline, 150);
    }
  }

  function runPipeline() {
    state.rawText = DOM.rawInputText.value;
    const text = state.rawText;

    if (!text || text.trim().length === 0) {
      renderEmptyState();
      return;
    }

    // 1. Detection Phase
    const detectors = window.RedactIQDetectors;
    const redactor = window.RedactIQRedactor;

    const detRes = detectors.detectAll(text, state.enabledTypes);
    state.detectionResult = detRes;

    // 2. Redaction Phase
    const redRes = redactor.redact(text, detRes.entities, state.currentMode, {
      includeTypeTag: state.includeTypeTag
    });
    state.redactionResult = redRes;

    // 3. Render Output & Diff
    renderOutput();
  }

  function renderEmptyState() {
    state.detectionResult = null;
    state.redactionResult = null;

    DOM.originalCharCount.textContent = '0 chars';
    DOM.sanitizedCharCount.textContent = '0 chars';

    DOM.statTotalCount.textContent = '0';
    DOM.statRejectedCount.textContent = '0';
    if (DOM.navTotalBadge) DOM.navTotalBadge.textContent = '0';

    Object.keys(DOM.sidebarCounts).forEach(type => {
      if (DOM.sidebarCounts[type]) DOM.sidebarCounts[type].textContent = '0';
    });

    Object.keys(DOM.chartBars).forEach(type => {
      if (DOM.chartBars[type]) DOM.chartBars[type].style.height = '6%';
    });

    if (DOM.gaugePercentVal) DOM.gaugePercentVal.textContent = '0%';
    if (DOM.gaugePath) DOM.gaugePath.style.strokeDashoffset = '126';

    DOM.originalContentPane.innerHTML = `
      <div class="empty-hero">
        <div class="empty-hero-icon">📋</div>
        <div class="empty-hero-title">No Input Text Loaded</div>
        <div class="empty-hero-desc">Paste text above, drop a file, or click one of the sample buttons to start.</div>
      </div>
    `;

    DOM.sanitizedContentPane.innerHTML = `
      <div class="empty-hero">
        <div class="empty-hero-icon">🛡️</div>
        <div class="empty-hero-title">Sanitized View Ready</div>
        <div class="empty-hero-desc">Tokens and pseudonyms render here in real-time with zero data leakage.</div>
      </div>
    `;

    DOM.mappingSection.style.display = 'none';
  }

  function renderOutput() {
    const det = state.detectionResult;
    const red = state.redactionResult;

    // Update Counts
    DOM.statTotalCount.textContent = det.counts.TOTAL;
    DOM.statRejectedCount.textContent = det.rejectedCount;
    if (DOM.navTotalBadge) DOM.navTotalBadge.textContent = det.counts.TOTAL;

    // Update Sidebar Counts
    if (DOM.sidebarCounts.EMAIL) DOM.sidebarCounts.EMAIL.textContent = det.counts.EMAIL;
    if (DOM.sidebarCounts.PHONE) DOM.sidebarCounts.PHONE.textContent = det.counts.PHONE;
    if (DOM.sidebarCounts.IP) DOM.sidebarCounts.IP.textContent = det.counts.IP;
    if (DOM.sidebarCounts.PAN) DOM.sidebarCounts.PAN.textContent = det.counts.PAN;
    if (DOM.sidebarCounts.AADHAAR) DOM.sidebarCounts.AADHAAR.textContent = det.counts.AADHAAR;
    if (DOM.sidebarCounts.CREDIT_CARD) DOM.sidebarCounts.CREDIT_CARD.textContent = det.counts.CREDIT_CARD;

    // Update Minimalist Chart Bars
    const maxVal = Math.max(1, det.counts.EMAIL, det.counts.PHONE, det.counts.IP, det.counts.PAN, det.counts.AADHAAR, det.counts.CREDIT_CARD);
    if (DOM.chartBars.EMAIL) DOM.chartBars.EMAIL.style.height = `${Math.max(8, Math.round((det.counts.EMAIL / maxVal) * 88))}%`;
    if (DOM.chartBars.PHONE) DOM.chartBars.PHONE.style.height = `${Math.max(8, Math.round((det.counts.PHONE / maxVal) * 88))}%`;
    if (DOM.chartBars.IP) DOM.chartBars.IP.style.height = `${Math.max(8, Math.round((det.counts.IP / maxVal) * 88))}%`;
    if (DOM.chartBars.PAN) DOM.chartBars.PAN.style.height = `${Math.max(8, Math.round((det.counts.PAN / maxVal) * 88))}%`;
    if (DOM.chartBars.AADHAAR) DOM.chartBars.AADHAAR.style.height = `${Math.max(8, Math.round((det.counts.AADHAAR / maxVal) * 88))}%`;
    if (DOM.chartBars.CREDIT_CARD) DOM.chartBars.CREDIT_CARD.style.height = `${Math.max(8, Math.round((det.counts.CREDIT_CARD / maxVal) * 88))}%`;

    // Update Arc Gauge
    if (DOM.gaugePercentVal && DOM.gaugePath) {
      const pct = det.counts.TOTAL > 0 ? 100 : 0;
      DOM.gaugePercentVal.textContent = `${pct}%`;
      DOM.gaugePath.style.strokeDashoffset = pct === 100 ? 0 : 126;
    }

    // Update Char Counts
    DOM.originalCharCount.textContent = `${state.rawText.length.toLocaleString()} chars`;
    DOM.sanitizedCharCount.textContent = `${red.sanitizedText.length.toLocaleString()} chars`;

    // Render HTML in Panes
    DOM.originalContentPane.innerHTML = red.originalHtml;
    DOM.sanitizedContentPane.innerHTML = red.sanitizedHtml;

    // Render Pseudonymization Table if in pseudo mode
    if (state.currentMode === 'pseudo') {
      DOM.mappingSection.style.display = 'block';
      renderMappingTable(red.mapping);
    } else {
      DOM.mappingSection.style.display = 'none';
    }
  }

  function renderMappingTable(mapping) {
    const list = Object.values(mapping || {});
    DOM.mappingCountBadge.textContent = list.length;
    if (DOM.navMappingBadge) DOM.navMappingBadge.textContent = list.length;
    DOM.mappingTableBody.innerHTML = '';

    if (list.length === 0) {
      DOM.mappingTableBody.innerHTML = `
        <tr>
          <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 2rem;">
            No pseudonymized entities generated for current filters.
          </td>
        </tr>
      `;
      return;
    }

    // Sort by type then id
    list.sort((a, b) => a.id.localeCompare(b.id));

    const fragment = document.createDocumentFragment();
    for (const item of list) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong style="color: var(--accent-blue);">${window.RedactIQRedactor.escapeHtml(item.id)}</strong></td>
        <td><span class="card-status-pill pill-original">${window.RedactIQRedactor.escapeHtml(item.type)}</span></td>
        <td><code>${window.RedactIQRedactor.escapeHtml(item.normalized)}</code></td>
        <td><code>${window.RedactIQRedactor.escapeHtml(item.originalValue)}</code></td>
        <td><strong>${item.count}</strong></td>
      `;
      fragment.appendChild(tr);
    }
    DOM.mappingTableBody.appendChild(fragment);
  }

  // =========================================================================
  // Synchronized Scrolling
  // =========================================================================
  function initSyncScroll() {
    const orig = DOM.originalContentPane;
    const sanit = DOM.sanitizedContentPane;

    orig.addEventListener('scroll', () => {
      if (state.isSyncScrolling) return;
      state.isSyncScrolling = true;

      const maxOrig = orig.scrollHeight - orig.clientHeight;
      if (maxOrig > 0) {
        const percentage = orig.scrollTop / maxOrig;
        const maxSanit = sanit.scrollHeight - sanit.clientHeight;
        sanit.scrollTop = percentage * maxSanit;
      }

      requestAnimationFrame(() => {
        state.isSyncScrolling = false;
      });
    }, { passive: true });

    sanit.addEventListener('scroll', () => {
      if (state.isSyncScrolling) return;
      state.isSyncScrolling = true;

      const maxSanit = sanit.scrollHeight - sanit.clientHeight;
      if (maxSanit > 0) {
        const percentage = sanit.scrollTop / maxSanit;
        const maxOrig = orig.scrollHeight - orig.clientHeight;
        orig.scrollTop = percentage * maxOrig;
      }

      requestAnimationFrame(() => {
        state.isSyncScrolling = false;
      });
    }, { passive: true });
  }

  // =========================================================================
  // Interactive Floating Tooltips
  // =========================================================================
  function initTooltips() {
    const tooltip = DOM.floatingTooltip;

    function handleMouseOver(e) {
      const mark = e.target.closest('.pii-mark');
      if (mark && mark.dataset.tooltip) {
        tooltip.textContent = mark.dataset.tooltip;
        tooltip.classList.add('visible');
        updateTooltipPosition(e);
      }
    }

    function handleMouseMove(e) {
      if (tooltip.classList.contains('visible')) {
        updateTooltipPosition(e);
      }
    }

    function handleMouseOut(e) {
      const mark = e.target.closest('.pii-mark');
      if (mark) {
        tooltip.classList.remove('visible');
      }
    }

    function updateTooltipPosition(e) {
      const margin = 14;
      let left = e.clientX + margin;
      let top = e.clientY + margin;

      const tooltipRect = tooltip.getBoundingClientRect();
      const winW = window.innerWidth;
      const winH = window.innerHeight;

      if (left + tooltipRect.width > winW - 10) {
        left = e.clientX - tooltipRect.width - margin;
      }
      if (top + tooltipRect.height > winH - 10) {
        top = e.clientY - tooltipRect.height - margin;
      }

      tooltip.style.left = `${Math.max(10, left)}px`;
      tooltip.style.top = `${Math.max(10, top)}px`;
    }

    DOM.originalContentPane.addEventListener('mouseover', handleMouseOver);
    DOM.originalContentPane.addEventListener('mousemove', handleMouseMove);
    DOM.originalContentPane.addEventListener('mouseout', handleMouseOut);

    DOM.sanitizedContentPane.addEventListener('mouseover', handleMouseOver);
    DOM.sanitizedContentPane.addEventListener('mousemove', handleMouseMove);
    DOM.sanitizedContentPane.addEventListener('mouseout', handleMouseOut);
  }

  // =========================================================================
  // File Upload & Drag-and-Drop
  // =========================================================================
  function initFileUpload() {
    const dropzone = DOM.dropzone;
    const fileInput = DOM.fileInput;

    dropzone.addEventListener('click', () => fileInput.click());

    dropzone.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        fileInput.click();
      }
    });

    ['dragenter', 'dragover'].forEach(name => {
      dropzone.addEventListener(name, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.add('dragover');
      });
    });

    ['dragleave', 'drop'].forEach(name => {
      dropzone.addEventListener(name, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.remove('dragover');
      });
    });

    dropzone.addEventListener('drop', (e) => {
      const files = e.dataTransfer.files;
      if (files && files.length > 0) {
        handleIncomingFile(files[0]);
      }
    });

    fileInput.addEventListener('change', (e) => {
      const files = e.target.files;
      if (files && files.length > 0) {
        handleIncomingFile(files[0]);
      }
    });

    DOM.removeFileBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      state.fileName = '';
      state.fileType = 'txt';
      DOM.fileInfoChip.style.display = 'none';
      DOM.downloadFileTypeLabel.textContent = 'sanitized.txt';
      DOM.fileInput.value = '';
      showToast('File unlinked. Raw text preserved.', 'info');
    });
  }

  function handleIncomingFile(file) {
    const name = file.name || '';
    const ext = name.split('.').pop().toLowerCase();

    if (ext !== 'txt' && ext !== 'csv') {
      showToast(`Unsupported file: "${name}". RedactIQ only supports .txt and .csv files.`, 'error', 4500);
      return;
    }

    if (file.size > 2.5 * 1024 * 1024) {
      showToast(`File size is ${(file.size / 1024 / 1024).toFixed(1)}MB. Recommended max is ~2MB for optimal browser speed.`, 'error', 4500);
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      state.fileName = name;
      state.fileType = ext === 'csv' ? 'csv' : 'txt';

      DOM.fileInfoText.textContent = `${name} (${(file.size / 1024).toFixed(1)} KB)`;
      DOM.fileInfoChip.style.display = 'inline-flex';
      DOM.downloadFileTypeLabel.textContent = state.fileType === 'csv' ? 'sanitized.csv' : 'sanitized.txt';

      DOM.rawInputText.value = content;
      process(true);
      showToast(`Loaded ${name} (${state.fileType.toUpperCase()}) successfully.`, 'success');
    };

    reader.onerror = () => {
      showToast('Failed to read file from local disk.', 'error');
    };

    reader.readAsText(file);
  }

  // =========================================================================
  // Modal for Rejected Candidates
  // =========================================================================
  function initRejectedModal() {
    DOM.statRejectedCard.addEventListener('click', () => {
      openRejectedModal();
    });

    DOM.modalCloseBtn.addEventListener('click', () => {
      closeRejectedModal();
    });

    DOM.rejectedModalBackdrop.addEventListener('click', (e) => {
      if (e.target === DOM.rejectedModalBackdrop) {
        closeRejectedModal();
      }
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && DOM.rejectedModalBackdrop.classList.contains('active')) {
        closeRejectedModal();
      }
    });
  }

  function openRejectedModal() {
    const det = state.detectionResult;
    const list = (det && det.rejected) ? det.rejected : [];
    DOM.modalRejectedCountBadge.textContent = list.length;
    DOM.modalRejectedList.innerHTML = '';

    if (list.length === 0) {
      DOM.modalRejectedList.innerHTML = `
        <div style="text-align: center; color: var(--text-muted); padding: 2rem;">
          No candidates were rejected by algorithmic validation in the current text.
        </div>
      `;
    } else {
      const fragment = document.createDocumentFragment();
      list.forEach((item) => {
        const div = document.createElement('div');
        div.className = 'rejected-row';
        div.innerHTML = `
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <span class="card-status-pill pill-original">${window.RedactIQRedactor.escapeHtml(item.type)}</span>
            <span style="font-size: 0.72rem; color: var(--text-muted);">Span: [${item.start} - ${item.end}]</span>
          </div>
          <div style="font-family: var(--font-mono); font-weight: 700; color: var(--text-primary); margin: 0.2rem 0;">"${window.RedactIQRedactor.escapeHtml(item.value)}"</div>
          <div style="color: var(--danger); font-size: 0.78rem; font-weight: 600;">✗ ${window.RedactIQRedactor.escapeHtml(item.reason)}</div>
        `;
        fragment.appendChild(div);
      });
      DOM.modalRejectedList.appendChild(fragment);
    }

    DOM.rejectedModalBackdrop.classList.add('active');
    DOM.rejectedModalBackdrop.setAttribute('aria-hidden', 'false');
  }

  function closeRejectedModal() {
    DOM.rejectedModalBackdrop.classList.remove('active');
    DOM.rejectedModalBackdrop.setAttribute('aria-hidden', 'true');
  }

  // =========================================================================
  // Export & Download Actions
  // =========================================================================
  function initExportActions() {
    // 1. Download Sanitized File (.txt or .csv)
    DOM.downloadSanitizedBtn.addEventListener('click', () => {
      if (!state.redactionResult || !state.redactionResult.sanitizedText) {
        showToast('No sanitized text to export.', 'error');
        return;
      }

      const isCsv = state.fileType === 'csv';
      const filename = isCsv ? 'sanitized.csv' : 'sanitized.txt';
      const mime = isCsv ? 'text/csv;charset=utf-8;' : 'text/plain;charset=utf-8;';

      const blob = new Blob([state.redactionResult.sanitizedText], { type: mime });
      downloadBlob(blob, filename);
      showToast(`Downloaded ${filename} successfully.`, 'success');
    });

    // 2. Copy to Clipboard
    DOM.copyClipboardBtn.addEventListener('click', async () => {
      if (!state.redactionResult || !state.redactionResult.sanitizedText) {
        showToast('Nothing to copy.', 'error');
        return;
      }

      try {
        await navigator.clipboard.writeText(state.redactionResult.sanitizedText);
        DOM.copyBtnIcon.textContent = '✓';
        DOM.copyBtnText.textContent = 'Copied!';
        showToast('Sanitized output copied to clipboard.', 'success');

        setTimeout(() => {
          DOM.copyBtnIcon.textContent = '📋';
          DOM.copyBtnText.textContent = 'Copy';
        }, 2000);
      } catch (err) {
        showToast('Clipboard access was blocked by browser permissions.', 'error');
      }
    });

    // 3. Download Audit Report JSON (NO raw PII inside!)
    DOM.downloadAuditBtn.addEventListener('click', () => {
      if (!state.detectionResult) {
        showToast('Load and process text first before generating an audit report.', 'error');
        return;
      }

      const auditPayload = {
        application: 'RedactIQ',
        version: '1.0.0',
        generatedAt: new Date().toISOString(),
        privacyStatement: 'This audit report contains aggregate statistical counts only. Zero raw PII is included.',
        redactionMode: state.currentMode,
        fileType: state.fileType,
        detectionStatistics: {
          totalEntitiesDetected: state.detectionResult.counts.TOTAL,
          breakdownByType: state.detectionResult.counts,
          candidatesRejectedByValidation: state.detectionResult.rejectedCount
        },
        rejectionDetailsSummary: (state.detectionResult.rejected || []).map(r => ({
          type: r.type,
          spanLength: r.end - r.start,
          reason: r.reason
        })),
        activeFilters: state.enabledTypes
      };

      const jsonString = JSON.stringify(auditPayload, null, 2);
      const blob = new Blob([jsonString], { type: 'application/json;charset=utf-8;' });
      downloadBlob(blob, `redactiq-audit-report-${Date.now()}.json`);
      showToast('Downloaded audit report JSON (zero raw PII).', 'success');
    });

    // 4. Download Pseudonym Mapping JSON
    DOM.downloadMappingBtn.addEventListener('click', () => {
      if (!state.redactionResult || !state.redactionResult.mapping) {
        showToast('No active pseudonymization mapping exists.', 'error');
        return;
      }

      const mappingData = Object.values(state.redactionResult.mapping);
      const payload = {
        application: 'RedactIQ',
        exportType: 'PseudonymizationMapping',
        timestamp: new Date().toISOString(),
        totalEntities: mappingData.length,
        mapping: mappingData
      };

      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json;charset=utf-8;' });
      downloadBlob(blob, `redactiq-mapping-${Date.now()}.json`);
      showToast('Downloaded pseudonym mapping JSON.', 'success');
    });
  }

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // =========================================================================
  // Control Listeners & Buttons
  // =========================================================================
  function initControls() {
    // Mode Switcher Tabs
    DOM.modeTabs.forEach(btn => {
      btn.addEventListener('click', () => {
        DOM.modeTabs.forEach(b => {
          b.classList.remove('active');
          b.setAttribute('aria-checked', 'false');
        });
        btn.classList.add('active');
        btn.setAttribute('aria-checked', 'true');

        state.currentMode = btn.dataset.mode;

        // Toggle visibility of full-mask option
        if (state.currentMode === 'full') {
          DOM.typeTagToggleLabel.style.display = 'inline-flex';
        } else {
          DOM.typeTagToggleLabel.style.display = 'none';
        }

        process(true);
      });
    });

    // Type tag checkbox for Full Mask
    DOM.includeTypeTagCheckbox.addEventListener('change', (e) => {
      state.includeTypeTag = e.target.checked;
      process(true);
    });

    // Sidebar Entity Detector Items
    Object.keys(DOM.filterCheckboxes).forEach(type => {
      const checkbox = DOM.filterCheckboxes[type];
      if (!checkbox) return;
      const parentLabel = checkbox.closest('.detector-item');

      parentLabel.addEventListener('click', (e) => {
        e.preventDefault();
        checkbox.checked = !checkbox.checked;
        state.enabledTypes[type] = checkbox.checked;
        parentLabel.classList.toggle('active', checkbox.checked);
        process(true);
      });
    });

    // Navigation item listeners
    if (DOM.navMappingBtn) {
      DOM.navMappingBtn.addEventListener('click', () => {
        DOM.modePseudoBtn.click();
        setTimeout(() => {
          DOM.mappingSection.scrollIntoView({ behavior: 'smooth' });
        }, 100);
      });
    }

    if (DOM.navStudioBtn) {
      DOM.navStudioBtn.addEventListener('click', () => {
        window.scrollTo({ top: 0, behavior: 'smooth' });
      });
    }

    // Raw input typing with debounce
    DOM.rawInputText.addEventListener('input', () => {
      process(false);
    });

    // Toggle Input Textarea view
    DOM.toggleInputExpandBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const isHidden = DOM.rawTextareaWrapper.style.display === 'none';
      if (isHidden) {
        DOM.rawTextareaWrapper.style.display = 'block';
        DOM.inputExpandText.textContent = 'Hide Raw Input';
      } else {
        DOM.rawTextareaWrapper.style.display = 'none';
        DOM.inputExpandText.textContent = 'Show Raw Input';
      }
    });

    // Clear Button
    DOM.clearBtn.addEventListener('click', () => {
      DOM.rawInputText.value = '';
      state.fileName = '';
      state.fileType = 'txt';
      DOM.fileInfoChip.style.display = 'none';
      DOM.downloadFileTypeLabel.textContent = 'sanitized.txt';
      DOM.fileInput.value = '';
      process(true);
      showToast('Cleared input and sanitized output.', 'info');
    });

    // Sample Data Buttons
    DOM.loadSampleBtn.addEventListener('click', () => {
      if (window.RedactIQSamples && window.RedactIQSamples.NOISY_SAMPLE) {
        DOM.rawInputText.value = window.RedactIQSamples.NOISY_SAMPLE;
        state.fileType = 'txt';
        state.fileName = 'sample-intake-note.txt';
        DOM.downloadFileTypeLabel.textContent = 'sanitized.txt';
        DOM.fileInfoText.textContent = 'sample-intake-note.txt';
        DOM.fileInfoChip.style.display = 'inline-flex';
        process(true);
        showToast('Loaded realistic noisy clinical/support ticket mix.', 'success');
      }
    });

    DOM.loadResumeBtn.addEventListener('click', () => {
      if (window.RedactIQSamples && window.RedactIQSamples.RESUME_SAMPLE) {
        DOM.rawInputText.value = window.RedactIQSamples.RESUME_SAMPLE;
        state.fileType = 'txt';
        state.fileName = 'candidate-resume.txt';
        DOM.downloadFileTypeLabel.textContent = 'sanitized.txt';
        DOM.fileInfoText.textContent = 'candidate-resume.txt';
        DOM.fileInfoChip.style.display = 'inline-flex';
        process(true);
        showToast('Loaded candidate resume with PII & technical decoys.', 'success');
      }
    });

    DOM.loadCsvSampleBtn.addEventListener('click', () => {
      if (window.RedactIQSamples && window.RedactIQSamples.CSV_SAMPLE) {
        DOM.rawInputText.value = window.RedactIQSamples.CSV_SAMPLE;
        state.fileType = 'csv';
        state.fileName = 'sample-patients.csv';
        DOM.downloadFileTypeLabel.textContent = 'sanitized.csv';
        DOM.fileInfoText.textContent = 'sample-patients.csv';
        DOM.fileInfoChip.style.display = 'inline-flex';
        process(true);
        showToast('Loaded sample structured CSV dataset.', 'success');
      }
    });
  }

  // =========================================================================
  // Initialization
  // =========================================================================
  function init() {
    initDOMElements();
    initTheme();
    initSyncScroll();
    initTooltips();
    initFileUpload();
    initRejectedModal();
    initExportActions();
    initControls();

    // Auto-load sample noisy text on first startup
    if (window.RedactIQSamples && window.RedactIQSamples.NOISY_SAMPLE) {
      DOM.rawInputText.value = window.RedactIQSamples.NOISY_SAMPLE;
      state.fileType = 'txt';
      state.fileName = 'sample-intake-note.txt';
      DOM.fileInfoText.textContent = 'sample-intake-note.txt';
      DOM.fileInfoChip.style.display = 'inline-flex';
      process(true);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
