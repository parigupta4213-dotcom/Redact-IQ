/**
 * RedactIQ - Redaction Engine (redactor.js)
 * Implements 3 redaction modes:
 * 1. Full Mask: [REDACTED] or [REDACTED:TYPE]
 * 2. Partial Mask: XXXX-XXXX-XXXX-1234, j***@domain.com, etc.
 * 3. Consistent Pseudonymization: EMAIL_01, PHONE_01, CARD_01 with normalized lookup
 *
 * Provides safe HTML generation with XSS protection and zero-copy/linear performance.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.RedactIQRedactor = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const RedactionMode = {
    FULL: 'full',
    PARTIAL: 'partial',
    PSEUDO: 'pseudo'
  };

  const TYPE_PREFIXES = {
    CREDIT_CARD: 'CARD',
    AADHAAR: 'AADHAAR',
    PAN: 'PAN',
    EMAIL: 'EMAIL',
    IP: 'IP',
    PHONE: 'PHONE'
  };

  /**
   * HTML Escaping utility to prevent XSS injection.
   *
   * @param {string} str - Raw string.
   * @returns {string} Sanitized string safe for HTML insertion.
   */
  function escapeHtml(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * Generates Full Mask replacement token.
   * E.g. [REDACTED] or [REDACTED:EMAIL]
   *
   * @param {Object} entity - Detected entity.
   * @param {boolean} includeTypeTag - If true, appends entity type.
   * @returns {string}
   */
  function getFullMask(entity, includeTypeTag = false) {
    if (includeTypeTag) {
      const tag = TYPE_PREFIXES[entity.type] || entity.type;
      return `[REDACTED:${tag}]`;
    }
    return '[REDACTED]';
  }

  /**
   * Generates Partial Mask keeping limited context.
   *
   * @param {Object} entity - Detected entity.
   * @returns {string}
   */
  function getPartialMask(entity) {
    const type = entity.type;
    const val = entity.value;

    switch (type) {
      case 'CREDIT_CARD': {
        const digits = entity.normalized || val.replace(/\D/g, '');
        const last4 = digits.slice(-4);
        if (digits.length === 15) {
          // American Express
          return `XXXX-XXXXXX-X${last4}`;
        }
        return `XXXX-XXXX-XXXX-${last4}`;
      }

      case 'AADHAAR': {
        const digits = entity.normalized || val.replace(/\D/g, '');
        const last4 = digits.slice(-4);
        return `XXXX-XXXX-${last4}`;
      }

      case 'PAN': {
        // Style: ABXXXXX34F (first 2 chars + XXXXX + last 3 chars)
        const clean = val.replace(/\s+/g, '').toUpperCase();
        if (clean.length === 10) {
          return `${clean.slice(0, 2)}XXXXX${clean.slice(-3)}`;
        }
        return `ABXXXXX${clean.slice(-3)}`;
      }

      case 'EMAIL': {
        const parts = val.split('@');
        if (parts.length === 2) {
          const user = parts[0];
          const domain = parts[1];
          const firstChar = user.length > 0 ? user[0] : 'u';
          return `${firstChar}***@${domain}`;
        }
        return '***@domain.com';
      }

      case 'IP': {
        if (val.includes(':')) {
          // IPv6: Keep first 2 groups
          const groups = val.split(':');
          const g1 = groups[0] || '2001';
          const g2 = groups[1] || 'db8';
          return `${g1}:${g2}:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX`;
        }
        // IPv4: Keep first 2 octets
        const octets = val.split('.');
        if (octets.length === 4) {
          return `${octets[0]}.${octets[1]}.X.X`;
        }
        return '192.168.X.X';
      }

      case 'PHONE': {
        const digits = val.replace(/\D/g, '');
        const last4 = digits.slice(-4);
        if (val.startsWith('+91') || (digits.length === 10 && /^[6-9]/.test(digits))) {
          return `+91-XXXXX-X${last4}`;
        } else if (val.startsWith('+1')) {
          return `+1-XXX-XXX-${last4}`;
        } else if (val.startsWith('+44')) {
          return `+44-XX-XXXX-${last4}`;
        } else if (val.startsWith('+')) {
          const codeMatch = val.match(/^\+([1-9]\d{0,2})/);
          const code = codeMatch ? codeMatch[1] : 'XX';
          return `+${code}-XXXXX-${last4}`;
        } else if (digits.length === 10) {
          return `XXXXXX${last4}`;
        } else if (val.startsWith('0') && val.includes('-')) {
          const std = val.split('-')[0];
          return `${std}-XXXX${last4}`;
        }
        return `XXX-XXX-${last4}`;
      }

      default:
        return '[REDACTED]';
    }
  }

  /**
   * Generates Consistent Pseudonym.
   * Maps identical normalized values to identical placeholder IDs (EMAIL_01, PHONE_01, etc.)
   *
   * @param {Object} entity - Detected entity.
   * @param {Object} state - State container holding mapping dictionary and type counters.
   * @returns {string} Pseudonym ID.
   */
  function getPseudonym(entity, state) {
    const type = entity.type;
    const prefix = TYPE_PREFIXES[type] || type;
    const key = `${type}::${entity.normalized || entity.value}`;

    if (state.mapping[key]) {
      state.mapping[key].count++;
      return state.mapping[key].id;
    }

    // Allocate new sequential index for this entity type
    state.counters[type] = (state.counters[type] || 0) + 1;
    const num = String(state.counters[type]).padStart(2, '0');
    const id = `${prefix}_${num}`;

    state.mapping[key] = {
      id: id,
      key: key,
      type: type,
      originalValue: entity.value,
      normalized: entity.normalized || entity.value,
      count: 1
    };

    return id;
  }

  /**
   * Helper to format tooltip text for UI presentation.
   */
  function formatTooltip(entity, replacement = null) {
    let details = entity.meta ? entity.meta.validation : '';
    if (!details) {
      details = `Type: ${entity.type}`;
    }

    if (replacement) {
      return `${entity.type} • ${details} ➔ ${replacement}`;
    }
    return `${entity.type} • ${details}`;
  }

  /**
   * Executes redaction pipeline over text and detected entities.
   * Builds sanitized plaintext and side-by-side highlighting HTML.
   *
   * @param {string} text - Raw input text.
   * @param {Array} entities - Sorted, non-overlapping detected entities.
   * @param {string} mode - RedactionMode ('full', 'partial', 'pseudo').
   * @param {Object} options - Configuration options (e.g. { includeTypeTag: true }).
   * @returns {Object} { sanitizedText, originalHtml, sanitizedHtml, mapping, stats }
   */
  function redact(text, entities, mode = RedactionMode.FULL, options = {}) {
    if (!text) {
      return {
        sanitizedText: '',
        originalHtml: '',
        sanitizedHtml: '',
        mapping: {},
        stats: { totalRedacted: 0, byType: {} }
      };
    }

    if (!entities || entities.length === 0) {
      const escaped = escapeHtml(text);
      return {
        sanitizedText: text,
        originalHtml: escaped,
        sanitizedHtml: escaped,
        mapping: {},
        stats: { totalRedacted: 0, byType: {} }
      };
    }

    const includeTypeTag = Boolean(options.includeTypeTag);
    const pseudoState = {
      mapping: {},
      counters: {}
    };

    const sanitizedPieces = [];
    const origHtmlPieces = [];
    const sanitHtmlPieces = [];

    const stats = {
      totalRedacted: entities.length,
      byType: {}
    };

    let lastIndex = 0;

    for (let i = 0; i < entities.length; i++) {
      const ent = entities[i];
      const start = ent.start;
      const end = ent.end;

      // Unchanged text prior to entity
      if (start > lastIndex) {
        const chunk = text.slice(lastIndex, start);
        sanitizedPieces.push(chunk);
        const chunkEscaped = escapeHtml(chunk);
        origHtmlPieces.push(chunkEscaped);
        sanitHtmlPieces.push(chunkEscaped);
      }

      // Compute replacement based on active mode
      let replacement = '';
      if (mode === RedactionMode.FULL) {
        replacement = getFullMask(ent, includeTypeTag);
      } else if (mode === RedactionMode.PARTIAL) {
        replacement = getPartialMask(ent);
      } else if (mode === RedactionMode.PSEUDO) {
        replacement = getPseudonym(ent, pseudoState);
      } else {
        replacement = '[REDACTED]';
      }

      sanitizedPieces.push(replacement);

      // Track stats
      stats.byType[ent.type] = (stats.byType[ent.type] || 0) + 1;

      // Construct highlight HTML
      const origTooltip = formatTooltip(ent, replacement);
      const sanitTooltip = `${ent.type} • Original: ${ent.value}`;

      const typeClass = `pii-${ent.type.toLowerCase()}`;

      origHtmlPieces.push(
        `<mark class="pii-mark ${typeClass}" data-type="${ent.type}" data-tooltip="${escapeHtml(origTooltip)}">${escapeHtml(ent.value)}</mark>`
      );

      sanitHtmlPieces.push(
        `<mark class="pii-mark ${typeClass} pii-sanitized" data-type="${ent.type}" data-tooltip="${escapeHtml(sanitTooltip)}">${escapeHtml(replacement)}</mark>`
      );

      lastIndex = end;
    }

    // Append remaining text after last entity
    if (lastIndex < text.length) {
      const remaining = text.slice(lastIndex);
      sanitizedPieces.push(remaining);
      const remainingEscaped = escapeHtml(remaining);
      origHtmlPieces.push(remainingEscaped);
      sanitHtmlPieces.push(remainingEscaped);
    }

    return {
      sanitizedText: sanitizedPieces.join(''),
      originalHtml: origHtmlPieces.join(''),
      sanitizedHtml: sanitHtmlPieces.join(''),
      mapping: pseudoState.mapping,
      stats: stats
    };
  }

  return {
    RedactionMode,
    TYPE_PREFIXES,
    escapeHtml,
    getFullMask,
    getPartialMask,
    getPseudonym,
    formatTooltip,
    redact
  };
}));
