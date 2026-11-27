/**
 * RedactIQ - Detection Engine (detectors.js)
 * Implements regex patterns and algorithmic validation for PII entities:
 * - Luhn algorithm for Credit Cards
 * - Verhoeff checksum algorithm for Aadhaar
 * - 4th character status validation for PAN
 * - Strict 0-255 octet validation & version disambiguation for IP
 * - Indian & International Phone numbers with boundary safety
 * - RFC 5322-compliant Email
 * - Overlap resolution with strict priority: CREDIT_CARD > AADHAAR > PAN > EMAIL > IP > PHONE
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.RedactIQDetectors = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // =========================================================================
  // 1. MATHEMATICAL ALGORITHMS
  // =========================================================================

  /**
   * Luhn Algorithm (Mod 10 Checksum)
   * Validates credit card and payment instrument identification numbers.
   * Doubles every second digit from the rightmost digit.
   * If the doubled value is greater than 9, subtracts 9 (adds digits).
   * The number is valid if the total sum modulo 10 equals 0.
   *
   * @param {string} numberString - The numeric string to validate.
   * @returns {boolean} True if passes Luhn checksum.
   */
  function luhnCheck(numberString) {
    if (!numberString || typeof numberString !== 'string') return false;
    const digits = numberString.replace(/\D/g, '');
    if (digits.length < 13 || digits.length > 19) return false;

    let sum = 0;
    let shouldDouble = false;

    // Traverse digits from right to left
    for (let i = digits.length - 1; i >= 0; i--) {
      let digit = parseInt(digits[i], 10);
      if (isNaN(digit)) return false;

      if (shouldDouble) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }

      sum += digit;
      shouldDouble = !shouldDouble;
    }

    return sum % 10 === 0;
  }

  /**
   * Verhoeff Checksum Algorithm
   * Based on the dihedral group D5 (the symmetry group of a regular pentagon).
   * UIDAI specifies Verhoeff algorithm for the 12th checksum digit of Indian Aadhaar numbers.
   * It catches all single-digit errors and all transposition errors of adjacent digits.
   */
  const VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
  ];

  const VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
  ];

  const VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

  /**
   * Validates a number string using the Verhoeff algorithm.
   *
   * @param {string} numberString - The numeric string including checksum digit.
   * @returns {boolean} True if the checksum resolves to 0.
   */
  function verhoeffCheck(numberString) {
    if (!numberString || typeof numberString !== 'string') return false;
    const digits = numberString.replace(/\D/g, '');
    if (digits.length !== 12) return false;

    let c = 0;
    const reversed = digits.split('').reverse().map(Number);

    for (let i = 0; i < reversed.length; i++) {
      const digit = reversed[i];
      if (isNaN(digit)) return false;
      c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit]];
    }

    return c === 0;
  }

  /**
   * Computes the Verhoeff check digit for an 11-digit base number.
   * Useful for testing and validation generation.
   *
   * @param {string} numberString11 - An 11-digit numeric string.
   * @returns {number} The calculated 12th Verhoeff digit.
   */
  function verhoeffGenerate(numberString11) {
    const digits = String(numberString11).replace(/\D/g, '');
    let c = 0;
    const reversed = digits.split('').reverse().map(Number);

    for (let i = 0; i < reversed.length; i++) {
      c = VERHOEFF_D[c][VERHOEFF_P[(i + 1) % 8][reversed[i]]];
    }

    return VERHOEFF_INV[c];
  }

  // =========================================================================
  // 2. CARD NETWORK PREFIXES AND METADATA
  // =========================================================================

  const CARD_NETWORKS = [
    {
      name: 'Visa',
      regex: /^4[0-9]{12}(?:[0-9]{3})?$/,
      validLengths: [13, 16]
    },
    {
      name: 'Mastercard',
      regex: /^(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}$/,
      validLengths: [16]
    },
    {
      name: 'American Express',
      regex: /^3[47][0-9]{13}$/,
      validLengths: [15]
    },
    {
      name: 'Discover',
      regex: /^6(?:011|5[0-9]{2}|4[4-9][0-9]|22(?:1(?:2[6-9]|[3-9][0-9])|[2-8][0-9]{2}|9(?:[01][0-9]|2[0-5])))[0-9]{12}$/,
      validLengths: [16]
    },
    {
      name: 'RuPay',
      regex: /^(?:508[0-9]{3}|60[0-9]{4}|65[0-9]{4}|81[0-9]{4}|82[0-9]{4})[0-9]{10}$/,
      validLengths: [16]
    }
  ];

  function getCardNetwork(digits) {
    for (const net of CARD_NETWORKS) {
      if (net.validLengths.includes(digits.length) && net.regex.test(digits)) {
        return net.name;
      }
    }
    return null;
  }

  // PAN 4th Character Taxpayer Category Map
  const PAN_CATEGORIES = {
    'P': 'Individual / Person',
    'C': 'Company',
    'H': 'Hindu Undivided Family (HUF)',
    'F': 'Firm / Limited Liability Partnership',
    'A': 'Association of Persons (AOP)',
    'T': 'Trust',
    'B': 'Body of Individuals (BOI)',
    'L': 'Local Authority',
    'J': 'Artificial Juridical Person',
    'G': 'Government Agency'
  };

  // Priority ranking for overlap resolution (higher index = higher priority)
  const ENTITY_PRIORITY = {
    'CREDIT_CARD': 60,
    'AADHAAR': 50,
    'PAN': 40,
    'EMAIL': 30,
    'IP': 20,
    'PHONE': 10
  };

  // =========================================================================
  // 3. INDIVIDUAL ENTITY DETECTORS
  // =========================================================================

  /**
   * Detect Credit Cards
   * 13-19 digits, optional spaces or dashes.
   * Validated against Card Network prefix and Luhn algorithm.
   */
  function detectCreditCards(text) {
    const results = [];
    const rejected = [];

    // Match candidate digit sequences with spaces or hyphens
    // Negative lookbehind & lookahead ensure we do not match inside longer sequences or order IDs
    const cardRegex = /(?<![A-Za-z0-9#_])(?:\d[ -]?){13,19}(?![A-Za-z0-9#_])/g;
    let match;

    while ((match = cardRegex.exec(text)) !== null) {
      const rawVal = match[0].trim();
      const digits = rawVal.replace(/\D/g, '');

      // Plausible credit card length
      if (digits.length < 13 || digits.length > 19) continue;

      const network = getCardNetwork(digits);
      const isLuhnValid = luhnCheck(digits);

      const startIndex = match.index + match[0].indexOf(rawVal);
      const endIndex = startIndex + rawVal.length;

      if (network && isLuhnValid) {
        results.push({
          type: 'CREDIT_CARD',
          start: startIndex,
          end: endIndex,
          value: rawVal,
          normalized: digits,
          meta: {
            network: network,
            validation: `Luhn valid (${network})`,
            digits: digits
          }
        });
      } else {
        // Track candidate rejected by validation
        let reason = 'Failed Luhn checksum';
        if (!network) reason = 'Invalid card network prefix or length';
        else if (!isLuhnValid) reason = `Failed Luhn checksum (${network} format)`;

        rejected.push({
          type: 'CREDIT_CARD',
          value: rawVal,
          start: startIndex,
          end: endIndex,
          reason: reason
        });
      }
    }

    return { results, rejected };
  }

  /**
   * Detect Aadhaar Numbers
   * 12 digits, first digit 2-9, optional 4-4-4 grouping.
   * Validated using Verhoeff algorithm.
   */
  function detectAadhaar(text) {
    const results = [];
    const rejected = [];

    // Match 12 digits with optional space or hyphen (4-4-4 format or unformatted)
    // First digit must be 2-9 per UIDAI specifications
    const aadhaarCandidateRegex = /(?<![A-Za-z0-9#_])([0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4})(?![A-Za-z0-9#_])/g;
    let match;

    while ((match = aadhaarCandidateRegex.exec(text)) !== null) {
      const rawVal = match[1];
      const digits = rawVal.replace(/\D/g, '');

      if (digits.length !== 12) continue;

      const startIndex = match.index;
      const endIndex = startIndex + rawVal.length;

      // UIDAI constraint: first digit must be 2-9 (0 and 1 are invalid)
      const firstDigit = parseInt(digits[0], 10);
      if (firstDigit < 2) {
        rejected.push({
          type: 'AADHAAR',
          value: rawVal,
          start: startIndex,
          end: endIndex,
          reason: 'Aadhaar first digit must be between 2 and 9'
        });
        continue;
      }

      const isValidVerhoeff = verhoeffCheck(digits);

      if (isValidVerhoeff) {
        results.push({
          type: 'AADHAAR',
          start: startIndex,
          end: endIndex,
          value: rawVal,
          normalized: digits,
          meta: {
            validation: 'Verhoeff checksum valid',
            digits: digits
          }
        });
      } else {
        rejected.push({
          type: 'AADHAAR',
          value: rawVal,
          start: startIndex,
          end: endIndex,
          reason: 'Failed Verhoeff checksum algorithm'
        });
      }
    }

    return { results, rejected };
  }

  /**
   * Detect PAN (Permanent Account Number)
   * Pattern: ^[A-Z]{5}[0-9]{4}[A-Z]$ with word boundaries.
   * 4th character must be one of P,C,H,F,A,T,B,L,J,G.
   */
  function detectPAN(text) {
    const results = [];
    const rejected = [];

    // Match 5 letters + 4 digits + 1 letter with boundary constraints
    const panRegex = /(?<![A-Za-z0-9])([A-Z]{5}[0-9]{4}[A-Z])(?![A-Za-z0-9])/g;
    let match;

    while ((match = panRegex.exec(text)) !== null) {
      const rawVal = match[1];
      const char4 = rawVal[3];
      const category = PAN_CATEGORIES[char4];

      const startIndex = match.index;
      const endIndex = startIndex + rawVal.length;

      if (category) {
        results.push({
          type: 'PAN',
          start: startIndex,
          end: endIndex,
          value: rawVal,
          normalized: rawVal.toUpperCase(),
          meta: {
            validation: `Valid PAN (${category})`,
            category: category
          }
        });
      } else {
        rejected.push({
          type: 'PAN',
          value: rawVal,
          start: startIndex,
          end: endIndex,
          reason: `Invalid 4th character '${char4}' (must be P, C, H, F, A, T, B, L, J, or G)`
        });
      }
    }

    return { results, rejected };
  }

  /**
   * Detect Email Addresses
   * Standard RFC 5322-compliant pattern.
   */
  function detectEmails(text) {
    const results = [];
    const rejected = [];

    const emailRegex = /(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})(?!(?:\.[a-zA-Z0-9]|[a-zA-Z0-9_%+-]))/g;
    let match;

    while ((match = emailRegex.exec(text)) !== null) {
      const rawVal = match[1];
      const startIndex = match.index;
      const endIndex = startIndex + rawVal.length;

      results.push({
        type: 'EMAIL',
        start: startIndex,
        end: endIndex,
        value: rawVal,
        normalized: rawVal.toLowerCase(),
        meta: {
          validation: 'RFC 5322 compliant email'
        }
      });
    }

    return { results, rejected };
  }

  /**
   * Detect IP Addresses (IPv4 and IPv6)
   * Validates IPv4 octets (each 0-255).
   * Distinguishes software versions (e.g. "version 1.2.3.4" or "v1.2.3.4").
   * Flags invalid IP octets (e.g. 999.1.1.1) under rejected.
   */
  function detectIPs(text) {
    const results = [];
    const rejected = [];

    // 1. IPv4 Candidates: 4 dot-separated numbers
    // Accommodate sentence-ending period while blocking 5th octet or alphanumeric domain
    const ipv4CandidateRegex = /(?<![A-Za-z0-9_.-])(\d{1,4}\.\d{1,4}\.\d{1,4}\.\d{1,4})(?!(?:\.[0-9]|[A-Za-z0-9_-]))/g;
    let match;

    while ((match = ipv4CandidateRegex.exec(text)) !== null) {
      const rawVal = match[1];
      const startIndex = match.index;
      const endIndex = startIndex + rawVal.length;

      // Disambiguation: Check if preceded by version keywords (e.g. "version 1.2.3.4", "v1.2.3.4", "build 1.2.3.4")
      const lookbackWindow = text.slice(Math.max(0, startIndex - 20), startIndex);
      const isVersionString = /(?:^|\s)(?:version|ver\.?|v\.?|release|build|firmware)\s*[:=]?\s*$/i.test(lookbackWindow);

      if (isVersionString) {
        // Version number decoy - do not flag as IP
        continue;
      }

      const octets = rawVal.split('.').map(Number);
      const allValidOctets = octets.length === 4 && octets.every(o => o >= 0 && o <= 255);

      if (allValidOctets) {
        results.push({
          type: 'IP',
          start: startIndex,
          end: endIndex,
          value: rawVal,
          normalized: octets.join('.'),
          meta: {
            validation: 'Valid IPv4 address (0-255 octets)',
            ipVersion: 'IPv4'
          }
        });
      } else {
        rejected.push({
          type: 'IP',
          value: rawVal,
          start: startIndex,
          end: endIndex,
          reason: 'IPv4 octet out of bounds (must be 0-255)'
        });
      }
    }

    // 2. IPv6 Addresses
    // Supports full 8-group and standard compressed IPv6 forms
    const ipv6FullRegex = /(?<![A-Za-z0-9:])([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7})(?![A-Za-z0-9:])/g;
    while ((match = ipv6FullRegex.exec(text)) !== null) {
      const rawVal = match[1];
      results.push({
        type: 'IP',
        start: match.index,
        end: match.index + rawVal.length,
        value: rawVal,
        normalized: rawVal.toLowerCase(),
        meta: {
          validation: 'Valid IPv6 (Full 128-bit)',
          ipVersion: 'IPv6'
        }
      });
    }

    // Compressed IPv6 with '::'
    const ipv6CompressedRegex = /(?<![A-Za-z0-9:])((?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7}|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})(?![A-Za-z0-9:])/g;
    while ((match = ipv6CompressedRegex.exec(text)) !== null) {
      const rawVal = match[1];
      if (!rawVal.includes('::') || rawVal.length < 3) continue;

      const start = match.index;
      const end = start + rawVal.length;
      if (results.some(r => r.start <= start && r.end >= end)) continue;

      results.push({
        type: 'IP',
        start: start,
        end: end,
        value: rawVal,
        normalized: rawVal.toLowerCase(),
        meta: {
          validation: 'Valid IPv6 (Compressed)',
          ipVersion: 'IPv6'
        }
      });
    }

    return { results, rejected };
  }

  /**
   * Detect Phone Numbers
   * Indian (+91, 0, 10-digit mobile starting with 6-9, STD landlines)
   * International E.164-style numbers.
   * Excludes order IDs, tracking barcodes, Aadhaar numbers, and card numbers.
   */
  function detectPhones(text) {
    const results = [];
    const rejected = [];

    // Prioritized candidate regexes:
    // 1. International with + (E.164-style with optional brackets and separators)
    //    e.g. +91 98765 43210, +91-91234-56789, +1 (555) 234-5678, +44 20 7946 0958
    const intlRegex = /(?<![A-Za-z0-9#_])(\+(?:[1-9]\d{0,2})[-. ]?(?:\(\d{1,5}\)|\d{1,5})(?:[-. ]?\d{1,5}){1,4})(?![A-Za-z0-9#_])/g;

    // 2. Indian 10-digit mobile starting with 6-9 with optional 0 prefix:
    //    e.g. 09876543210, 98765 43210, 9876543210
    const indianMobileRegex = /(?<![A-Za-z0-9#_])(0?[6-9]\d{4}[ -]?\d{5}|0?[6-9]\d{9})(?![A-Za-z0-9#_])/g;

    // 3. Indian Landline with STD code (e.g. 080-23456789, 011-23456789)
    const landlineRegex = /(?<![A-Za-z0-9#_])(0\d{2,4}[- ]\d{6,8})(?![A-Za-z0-9#_])/g;

    const regexList = [
      { regex: intlRegex, kind: 'intl' },
      { regex: indianMobileRegex, kind: 'indian_mobile' },
      { regex: landlineRegex, kind: 'landline' }
    ];

    for (const item of regexList) {
      let match;
      while ((match = item.regex.exec(text)) !== null) {
        const rawVal = match[1];
        const digits = rawVal.replace(/\D/g, '');

        // Digits length safety: phones should have between 7 and 15 digits
        if (digits.length < 7 || digits.length > 15) continue;

        // Discard 12-digit un-prefixed numbers that could be Aadhaar
        if (!rawVal.startsWith('+') && digits.length === 12 && /^[2-9]/.test(digits)) {
          continue;
        }

        const startIndex = match.index;
        const endIndex = startIndex + rawVal.length;

        // Check if an existing match already spans this range or overlaps with an international match
        if (results.some(r => (startIndex >= r.start && endIndex <= r.end) || (r.start >= startIndex && r.end <= endIndex))) {
          continue;
        }

        // Normalization:
        // For Indian 10-digit mobile numbers (e.g. 98765 43210, +91 98765 43210, 09876543210),
        // normalize to standard +91XXXXXXXXXX so identical numbers map to the same pseudonym!
        let normalized = digits;
        if (rawVal.startsWith('+91') || (digits.length === 10 && /^[6-9]/.test(digits))) {
          const tenDigits = digits.length === 12 && digits.startsWith('91') ? digits.slice(2) : digits;
          normalized = '+91' + tenDigits;
        } else if (digits.length === 11 && digits.startsWith('0') && /^[6-9]/.test(digits.slice(1))) {
          normalized = '+91' + digits.slice(1);
        } else if (rawVal.startsWith('+')) {
          normalized = '+' + digits;
        }

        let desc = 'Valid Phone';
        if (rawVal.includes('+91') || (digits.length === 10 && /^[6-9]/.test(digits))) {
          desc = 'Indian Mobile (+91 format)';
        } else if (rawVal.startsWith('+1')) {
          desc = 'North American Number (+1)';
        } else if (rawVal.startsWith('+44')) {
          desc = 'UK Phone (+44)';
        } else if (rawVal.startsWith('+')) {
          desc = 'International E.164 Number';
        } else if (item.kind === 'landline') {
          desc = 'Indian Landline (STD format)';
        }

        results.push({
          type: 'PHONE',
          start: startIndex,
          end: endIndex,
          value: rawVal,
          normalized: normalized,
          meta: {
            validation: desc,
            digits: digits
          }
        });
      }
    }

    return { results, rejected };
  }

  // =========================================================================
  // 4. OVERLAP RESOLUTION
  // =========================================================================

  /**
   * Resolves overlaps between detected spans based on strict priority:
   * CREDIT_CARD > AADHAAR > PAN > EMAIL > IP > PHONE.
   * If priority is tied, longer match wins.
   * Ensures no span is double-redacted or split improperly.
   *
   * @param {Array} entities - List of candidate entity objects.
   * @returns {Array} Sorted, non-overlapping entities.
   */
  function resolveOverlaps(entities) {
    if (!entities || entities.length <= 1) return entities || [];

    // Sort by priority descending, then length descending, then start index ascending
    const sortedCandidates = [...entities].sort((a, b) => {
      const prioA = ENTITY_PRIORITY[a.type] || 0;
      const prioB = ENTITY_PRIORITY[b.type] || 0;
      if (prioB !== prioA) return prioB - prioA;

      const lenA = a.end - a.start;
      const lenB = b.end - b.start;
      if (lenB !== lenA) return lenB - lenA;

      return a.start - b.start;
    });

    const accepted = [];

    for (const cand of sortedCandidates) {
      // Check if this candidate overlaps with any already accepted candidate
      const overlaps = accepted.some(acc => {
        return cand.start < acc.end && acc.start < cand.end;
      });

      if (!overlaps) {
        accepted.push(cand);
      }
    }

    // Return in document order (start ascending)
    return accepted.sort((a, b) => a.start - b.start);
  }

  // =========================================================================
  // 5. UNIFIED DETECTION PIPELINE
  // =========================================================================

  /**
   * Detects all PII entities in the input text with filtering, validation,
   * overlap resolution, and rejection accounting.
   *
   * @param {string} text - Raw input text.
   * @param {Object} [enabledTypes] - Optional map of boolean flags per entity type.
   * @returns {Object} { entities: Array, rejected: Array, counts: Object, rejectedCount: number }
   */
  function detectAll(text, enabledTypes = null) {
    if (!text || typeof text !== 'string') {
      return {
        entities: [],
        rejected: [],
        counts: {
          EMAIL: 0,
          PHONE: 0,
          IP: 0,
          PAN: 0,
          AADHAAR: 0,
          CREDIT_CARD: 0,
          TOTAL: 0
        },
        rejectedCount: 0
      };
    }

    const isEnabled = (type) => !enabledTypes || enabledTypes[type] !== false;

    let allDetected = [];
    let allRejected = [];

    // Run each detector
    if (isEnabled('CREDIT_CARD')) {
      const cardRes = detectCreditCards(text);
      allDetected.push(...cardRes.results);
      allRejected.push(...cardRes.rejected);
    }

    if (isEnabled('AADHAAR')) {
      const aadhRes = detectAadhaar(text);
      allDetected.push(...aadhRes.results);
      allRejected.push(...aadhRes.rejected);
    }

    if (isEnabled('PAN')) {
      const panRes = detectPAN(text);
      allDetected.push(...panRes.results);
      allRejected.push(...panRes.rejected);
    }

    if (isEnabled('EMAIL')) {
      const emailRes = detectEmails(text);
      allDetected.push(...emailRes.results);
      allRejected.push(...emailRes.rejected);
    }

    if (isEnabled('IP')) {
      const ipRes = detectIPs(text);
      allDetected.push(...ipRes.results);
      allRejected.push(...ipRes.rejected);
    }

    if (isEnabled('PHONE')) {
      const phoneRes = detectPhones(text);
      allDetected.push(...phoneRes.results);
      allRejected.push(...phoneRes.rejected);
    }

    // Resolve overlaps
    const resolvedEntities = resolveOverlaps(allDetected);

    // Compute live stats counts
    const counts = {
      EMAIL: 0,
      PHONE: 0,
      IP: 0,
      PAN: 0,
      AADHAAR: 0,
      CREDIT_CARD: 0,
      TOTAL: resolvedEntities.length
    };

    for (const ent of resolvedEntities) {
      if (counts[ent.type] !== undefined) {
        counts[ent.type]++;
      }
    }

    return {
      entities: resolvedEntities,
      rejected: allRejected,
      counts: counts,
      rejectedCount: allRejected.length
    };
  }

  return {
    luhnCheck,
    verhoeffCheck,
    verhoeffGenerate,
    detectCreditCards,
    detectAadhaar,
    detectPAN,
    detectEmails,
    detectIPs,
    detectPhones,
    resolveOverlaps,
    detectAll,
    CARD_NETWORKS,
    PAN_CATEGORIES,
    ENTITY_PRIORITY
  };
}));
