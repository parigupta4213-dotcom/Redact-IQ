/**
 * RedactIQ - Unit Test Suite (tests.js)
 * Executable in Node.js via `node tests.js` and in the browser via `tests.html`.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    const detectors = require('./detectors.js');
    const redactor = require('./redactor.js');
    const samples = require('./samples.js');
    module.exports = factory(detectors, redactor, samples);
  } else {
    root.RedactIQTests = factory(root.RedactIQDetectors, root.RedactIQRedactor, root.RedactIQSamples);
  }
}(typeof self !== 'undefined' ? self : this, function (detectors, redactor, samples) {
  'use strict';

  const testResults = [];

  function assert(condition, testName, category, details = '') {
    const passed = Boolean(condition);
    const item = { name: testName, category, passed, details };
    testResults.push(item);
    return passed;
  }

  function runAllTests() {
    testResults.length = 0;

    // =========================================================================
    // 1. LUHN ALGORITHM TESTS
    // =========================================================================
    // Known valid cards
    assert(detectors.luhnCheck('4532015112830366'), 'Visa 16-digit valid Luhn', 'Luhn Algorithm');
    assert(detectors.luhnCheck('5425233430109903'), 'Mastercard 16-digit valid Luhn', 'Luhn Algorithm');
    assert(detectors.luhnCheck('378282246310005'), 'Amex 15-digit valid Luhn', 'Luhn Algorithm');
    assert(detectors.luhnCheck('6011000990139424'), 'Discover 16-digit valid Luhn', 'Luhn Algorithm');
    assert(detectors.luhnCheck('4532 0151 1283 0366'), 'Visa with spaces valid Luhn', 'Luhn Algorithm');
    assert(detectors.luhnCheck('5425-2334-3010-9903'), 'Mastercard with dashes valid Luhn', 'Luhn Algorithm');

    // Negative Luhn cases
    assert(!detectors.luhnCheck('4532015112830367'), 'Card checksum corrupted by 1 rejected', 'Luhn Algorithm');
    assert(!detectors.luhnCheck('1234567812345671'), 'Random 16 digits failing Luhn rejected', 'Luhn Algorithm');
    assert(!detectors.luhnCheck('12345'), 'Too short string (<13) rejected', 'Luhn Algorithm');
    assert(!detectors.luhnCheck('123456789012345678901'), 'Too long string (>19) rejected', 'Luhn Algorithm');
    assert(!detectors.luhnCheck(''), 'Empty string rejected', 'Luhn Algorithm');

    // =========================================================================
    // 2. VERHOEFF ALGORITHM TESTS
    // =========================================================================
    // Positive Verhoeff cases
    assert(detectors.verhoeffCheck('283456789019'), 'Aadhaar 1 valid Verhoeff', 'Verhoeff Algorithm');
    assert(detectors.verhoeffCheck('543210987652'), 'Aadhaar 2 valid Verhoeff', 'Verhoeff Algorithm');
    assert(detectors.verhoeffCheck('901234567892'), 'Aadhaar 3 valid Verhoeff', 'Verhoeff Algorithm');
    assert(detectors.verhoeffCheck('2834 5678 9019'), 'Aadhaar with spaces valid Verhoeff', 'Verhoeff Algorithm');
    assert(detectors.verhoeffCheck('5432-1098-7652'), 'Aadhaar with hyphens valid Verhoeff', 'Verhoeff Algorithm');

    // Checksum generation and verification
    const base11 = '41239874561';
    const checkDigit = detectors.verhoeffGenerate(base11);
    assert(detectors.verhoeffCheck(base11 + checkDigit), `Generated check digit (${checkDigit}) passes Verhoeff`, 'Verhoeff Algorithm');

    // Negative Verhoeff cases
    assert(!detectors.verhoeffCheck('283456789010'), 'Single digit change fails Verhoeff', 'Verhoeff Algorithm');
    assert(!detectors.verhoeffCheck('284356789019'), 'Adjacent transposition error (34->43) caught', 'Verhoeff Algorithm');
    assert(!detectors.verhoeffCheck('12345678901'), '11 digits fails length', 'Verhoeff Algorithm');
    assert(!detectors.verhoeffCheck('1234567890123'), '13 digits fails length', 'Verhoeff Algorithm');

    // =========================================================================
    // 3. CREDIT CARD DETECTOR TESTS
    // =========================================================================
    const cardText = `
      Valid Visa: 4532 0151 1283 0366
      Valid MC: 5425-2334-3010-9903
      Valid Amex: 3782 822463 10005
      Decoy Card: 4532 0151 1283 0367
      Order ID: ORD-9823471029384
    `;
    const cardDetections = detectors.detectCreditCards(cardText);
    assert(cardDetections.results.length === 3, 'Detects exactly 3 valid cards', 'Credit Card Detector', `Found: ${cardDetections.results.length}`);
    assert(cardDetections.results.some(c => c.meta.network === 'Visa'), 'Identifies Visa', 'Credit Card Detector');
    assert(cardDetections.results.some(c => c.meta.network === 'Mastercard'), 'Identifies Mastercard', 'Credit Card Detector');
    assert(cardDetections.results.some(c => c.meta.network === 'American Express'), 'Identifies American Express', 'Credit Card Detector');
    assert(cardDetections.rejected.some(r => r.value.includes('4532 0151 1283 0367')), 'Flags Luhn failure under rejected', 'Credit Card Detector');

    // =========================================================================
    // 4. AADHAAR DETECTOR TESTS
    // =========================================================================
    const aadhaarText = `
      Aadhaar 1: 2834 5678 9019
      Aadhaar 2: 5432-1098-7652
      Aadhaar 3: 901234567892
      Decoy Aadhaar (Bad checksum): 2834 5678 9010
      Decoy Aadhaar (Starts with 1): 1234 5678 9012
    `;
    const aadhaarDetections = detectors.detectAadhaar(aadhaarText);
    assert(aadhaarDetections.results.length === 3, 'Detects exactly 3 valid Aadhaar numbers', 'Aadhaar Detector', `Found: ${aadhaarDetections.results.length}`);
    assert(aadhaarDetections.rejected.some(r => r.value.includes('2834 5678 9010')), 'Rejects Aadhaar with invalid Verhoeff checksum', 'Aadhaar Detector');
    assert(aadhaarDetections.rejected.some(r => r.value.includes('1234 5678 9012')), 'Rejects Aadhaar starting with 1', 'Aadhaar Detector');

    // =========================================================================
    // 5. PAN DETECTOR TESTS
    // =========================================================================
    const panText = `
      Valid Person: ABCPE1234F
      Valid Company: AAAPC1234F
      Valid Firm: BLHFA1234F
      Decoy (Invalid 4th char 'E'): ABCDE1234F
      Invalid PAN: 12345ABCDE
    `;
    const panDetections = detectors.detectPAN(panText);
    assert(panDetections.results.length === 3, 'Detects 3 valid PANs', 'PAN Detector', `Found: ${panDetections.results.length}`);
    assert(panDetections.rejected.some(r => r.value === 'ABCDE1234F'), 'Rejects PAN with invalid 4th character', 'PAN Detector');

    // =========================================================================
    // 6. EMAIL DETECTOR TESTS
    // =========================================================================
    const emailText = 'Contact support@apexcare.in or dr.sharma+cardio@med-hospital.co.uk for help. Do not email user@ or @domain.';
    const emailDetections = detectors.detectEmails(emailText);
    assert(emailDetections.results.length === 2, 'Detects 2 valid emails', 'Email Detector', `Found: ${emailDetections.results.length}`);
    assert(emailDetections.results[0].normalized === 'support@apexcare.in', 'Normalizes email to lowercase', 'Email Detector');

    // =========================================================================
    // 7. IP ADDRESS & VERSION DISAMBIGUATION TESTS
    // =========================================================================
    const ipText = `
      Workstation IP: 192.168.1.104
      Server: 10.0.4.250
      Gateway IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
      Decoy Version: version 1.2.3.4
      Decoy Firmware: v1.2.3.4
      Invalid Octet: 999.1.1.1
    `;
    const ipDetections = detectors.detectIPs(ipText);
    assert(ipDetections.results.length === 3, 'Detects 3 valid IPs (2 IPv4, 1 IPv6)', 'IP Detector', `Found: ${ipDetections.results.length}`);
    assert(!ipDetections.results.some(r => r.value === '1.2.3.4'), 'Rejects version numbers (1.2.3.4) as IP', 'IP Detector');
    assert(ipDetections.rejected.some(r => r.value === '999.1.1.1'), 'Flags 999.1.1.1 with octet out of bounds under rejected', 'IP Detector');

    // =========================================================================
    // 8. PHONE DETECTOR TESTS
    // =========================================================================
    const phoneText = `
      Primary: +91 98765 43210
      Hyphenated: +91-91234-56789
      Plain 10: 9876543210
      Landline: 080-23456789
      US Line: +1 (555) 234-5678
      UK Line: +44 20 7946 0958
      Order Code: ORD-9823471029384
    `;
    const phoneDetections = detectors.detectPhones(phoneText);
    assert(phoneDetections.results.length === 6, 'Detects 6 valid phone numbers', 'Phone Detector', `Found: ${phoneDetections.results.length}`);
    assert(!phoneDetections.results.some(r => r.value.includes('ORD-')), 'Does not match inside order codes', 'Phone Detector');

    // =========================================================================
    // 9. OVERLAP RESOLUTION TESTS
    // =========================================================================
    // Synthetic overlap: Aadhaar (span 0-14) vs Phone (span 5-14)
    const mockCandidates = [
      { type: 'PHONE', start: 5, end: 14, value: '9876543210' },
      { type: 'AADHAAR', start: 0, end: 14, value: '2834 5678 9019' },
      { type: 'CREDIT_CARD', start: 30, end: 49, value: '4532 0151 1283 0366' },
      { type: 'PHONE', start: 35, end: 49, value: '0151 1283 0366' }
    ];
    const resolved = detectors.resolveOverlaps(mockCandidates);
    assert(resolved.length === 2, 'Overlaps cleanly resolved', 'Overlap Resolution', `Surviving: ${resolved.length}`);
    assert(resolved[0].type === 'AADHAAR', 'Aadhaar takes priority over Phone', 'Overlap Resolution');
    assert(resolved[1].type === 'CREDIT_CARD', 'Credit Card takes priority over Phone', 'Overlap Resolution');

    // =========================================================================
    // 10. REDACTION MODES TESTS
    // =========================================================================
    const testDoc = 'Doctor: rajesh.sharma@apexcare.in, Aadhaar: 2834 5678 9019, Card: 4532 0151 1283 0366, PAN: ABCPE1234F';
    const detAll = detectors.detectAll(testDoc);

    // Full Mask
    const full = redactor.redact(testDoc, detAll.entities, 'full', { includeTypeTag: false });
    assert(full.sanitizedText.includes('[REDACTED]'), 'Full Mask replaces entities with [REDACTED]', 'Redaction Modes');
    assert(!full.sanitizedText.includes('rajesh.sharma@apexcare.in'), 'Full mask hides raw email', 'Redaction Modes');

    // Full Mask with Tags
    const fullTagged = redactor.redact(testDoc, detAll.entities, 'full', { includeTypeTag: true });
    assert(fullTagged.sanitizedText.includes('[REDACTED:EMAIL]'), 'Full Mask with tags emits [REDACTED:EMAIL]', 'Redaction Modes');
    assert(fullTagged.sanitizedText.includes('[REDACTED:CARD]'), 'Full Mask with tags emits [REDACTED:CARD]', 'Redaction Modes');

    // Partial Mask
    const partial = redactor.redact(testDoc, detAll.entities, 'partial');
    assert(partial.sanitizedText.includes('XXXX-XXXX-XXXX-0366'), 'Partial Mask shows last 4 of card', 'Redaction Modes');
    assert(partial.sanitizedText.includes('XXXX-XXXX-9019'), 'Partial Mask shows last 4 of Aadhaar', 'Redaction Modes');
    assert(partial.sanitizedText.includes('r***@apexcare.in'), 'Partial Mask shows initial of email', 'Redaction Modes');
    assert(partial.sanitizedText.includes('ABXXXXX34F'), 'Partial Mask preserves PAN format ABXXXXX34F', 'Redaction Modes');

    // =========================================================================
    // 11. CONSISTENT PSEUDONYMIZATION & NORMALIZATION TESTS
    // =========================================================================
    const repeatedDoc = `
      Case 1: Contact rajesh.sharma@apexcare.in or call +91 98765 43210.
      Case 2: Contact RAJESH.SHARMA@APEXCARE.IN or call 9876543210.
      Case 3: Unrelated person emergency@apexcare.in.
    `;
    const detRepeated = detectors.detectAll(repeatedDoc);
    const pseudo = redactor.redact(repeatedDoc, detRepeated.entities, 'pseudo');

    // Email check: uppercase and lowercase should map to exact same pseudonym ID
    const emailOccurrences = (pseudo.sanitizedText.match(/EMAIL_01/g) || []).length;
    assert(emailOccurrences === 2, 'Normalized emails map to identical EMAIL_01 pseudonym', 'Pseudonymization', `Found: ${emailOccurrences}`);

    // Phone check: formatted +91 and plain 10-digit should map to exact same pseudonym ID
    const phoneOccurrences = (pseudo.sanitizedText.match(/PHONE_01/g) || []).length;
    assert(phoneOccurrences === 2, 'Normalized phone numbers map to identical PHONE_01 pseudonym', 'Pseudonymization', `Found: ${phoneOccurrences}`);

    // Second distinct email maps to EMAIL_02
    assert(pseudo.sanitizedText.includes('EMAIL_02'), 'Second distinct email maps to EMAIL_02', 'Pseudonymization');

    // Mapping table integrity
    const mappingKeys = Object.keys(pseudo.mapping);
    assert(mappingKeys.length === 3, 'Mapping table contains exactly 3 distinct entity mappings', 'Pseudonymization', `Keys: ${mappingKeys.length}`);

    // =========================================================================
    // 12. XSS PREVENTION TESTS
    // =========================================================================
    const xssPayload = '<script>alert("xss")</script> and user@<script>evil.com';
    const xssEscaped = redactor.escapeHtml(xssPayload);
    assert(!xssEscaped.includes('<script>'), 'HTML escaping prevents script tags', 'Security / XSS');
    assert(xssEscaped.includes('&lt;script&gt;'), 'Script tags correctly converted to entities', 'Security / XSS');

    const totalPassed = testResults.filter(t => t.passed).length;
    const totalFailed = testResults.filter(t => !t.passed).length;

    return {
      results: testResults,
      totalPassed,
      totalFailed,
      totalCount: testResults.length
    };
  }

  // CLI runner for Node.js
  if (typeof module !== 'undefined' && require.main === module) {
    const summary = runAllTests();
    console.log(`\n======================================================`);
    console.log(` RedactIQ Unit Test Suite: ${summary.totalPassed}/${summary.totalCount} PASSED (${summary.totalFailed} FAILED)`);
    console.log(`======================================================\n`);

    let currentCat = '';
    summary.results.forEach(t => {
      if (t.category !== currentCat) {
        currentCat = t.category;
        console.log(`\n[${currentCat}]`);
      }
      const mark = t.passed ? '✓ PASS' : '✗ FAIL';
      console.log(`  ${mark} - ${t.name} ${t.details ? '(' + t.details + ')' : ''}`);
    });

    if (summary.totalFailed > 0) {
      process.exit(1);
    }
  }

  return {
    runAllTests
  };
}));
