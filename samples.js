/**
 * RedactIQ - Sample Data
 * Realistic noisy text containing support tickets, clinical notes, and onboarding records.
 * Contains both valid PII entities and decoy tokens that must NOT be flagged.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.RedactIQSamples = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const NOISY_SAMPLE = `--- INCIDENT TICKET & INTAKE RECORD #TCK-2026-9812 ---
Patient / Client Name: Dr. Rajesh Sharma, MD
Attending Consultant: Priya K. Nambiar (ID: EMP-8492)
Facility: Apex Healthcare Metro Pavilion, Bengaluru, Karnataka
Intake Timestamp: 2026-11-27T08:45:00Z | Workstation IP: 192.168.1.104
Gateway IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
Application Build: version 1.2.3.4 (Release Candidate 3)
Server Cluster Node: 10.0.4.250 | Remote Diagnostic Host: 999.1.1.1 (DECOY: Invalid Octet)

==================== SECTION 1: IDENTITY & BILLING ====================
Primary Contact Email: rajesh.sharma@apexcare.in
Emergency Department Contact: emergency@apexcare.in
Billing Dispute Escalation Email: rajesh.sharma@apexcare.in
US Clinical Affiliate Email: r.sharma.fellow@bostonhealth.org

Contact Numbers:
- Primary Mobile (India): +91 98765 43210
- Alternate Mobile (India formatted): +91-91234-56789
- Clinic Landline (Direct): 080-23456789
- Personal Mobile (Unformatted 10-digit): 9876543210
- US Office Liaison: +1 (555) 234-5678
- London Research Desk: +44 20 7946 0958

Government Identity Tokens:
- Permanent Account Number (PAN - Individual): ABCPE1234F
- Corporate PAN (Hospital Billing Wing): DELPB5541K
- Aadhaar UID (Formatted with spaces): 2834 5678 9019
- Aadhaar UID (Formatted with hyphens): 5432-1098-7652
- Aadhaar UID (Plain 12 digits): 901234567892

Payment Instruments on File:
- Visa Corporate Card: 4532 0151 1283 0366
- Mastercard Executive: 5425-2334-3010-9903
- American Express Platinum: 3782 822463 10005

==================== SECTION 2: SYSTEM DECOYS (DO NOT REDACT) ====================
The following strings resemble PII patterns but MUST fail validation:
1. Luhn Checksum Failure (16-digit card decoy): 4532 0151 1283 0367
2. Verhoeff Checksum Failure (12-digit Aadhaar decoy): 2834 5678 9010
3. Invalid Tax Category PAN (4th letter 'E' is invalid): ABCDE1234F
4. Software Version Number: v1.2.3.4
5. Out-of-range IP Octet: 999.1.1.1
6. E-Commerce Order Reference: ORD-9823471029384
7. Lab Specimen Barcode: #849204820193
8. Shipping Tracking ID: TRACK-992384710293

==================== SECTION 3: CLINICAL ENCOUNTER NOTE ====================
Patient presented with elevated vitals at triage station 4. Dr. Rajesh Sharma (rajesh.sharma@apexcare.in)
administered intravenous normal saline. Consultation notes were forwarded to emergency@apexcare.in and
verified via SMS notification to +91 98765 43210.

A copay of INR 2,500 was authorized on corporate card 4532-0151-1283-0366. For insurance adjudication,
Aadhaar 2834 5678 9019 and PAN ABCPE1234F were verified against the state health registry.
Backup telemetry logs were synchronized to secure node 172.16.254.1.

Technician Note: Barcode scanner read barcode #849204820193 successfully. Firmware v1.2.3.4 verified.
Discharge summary submitted under tracking batch ORD-9823471029384.

==================== SECTION 4: CANDIDATE RESUME & ONBOARDING PROFILE ====================
Candidate Name: Priya K. Nambiar, Senior Health Informatics Specialist
Current Employer: Apex Healthcare Metro Pavilion (priya.n@techcorp.in)
Personal Email: priya.nambiar@apexcare.in | Contact: +91-91234-56789
Home Address Registration: Aadhaar UID 5432-1098-7652 verified with UIDAI biometric portal.
Income Tax Assessment ID: PAN DELPB5541K (Individual category).
Direct Reimbursement Card: 5425-2334-3010-9903 (Mastercard Corporate Travel).
Previous Workstation Gateway IP: 10.0.4.250 | Remote Lab Server: 192.168.1.104
Prior Reference Verification Code: REF#849204820193 (Decoy ID)
--- END OF RECORD ---`;

  const RESUME_SAMPLE = `==================== CURRICULUM VITAE / CANDIDATE DOSSIER ====================
NAME: Marcus Vance, Lead Health Systems Architect
CONTACT INFORMATION:
- Primary Email: m.vance@globalhealth.org
- Alternate Personal Email: marcus.vance@techcorp.in
- US Direct Phone: +1 (555) 234-5678
- India Office Mobile: +91 98765 43210
- London Liaison: +44 20 7946 0958

IDENTITY & STATUTORY CREDENTIALS:
- Permanent Account Number (PAN): BLHPT9821K (Category: Individual)
- Indian Aadhaar Identity: 901234567892 (Verhoeff Verified)
- Alternate Aadhaar: 2834 5678 9019

CORPORATE PAYMENT & EXPENSE ACCOUNTS:
- American Express Executive: 3782 822463 10005
- Visa Travel Card: 4532 0151 1283 0366

TECHNICAL INFRASTRUCTURE EXPERIENCE:
- Primary Production Host: 172.16.254.1
- Management Bastion Node: 192.168.1.104
- Cloud Gateway IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334

DECOY CERTIFICATES & NON-PII IDENTIFIERS (DO NOT FLAG):
- AWS Certification Badge: AWS-9823471029384 (Decoy credential)
- OpenSSL Version: v1.2.3.4 (Decoy version number)
- Test Environment Decoy IP: 999.1.1.1 (Decoy invalid octet)
- IEEE Publication Reference: #849204820193 (Decoy paper ID)
- Invalid Test Card (Fails Luhn): 4532 0151 1283 0367
==================== END OF RESUME ====================`;

  const CSV_SAMPLE = `Record_ID,Full_Name,Email_Address,Phone_Number,Tax_ID,Aadhaar_Number,Credit_Card,IP_Address,System_Notes
101,Rajesh Sharma,rajesh.sharma@apexcare.in,+91 98765 43210,ABCPE1234F,2834 5678 9019,4532 0151 1283 0366,192.168.1.104,Order ORD-9823471029384
102,Priya Nambiar,priya.n@techcorp.in,+91-91234-56789,DELPB5541K,5432-1098-7652,5425-2334-3010-9903,10.0.4.250,Version v1.2.3.4
103,Marcus Vance,m.vance@globalhealth.org,+1 (555) 234-5678,BLHPT9821K,901234567892,3782 822463 10005,172.16.254.1,Sample #849204820193
104,Elena Rostova,elena.r@euroclinic.co.uk,+44 20 7946 0958,AAAPC9912F,2834 5678 9019,4532 0151 1283 0366,192.168.1.104,Repeated patient`;

  return {
    NOISY_SAMPLE,
    RESUME_SAMPLE,
    CSV_SAMPLE
  };
}));
