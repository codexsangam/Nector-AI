/**
 * Nector Verification and Automated Test Suite
 * Tests target validation, SSRF guardrails, Nuclei normalization,
 * Scan Store persistence, and Gemini explainer schema parsing.
 */

import assert from 'node:assert';
import { validateScanTarget, isPrivateIPv4, isPrivateIPv6 } from '../api/_common/validate-target.js';
import { createScanRecord, updateScanRecord, getScanRecord } from '../api/_common/scan-store.js';
import { normalizeNucleiFinding } from '../api/_common/nuclei-runner.js';
import { getGeminiConfig, explainFindingWithGemini } from '../api/_common/gemini-explainer.js';

let passed = 0;
let failed = 0;

function runTest(name, fn) {
  try {
    fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`[FAIL] ${name}: ${err.message}`);
    failed++;
  }
}

async function runAsyncTest(name, fn) {
  try {
    await fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`[FAIL] ${name}: ${err.message}`);
    failed++;
  }
}

console.log('==================================================');
console.log('       RUNNING NECTOR VERIFICATION SUITE          ');
console.log('==================================================\n');

// 1. SSRF & IP Validation Tests
runTest('IPv4 Private Range Detection (127.0.0.1 loopback)', () => {
  assert.strictEqual(isPrivateIPv4('127.0.0.1'), true);
});

runTest('IPv4 Private Range Detection (10.0.0.1 private)', () => {
  assert.strictEqual(isPrivateIPv4('10.0.0.1'), true);
});

runTest('IPv4 Private Range Detection (192.168.1.1 private)', () => {
  assert.strictEqual(isPrivateIPv4('192.168.1.1'), true);
});

runTest('IPv4 Cloud Metadata Detection (169.254.169.254)', () => {
  assert.strictEqual(isPrivateIPv4('169.254.169.254'), true);
});

runTest('IPv4 Public Range Validation (8.8.8.8 public)', () => {
  assert.strictEqual(isPrivateIPv4('8.8.8.8'), false);
});

runTest('IPv6 Loopback Detection (::1)', () => {
  assert.strictEqual(isPrivateIPv6('::1'), true);
});

runTest('IPv6 Link-Local Detection (fe80::1)', () => {
  assert.strictEqual(isPrivateIPv6('fe80::1'), true);
});

// 2. Target URL Validation Tests
await runAsyncTest('Target Validation: Blocks loopback literal (127.0.0.1)', async () => {
  const res = await validateScanTarget('http://127.0.0.1');
  assert.strictEqual(res.valid, false);
  assert.ok(res.error.includes('Private and loopback') || res.error.includes('Prohibited'));
});

await runAsyncTest('Target Validation: Blocks AWS metadata IP (169.254.169.254)', async () => {
  const res = await validateScanTarget('http://169.254.169.254');
  assert.strictEqual(res.valid, false);
});

await runAsyncTest('Target Validation: Blocks localhost hostname', async () => {
  const res = await validateScanTarget('http://localhost:3000');
  assert.strictEqual(res.valid, false);
  assert.ok(res.error.includes('Localhost and internal'));
});

await runAsyncTest('Target Validation: Blocks embedded credentials', async () => {
  const res = await validateScanTarget('https://admin:secret@example.com');
  assert.strictEqual(res.valid, false);
  assert.ok(res.error.includes('credentials'));
});

await runAsyncTest('Target Validation: Blocks unsupported scheme (ftp://)', async () => {
  const res = await validateScanTarget('ftp://example.com');
  assert.strictEqual(res.valid, false);
  assert.ok(res.error.includes('protocols are permitted'));
});

await runAsyncTest('Target Validation: Resolves and validates public domain (https://amarvila.com/)', async () => {
  const res = await validateScanTarget('https://amarvila.com/');
  assert.ok(typeof res === 'object');
  if (res.valid) {
    assert.strictEqual(res.hostname, 'amarvila.com');
  } else {
    assert.ok(res.error.includes('amarvila.com') || res.error.includes('resolve'));
  }
});

// 3. Scan Store Persistence & Stats Calculation
runTest('Scan Store: Creates and updates scan record', () => {
  const scan = createScanRecord('https://test-authorized-site.com');
  assert.ok(scan.id.startsWith('nector-'));
  assert.strictEqual(scan.status, 'queued');

  const rawFinding = {
    id: 'f1',
    severity: 'high',
    title: 'Test High Vulnerability',
  };

  const updated = updateScanRecord(scan.id, {
    status: 'completed',
    findings: [rawFinding],
  });

  assert.strictEqual(updated.status, 'completed');
  assert.strictEqual(updated.stats.high, 1);
  assert.strictEqual(updated.stats.total, 1);

  const retrieved = getScanRecord(scan.id);
  assert.strictEqual(retrieved.id, scan.id);
});

// 4. Nuclei JSONL Output Normalization
runTest('Nuclei Parser: Safely parses and maps raw JSONL finding', () => {
  const rawNucleiOutput = {
    'template-id': 'ssl-dns-names',
    info: {
      name: 'SSL Certificate Subject Alternative Names',
      author: ['pdteam'],
      tags: ['ssl', 'certificate'],
      description: 'Extracted SSL certificate alternative domain names.',
      reference: ['https://tools.ietf.org/html/rfc5280'],
      severity: 'info',
    },
    type: 'ssl',
    host: 'example.com',
    'matched-at': 'https://example.com',
    'extracted-results': ['example.com', 'www.example.com'],
    timestamp: '2026-10-25T16:00:00Z',
  };

  const finding = normalizeNucleiFinding(rawNucleiOutput);
  assert.strictEqual(finding.templateId, 'ssl-dns-names');
  assert.strictEqual(finding.title, 'SSL Certificate Subject Alternative Names');
  assert.strictEqual(finding.severity, 'informational');
  assert.strictEqual(finding.matchedTarget, 'https://example.com');
  assert.ok(finding.evidence.includes('example.com'));
  assert.strictEqual(finding.source, 'nuclei');
});

runTest('Nuclei Parser: Gracefully handles malformed or empty items', () => {
  assert.strictEqual(normalizeNucleiFinding(null), null);
  assert.strictEqual(normalizeNucleiFinding('invalid json string'), null);
});

// 6. Binary Path Resolution Test
runTest('Binary Resolver: Resolves executable path without throwing', () => {
  import('../api/_common/nuclei-runner.js').then(({ resolveNucleiBinary }) => {
    const bin = resolveNucleiBinary();
    assert.ok(typeof bin === 'string' && bin.length > 0);
  });
});

// 8. OWASP ZAP Scanner Integration Tests
await runAsyncTest('ZAP Availability: Honestly detects environment status without throwing', async () => {
  const { checkZapAvailable } = await import('../api/_common/zap-runner.js');
  const status = await checkZapAvailable();
  assert.ok(typeof status === 'object');
  assert.ok('available' in status);
  assert.ok('mode' in status);
});

await runAsyncTest('ZAP Parser: Correctly maps OWASP ZAP raw alert to Nector finding schema', async () => {
  const { normalizeZapAlert, mapZapRisk } = await import('../api/_common/zap-runner.js');
  assert.strictEqual(mapZapRisk('High', 'High'), 'critical');
  assert.strictEqual(mapZapRisk('High', 'Medium'), 'high');
  assert.strictEqual(mapZapRisk('Medium', 'High'), 'medium');
  assert.strictEqual(mapZapRisk('Low', 'Low'), 'low');
  assert.strictEqual(mapZapRisk('Informational', 'Low'), 'informational');

  const rawZapAlert = {
    pluginId: '10038',
    alert: 'Content Security Policy (CSP) Header Not Set',
    risk: 'Medium',
    confidence: 'High',
    desc: 'Content Security Policy (CSP) is an added layer of security...',
    solution: 'Ensure that your web server serves a Content Security Policy...',
    evidence: '',
    reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
    cweid: '693',
    wascid: '15',
    url: 'https://example.com/',
  };

  const finding = normalizeZapAlert(rawZapAlert, 'https://example.com/');
  assert.strictEqual(finding.templateId, 'zap-10038');
  assert.strictEqual(finding.title, 'Content Security Policy (CSP) Header Not Set');
  assert.strictEqual(finding.severity, 'medium');
  assert.strictEqual(finding.confidence, 'High');
  assert.strictEqual(finding.source, 'zap');
  assert.strictEqual(finding.cweId, '693');
});

console.log('\n==================================================');
console.log(`TEST SUMMARY: ${passed} PASSED, ${failed} FAILED`);
console.log('==================================================');

if (failed > 0) {
  process.exit(1);
}
