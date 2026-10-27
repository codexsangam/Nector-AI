import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import http from 'node:http';

const ZAP_API_URL = (process.env.ZAP_API_URL || 'http://localhost:8090').replace(/\/+$/, '');
const ZAP_API_KEY = process.env.ZAP_API_KEY || '';
const ZAP_SCAN_TIMEOUT_MS = parseInt(process.env.ZAP_SCAN_TIMEOUT || '120000', 10);
const ZAP_DOCKER_IMAGE = process.env.ZAP_DOCKER_IMAGE || 'ghcr.io/zaproxy/zaproxy:stable';

/**
 * Maps ZAP risk & confidence to Nector's severity ratings.
 */
export function mapZapRisk(risk, confidence) {
  const r = String(risk || '').toLowerCase();
  const c = String(confidence || '').toLowerCase();

  if (r === 'high' || r === '3') {
    return c === 'high' || c === '3' ? 'critical' : 'high';
  }
  if (r === 'medium' || r === '2') return 'medium';
  if (r === 'low' || r === '1') return 'low';
  return 'informational';
}

/**
 * Parse references string or array from ZAP alert.
 */
function parseReferences(ref) {
  if (!ref) return [];
  if (Array.isArray(ref)) return ref;
  return String(ref)
    .split(/[\r\n]+/)
    .map((s) => s.trim())
    .filter((s) => s.startsWith('http://') || s.startsWith('https://'));
}

/**
 * Normalizes an OWASP ZAP alert object into Nector's standard finding schema.
 */
export function normalizeZapAlert(rawAlert, targetUrl = '') {
  if (!rawAlert || typeof rawAlert !== 'object') return null;

  const severity = mapZapRisk(rawAlert.risk, rawAlert.confidence);
  const pluginId = rawAlert.pluginId || rawAlert.alertRef || '';
  const references = parseReferences(rawAlert.reference);

  let evidence = rawAlert.evidence || rawAlert.other || '';
  if (rawAlert.param) {
    evidence = evidence ? `Parameter: ${rawAlert.param} | Evidence: ${evidence}` : `Parameter: ${rawAlert.param}`;
  }

  return {
    id: 'zap-' + Math.random().toString(36).slice(2, 9),
    templateId: pluginId ? `zap-${pluginId}` : 'zap-alert',
    title: rawAlert.alert || rawAlert.name || 'OWASP ZAP Security Observation',
    severity,
    status: 'finding',
    category: rawAlert.category || 'OWASP ZAP Security Check',
    description: rawAlert.desc || rawAlert.description || 'Vulnerability or misconfiguration detected by OWASP ZAP baseline scan.',
    recommendation: rawAlert.solution || 'Review application headers and configurations in accordance with OWASP guidelines.',
    matchedTarget: rawAlert.url || targetUrl,
    evidence: evidence || `Matched URL: ${rawAlert.url || targetUrl}`,
    references,
    cweId: rawAlert.cweid || null,
    wascId: rawAlert.wascid || null,
    confidence: rawAlert.confidence || 'Medium',
    source: 'zap',
    timestamp: new Date().toISOString(),
    aiStatus: 'pending',
    aiExplanation: null,
  };
}

/**
 * Pings the ZAP REST API daemon.
 */
async function pingZapApi() {
  return new Promise((resolve) => {
    try {
      const u = new URL(`${ZAP_API_URL}/JSON/core/view/version/`);
      if (ZAP_API_KEY) u.searchParams.set('apikey', ZAP_API_KEY);

      const req = http.get(u.href, { timeout: 3000 }, (res) => {
        let data = '';
        res.on('data', (d) => { data += d.toString(); });
        res.on('end', () => {
          if (res.statusCode === 200) {
            try {
              const parsed = JSON.parse(data);
              resolve({ available: true, version: parsed.version || 'connected', endpoint: ZAP_API_URL });
            } catch {
              resolve({ available: false, error: 'Malformed response from ZAP API' });
            }
          } else {
            resolve({ available: false, error: `ZAP API returned HTTP ${res.statusCode}` });
          }
        });
      });
      req.on('timeout', () => { req.destroy(); resolve({ available: false, error: 'ZAP API connection timed out' }); });
      req.on('error', (err) => resolve({ available: false, error: err.message }));
    } catch (err) {
      resolve({ available: false, error: err.message });
    }
  });
}

/**
 * Checks if Docker daemon is running and reachable.
 */
async function checkDocker() {
  return new Promise((resolve) => {
    try {
      const proc = spawn('docker', ['--version'], { windowsHide: true });
      let output = '';
      proc.stdout.on('data', (d) => { output += d.toString(); });
      proc.on('error', (err) => resolve({ available: false, error: err.message }));
      proc.on('close', (code) => {
        if (code === 0) {
          resolve({ available: true, version: output.trim() });
        } else {
          resolve({ available: false, error: `Docker exited with code ${code}` });
        }
      });
    } catch (err) {
      resolve({ available: false, error: err.message });
    }
  });
}

/**
 * Check if OWASP ZAP is available in any supported execution mode:
 * 1. ZAP REST API / Daemon (default port 8090)
 * 2. ZAP Docker Baseline Scan container
 * 3. ZAP Local CLI
 */
export async function checkZapAvailable() {
  // 1. Try ZAP REST API daemon
  const apiCheck = await pingZapApi();
  if (apiCheck.available) {
    return {
      available: true,
      mode: 'api',
      version: apiCheck.version,
      endpoint: apiCheck.endpoint,
      error: null,
    };
  }

  // 2. Try Docker baseline scan
  const dockerCheck = await checkDocker();
  if (dockerCheck.available) {
    return {
      available: true,
      mode: 'docker',
      version: dockerCheck.version,
      image: ZAP_DOCKER_IMAGE,
      error: null,
    };
  }

  return {
    available: false,
    mode: 'none',
    version: null,
    error: `OWASP ZAP daemon is not responding at ${ZAP_API_URL} (${apiCheck.error}), and Docker is not available (${dockerCheck.error}).`,
  };
}

/**
 * Executes a scan via the ZAP REST API daemon.
 */
async function runZapViaApi(targetUrl, options = {}) {
  const onFinding = options.onFinding || (() => {});
  const onProgress = options.onProgress || (() => {});

  const apiKeyParam = ZAP_API_KEY ? `&apikey=${encodeURIComponent(ZAP_API_KEY)}` : '';

  // 1. Trigger Spider
  const spiderRes = await fetch(`${ZAP_API_URL}/JSON/spider/action/scan/?url=${encodeURIComponent(targetUrl)}&maxChildren=10&recurse=false${apiKeyParam}`);
  const spiderData = await spiderRes.json();
  const scanId = spiderData.scan;

  // Poll spider status (max 45 seconds)
  const spiderStart = Date.now();
  while (Date.now() - spiderStart < 45000) {
    await new Promise((r) => setTimeout(r, 1500));
    try {
      const stRes = await fetch(`${ZAP_API_URL}/JSON/spider/view/status/?scanId=${encodeURIComponent(scanId)}${apiKeyParam}`);
      const stData = await stRes.json();
      const pct = parseInt(stData.status || '100', 10);
      onProgress(30 + Math.round(pct * 0.3));
      if (pct >= 100) break;
    } catch {
      break;
    }
  }

  // 2. Wait for passive scan records to complete (up to 15 seconds)
  const pscanStart = Date.now();
  while (Date.now() - pscanStart < 15000) {
    await new Promise((r) => setTimeout(r, 1000));
    try {
      const pRes = await fetch(`${ZAP_API_URL}/JSON/pscan/view/recordsToScan/?${apiKeyParam}`);
      const pData = await pRes.json();
      const records = parseInt(pData.recordsToScan || '0', 10);
      if (records <= 0) break;
    } catch {
      break;
    }
  }

  // 3. Fetch alerts
  const alertsRes = await fetch(`${ZAP_API_URL}/JSON/alert/view/alerts/?baseurl=${encodeURIComponent(targetUrl)}${apiKeyParam}`);
  const alertsData = await alertsRes.json();
  const rawAlerts = alertsData.alerts || [];

  const findings = [];
  for (const raw of rawAlerts) {
    const finding = normalizeZapAlert(raw, targetUrl);
    if (finding) {
      findings.push(finding);
      onFinding(finding);
    }
  }

  return {
    success: true,
    findings,
    scannerSource: 'zap',
    mode: 'api',
  };
}

/**
 * Executes a baseline scan via ZAP Docker container.
 * Crucial ZAP Baseline Exit Code Handling:
 * Exit code 0: No warnings or failures.
 * Exit code 1: WARN alerts found (valid alerts in JSON report).
 * Exit code 2: FAIL alerts found (valid alerts in JSON report).
 * Exit code 3: Real execution error.
 */
async function runZapViaDocker(targetUrl, options = {}) {
  const onFinding = options.onFinding || (() => {});
  const tempDir = path.resolve('.nector_data', `zap_tmp_${Date.now()}`);

  try {
    fs.mkdirSync(tempDir, { recursive: true });
  } catch {}

  const reportFileName = 'zap_report.json';
  const reportPath = path.join(tempDir, reportFileName);

  const args = [
    'run', '--rm',
    '-v', `${tempDir}:/zap/wrk/:rw`,
    '-t', ZAP_DOCKER_IMAGE,
    'zap-baseline.py',
    '-t', targetUrl,
    '-J', reportFileName,
    '-d', // detailed debug
  ];

  return new Promise((resolve) => {
    let proc;
    try {
      proc = spawn('docker', args, { windowsHide: true });
    } catch (err) {
      return resolve({
        success: false,
        error: `Failed to spawn Docker process for ZAP: ${err.message}`,
        findings: [],
      });
    }

    let stderr = '';
    proc.stderr.on('data', (d) => { stderr += d.toString(); });

    const timeoutHandle = setTimeout(() => {
      try { proc.kill('SIGTERM'); } catch {}
      resolve({
        success: false,
        error: 'ZAP Docker scan timed out after 120 seconds.',
        findings: [],
        timedOut: true,
      });
    }, ZAP_SCAN_TIMEOUT_MS);

    proc.on('close', (code) => {
      clearTimeout(timeoutHandle);

      // Codes 0, 1, 2 represent valid completed scans with reports!
      if (code === 0 || code === 1 || code === 2) {
        if (fs.existsSync(reportPath)) {
          try {
            const rawContent = fs.readFileSync(reportPath, 'utf-8');
            const parsed = JSON.parse(rawContent);
            const siteArray = parsed.site || [];
            const findings = [];

            for (const s of siteArray) {
              const alerts = s.alerts || [];
              for (const a of alerts) {
                const normalized = normalizeZapAlert(a, targetUrl);
                if (normalized) {
                  findings.push(normalized);
                  onFinding(normalized);
                }
              }
            }

            // Cleanup temp dir
            try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch {}

            return resolve({
              success: true,
              findings,
              scannerSource: 'zap',
              mode: 'docker',
              exitCode: code,
            });
          } catch (parseErr) {
            return resolve({
              success: false,
              error: `Failed to parse ZAP JSON report: ${parseErr.message}`,
              findings: [],
            });
          }
        }
      }

      // Cleanup temp dir
      try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch {}

      resolve({
        success: false,
        error: stderr.trim() || `ZAP Docker execution failed with code ${code}`,
        findings: [],
      });
    });
  });
}

/**
 * Main entry point for OWASP ZAP scanning in Nector.
 */
export async function runZapScan(targetUrl, options = {}) {
  const check = await checkZapAvailable();

  if (!check.available) {
    return {
      success: false,
      installed: false,
      error: check.error,
      findings: [],
    };
  }

  if (check.mode === 'api') {
    return runZapViaApi(targetUrl, options);
  }

  if (check.mode === 'docker') {
    return runZapViaDocker(targetUrl, options);
  }

  return {
    success: false,
    installed: false,
    error: 'No compatible ZAP execution mode available.',
    findings: [],
  };
}

export default {
  checkZapAvailable,
  runZapScan,
  normalizeZapAlert,
  mapZapRisk,
};
