import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import readline from 'node:readline';

const SCAN_TIMEOUT_MS = parseInt(process.env.NECTOR_SCAN_TIMEOUT || '90000', 10); // 90 seconds max

/**
 * Resolves the path to the Nuclei binary, checking environment variables,
 * default PATH, and common Windows locations (Go bin, WinGet, Chocolatey).
 */
export function resolveNucleiBinary() {
  if (process.env.NECTOR_NUCLEI_PATH) {
    try {
      if (fs.existsSync(process.env.NECTOR_NUCLEI_PATH)) {
        return process.env.NECTOR_NUCLEI_PATH;
      }
    } catch {}
  }

  const isWin = process.platform === 'win32';
  if (isWin) {
    const userProfile = process.env.USERPROFILE || '';
    const localAppData = process.env.LOCALAPPDATA || '';
    const candidates = [
      path.join(userProfile, 'go', 'bin', 'nuclei.exe'),
      path.join(localAppData, 'Microsoft', 'WinGet', 'Links', 'nuclei.exe'),
      'C:\\tools\\nuclei\\nuclei.exe',
      'C:\\ProgramData\\chocolatey\\bin\\nuclei.exe',
    ];

    for (const candidate of candidates) {
      try {
        if (fs.existsSync(candidate)) {
          return candidate;
        }
      } catch {}
    }
    return 'nuclei.exe';
  }

  return 'nuclei';
}

/**
 * Check if the Nuclei executable is available in PATH or at NECTOR_NUCLEI_PATH.
 */
export async function checkNucleiAvailable() {
  const binary = resolveNucleiBinary();
  return new Promise((resolve) => {
    try {
      const proc = spawn(binary, ['-version'], { windowsHide: true });
      let output = '';

      proc.stdout.on('data', (d) => { output += d.toString(); });
      proc.stderr.on('data', (d) => { output += d.toString(); });

      proc.on('error', (err) => {
        resolve({ available: false, error: err.message, version: null, binary });
      });

      proc.on('close', (code) => {
        if (code === 0 || output.toLowerCase().includes('nuclei')) {
          const match = output.match(/v\d+\.\d+\.\d+/);
          resolve({ available: true, version: match ? match[0] : 'installed', error: null, binary });
        } else {
          resolve({ available: false, error: `Exited with code ${code}`, version: null, binary });
        }
      });
    } catch (err) {
      resolve({ available: false, error: err.message, version: null, binary });
    }
  });
}

/**
 * Normalizes a raw JSON finding line from Nuclei JSONL stream.
 */
export function normalizeNucleiFinding(rawItem) {
  if (!rawItem || typeof rawItem !== 'object') return null;

  const info = rawItem.info || {};
  let rawSeverity = String(info.severity || rawItem.type || 'info').toLowerCase();
  if (rawSeverity === 'info') rawSeverity = 'informational';

  const validSeverities = ['critical', 'high', 'medium', 'low', 'informational'];
  const severity = validSeverities.includes(rawSeverity) ? rawSeverity : 'informational';

  let evidence = '';
  if (rawItem['extracted-results'] && rawItem['extracted-results'].length > 0) {
    evidence = Array.isArray(rawItem['extracted-results'])
      ? rawItem['extracted-results'].join(', ')
      : String(rawItem['extracted-results']);
  } else if (rawItem['matcher-name']) {
    evidence = `Matched rule: ${rawItem['matcher-name']}`;
  } else if (rawItem['curl-command']) {
    evidence = rawItem['curl-command'];
  }

  const references = Array.isArray(info.reference)
    ? info.reference
    : info.reference ? [info.reference] : [];

  return {
    id: 'nuc-' + Math.random().toString(36).slice(2, 9),
    templateId: rawItem['template-id'] || 'custom-check',
    title: info.name || rawItem['template-id'] || 'Detected Security Observation',
    severity,
    status: 'finding',
    category: info.tags ? (Array.isArray(info.tags) ? info.tags.join(', ') : String(info.tags)) : 'Vulnerability',
    description: info.description || 'Observed security exposure or misconfiguration during template check.',
    matchedTarget: rawItem['matched-at'] || rawItem.host || '',
    evidence,
    references,
    source: 'nuclei',
    timestamp: rawItem.timestamp || new Date().toISOString(),
    aiStatus: 'pending',
    aiExplanation: null,
  };
}

/**
 * Executes a controlled, safe Nuclei scan against the validated target URL.
 * Emits progress callbacks as findings arrive.
 */
export async function runNucleiScan(targetUrl, options = {}) {
  const onFinding = options.onFinding || (() => {});
  const onProgress = options.onProgress || (() => {});

  const check = await checkNucleiAvailable();
  if (!check.available) {
    return {
      success: false,
      error: `Nuclei scanner is not available: ${check.error}. Please install Nuclei (https://docs.projectdiscovery.io/tools/nuclei/install) and ensure it is in PATH.`,
      findings: [],
      installed: false,
    };
  }

  return new Promise((resolve) => {
    // Safe non-destructive template tags: ssl, dns, tech, exposure, misconfiguration
    // Strictly avoiding destructive, dos, fuzzing, or intrusive exploits
    const args = [
      '-target', targetUrl,
      '-tags', 'ssl,dns,tech,exposure,misconfiguration',
      '-severity', 'info,low,medium,high,critical',
      '-jsonl',
      '-silent',
      '-no-interactsh', // Defensive posture: avoid outbound third-party callback testing
      '-timeout', '10',
      '-rate-limit', '25',
    ];

    let proc;
    const binary = check.binary || resolveNucleiBinary();
    try {
      proc = spawn(binary, args, { windowsHide: true });
    } catch (err) {
      return resolve({
        success: false,
        error: `Failed to spawn Nuclei process: ${err.message}`,
        findings: [],
        installed: true,
      });
    }

    const findings = [];
    let stderrOutput = '';

    const rl = readline.createInterface({
      input: proc.stdout,
      terminal: false,
    });

    rl.on('line', (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      try {
        const jsonItem = JSON.parse(trimmed);
        const finding = normalizeNucleiFinding(jsonItem);
        if (finding) {
          findings.push(finding);
          onFinding(finding);
        }
      } catch {
        // Not a JSON line, ignore banner or informational text
      }
    });

    proc.stderr.on('data', (d) => {
      stderrOutput += d.toString();
    });

    const timeoutHandle = setTimeout(() => {
      try {
        proc.kill('SIGTERM');
      } catch {}
      resolve({
        success: findings.length > 0, // partial results preserved
        error: 'Scan timed out before full completion. Partial results preserved.',
        findings,
        installed: true,
        timedOut: true,
      });
    }, SCAN_TIMEOUT_MS);

    proc.on('error', (err) => {
      clearTimeout(timeoutHandle);
      resolve({
        success: false,
        error: `Scanner execution error: ${err.message}`,
        findings,
        installed: true,
      });
    });

    proc.on('close', (code) => {
      clearTimeout(timeoutHandle);
      if (code === 0 || findings.length > 0) {
        resolve({
          success: true,
          findings,
          installed: true,
          error: null,
        });
      } else {
        resolve({
          success: false,
          error: stderrOutput.trim() || `Nuclei exited with status ${code}`,
          findings,
          installed: true,
        });
      }
    });
  });
}

export default {
  checkNucleiAvailable,
  normalizeNucleiFinding,
  runNucleiScan,
};
