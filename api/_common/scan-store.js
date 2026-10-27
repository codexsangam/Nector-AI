import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.resolve(__dirname, '../../.nector_data/scans');

// Ensure storage directory exists
try {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
} catch (e) {
  console.warn('Could not create scan data directory:', e.message);
}

// In-memory cache for fast lookups
const inMemoryScans = new Map();

// Load existing scans from disk on startup
try {
  if (fs.existsSync(DATA_DIR)) {
    const files = fs.readdirSync(DATA_DIR).filter((f) => f.endsWith('.json'));
    for (const file of files) {
      try {
        const raw = fs.readFileSync(path.join(DATA_DIR, file), 'utf-8');
        const scan = JSON.parse(raw);
        if (scan && scan.id) {
          inMemoryScans.set(scan.id, scan);
        }
      } catch {
        // Skip corrupted files
      }
    }
  }
} catch (e) {
  console.warn('Error loading cached scans:', e.message);
}

function persistScanToDisk(scan) {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    const filePath = path.join(DATA_DIR, `${scan.id}.json`);
    fs.writeFileSync(filePath, JSON.stringify(scan, null, 2), 'utf-8');
  } catch (err) {
    console.error(`Failed to persist scan ${scan.id} to disk:`, err.message);
  }
}

export function createScanRecord(targetUrl) {
  const scanId = 'nector-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  const now = new Date().toISOString();

  const scan = {
    id: scanId,
    target: targetUrl,
    status: 'queued', // queued | running | completed | failed | partial
    stage: 'Target validation',
    progress: 5,
    startedAt: now,
    completedAt: null,
    durationMs: 0,
    findings: [],
    stats: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0,
      total: 0,
    },
    scannerSource: 'nuclei',
    aiStatus: 'pending', // pending | analyzing | completed | failed | unconfigured
    error: null,
  };

  inMemoryScans.set(scanId, scan);
  persistScanToDisk(scan);
  return scan;
}

export function updateScanRecord(scanId, patch) {
  const existing = inMemoryScans.get(scanId);
  if (!existing) return null;

  const updated = {
    ...existing,
    ...patch,
  };

  if (patch.findings) {
    // Recalculate stats based on normalized findings
    const stats = { critical: 0, high: 0, medium: 0, low: 0, informational: 0, total: 0 };
    for (const f of patch.findings) {
      const sev = (f.severity || 'informational').toLowerCase();
      if (stats[sev] !== undefined) {
        stats[sev]++;
      } else {
        stats.informational++;
      }
      stats.total++;
    }
    updated.stats = stats;
  }

  inMemoryScans.set(scanId, updated);
  persistScanToDisk(updated);
  return updated;
}

export function getScanRecord(scanId) {
  return inMemoryScans.get(scanId) || null;
}

export function listScanRecords(limit = 20) {
  const all = Array.from(inMemoryScans.values());
  all.sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt));
  return all.slice(0, limit);
}

export default {
  createScanRecord,
  updateScanRecord,
  getScanRecord,
  listScanRecords,
};
