import { validateScanTarget } from './validate-target.js';
import {
  createScanRecord,
  updateScanRecord,
  getScanRecord,
  listScanRecords,
} from './scan-store.js';
import { runZapScan, checkZapAvailable } from './zap-runner.js';
import { runNucleiScan, checkNucleiAvailable } from './nuclei-runner.js';
import { runBuiltinAudit } from './builtin-scanner.js';
import { explainFindingWithGemini, getGeminiConfig } from './gemini-explainer.js';

// Concurrency queue to prevent process exhaustion
const activeScans = new Set();
const MAX_CONCURRENT_SCANS = parseInt(process.env.NECTOR_MAX_CONCURRENCY || '2', 10);

/**
 * Initiates an authorized scan job.
 * Validates the target and queues the background execution immediately.
 */
export async function queueScan(rawUrl) {
  // 1. Target validation and SSRF guardrails
  const validation = await validateScanTarget(rawUrl);
  if (!validation.valid) {
    return {
      success: false,
      error: validation.error,
    };
  }

  // 2. Concurrency check
  if (activeScans.size >= MAX_CONCURRENT_SCANS) {
    return {
      success: false,
      error: 'Scanner is currently at peak capacity. Please wait a moment for ongoing scans to complete.',
    };
  }

  // 3. Create scan record
  const scan = createScanRecord(validation.normalizedUrl);

  // 4. Fire background runner (non-blocking)
  executeScanJob(scan.id, validation.normalizedUrl).catch((err) => {
    console.error(`Unhandled error in scan job ${scan.id}:`, err);
    updateScanRecord(scan.id, {
      status: 'failed',
      error: err.message || 'An unexpected error occurred during scan execution.',
    });
    activeScans.delete(scan.id);
  });

  return {
    success: true,
    scanId: scan.id,
    target: validation.normalizedUrl,
    status: scan.status,
  };
}

/**
 * Background worker executing the complete scanner -> Gemini pipeline.
 */
async function executeScanJob(scanId, targetUrl) {
  activeScans.add(scanId);
  const startedAt = Date.now();

  try {
    // Stage 1: Initializing
    updateScanRecord(scanId, {
      status: 'running',
      stage: 'Starting vulnerability checks',
      progress: 15,
    });

    let rawFindings = [];
    let scannerSource = 'zap';
    let nucleiNotice = null;

    // Check OWASP ZAP availability first
    const zapStatus = await checkZapAvailable();

    if (zapStatus.available) {
      scannerSource = 'zap';
      updateScanRecord(scanId, {
        stage: `Running OWASP ZAP scan (${zapStatus.mode === 'api' ? 'Daemon ' + zapStatus.version : 'Docker Container'})`,
        progress: 30,
        scannerSource: 'zap',
        scannerVersion: zapStatus.version,
      });

      const zapResult = await runZapScan(targetUrl, {
        onFinding: (finding) => {
          const current = getScanRecord(scanId);
          if (current) {
            const updatedFindings = [...current.findings, finding];
            updateScanRecord(scanId, {
              findings: updatedFindings,
              progress: Math.min(75, 30 + updatedFindings.length * 5),
            });
          }
        },
      });

      rawFindings = zapResult.findings || [];
    } else {
      // ZAP daemon or Docker not running in current environment: check Nuclei
      const nucleiStatus = await checkNucleiAvailable();

      if (nucleiStatus.available) {
        scannerSource = 'nuclei';
        nucleiNotice = 'OWASP ZAP daemon not detected on port 8090. Scan executed via ProjectDiscovery Nuclei. To run ZAP: docker run -u zap -p 8090:8090 -d ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.disablekey=true';
        updateScanRecord(scanId, {
          stage: `Running Nuclei vulnerability checks (${nucleiStatus.version})`,
          progress: 30,
          scannerSource: 'nuclei',
          scannerVersion: nucleiStatus.version,
          nucleiNotice,
        });

        const scanResult = await runNucleiScan(targetUrl, {
          onFinding: (finding) => {
            const current = getScanRecord(scanId);
            if (current) {
              const updatedFindings = [...current.findings, finding];
              updateScanRecord(scanId, {
                findings: updatedFindings,
                progress: Math.min(75, 30 + updatedFindings.length * 5),
              });
            }
          },
        });

        rawFindings = scanResult.findings || [];
      } else {
        // Run Nector Built-in Security Engine
        scannerSource = 'builtin';
        nucleiNotice = 'OWASP ZAP daemon is not responding on port 8090, and Docker is not available. Scan completed using Nector Built-in Security Engine. To enable real OWASP ZAP scanning: start ZAP daemon or run with Docker.';

        updateScanRecord(scanId, {
          stage: 'Running Nector Built-in Security Engine (ZAP daemon not in environment)',
          progress: 35,
          scannerSource,
          nucleiNotice,
        });

        const builtinResult = await runBuiltinAudit(targetUrl, {
          onFinding: (finding) => {
            const current = getScanRecord(scanId);
            if (current) {
              const updatedFindings = [...current.findings, finding];
              updateScanRecord(scanId, {
                findings: updatedFindings,
                progress: Math.min(75, 35 + updatedFindings.length * 6),
              });
            }
          },
        });

        if (!builtinResult.success && (!builtinResult.findings || builtinResult.findings.length === 0)) {
          updateScanRecord(scanId, {
            status: 'failed',
            stage: 'Assessment failed',
            progress: 100,
            completedAt: new Date().toISOString(),
            durationMs: Date.now() - startedAt,
            error: builtinResult.error || 'Failed to reach website target.',
          });
          activeScans.delete(scanId);
          return;
        }

        rawFindings = builtinResult.findings || [];
      }
    }

    // Stage 3: Gemini AI Remediation Guidance
    const geminiConfig = getGeminiConfig();
    updateScanRecord(scanId, {
      findings: rawFindings,
      stage: geminiConfig.isConfigured
        ? 'Synthesizing AI remediation guidance with Google Gemini'
        : 'Scan completed (Gemini AI unconfigured)',
      progress: 80,
      aiStatus: geminiConfig.isConfigured ? 'analyzing' : 'unconfigured',
    });

    const enrichedFindings = [];
    for (let i = 0; i < rawFindings.length; i++) {
      const f = rawFindings[i];
      if (geminiConfig.isConfigured) {
        updateScanRecord(scanId, {
          stage: `Synthesizing AI remediation for finding ${i + 1} of ${rawFindings.length}`,
          progress: 80 + Math.round(((i + 1) / rawFindings.length) * 18),
        });

        try {
          const aiRes = await explainFindingWithGemini(f);
          if (aiRes.success) {
            enrichedFindings.push({
              ...f,
              aiStatus: 'completed',
              aiExplanation: aiRes.explanation,
            });
          } else {
            enrichedFindings.push({
              ...f,
              aiStatus: 'failed',
              aiExplanation: null,
              aiError: aiRes.error,
            });
          }
        } catch (err) {
          enrichedFindings.push({
            ...f,
            aiStatus: 'failed',
            aiExplanation: null,
            aiError: err.message,
          });
        }
      } else {
        enrichedFindings.push({
          ...f,
          aiStatus: 'unconfigured',
          aiExplanation: null,
        });
      }
    }

    // Stage 4: Scan Finalization
    const durationMs = Date.now() - startedAt;
    const isTimedOut = Boolean(typeof scanResult !== 'undefined' && scanResult && scanResult.timedOut);
    const finalStatus = isTimedOut ? 'partial' : 'completed';

    updateScanRecord(scanId, {
      status: finalStatus,
      stage: finalStatus === 'partial' ? 'Scan timed out (partial results)' : 'Assessment complete',
      progress: 100,
      completedAt: new Date().toISOString(),
      durationMs,
      findings: enrichedFindings,
      aiStatus: geminiConfig.isConfigured ? 'completed' : 'unconfigured',
      scannerSource,
      nucleiNotice,
      error: isTimedOut ? (scanResult?.error || 'Scan timed out') : null,
    });
  } catch (err) {
    updateScanRecord(scanId, {
      status: 'failed',
      stage: 'Scan encountered an error',
      progress: 100,
      completedAt: new Date().toISOString(),
      durationMs: Date.now() - startedAt,
      error: err.message,
    });
  } finally {
    activeScans.delete(scanId);
  }
}

/**
 * Retries Gemini explanation for a single finding or all unanalyzed findings.
 */
export async function retryAiExplanation(scanId, findingId = null) {
  const scan = getScanRecord(scanId);
  if (!scan) return { success: false, error: 'Scan not found.' };

  const geminiConfig = getGeminiConfig();
  if (!geminiConfig.isConfigured) {
    return {
      success: false,
      error: 'GEMINI_API_KEY environment variable is still unconfigured.',
    };
  }

  const updatedFindings = [...scan.findings];
  let updatedCount = 0;

  for (let i = 0; i < updatedFindings.length; i++) {
    const f = updatedFindings[i];
    if (findingId && f.id !== findingId) continue;
    if (f.aiStatus === 'completed') continue;

    const res = await explainFindingWithGemini(f);
    if (res.success) {
      updatedFindings[i] = {
        ...f,
        aiStatus: 'completed',
        aiExplanation: res.explanation,
        aiError: null,
      };
      updatedCount++;
    } else {
      updatedFindings[i] = {
        ...f,
        aiStatus: 'failed',
        aiError: res.error,
      };
    }
  }

  updateScanRecord(scanId, {
    findings: updatedFindings,
    aiStatus: updatedFindings.every((f) => f.aiStatus === 'completed') ? 'completed' : 'partial',
  });

  return {
    success: true,
    updatedCount,
    scan: getScanRecord(scanId),
  };
}

export default {
  queueScan,
  getScan: getScanRecord,
  listScans: listScanRecords,
  retryAiExplanation,
};
