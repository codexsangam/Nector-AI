import http from 'node:http';
import https from 'node:https';
import { URL } from 'node:url';

/**
 * Built-in Security & Vulnerability Auditor for Nector.
 * Provides resilient, zero-dependency active security evaluation when Nuclei
 * CLI binary is not present in the host environment.
 */
export async function runBuiltinAudit(targetUrl, options = {}) {
  const onFinding = options.onFinding || (() => {});
  const findings = [];

  function addFinding(f) {
    const finding = {
      id: 'nct-' + Math.random().toString(36).slice(2, 9),
      templateId: f.templateId || 'builtin-check',
      title: f.title,
      severity: f.severity || 'low',
      status: 'finding',
      category: f.category || 'Security Configuration',
      description: f.description,
      matchedTarget: targetUrl,
      evidence: f.evidence || '',
      references: f.references || [],
      source: 'builtin',
      timestamp: new Date().toISOString(),
      aiStatus: 'pending',
      aiExplanation: null,
    };
    findings.push(finding);
    onFinding(finding);
  }

  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return { success: false, findings: [], error: 'Invalid URL format' };
  }

  // 1. Fetch root page response headers
  let respHeaders = {};
  let statusCode = 0;
  let isHttps = parsed.protocol === 'https:';

  try {
    const res = await new Promise((resolve, reject) => {
      const client = isHttps ? https : http;
      const req = client.get(
        targetUrl,
        {
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) NectorSecurityScanner/2.0',
            Accept: '*/*',
          },
          timeout: 12000,
          rejectUnauthorized: false, // examine cert without aborting check
        },
        (r) => {
          respHeaders = r.headers || {};
          statusCode = r.statusCode || 0;
          r.resume();
          resolve(r);
        }
      );
      req.on('timeout', () => { req.destroy(); reject(new Error('Connection timed out')); });
      req.on('error', reject);
    });
  } catch (err) {
    return {
      success: false,
      findings: [],
      error: `Could not connect to target host: ${err.message}`,
    };
  }

  // 2. HTTPS & HSTS Evaluation
  if (!isHttps) {
    addFinding({
      templateId: 'insecure-http-transport',
      title: 'Target Communicating Over Insecure HTTP',
      severity: 'high',
      category: 'Transport Security',
      description: 'The target website is accessible over unencrypted HTTP, allowing network eavesdropping and traffic tampering.',
      evidence: `Scheme: ${parsed.protocol}`,
      references: ['https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security'],
    });
  } else {
    const hsts = respHeaders['strict-transport-security'];
    if (!hsts) {
      addFinding({
        templateId: 'missing-hsts-header',
        title: 'Missing HTTP Strict Transport Security (HSTS)',
        severity: 'medium',
        category: 'Transport Security',
        description: 'The server does not enforce HTTPS connections using the Strict-Transport-Security header, leaving users vulnerable to SSL stripping attacks.',
        evidence: 'Strict-Transport-Security header is not served.',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html'],
      });
    } else {
      const lowerHsts = String(hsts).toLowerCase();
      const maxAgeMatch = lowerHsts.match(/max-age=(\d+)/);
      const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
      if (maxAge < 10886400) {
        addFinding({
          templateId: 'weak-hsts-max-age',
          title: 'HSTS max-age Duration Is Below Best Practices',
          severity: 'low',
          category: 'Transport Security',
          description: `The HSTS max-age directive is set to ${maxAge} seconds, below the recommended 10,886,400 seconds (126 days) or 1 year.`,
          evidence: `Strict-Transport-Security: ${hsts}`,
          references: ['https://hstspreload.org/'],
        });
      }
    }
  }

  // 3. Content Security Policy (CSP)
  const csp = respHeaders['content-security-policy'];
  if (!csp) {
    addFinding({
      templateId: 'missing-content-security-policy',
      title: 'Missing Content Security Policy (CSP)',
      severity: 'medium',
      category: 'Security Headers',
      description: 'No Content-Security-Policy header was detected. CSP restricts where scripts, styles, and other resources can load from, preventing Cross-Site Scripting (XSS).',
      evidence: 'Content-Security-Policy header is absent.',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'],
    });
  }

  // 4. Anti-Clickjacking: X-Frame-Options / CSP frame-ancestors
  const xfo = respHeaders['x-frame-options'];
  const hasFrameAncestors = csp && /frame-ancestors/i.test(csp);
  if (!xfo && !hasFrameAncestors) {
    addFinding({
      templateId: 'missing-anti-clickjacking-protection',
      title: 'Missing Anti-Clickjacking Header (X-Frame-Options)',
      severity: 'low',
      category: 'Security Headers',
      description: 'Neither X-Frame-Options nor CSP frame-ancestors was observed. Malicious websites may be able to embed this page in a hidden iframe to manipulate user clicks.',
      evidence: 'X-Frame-Options and frame-ancestors are absent.',
      references: ['https://owasp.org/www-community/attacks/Clickjacking'],
    });
  }

  // 5. MIME-Sniffing: X-Content-Type-Options
  const xcto = respHeaders['x-content-type-options'];
  if (!xcto || !String(xcto).toLowerCase().includes('nosniff')) {
    addFinding({
      templateId: 'missing-x-content-type-options',
      title: 'Missing X-Content-Type-Options Header',
      severity: 'low',
      category: 'Security Headers',
      description: 'The response does not specify "X-Content-Type-Options: nosniff", allowing legacy browsers to misinterpret file content types and execute script in non-script files.',
      evidence: `X-Content-Type-Options: ${xcto || 'none'}`,
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'],
    });
  }

  // 6. Technology & Version Disclosure
  const serverHeader = respHeaders['server'];
  if (serverHeader && /\d+\.\d+/.test(serverHeader)) {
    addFinding({
      templateId: 'detailed-server-version-leak',
      title: 'Server Banner Discloses Version Information',
      severity: 'informational',
      category: 'Information Disclosure',
      description: 'The Server response header discloses specific web server software and version numbers, helping attackers identify version-specific exploits.',
      evidence: `Server: ${serverHeader}`,
      references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server'],
    });
  }

  const poweredBy = respHeaders['x-powered-by'];
  if (poweredBy) {
    addFinding({
      templateId: 'x-powered-by-disclosure',
      title: 'Application Framework Disclosure (X-Powered-By)',
      severity: 'informational',
      category: 'Information Disclosure',
      description: 'The X-Powered-By header advertises backend framework and language technologies (e.g. Express, PHP, ASP.NET).',
      evidence: `X-Powered-By: ${poweredBy}`,
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html'],
    });
  }

  // 7. Cookie Security Attributes
  const rawCookies = respHeaders['set-cookie'];
  if (rawCookies) {
    const cookieArray = Array.isArray(rawCookies) ? rawCookies : [rawCookies];
    for (const cookieStr of cookieArray) {
      const lower = cookieStr.toLowerCase();
      const cookieName = cookieStr.split('=')[0].trim();
      const missing = [];
      if (isHttps && !lower.includes('secure')) missing.push('Secure');
      if (!lower.includes('httponly')) missing.push('HttpOnly');
      if (!lower.includes('samesite')) missing.push('SameSite');

      if (missing.length > 0) {
        addFinding({
          templateId: 'insecure-cookie-attributes',
          title: `Cookie "${cookieName}" Missing Security Attributes (${missing.join(', ')})`,
          severity: missing.includes('Secure') || missing.includes('HttpOnly') ? 'medium' : 'low',
          category: 'Session Security',
          description: `The cookie "${cookieName}" is set without one or more essential defense flags (${missing.join(', ')}), increasing susceptibility to interception or cross-site theft.`,
          evidence: `Set-Cookie: ${cookieStr.slice(0, 120)}...`,
          references: ['https://owasp.org/www-community/controls/SecureFlag'],
        });
      }
    }
  }

  // 8. Security.txt Discovery Check
  try {
    const secUrl = `${parsed.protocol}//${parsed.host}/.well-known/security.txt`;
    const secRes = await new Promise((resolve) => {
      const client = isHttps ? https : http;
      const req = client.get(secUrl, { timeout: 6000, rejectUnauthorized: false }, (r) => {
        r.resume();
        resolve(r.statusCode === 200);
      });
      req.on('error', () => resolve(false));
      req.on('timeout', () => { req.destroy(); resolve(false); });
    });

    if (!secRes) {
      addFinding({
        templateId: 'missing-security-txt',
        title: 'Security Vulnerability Disclosure Policy Missing (security.txt)',
        severity: 'informational',
        category: 'Vulnerability Disclosure',
        description: 'No RFC 9116 security.txt file was found at /.well-known/security.txt. Publishing this file helps white-hat researchers responsibly report vulnerabilities to your team.',
        evidence: 'Queried: /.well-known/security.txt (Returned 404 or connection failed)',
        references: ['https://rfc-editor.org/rfc/rfc9116.html'],
      });
    }
  } catch {}

  return {
    success: true,
    findings,
    scannerSource: 'builtin',
  };
}

export default {
  runBuiltinAudit,
};
