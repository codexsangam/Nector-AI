/**
 * Sample data for the demo report section — purely illustrative.
 * None of this reflects a real scan of any website.
 */

export type Severity = "Medium" | "Low";

export interface DemoFinding {
  id: string;
  title: string;
  severity: Severity;
  /** Plain-language description of what the issue is and why it matters. */
  explanation: string;
  /** What a scanner would show as evidence for this issue. */
  evidence: string;
  /** Practical next step to fix it. */
  recommendation: string;
}

export const DEMO_TARGET = "demo.nector.test";

export const demoFindings: DemoFinding[] = [
  {
    id: "missing-csp",
    title: "Missing Content-Security-Policy",
    severity: "Medium",
    explanation:
      "The site sends no Content-Security-Policy header. Without one, the browser has no extra rules limiting which scripts can run, so injected code has more room to act.",
    evidence: 'Response headers for / contain no Content-Security-Policy header.',
    recommendation:
      "Add a Content-Security-Policy header. Start with a report-only policy that allows yourself, then tighten it to restrict script and style sources before enforcing it.",
  },
  {
    id: "sample-cookie-httponly",
    title: "Missing HttpOnly attribute on a sample session cookie",
    severity: "Medium",
    explanation:
      "A session cookie is set without the HttpOnly attribute, so scripts running in the page could read it. If any scripting flaw exists, that raises the impact.",
    evidence:
      'Set-Cookie: session=30d1c9… (sample session id) lacks both HttpOnly and Secure attributes.',
    recommendation:
      "Set HttpOnly and Secure on session cookies, and consider the SameSite attribute as well. No real cookie from a live site was collected here.",
  },
  {
    id: "server-version",
    title: "Server version disclosure",
    severity: "Low",
    explanation:
      "The server announces its exact software version in responses. That information makes it easier for attackers to look up known vulnerabilities for that specific version.",
    evidence: "Server: nginx/1.18.0 (example build shown for illustration).",
    recommendation:
      "Turn off version banners in the server configuration so responses no longer advertise the exact software version.",
  },
];
