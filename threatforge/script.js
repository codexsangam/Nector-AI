/* ============================================================
   Nector — script.js
   Vanilla JS frontend for the existing Web-Check backend.

   The backend (server.js) auto-registers every handler in api/
   as a GET route: /api/<check>?url=<target>. This frontend calls
   those EXISTING endpoints only. No backend logic lives here,
   and no mock data is used — every finding is derived from the
   real responses returned by the running server.
   ============================================================ */

(function () {
  "use strict";

  // Clickjacking guard: never render this page inside someone else's frame.
  // (serve.mjs also sends X-Frame-Options: DENY + frame-ancestors 'none';
  // this is the fallback for hosts that cannot set headers.)
  try {
    if (window.top !== window.self) {
      document.documentElement.style.display = "none";
      window.top.location = window.self.location;
    }
  } catch (err) {
    // Cross-origin frame: we cannot bust out, so refuse to render at all
    document.documentElement.style.display = "none";
  }

  // Reveal animations only hide content when JS is confirmed running
  document.documentElement.classList.add("js");

  /* ---------------- Configuration ---------------- */

  // API base resolution:
  //   1. ?api= query parameter (e.g. index.html?api=http://localhost:3000)
  //   2. same origin, when this page is served by the backend itself
  //   3. http://localhost:3000 (the existing `node server.js` default)
  const params = new URLSearchParams(window.location.search);
  const API_BASE = (function () {
    const explicit = params.get("api");
    if (explicit) return explicit.replace(/\/+$/, "");
    if (location.origin.startsWith("http") && (location.port === "3000" || location.port === "")) return "";
    return "http://localhost:3000";
  })();

  const REQUEST_TIMEOUT_MS = 45000;

  const CHECKS = [
    { key: "status", endpoint: "status", stage: 0 },
    { key: "redirects", endpoint: "redirects", stage: 0 },
    { key: "ssl", endpoint: "ssl", stage: 1 },
    { key: "hsts", endpoint: "hsts", stage: 1 },
    { key: "headers", endpoint: "headers", stage: 2 },
    { key: "cookies", endpoint: "cookies", stage: 3 },
    { key: "securityTxt", endpoint: "security-txt", stage: 4 },
  ];

  const STAGES = [
    { label: "Validating website target" },
    { label: "Running vulnerability checks" },
    { label: "Analyzing security findings" },
    { label: "Synthesizing AI remediation guidance" },
    { label: "Compiling assessment report" },
  ];

  // Progress ranges per stage, so the bar moves with real work
  const STAGE_RANGES = [
    [0, 20],
    [20, 60],
    [60, 75],
    [75, 95],
    [95, 100],
  ];

  const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
  const SEVERITY_DEDUCTION = { critical: 25, high: 15, medium: 8, low: 3, informational: 0 };

  /* ---------------- Small helpers ---------------- */

  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.prototype.slice.call((root || document).querySelectorAll(sel));

  const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

  const SVG_CHECK = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 13l4 4L19 7"/></svg>';
  const SVG_ALERT = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 6v7M12 17h.01"/></svg>';
  const SVG_DASH = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 12h12"/></svg>';
  const SVG_CHEVRON = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 9l6 6 6-6"/></svg>';

  // Status dot / badge classes per severity
  const SEVERITY_CLASS = {
    critical: "badge-critical",
    high: "badge-high",
    medium: "badge-medium",
    low: "badge-low",
    informational: "badge-informational",
  };

  function severityBadgeClass(sev) {
    return SEVERITY_CLASS[sev] || "badge-informational";
  }

  // "Low" uses the passed/safe tone per design rules
  function badgeClassFor(finding) {
    if (finding.status === "passed") return "badge-pass";
    if (finding.severity === "low") return "badge-low";
    return severityBadgeClass(finding.severity);
  }

  function severityDotClass(finding) {
    switch (finding.severity) {
      case "critical": return "dot-critical";
      case "high": return "dot-high";
      case "medium": return "dot-medium";
      case "low": return "dot-safe";
      default: return "dot-info";
    }
  }

  function statusIconFor(finding) {
    const span = document.createElement("span");
    span.className = "finding-status-icon";
    if (finding.status === "passed") {
      span.style.background = "var(--safe)";
      span.innerHTML = SVG_CHECK;
    } else if (finding.status === "skipped") {
      span.style.background = "var(--border-strong)";
      span.innerHTML = SVG_DASH;
    } else if (finding.status === "informational") {
      span.style.background = "var(--info)";
      span.innerHTML = SVG_DASH;
    } else {
      span.style.background = finding.severity === "critical" || finding.severity === "high"
        ? "var(--high)" : "var(--medium)";
      span.innerHTML = SVG_ALERT;
    }
    return span;
  }

  function badge(text, cls) {
    const el = document.createElement("span");
    el.className = "badge " + cls;
    el.textContent = text;
    return el;
  }

  function severityLabel(finding) {
    if (finding.status === "passed") return "Passed";
    if (finding.status === "skipped") return "Skipped";
    return finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1);
  }

  function truncate(str, max) {
    str = String(str == null ? "" : str);
    return str.length > max ? str.slice(0, max - 1) + "…" : str;
  }

  function normalizeHeaders(raw) {
    const out = {};
    if (!raw || typeof raw !== "object") return out;
    Object.keys(raw).forEach(function (k) {
      const v = raw[k];
      out[String(k).toLowerCase()] = Array.isArray(v) ? v.join(", ") : String(v == null ? "" : v);
    });
    return out;
  }

  function isUnavailable(body) {
    return !body || typeof body !== "object" ||
      body.error != null || body.skipped != null;
  }

  function friendlyApiError(status) {
    if (status === 429) {
      return "The assessment service is rate-limiting requests right now. Please wait a few minutes and try again.";
    }
    if (status === 408) {
      return "One of the checks timed out. The website may be slow to respond. Please try again.";
    }
    return "The assessment service returned an unexpected response. Please try again shortly.";
  }

  /* ---------------- Toast + elapsed timer (UI-only helpers) ---------------- */

  let toastTimer = null;
  function toast(message) {
    let region = $("#tf-toast");
    if (!region) {
      region = document.createElement("div");
      region.id = "tf-toast";
      region.className = "tf-toast";
      region.setAttribute("role", "status");
      region.setAttribute("aria-live", "polite");
      document.body.appendChild(region);
    }
    region.textContent = message;
    region.classList.add("is-visible");
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(function () {
      region.classList.remove("is-visible");
    }, 2400);
  }

  // elapsed timer helpers are defined below with the assessment state

  /* ---------------- Form wiring ---------------- */

  function isValidTarget(value) {
    if (!value || value.length > 2048 || /\s/.test(value)) return false;
    const candidate = /^https?:\/\//i.test(value) ? value : "https://" + value;
    let url;
    try {
      url = new URL(candidate);
    } catch (err) {
      return false;
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") return false;
    // Reject embedded credentials (https://user:pass@host) outright
    if (url.username || url.password) return false;
    const host = url.hostname;
    if (!host) return false;
    if (host === "localhost" || host.startsWith("[")) return true;
    // Require a dotted hostname of letter/digit/hyphen labels (e.g. example.com)
    return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+\.?$/i.test(host);
  }

  function normalizeTarget(value) {
    const candidate = /^https?:\/\//i.test(value) ? value : "https://" + value;
    return new URL(candidate).href;
  }

  function wireCheckForm(form) {
    const input = $(".url-input", form);
    const checkbox = $('.authorization-label input', form);
    const errorEl = $(".form-error", form);
    const button = $(".check-submit", form);
    const labelEl = $(".button-label", button);

    function refresh() {
      const urlOk = isValidTarget(input.value.trim());
      const authOk = checkbox.checked;
      button.disabled = !(urlOk && authOk);
      if (!input.value.trim()) {
        input.removeAttribute("aria-invalid");
        errorEl.textContent = "";
      } else if (!urlOk) {
        input.setAttribute("aria-invalid", "true");
        errorEl.textContent = "Enter a full website address, starting with http:// or https://.";
      } else {
        input.removeAttribute("aria-invalid");
        errorEl.textContent = "";
      }
    }

    input.addEventListener("input", refresh);
    input.addEventListener("blur", refresh);
    checkbox.addEventListener("change", refresh);
    refresh();

    form.addEventListener("submit", function (event) {
      event.preventDefault();
      if (assessmentState.running) return;

      const value = input.value.trim();
      if (!isValidTarget(value)) {
        input.setAttribute("aria-invalid", "true");
        errorEl.textContent = "Enter a full website address, starting with http:// or https://.";
        input.focus();
        return;
      }
      if (!checkbox.checked) {
        errorEl.textContent = "Please confirm you own this website or have authorization to assess it.";
        checkbox.focus();
        return;
      }
      errorEl.textContent = "";

      // Sync the same URL into every other check form
      $$(".check-form").forEach(function (other) {
        if (other !== form) $(".url-input", other).value = value;
      });

      const target = normalizeTarget(value);
      button.disabled = true;
      button.classList.add("is-loading");
      button.setAttribute("aria-busy", "true");
      labelEl.textContent = "Starting secure check…";

      runAssessment(target)
        .catch(function (err) {
          const failedStage = (err && typeof err.failedStage === "number") ? err.failedStage : 0;
          showScanFailure(err && err.message ? err.message :
            "The assessment could not be started. Please make sure the local server is running and try again.", failedStage);
        })
        .then(function () {
          assessmentState.running = false;
          assessmentState.abort = null;
          button.classList.remove("is-loading");
          button.removeAttribute("aria-busy");
          labelEl.textContent = "Check Website";
          button.disabled = !input.value.trim() || !checkbox.checked;
        });
    });
  }

  /* ---------------- Assessment state + DOM refs ---------------- */

  const assessmentState = { running: false, abort: null };
  let elapsedTimerHandle = null;
  let assessmentStartTime = 0;

  function startElapsedTimer() {
    stopElapsedTimer();
    assessmentStartTime = Date.now();
    const el = $("#progress-elapsed");
    if (el) el.textContent = "0s";
    elapsedTimerHandle = setInterval(function () {
      if (!assessmentStartTime) return;
      const sec = Math.max(0, Math.floor((Date.now() - assessmentStartTime) / 1000));
      if (el) el.textContent = sec + "s";
    }, 1000);
  }

  function stopElapsedTimer() {
    if (elapsedTimerHandle) {
      clearInterval(elapsedTimerHandle);
      elapsedTimerHandle = null;
    }
    if (assessmentStartTime) {
      const sec = Math.max(1, Math.round((Date.now() - assessmentStartTime) / 1000));
      const el = $("#progress-elapsed");
      if (el) el.textContent = sec + "s";
    }
  }

  const progressSection = $("#scan-progress");
  const resultsSection = $("#results");
  const progressBar = $("#progress-bar");
  const progressFill = $("#progress-fill");
  const progressPercent = $("#progress-percent");
  const progressStageLabel = $("#progress-current-stage");
  const progressBadge = $("#progress-status-badge");
  const stageList = $("#stage-list");
  const failureBox = $("#progress-failure");
  const failureReason = $("#progress-failure-reason");

  function buildStageList() {
    stageList.textContent = "";
    STAGES.forEach(function (stage, index) {
      const li = document.createElement("li");
      li.dataset.stage = String(index);

      const marker = document.createElement("span");
      marker.className = "stage-marker";
      marker.setAttribute("aria-hidden", "true");

      const label = document.createElement("span");
      label.className = "stage-label";
      label.textContent = stage.label;

      const status = document.createElement("span");
      status.className = "stage-status";
      status.textContent = "Pending";

      li.appendChild(marker);
      li.appendChild(label);
      li.appendChild(status);
      stageList.appendChild(li);
    });
  }

  function setStageStatus(index, state) {
    const li = stageList.querySelector('li[data-stage="' + index + '"]');
    if (!li) return;
    li.className = state ? "is-" + state : "";
    const status = $(".stage-status", li);
    const marker = $(".stage-marker", li);
    const labels = {
      pending: "Pending",
      running: "In progress",
      complete: "Complete",
      warning: "Complete with warnings",
      failed: "Unavailable",
    };
    if (status) status.textContent = labels[state] || "Pending";
    if (marker) {
      if (state === "complete") marker.innerHTML = SVG_CHECK;
      else if (state === "warning") marker.innerHTML = SVG_CHECK;
      else if (state === "failed") marker.innerHTML = SVG_DASH;
      else marker.textContent = "";
    }
  }

  function setProgress(percent, stageLabel) {
    const pct = Math.max(0, Math.min(100, Math.round(percent)));
    progressFill.style.width = pct + "%";
    progressPercent.textContent = pct + "%";
    progressBar.setAttribute("aria-valuenow", String(pct));
    if (stageLabel) progressStageLabel.textContent = stageLabel;
  }

  function setProgressBadge(text, cls) {
    progressBadge.className = "badge " + cls;
    progressBadge.textContent = text;
  }

  function scrollToElement(el) {
    if (prefersReducedMotion.matches) {
      el.scrollIntoView();
    } else {
      el.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  function showScanFailure(message, failedStageIndex) {
    const heading = $("#progress-heading");
    if (heading) heading.textContent = "The assessment could not complete";
    stopElapsedTimer();
    progressBadge.className = "badge badge-critical";
    progressBadge.textContent = "Failed";
    progressStageLabel.textContent = "Assessment failed";
    failureReason.textContent = message;
    failureBox.hidden = false;
    const stageIdx = typeof failedStageIndex === "number" ? failedStageIndex : 0;
    setStageStatus(stageIdx, "failed");
  }

  /* ---------------- API calls ---------------- */

  function fetchCheck(endpoint, target, signal) {
    const url = API_BASE + "/api/" + endpoint + "?url=" + encodeURIComponent(target);
    return fetch(url, { signal: signal, headers: { Accept: "application/json" } })
      .then(function (res) {
        return res.json().catch(function () { return {}; }).then(function (body) {
          if (!res.ok) {
            const err = new Error(friendlyApiError(res.status));
            err.apiStatus = res.status;
            throw err;
          }
          return body;
        });
      })
      .catch(function (err) {
        if (err && (err.name === "AbortError")) {
          const aborted = new Error("Assessment cancelled.");
          aborted.aborted = true;
          throw aborted;
        }
        if (err && err.apiStatus) throw err;
        // Network-level failure: server not reachable
        const unreachable = new Error(
          "Could not reach the assessment service. Make sure the local server is running (node server.js) and try again."
        );
        unreachable.unreachable = true;
        throw unreachable;
      });
  }

  /* ---------------- Finding builders (real backend data) ---------------- */

  function baseFinding(overrides) {
    return Object.assign({
      id: "f" + Math.random().toString(36).slice(2, 9),
      title: "",
      category: "Browser protections",
      severity: "informational",
      status: "informational",
      confidence: "High",
      observation: "",
      evidence: "",
      recommendation: "",
      affectedUrl: "",
    }, overrides);
  }

  function unavailableFinding(title, category) {
    return baseFinding({
      title: title,
      category: category,
      status: "skipped",
      severity: "informational",
      confidence: "—",
      observation: "This check did not return a result for the sampled responses, so it is excluded from the score.",
      recommendation: "Retry the assessment. If the check still cannot complete, it may not be supported for this website.",
    });
  }

  function buildStatusFindings(body, target) {
    if (isUnavailable(body)) return [unavailableFinding("Availability check could not complete", "Availability")];
    return [baseFinding({
      title: "Website responded as expected",
      category: "Availability",
      status: "passed",
      severity: "informational",
      observation: "The website returned HTTP " + body.responseCode + " to the sampled request.",
      evidence: "responseCode: " + body.responseCode + ", responseTime: " + Math.round(body.responseTime || 0) + "ms",
      recommendation: "No action needed — the target responded normally.",
      affectedUrl: target,
    })];
  }

  function buildRedirectFindings(body, target) {
    if (isUnavailable(body)) return [unavailableFinding("Redirect check could not complete", "Transport security")];
    const chain = Array.isArray(body.redirects) ? body.redirects : [];
    const hops = Math.max(0, chain.length - 1);
    const targetIsHttp = target.indexOf("http://") === 0;
    const endsOnHttps = chain.length > 0 && String(chain[chain.length - 1]).indexOf("https://") === 0;

    const finding = baseFinding({
      category: "Transport security",
      confidence: "Medium",
      affectedUrl: target,
      evidence: hops > 0 ? truncate(chain.join("  →  "), 160) : "No redirects observed",
    });

    if (targetIsHttp && !endsOnHttps) {
      finding.title = "Redirects do not upgrade to HTTPS";
      finding.severity = "medium";
      finding.status = "finding";
      finding.observation = "The sampled redirect chain does not end on an HTTPS address.";
      finding.recommendation = "Redirect all HTTP traffic to HTTPS, ideally with a permanent (301) redirect.";
    } else {
      finding.title = hops > 0 ? "Redirect behavior reviewed" : "No unnecessary redirects observed";
      finding.status = "passed";
      finding.severity = "informational";
      finding.observation = hops > 0
        ? "The redirect chain (" + hops + " hop" + (hops === 1 ? "" : "s") + ") was followed safely."
        : "The sampled response was served directly, without redirects.";
      finding.recommendation = "No action needed — keep redirect chains short and HTTPS-only.";
    }
    return [finding];
  }

  function buildSslFindings(body, target, targetIsHttp) {
    if (isUnavailable(body)) {
      if (targetIsHttp) {
        return [baseFinding({
          title: "Website served over plain HTTP",
          category: "Transport security",
          severity: "medium",
          status: "finding",
          confidence: "High",
          observation: "The submitted address uses HTTP, so transport encryption could not be reviewed.",
          evidence: "Target scheme: http:",
          recommendation: "Serve the website over HTTPS and redirect HTTP traffic to the secure address.",
          affectedUrl: target,
        })];
      }
      return [unavailableFinding("Certificate check could not complete", "Transport security")];
    }

    if (body.isValid === false) {
      return [baseFinding({
        title: "TLS certificate could not be validated",
        category: "Transport security",
        severity: "high",
        status: "finding",
        confidence: "High",
        observation: "The certificate presented by the server did not validate against trusted authorities.",
        evidence: "Validation error reported during the TLS handshake.",
        recommendation: "Renew or correctly install the TLS certificate, including any required intermediate certificates.",
        affectedUrl: target,
      })];
    }

    const validTo = body.valid_to ? new Date(body.valid_to) : null;
    const daysLeft = validTo && !isNaN(validTo.getTime())
      ? Math.floor((validTo.getTime() - Date.now()) / 86400000) : null;

    if (daysLeft != null && daysLeft < 30) {
      return [baseFinding({
        title: "TLS certificate expires soon",
        category: "Transport security",
        severity: "medium",
        status: "finding",
        confidence: "High",
        observation: "The certificate is valid but is approaching expiry in about " + Math.max(0, daysLeft) + " day(s).",
        evidence: "valid_to: " + body.valid_to,
        recommendation: "Renew the certificate before it expires to avoid an outage or browser warnings.",
        affectedUrl: target,
      })];
    }

    const issuer = body.issuer && (body.issuer.O || body.issuer.CN) ? (body.issuer.O || body.issuer.CN) : "Unknown issuer";
    return [baseFinding({
      title: "Valid TLS certificate observed",
      category: "Transport security",
      status: "passed",
      severity: "informational",
      observation: "The server presented a trusted certificate" + (daysLeft != null ? " with roughly " + daysLeft + " days remaining" : "") + ".",
      evidence: "issuer: " + issuer + (body.valid_to ? ", valid_to: " + body.valid_to : ""),
      recommendation: "No action needed — keep auto-renewal in place.",
      affectedUrl: target,
    })];
  }

  function buildHstsFindings(body, target) {
    if (isUnavailable(body)) return [unavailableFinding("HSTS check could not complete", "Transport security")];
    const finding = baseFinding({
      category: "Transport security",
      confidence: "High",
      affectedUrl: target,
      evidence: body.hstsHeader ? truncate(body.hstsHeader, 120) : "No Strict-Transport-Security header in sampled response",
    });
    if (body.compatible) {
      finding.title = "Strict transport policy observed";
      finding.status = "passed";
      finding.severity = "informational";
      finding.observation = body.message || "The site is compatible with the HSTS preload list.";
      finding.recommendation = "No action needed — keep the Strict-Transport-Security header in place.";
    } else if (body.hstsHeader) {
      finding.title = "Strict transport policy is not fully configured";
      finding.severity = "medium";
      finding.status = "finding";
      finding.observation = body.message || "The Strict-Transport-Security header is present but does not meet the recommended baseline.";
      finding.recommendation = "Review the header directives; a long max-age with includeSubDomains is a common baseline.";
    } else {
      finding.title = "Strict transport policy not observed";
      finding.severity = "medium";
      finding.status = "finding";
      finding.observation = "The sampled public response did not include a Strict-Transport-Security header.";
      finding.recommendation = "Consider adding a Strict-Transport-Security header once HTTPS is stable across the website.";
    }
    return [finding];
  }

  var HEADER_CHECKS = [
    {
      header: "content-security-policy", frameAlt: true, title: "Content security policy",
      severity: "medium",
      absent: "Content security policy not observed",
      absentObservation: "The sampled public response did not include a Content-Security-Policy header.",
      absentRecommendation: "Review whether a Content Security Policy fits the website's application architecture.",
      present: "Content security policy observed"
    },
    {
      header: "x-frame-options", frameGroup: true, title: "Clickjacking protection",
      severity: "medium",
      absent: "Clickjacking protection not observed",
      absentObservation: "No X-Frame-Options header or CSP frame-ancestors directive was observed in the sampled response.",
      absentRecommendation: "Consider X-Frame-Options: DENY (or a CSP frame-ancestors directive) to restrict framing by other sites.",
      present: "Clickjacking protection observed"
    },
    {
      header: "x-content-type-options", title: "MIME type sniffing protection",
      severity: "low",
      absent: "MIME type sniffing protection not observed",
      absentObservation: "The X-Content-Type-Options header was not observed in the sampled response.",
      absentRecommendation: "Consider adding X-Content-Type-Options: nosniff to responses.",
      present: "MIME type sniffing protection observed"
    },
    {
      header: "referrer-policy", title: "Referrer policy",
      severity: "low",
      absent: "Referrer policy not observed",
      absentObservation: "The Referrer-Policy header was not observed in the sampled response.",
      absentRecommendation: "Consider setting a Referrer-Policy such as strict-origin-when-cross-origin.",
      present: "Referrer policy observed"
    },
    {
      header: "permissions-policy", title: "Permissions policy",
      severity: "informational",
      absent: "Permissions policy not observed",
      absentObservation: "The Permissions-Policy header was not observed in the sampled response.",
      absentRecommendation: "Review which browser features the website needs, and consider restricting the rest via Permissions-Policy.",
      present: "Permissions policy observed"
    },
  ];

  function buildHeaderFindings(rawHeaders, target) {
    if (isUnavailable(rawHeaders)) return [unavailableFinding("Header check could not complete", "Browser protections")];
    const headers = normalizeHeaders(rawHeaders);
    const findings = [];

    HEADER_CHECKS.forEach(function (spec, index) {
      const value = headers[spec.header];
      if (spec.frameGroup && !value && headers["content-security-policy"] &&
        /frame-ancestors/i.test(headers["content-security-policy"])) {
        // Covered by the CSP frame-ancestors directive — treat as present
        findings.push(baseFinding({
          id: "hdr" + index,
          title: spec.present,
          category: "Browser protections",
          status: "passed",
          severity: "informational",
          observation: "Framing restriction was observed via the CSP frame-ancestors directive.",
          evidence: truncate(headers["content-security-policy"], 140),
          recommendation: "No action needed — keep the framing restriction in place.",
          affectedUrl: target,
        }));
        return;
      }
      if (value) {
        findings.push(baseFinding({
          id: "hdr" + index,
          title: spec.present,
          category: "Browser protections",
          status: "passed",
          severity: "informational",
          observation: "The " + spec.header + " header was observed in the sampled response.",
          evidence: truncate(spec.header + ": " + value, 140),
          recommendation: "No action needed — keep this header in place.",
          affectedUrl: target,
        }));
      } else {
        findings.push(baseFinding({
          id: "hdr" + index,
          title: spec.absent,
          category: "Browser protections",
          status: spec.severity === "informational" ? "informational" : "finding",
          severity: spec.severity,
          observation: spec.absentObservation,
          evidence: "No " + spec.header + " header in the sampled response.",
          recommendation: spec.absentRecommendation,
          affectedUrl: target,
        }));
      }
    });

    // Public exposure signals from the same sampled response
    const serverHeader = headers["server"];
    if (serverHeader && /\d/.test(serverHeader)) {
      findings.push(baseFinding({
        title: "Server version disclosure",
        category: "Public exposure",
        status: "finding",
        severity: "low",
        confidence: "High",
        observation: "The sampled response discloses the server software and version.",
        evidence: truncate("server: " + serverHeader, 120),
        recommendation: "Consider hiding the server version banner so known-version attacks are not trivially targeted.",
        affectedUrl: target,
      }));
    }
    if (headers["x-powered-by"]) {
      findings.push(baseFinding({
        title: "Backend technology disclosure",
        category: "Public exposure",
        status: "finding",
        severity: "low",
        confidence: "High",
        observation: "The sampled response discloses the backend technology via the X-Powered-By header.",
        evidence: truncate("x-powered-by: " + headers["x-powered-by"], 120),
        recommendation: "Consider removing the X-Powered-By header from responses.",
        affectedUrl: target,
      }));
    }
    return findings;
  }

  function parseCookieStrings(list) {
    return (Array.isArray(list) ? list : []).map(function (raw) {
      const text = String(raw);
      const firstSegment = text.split(";")[0] || "";
      const eq = firstSegment.indexOf("=");
      const flags = text.toLowerCase();
      return {
        name: eq > -1 ? firstSegment.slice(0, eq).trim() : firstSegment.trim(),
        secure: /\bsecure\b/.test(flags),
        httpOnly: /\bhttponly\b/.test(flags),
        sameSite: /samesite=(lax|strict|none)/.test(flags),
      };
    }).filter(function (cookie) { return !!cookie.name; });
  }

  function buildCookieFindings(body, target) {
    if (isUnavailable(body)) return [unavailableFinding("Cookie check could not complete", "Browser protections")];
    const cookies = parseCookieStrings(body.headerCookies);
    if (cookies.length === 0) {
      return [baseFinding({
        title: "No cookies observed in sampled response",
        category: "Browser protections",
        status: "passed",
        severity: "informational",
        observation: "No Set-Cookie headers were observed in the sampled public response.",
        evidence: "set-cookie headers: none",
        recommendation: "No action needed — no cookie configuration signals were available to review.",
        affectedUrl: target,
      })];
    }

    const names = function (list) { return list.map(function (c) { return c.name; }).join(", "); };
    const findings = [];
    const missingSecure = cookies.filter(function (c) { return !c.secure; });
    const missingHttpOnly = cookies.filter(function (c) { return !c.httpOnly; });
    const missingSameSite = cookies.filter(function (c) { return !c.sameSite; });

    if (missingSecure.length > 0) {
      findings.push(baseFinding({
        title: "Secure cookie flag not observed",
        category: "Browser protections",
        status: "finding",
        severity: "high",
        confidence: "High",
        observation: "Some cookies observed in the sampled response do not set the Secure attribute, so they may be sent over unencrypted connections.",
        evidence: "cookies without Secure: " + truncate(names(missingSecure), 100),
        recommendation: "Set the Secure attribute on all cookies so they are only transmitted over HTTPS.",
        affectedUrl: target,
      }));
    }
    if (missingHttpOnly.length > 0) {
      findings.push(baseFinding({
        title: "HttpOnly cookie flag not observed",
        category: "Browser protections",
        status: "finding",
        severity: "medium",
        confidence: "High",
        observation: "Some cookies observed in the sampled response do not set the HttpOnly attribute, making them readable by browser scripts.",
        evidence: "cookies without HttpOnly: " + truncate(names(missingHttpOnly), 100),
        recommendation: "Set the HttpOnly attribute on session-related cookies to limit script access.",
        affectedUrl: target,
      }));
    }
    if (missingSameSite.length > 0) {
      findings.push(baseFinding({
        title: "SameSite cookie attribute not observed",
        category: "Browser protections",
        status: "finding",
        severity: "medium",
        confidence: "High",
        observation: "Some cookies observed in the sampled response do not declare a SameSite attribute.",
        evidence: "cookies without SameSite: " + truncate(names(missingSameSite), 100),
        recommendation: "Set SameSite=Lax or Strict on cookies to reduce cross-site request risk.",
        affectedUrl: target,
      }));
    }
    if (findings.length === 0) {
      findings.push(baseFinding({
        title: "Cookie security attributes observed",
        category: "Browser protections",
        status: "passed",
        severity: "informational",
        observation: "The cookies observed in the sampled response declare Secure, HttpOnly, and SameSite attributes.",
        evidence: "cookies: " + truncate(names(cookies), 100),
        recommendation: "No action needed — keep cookie attributes restricted.",
        affectedUrl: target,
      }));
    }
    return findings;
  }

  function buildSecurityTxtFindings(body, target) {
    if (isUnavailable(body)) return [unavailableFinding("security.txt check could not complete", "Public exposure")];
    if (body.isPresent) {
      return [baseFinding({
        title: "Security policy file published",
        category: "Public exposure",
        status: "passed",
        severity: "informational",
        confidence: "Medium",
        observation: "A security.txt file was published at " + (body.foundIn || "/.well-known/security.txt") + ", giving researchers a way to report issues.",
        evidence: "foundIn: " + (body.foundIn || "n/a"),
        recommendation: "No action needed — keep the contact details in security.txt up to date.",
        affectedUrl: target,
      })];
    }
    return [baseFinding({
      title: "No security.txt published",
      category: "Public exposure",
      status: "informational",
      severity: "informational",
      confidence: "Medium",
      observation: "No security.txt file was found at the well-known locations in the sampled responses.",
      evidence: "checked: /.well-known/security.txt, /security.txt",
      recommendation: "Consider publishing /.well-known/security.txt so security researchers know how to reach you.",
      affectedUrl: target,
    })];
  }

  /* ---------------- Scoring ---------------- */

  function scoreAssessment(findings) {
    let score = 100;
    const counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };

    findings.forEach(function (f) {
      if (f.status === "passed" || f.status === "skipped") return;
      counts[f.severity] = (counts[f.severity] || 0) + 1;
      score -= SEVERITY_DEDUCTION[f.severity] || 0;
    });
    score = Math.max(0, Math.min(100, Math.round(score)));

    let riskLevel = "low";
    if (score < 35) riskLevel = "critical";
    else if (score < 60) riskLevel = "high";
    else if (score < 85) riskLevel = "medium";

    return { score: score, riskLevel: riskLevel, counts: counts };
  }

  function riskLabel(riskLevel) {
    return riskLevel.charAt(0).toUpperCase() + riskLevel.slice(1);
  }

  function buildSummary(scored, findings) {
    const attention = findings.filter(function (f) {
      return f.status !== "passed" && f.status !== "skipped";
    });
    const passed = findings.filter(function (f) { return f.status === "passed"; }).length;
    let summary = attention.length === 0
      ? "No findings requiring attention were observed in the sampled responses. " + passed + " checks passed."
      : attention.length + " finding" + (attention.length === 1 ? "" : "s") + " require attention; " +
      passed + " checks passed.";
    const top = attention.sort(function (a, b) { return SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]; })[0];
    if (top) summary += " Priority item: " + top.title + ".";
    return summary;
  }

  /* ---------------- Assessment runner ---------------- */

  function runPassiveAssessmentFallback(target, startedAt, scanId) {
    const targetIsHttp = target.indexOf("http://") === 0;
    const collected = {};
    const stageCalls = {};
    const stageDone = {};
    CHECKS.forEach(function (check) {
      stageCalls[check.stage] = (stageCalls[check.stage] || 0) + 1;
      stageDone[check.stage] = 0;
    });
    STAGES.forEach(function (_, index) { setStageStatus(index, "pending"); });

    function advanceProgress(stage) {
      const range = STAGE_RANGES[stage];
      const total = stageCalls[stage] || 1;
      const done = stageDone[stage];
      const percent = range[0] + (range[1] - range[0]) * (done / total);
      setProgress(percent, STAGES[stage].label + "…");
    }

    function beginStage(stage) {
      setStageStatus(stage, "running");
      setProgressBadge("Running", "badge-neutral");
      advanceProgress(stage);
    }

    function finishStage(stage, hadUnavailable) {
      stageDone[stage] = stageCalls[stage];
      setStageStatus(stage, hadUnavailable ? "warning" : "complete");
      advanceProgress(stage);
    }

    let chain = Promise.resolve();
    CHECKS.forEach(function (check) {
      chain = chain.then(function () {
        beginStage(check.stage);
        return fetchCheck(check.endpoint, target, assessmentState.abort.signal)
          .then(function (body) {
            collected[check.key] = isUnavailable(body) ? { unavailable: true } : body;
            stageDone[check.stage] += 1;
            if (stageDone[check.stage] >= stageCalls[check.stage]) {
              finishStage(check.stage, collected[check.key].unavailable === true);
            } else {
              advanceProgress(check.stage);
            }
          })
          .catch(function (err) {
            if (err && err.aborted) throw err;
            if (err && err.unreachable) throw err;
            if (err && err.apiStatus === 429) throw err;
            collected[check.key] = { unavailable: true };
            stageDone[check.stage] += 1;
            if (stageDone[check.stage] >= stageCalls[check.stage]) {
              finishStage(check.stage, true);
            } else {
              advanceProgress(check.stage);
            }
          });
      });
    });

    return chain.then(function () {
      const hardFailures = ["status", "headers", "cookies"].filter(function (key) {
        return collected[key] && collected[key].unavailable;
      });
      if (hardFailures.length >= 2) {
        throw new Error("The website could not be reached, or it refused the assessment requests. " +
          "Verify the address is correct and publicly reachable, then try again.");
      }

      setStageStatus(4, "running");
      setProgress(94, STAGES[4].label + "…");

      const findings = []
        .concat(buildStatusFindings(collected.status, target))
        .concat(buildRedirectFindings(collected.redirects, target))
        .concat(buildSslFindings(collected.ssl, target, targetIsHttp))
        .concat(buildHstsFindings(collected.hsts, target))
        .concat(buildHeaderFindings(collected.headers, target))
        .concat(buildCookieFindings(collected.cookies, target))
        .concat(buildSecurityTxtFindings(collected.securityTxt, target));

      const scored = scoreAssessment(findings);
      const durationMs = Date.now() - startedAt;
      const completedAt = new Date();

      setStageStatus(4, "complete");
      setProgress(100, "Assessment complete");
      setProgressBadge("Complete", "badge-pass");

      setTimeout(function () {
        renderResults({
          target: target,
          scanId: scanId,
          findings: findings,
          scored: scored,
          completedAt: completedAt,
          durationMs: durationMs,
        });
      }, prefersReducedMotion.matches ? 0 : 450);
    }).then(function () {
      assessmentState.running = false;
      assessmentState.abort = null;
    });
  }

  function runAssessment(target) {
    assessmentState.running = true;
    assessmentState.abort = new AbortController();
    const startedAt = Date.now();
    currentScanId = "nector-" + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);

    // Show the progress section
    failureBox.hidden = true;
    $("#progress-target-url").textContent = target;
    $("#progress-scan-id").textContent = currentScanId;
    buildStageList();
    setStageStatus(0, "running");
    setProgress(15, "Validating website target…");
    setProgressBadge("Running", "badge-neutral");
    progressSection.hidden = false;
    resultsSection.hidden = true;
    startElapsedTimer();
    scrollToElement(progressSection);

    // Primary Nuclei + Gemini background scan API
    return fetch(API_BASE + "/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({ url: target }),
      signal: assessmentState.abort.signal,
    })
      .then(function (res) {
        return res.json().then(function (data) {
          if (!res.ok) {
            const valErr = new Error(data.error || "Scan request failed (HTTP " + res.status + ")");
            valErr.failedStage = 0;
            throw valErr;
          }
          return data;
        });
      })
      .then(function (initData) {
        currentScanId = initData.scanId || currentScanId;
        $("#progress-scan-id").textContent = currentScanId;
        setStageStatus(0, "complete");
        setStageStatus(1, "running");
        setProgress(30, "Running vulnerability checks…");
        setProgressBadge("Running", "badge-neutral");

        // Poll /api/scan/:id
        return new Promise(function (resolve, reject) {
          const pollInterval = setInterval(function () {
            if (!assessmentState.running) {
              clearInterval(pollInterval);
              return;
            }
            fetch(API_BASE + "/api/scan/" + encodeURIComponent(currentScanId), {
              signal: assessmentState.abort ? assessmentState.abort.signal : null,
            })
              .then(function (r) { return r.json(); })
              .then(function (scan) {
                if (scan.status === "failed") {
                  clearInterval(pollInterval);
                  const scanErr = new Error(scan.error || "Scan execution failed.");
                  scanErr.failedStage = 1;
                  reject(scanErr);
                  return;
                }

                if (scan.progress != null) {
                  setProgress(scan.progress, scan.stage || "Scanning…");
                }

                // Stage transitions based on progress
                if (scan.progress >= 30 && scan.progress < 75) {
                  setStageStatus(0, "complete");
                  setStageStatus(1, "running");
                } else if (scan.progress >= 75 && scan.progress < 80) {
                  setStageStatus(0, "complete");
                  setStageStatus(1, "complete");
                  setStageStatus(2, "complete");
                  setStageStatus(3, "running");
                } else if (scan.progress >= 80 && scan.progress < 100) {
                  setStageStatus(0, "complete");
                  setStageStatus(1, "complete");
                  setStageStatus(2, "complete");
                  setStageStatus(3, "running");
                }

                if (scan.status === "completed" || scan.status === "partial") {
                  clearInterval(pollInterval);
                  for (let s = 0; s < 5; s++) setStageStatus(s, "complete");
                  setProgress(100, "Assessment complete");
                  setProgressBadge("Complete", "badge-pass");

                  let findings = scan.findings || [];
                  if (findings.length === 0) {
                    findings = [baseFinding({
                      title: "No vulnerabilities observed by configured checks",
                      category: "Security Checks",
                      status: "passed",
                      severity: "informational",
                      observation: "The target website was scanned with safe non-destructive checks and observed zero active vulnerabilities or misconfigurations.",
                      evidence: "Scanner: " + (scan.scannerSource === "zap" ? "OWASP ZAP" : scan.scannerSource === "nuclei" ? "Nuclei" : "Nector Security Engine"),
                      recommendation: "Keep system packages, certificates, and security headers updated regularly.",
                      affectedUrl: target,
                    })];
                  }

                  const scored = scoreAssessment(findings);
                  const durationMs = scan.durationMs || (Date.now() - startedAt);

                  setTimeout(function () {
                    renderResults({
                      target: scan.target || target,
                      scanId: currentScanId,
                      findings: findings,
                      scored: scored,
                      completedAt: new Date(scan.completedAt || Date.now()),
                      durationMs: durationMs,
                      nucleiNotice: scan.nucleiNotice,
                      scannerSource: scan.scannerSource,
                    });
                    resolve();
                  }, prefersReducedMotion.matches ? 0 : 450);
                }
              })
              .catch(function (pollErr) {
                if (pollErr && pollErr.name === "AbortError") {
                  clearInterval(pollInterval);
                  reject(new Error("Assessment cancelled."));
                }
              });
          }, 1200);
        });
      })
      .catch(function (err) {
        // If target rejected by SSRF guardrails or invalid, report directly
        if (err && err.message && (
          err.failedStage === 0 ||
          err.message.includes("Prohibited scan target") ||
          err.message.includes("private") ||
          err.message.includes("loopback") ||
          err.message.includes("DNS resolution failed") ||
          err.message.includes("credentials") ||
          err.message.includes("protocols are permitted") ||
          err.message.includes("Unable to resolve")
        )) {
          err.failedStage = 0;
          throw err;
        }
        // Fallback to passive check chain if scan API endpoint is unreachable
        return runPassiveAssessmentFallback(target, startedAt, currentScanId);
      });
  }

  /* ---------------- Results rendering ---------------- */

  let currentFindings = [];
  let currentFilter = "all";
  let currentTarget = "";
  let currentScanId = "";

  const RISK_RING_COLOR = { low: "var(--safe)", medium: "var(--medium)", high: "var(--high)", critical: "var(--critical)" };
  const RISK_BADGE_CLASS = { low: "badge-pass", medium: "badge-medium", high: "badge-high", critical: "badge-critical" };

  function renderResults(result) {
    stopElapsedTimer();
    currentFindings = result.findings;
    currentTarget = result.target;
    currentFilter = "all";

    $("#result-target-url").textContent = result.target;
    $("#result-scan-id").textContent = result.scanId;
    $("#result-completed-at").textContent = result.completedAt.toLocaleString();
    const seconds = result.durationMs / 1000;
    const durationText = seconds >= 10 ? seconds.toFixed(0) + "s" : seconds.toFixed(1) + "s";
    $("#result-duration").textContent = durationText;

    const scannerEl = $("#result-scanner");
    if (scannerEl) {
      scannerEl.textContent = result.scannerSource === "zap"
        ? "OWASP ZAP"
        : result.scannerSource === "nuclei"
          ? "Nuclei Scanner"
          : "Nector Security Engine";
    }

    const noticeBanner = $("#result-scanner-notice");
    const noticeText = $("#result-scanner-notice-text");
    if (noticeBanner && noticeText) {
      if (result.nucleiNotice) {
        noticeText.textContent = result.nucleiNotice;
        noticeBanner.hidden = false;
      } else {
        noticeBanner.hidden = true;
      }
    }

    // Score panel
    setScoreRing(result.scored.score, result.scored.riskLevel);
    animateScoreNumber(result.scored.score);
    $("#score-risk-badge").className = "badge " + RISK_BADGE_CLASS[result.scored.riskLevel];
    $("#score-risk-badge").textContent = riskLabel(result.scored.riskLevel) + " risk";
    $("#score-summary").textContent = buildSummary(result.scored, result.findings);

    // Stats
    const attention = result.findings.filter(function (f) {
      return f.status !== "passed" && f.status !== "skipped";
    });
    const passed = result.findings.filter(function (f) { return f.status === "passed"; }).length;
    $("#stat-reviewed").textContent = String(result.findings.length);
    $("#stat-attention").textContent = String(attention.length);
    $("#stat-passed").textContent = String(passed);
    $("#stat-duration").textContent = durationText;

    renderSeverityBars(result.scored.counts);
    renderCategorySummary(result.findings);
    renderFilters();
    renderFindings(true);
    renderRecommendedActions(attention);

    progressSection.hidden = true;
    resultsSection.hidden = false;
    scrollToElement(resultsSection);
  }

  function setScoreRing(score, riskLevel) {
    const circumference = 2 * Math.PI * 52;
    const fill = $("#score-ring-fill");
    fill.style.stroke = RISK_RING_COLOR[riskLevel] || "var(--info)";
    // Force a reflow so the transition runs from the empty state
    fill.style.strokeDashoffset = String(circumference);
    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        fill.style.strokeDashoffset = String(circumference * (1 - score / 100));
      });
    });
  }

  function animateScoreNumber(target) {
    const el = $("#score-number");
    // Show the real value immediately; the count-up below only refines it.
    // If animation frames are suspended (background tab), the correct
    // score is still displayed.
    el.textContent = String(target);
    if (prefersReducedMotion.matches || document.hidden) return;
    const duration = 700;
    const start = performance.now();
    function frame(now) {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      el.textContent = String(Math.round(eased * target));
      if (t < 1) requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  }

  function renderSeverityBars(counts) {
    const wrap = $("#severity-breakdown");
    const order = ["critical", "high", "medium", "low", "informational"];
    const max = Math.max.apply(null, [1].concat(order.map(function (k) { return counts[k] || 0; })));

    order.forEach(function (key) {
      let bar = wrap.querySelector('[data-severity="' + key + '"]');
      if (!bar) {
        bar = document.createElement("div");
        bar.className = "severity-bar";
        bar.dataset.severity = key;

        const label = document.createElement("span");
        label.className = "severity-bar-label";
        const dot = document.createElement("span");
        dot.className = "severity-dot";
        dot.setAttribute("aria-hidden", "true");
        dot.style.background = "var(--" + (key === "informational" ? "info" : key === "low" ? "safe" : key) + ")";
        label.appendChild(dot);
        label.appendChild(document.createTextNode(key.charAt(0).toUpperCase() + key.slice(1)));

        const track = document.createElement("div");
        track.className = "severity-bar-track";
        const fill = document.createElement("div");
        fill.className = "severity-bar-fill";
        fill.style.background = "var(--" + (key === "informational" ? "info" : key === "low" ? "safe" : key) + ")";
        track.appendChild(fill);

        const count = document.createElement("span");
        count.className = "severity-bar-count";

        bar.appendChild(label);
        bar.appendChild(track);
        bar.appendChild(count);
        wrap.appendChild(bar);
      }
      bar.querySelector(".severity-bar-fill").style.width = Math.round(((counts[key] || 0) / max) * 100) + "%";
      bar.querySelector(".severity-bar-count").textContent = String(counts[key] || 0);
    });

    $("#severity-summary-text").textContent =
      "Severity counts: critical " + (counts.critical || 0) + ", high " + (counts.high || 0) +
      ", medium " + (counts.medium || 0) + ", low " + (counts.low || 0) +
      ", informational " + (counts.informational || 0) + ".";
  }

  function matchesFilter(finding, filter) {
    switch (filter) {
      case "all": return true;
      case "attention": return finding.status !== "passed" && finding.status !== "skipped";
      case "passed": return finding.status === "passed";
      case "critical": return finding.severity === "critical" && finding.status !== "passed" && finding.status !== "skipped";
      case "high": return finding.severity === "high" && finding.status !== "passed" && finding.status !== "skipped";
      case "medium": return finding.severity === "medium" && finding.status !== "passed" && finding.status !== "skipped";
      case "low": return finding.severity === "low" && finding.status !== "passed" && finding.status !== "skipped";
      case "informational": return finding.severity === "informational" && finding.status !== "passed" && finding.status !== "skipped";
      default: return true;
    }
  }

  function renderFilters() {
    $$("#finding-filters .filter").forEach(function (button) {
      const isActive = button.dataset.filter === currentFilter;
      button.classList.toggle("is-active", isActive);
      button.setAttribute("aria-pressed", String(isActive));
    });
  }

  function renderFindings(withStagger) {
    const list = $("#finding-list");
    list.textContent = "";
    let shown = 0;

    currentFindings.forEach(function (finding, index) {
      if (!matchesFilter(finding, currentFilter)) return;
      shown += 1;

      const li = document.createElement("li");
      li.className = "finding-row";
      li.dataset.rule = finding.status === "passed" ? "passed"
        : finding.status === "skipped" ? "none"
          : finding.severity;

      const toggle = document.createElement("button");
      toggle.className = "finding-toggle";
      toggle.type = "button";
      toggle.setAttribute("aria-expanded", "false");
      toggle.setAttribute("aria-controls", "finding-detail-" + index);

      toggle.appendChild(statusIconFor(finding));

      const titleWrap = document.createElement("span");
      titleWrap.className = "finding-title-wrap";
      const title = document.createElement("span");
      title.className = "finding-title";
      title.textContent = finding.title;
      const sub = document.createElement("span");
      sub.className = "finding-sub";
      sub.textContent = finding.category + " — " + truncate(finding.observation, 90);
      titleWrap.appendChild(title);
      titleWrap.appendChild(sub);
      toggle.appendChild(titleWrap);

      const meta = document.createElement("span");
      meta.className = "finding-meta";
      meta.appendChild(badge(severityLabel(finding), badgeClassFor(finding)));
      const confidence = document.createElement("span");
      confidence.className = "finding-confidence";
      confidence.textContent = "Confidence: " + finding.confidence;
      meta.appendChild(confidence);
      toggle.appendChild(meta);

      const chevron = document.createElement("span");
      chevron.className = "finding-chevron";
      chevron.setAttribute("aria-hidden", "true");
      chevron.innerHTML = SVG_CHEVRON;
      toggle.appendChild(chevron);

      const detail = document.createElement("div");
      detail.className = "finding-detail";
      detail.id = "finding-detail-" + index;
      const detailInner = document.createElement("div");
      const detailList = document.createElement("dl");
      detailList.className = "finding-detail-inner";

      function detailRow(term, value, valueClass) {
        if (!value) return;
        const row = document.createElement("div");
        const dt = document.createElement("dt");
        dt.textContent = term;
        const dd = document.createElement("dd");
        if (valueClass) dd.className = valueClass;
        dd.textContent = value;
        row.appendChild(dt);
        row.appendChild(dd);
        detailList.appendChild(row);
      }

      if (finding.source === "zap" || finding.source === "nuclei" || finding.source === "builtin" || finding.aiExplanation || finding.aiStatus) {
        if (finding.templateId) {
          const idLabel = finding.source === "zap" ? "OWASP ZAP Rule ID" : finding.source === "nuclei" ? "Nuclei Template ID" : "Check Rule ID";
          detailRow(idLabel, finding.templateId, "template-tag");
        }
        if (finding.cweId) {
          detailRow("CWE Identifier", "CWE-" + finding.cweId);
        }
        if (finding.wascId) {
          detailRow("WASC Identifier", "WASC-" + finding.wascId);
        }
        detailRow("Target Endpoint", finding.matchedTarget || currentTarget);
        detailRow("Vulnerability Description", finding.description);
        detailRow("Scanner Evidence", finding.evidence, "evidence");
        if (finding.references && finding.references.length > 0) {
          detailRow("References", Array.isArray(finding.references) ? finding.references.join(", ") : String(finding.references));
        }

        // Gemini AI Remediation Guidance Box
        const aiBox = document.createElement("div");
        aiBox.className = "ai-remediation-box";

        const aiHeader = document.createElement("div");
        aiHeader.className = "ai-header";

        const aiTitleWrap = document.createElement("div");
        aiTitleWrap.className = "ai-title-wrap";
        aiTitleWrap.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v20M2 12h20M4.93 4.93l14.14 14.14M4.93 19.07l14.14-14.14"/></svg> <span>Google Gemini Remediation Guide</span>';
        aiHeader.appendChild(aiTitleWrap);

        if (finding.aiExplanation) {
          const aiBadge = document.createElement("span");
          aiBadge.className = "ai-badge";
          aiBadge.textContent = "AI Analyzed";
          aiHeader.appendChild(aiBadge);
          aiBox.appendChild(aiHeader);

          const aiExplain = document.createElement("p");
          aiExplain.style.fontSize = "14px";
          aiExplain.style.margin = "4px 0";
          aiExplain.textContent = finding.aiExplanation.simpleExplanation;
          aiBox.appendChild(aiExplain);

          if (finding.aiExplanation.whatIsWrong) {
            const wrongP = document.createElement("p");
            wrongP.style.fontSize = "13px";
            wrongP.style.color = "var(--text-2)";
            wrongP.innerHTML = "<strong>What is wrong:</strong> " + finding.aiExplanation.whatIsWrong;
            aiBox.appendChild(wrongP);
          }

          if (finding.aiExplanation.whyItMatters) {
            const whyP = document.createElement("p");
            whyP.style.fontSize = "13px";
            whyP.style.color = "var(--text-2)";
            whyP.innerHTML = "<strong>Why it matters:</strong> " + finding.aiExplanation.whyItMatters;
            aiBox.appendChild(whyP);
          }

          if (finding.aiExplanation.howToFix && finding.aiExplanation.howToFix.length > 0) {
            const stepsTitle = document.createElement("strong");
            stepsTitle.style.fontSize = "13px";
            stepsTitle.textContent = "Recommended Remediation Steps:";
            aiBox.appendChild(stepsTitle);

            const stepsOl = document.createElement("ol");
            stepsOl.className = "ai-steps-list";
            finding.aiExplanation.howToFix.forEach(function (step) {
              const stepLi = document.createElement("li");
              stepLi.textContent = step;
              stepsOl.appendChild(stepLi);
            });
            aiBox.appendChild(stepsOl);
          }

          if (finding.aiExplanation.codeExample) {
            const codeBox = document.createElement("div");
            codeBox.className = "ai-code-block";
            const pre = document.createElement("pre");
            pre.textContent = finding.aiExplanation.codeExample;
            codeBox.appendChild(pre);
            aiBox.appendChild(codeBox);
          }

          if (finding.aiExplanation.whereToFix) {
            const whereP = document.createElement("p");
            whereP.style.fontSize = "12.5px";
            whereP.style.color = "var(--text-3)";
            whereP.innerHTML = "<strong>Where to fix:</strong> " + finding.aiExplanation.whereToFix;
            aiBox.appendChild(whereP);
          }

          if (finding.aiExplanation.howToVerify) {
            const verifyP = document.createElement("p");
            verifyP.style.fontSize = "12.5px";
            verifyP.style.color = "var(--text-2)";
            verifyP.innerHTML = "<strong>How to verify:</strong> " + finding.aiExplanation.howToVerify;
            aiBox.appendChild(verifyP);
          }

          if (finding.aiExplanation.limitations) {
            const limitP = document.createElement("p");
            limitP.style.fontSize = "12px";
            limitP.style.color = "var(--text-3)";
            limitP.innerHTML = "<em>" + finding.aiExplanation.limitations + "</em>";
            aiBox.appendChild(limitP);
          }
        } else {
          const aiBadge = document.createElement("span");
          aiBadge.className = "ai-badge";
          aiBadge.textContent = finding.aiStatus === "unconfigured" ? "AI Not Configured" : "AI Pending";
          aiHeader.appendChild(aiBadge);
          aiBox.appendChild(aiHeader);

          const aiMsg = document.createElement("p");
          aiMsg.style.fontSize = "13px";
          aiMsg.style.color = "var(--text-2)";
          aiMsg.textContent = finding.aiError || (finding.aiStatus === "unconfigured"
            ? "Set GEMINI_API_KEY in .env to receive automated, step-by-step remediation advice and code examples."
            : "Remediation analysis was not generated.");
          aiBox.appendChild(aiMsg);

          const retryBtn = document.createElement("button");
          retryBtn.className = "ai-retry-btn";
          retryBtn.type = "button";
          retryBtn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg> Retry AI Analysis';
          retryBtn.addEventListener("click", function () {
            retryBtn.disabled = true;
            retryBtn.textContent = "Analyzing…";
            fetch(API_BASE + "/api/scan/" + encodeURIComponent(currentScanId) + "/retry-ai", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ findingId: finding.id }),
            })
              .then(function (r) { return r.json(); })
              .then(function (data) {
                if (data.scan && data.scan.findings) {
                  currentFindings = data.scan.findings;
                  renderFindings(false);
                  toast("AI remediation updated");
                } else if (data.error) {
                  toast("AI retry error: " + data.error);
                  retryBtn.disabled = false;
                  retryBtn.textContent = "Retry AI Analysis";
                }
              })
              .catch(function (e) {
                toast("AI retry failed: " + e.message);
                retryBtn.disabled = false;
                retryBtn.textContent = "Retry AI Analysis";
              });
          });
          aiBox.appendChild(retryBtn);
        }

        detailList.appendChild(aiBox);
      } else {
        detailRow("What we observed", finding.observation);
        detailRow("Recommended next step", finding.recommendation);
        detailRow("Evidence from sampled public response", finding.evidence, "evidence");
        if (finding.affectedUrl) detailRow("Affected URL", finding.affectedUrl);
        detailRow("Confidence", finding.confidence === "—" ? "Not available" :
          finding.confidence + ", based on the sampled public response.");
        detailRow("Source check category", finding.category);
      }

      const askAiBtn = document.createElement("button");
      askAiBtn.className = "ask-ai-finding-btn";
      askAiBtn.type = "button";
      askAiBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg> Ask AI About This Finding';
      askAiBtn.addEventListener("click", function (ev) {
        ev.stopPropagation();
        if (window.nectorAI) {
          window.nectorAI.openWithFinding(currentScanId, finding.id, finding.title || finding.name);
        }
      });
      detailList.appendChild(askAiBtn);

      const limit = document.createElement("p");
      limit.className = "finding-limit";
      limit.textContent = "Manual verification may be required.";
      detailList.appendChild(limit);

      detailInner.appendChild(detailList);
      detail.appendChild(detailInner);

      li.appendChild(toggle);
      li.appendChild(detail);
      if (withStagger && !prefersReducedMotion.matches) {
        li.classList.add("is-entering");
        li.style.animationDelay = ((shown - 1) * 45) + "ms";
      }
      list.appendChild(li);
    });

    $("#findings-empty").hidden = shown > 0;

    const countEl = $("#findings-count");
    if (countEl) {
      countEl.textContent = shown === currentFindings.length
        ? currentFindings.length + " checks reviewed"
        : shown + " of " + currentFindings.length + " checks shown";
    }
  }

  function renderCategorySummary(findings) {
    const wrap = $("#category-summary");
    if (!wrap) return;
    let chips = wrap.querySelector(".category-chips");
    if (!chips) {
      chips = document.createElement("ul");
      chips.className = "category-chips";
      wrap.appendChild(chips);
    }
    chips.textContent = "";

    const areas = [];
    findings.forEach(function (f) {
      let area = null;
      for (let i = 0; i < areas.length; i++) {
        if (areas[i].name === f.category) { area = areas[i]; break; }
      }
      if (!area) {
        area = { name: f.category, attention: 0, passed: 0 };
        areas.push(area);
      }
      if (f.status === "passed") area.passed += 1;
      else if (f.status !== "skipped") area.attention += 1;
    });

    areas.forEach(function (area) {
      const li = document.createElement("li");
      li.className = "category-chip";
      const dot = document.createElement("span");
      dot.className = "dot " + (area.attention === 0 ? "dot-safe" : "dot-medium");
      dot.setAttribute("aria-hidden", "true");
      li.appendChild(dot);
      li.appendChild(document.createTextNode(area.name + " · " +
        (area.attention === 0
          ? "all clear"
          : area.attention + (area.attention === 1 ? " finding" : " findings"))));
      chips.appendChild(li);
    });
  }

  function renderRecommendedActions(attention) {
    const list = $("#recommended-actions");
    list.textContent = "";
    const ranked = attention.slice().sort(function (a, b) {
      return SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    }).slice(0, 5);

    if (ranked.length === 0) {
      const li = document.createElement("li");
      const number = document.createElement("span");
      number.className = "action-number";
      number.textContent = "✓";
      const body = document.createElement("div");
      const p = document.createElement("p");
      p.textContent = "No immediate actions were identified in the sampled responses. Re-run the assessment after major changes.";
      body.appendChild(p);
      li.appendChild(number);
      li.appendChild(body);
      list.appendChild(li);
      return;
    }

    ranked.forEach(function (finding, index) {
      const li = document.createElement("li");
      const number = document.createElement("span");
      number.className = "action-number";
      number.textContent = String(index + 1).padStart(2, "0");
      const body = document.createElement("div");
      const h4 = document.createElement("h4");
      h4.textContent = finding.title;
      const p = document.createElement("p");
      p.textContent = finding.recommendation;
      body.appendChild(h4);
      body.appendChild(p);
      li.appendChild(number);
      li.appendChild(body);
      list.appendChild(li);
    });
  }

  /* ---------------- Results interactions ---------------- */

  $("#finding-list").addEventListener("click", function (event) {
    const toggle = event.target.closest(".finding-toggle");
    if (!toggle) return;
    const expanded = toggle.getAttribute("aria-expanded") === "true";
    toggle.setAttribute("aria-expanded", String(!expanded));
  });

  $("#finding-filters").addEventListener("click", function (event) {
    const button = event.target.closest(".filter");
    if (!button) return;
    currentFilter = button.dataset.filter;
    renderFilters();
    renderFindings(false);
  });

  $("#result-check-another").addEventListener("click", function () {
    const heroInput = $("#website-url");
    progressSection.hidden = true;
    resultsSection.hidden = true;
    scrollToElement($("#check"));
    setTimeout(function () { heroInput.focus(); }, prefersReducedMotion.matches ? 0 : 400);
  });

  $("#progress-new-check").addEventListener("click", function () {
    progressSection.hidden = true;
    scrollToElement($("#check"));
  });

  $("#failure-try-another").addEventListener("click", function () {
    progressSection.hidden = true;
    scrollToElement($("#check"));
  });

  $("#result-copy-link").addEventListener("click", function () {
    const shareUrl = location.origin + location.pathname + "?url=" + encodeURIComponent(currentTarget);
    const done = function () {
      toast("Report link copied to clipboard");
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(shareUrl).then(done, function () {
        toast("Could not copy — please copy the address bar link");
      });
    } else {
      const input = document.createElement("textarea");
      input.value = shareUrl;
      document.body.appendChild(input);
      input.select();
      try { document.execCommand("copy"); done(); } catch (err) { /* ignore */ }
      document.body.removeChild(input);
    }
  });

  $("#result-print").addEventListener("click", function () {
    window.print();
  });

  /* ---------------- Page chrome: header, menu, FAQ, reveal ---------------- */

  const header = $("#site-header");
  let scrollTicking = false;
  function onScroll() {
    if (scrollTicking) return;
    scrollTicking = true;
    requestAnimationFrame(function () {
      header.classList.toggle("is-scrolled", window.scrollY > 32);
      scrollTicking = false;
    });
  }
  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  const menuToggle = $("#menu-toggle");
  const siteNav = $("#site-nav");
  menuToggle.addEventListener("click", function () {
    const open = siteNav.classList.toggle("is-open");
    menuToggle.setAttribute("aria-expanded", String(open));
    menuToggle.setAttribute("aria-label", open ? "Close menu" : "Open menu");
  });
  siteNav.addEventListener("click", function (event) {
    if (event.target.closest("a")) {
      siteNav.classList.remove("is-open");
      menuToggle.setAttribute("aria-expanded", "false");
    }
  });
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && siteNav.classList.contains("is-open")) {
      siteNav.classList.remove("is-open");
      menuToggle.setAttribute("aria-expanded", "false");
      menuToggle.focus();
    }
  });

  $$(".faq-q").forEach(function (button) {
    button.addEventListener("click", function () {
      const item = button.closest(".faq-item");
      const open = button.getAttribute("aria-expanded") === "true";
      button.setAttribute("aria-expanded", String(!open));
      item.classList.toggle("is-open", !open);
    });
  });

  // Scroll reveal: one-time, 20% visibility, slight pre-trigger margin
  (function initReveal() {
    const items = $$("[data-reveal]");
    if (prefersReducedMotion.matches || !("IntersectionObserver" in window)) {
      items.forEach(function (el) { el.classList.add("is-visible"); });
      return;
    }
    const observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.2, rootMargin: "0px 0px -8% 0px" });
    items.forEach(function (el) { observer.observe(el); });
  })();

  // Decorative scan lines only run while their panel is on screen
  (function initInView() {
    const targets = $$("#scan-progress, .hero-visual");
    if (!("IntersectionObserver" in window)) {
      targets.forEach(function (el) { el.classList.add("is-inview"); });
      return;
    }
    const observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-inview");
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.1 });
    targets.forEach(function (el) { observer.observe(el); });
  })();

  // How-it-works timeline: the thin line fills as the section scrolls through
  (function initStepsTimeline() {
    const steps = $("[data-steps]");
    if (!steps || prefersReducedMotion.matches || !("IntersectionObserver" in window)) return;
    const items = $$(".step", steps);
    steps.classList.add("is-animated");
    let ticking = false;
    function update() {
      ticking = false;
      const rect = steps.getBoundingClientRect();
      const vh = window.innerHeight || 1;
      const ratio = Math.max(0, Math.min(1, (vh * 0.78 - rect.top) / Math.max(1, rect.height)));
      steps.style.setProperty("--steps-fill", ratio.toFixed(3));
      items.forEach(function (item, i) {
        item.classList.toggle("is-active", ratio >= (i + 0.5) / items.length);
      });
    }
    window.addEventListener("scroll", function () {
      if (!ticking) {
        ticking = true;
        requestAnimationFrame(update);
      }
    }, { passive: true });
    window.addEventListener("resize", update);
    update();
  })();

  /* ---------------- Boot ---------------- */

  $$(".check-form").forEach(wireCheckForm);

  // Prefill from ?url= (shared link)
  const prefill = params.get("url");
  if (prefill) {
    $$(".check-form .url-input").forEach(function (input) {
      input.value = prefill;
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
  }

  window.addEventListener("load", function () {
    document.body.classList.add("is-ready");
  });
  // Fallback if load already fired or takes too long
  setTimeout(function () { document.body.classList.add("is-ready"); }, 600);

  // Abort any in-flight assessment requests when the page is closed or hidden
  window.addEventListener("pagehide", function () {
    if (assessmentState.abort) assessmentState.abort.abort();
  });

  /* ---------------- Nector AI Security Assistant Chatbox ---------------- */

  (function initNectorAIChat() {
    const toggleBtn = $("#ai-chat-toggle");
    const panel = $("#ai-chat-panel");
    const closeBtn = $("#ai-chat-close-btn");
    const clearBtn = $("#ai-chat-clear-btn");
    const messagesEl = $("#ai-chat-messages");
    const chipsEl = $("#ai-chat-chips");
    const inputEl = $("#ai-chat-input");
    const sendBtn = $("#ai-chat-send");
    const contextBanner = $("#ai-chat-context-banner");
    const contextText = $("#ai-chat-context-text");
    const contextClearBtn = $("#ai-chat-context-clear");

    if (!toggleBtn || !panel || !inputEl || !sendBtn) return;

    let isOpen = false;
    let isLoading = false;
    let activeScanId = null;
    let activeFindingId = null;

    // Persistent session ID per browser tab
    let sessionId = "";
    try {
      sessionId = sessionStorage.getItem("nector_ai_session_id") || "";
      if (!sessionId) {
        sessionId = typeof crypto !== "undefined" && crypto.randomUUID
          ? crypto.randomUUID()
          : "nector-sess-" + Math.random().toString(36).slice(2, 10) + "-" + Date.now().toString(36);
        sessionStorage.setItem("nector_ai_session_id", sessionId);
      }
    } catch (e) {
      sessionId = "nector-sess-" + Math.random().toString(36).slice(2, 10);
    }

    function scrollMessagesToBottom() {
      if (messagesEl) {
        messagesEl.scrollTop = messagesEl.scrollHeight;
      }
    }

    function openPanel() {
      isOpen = true;
      panel.hidden = false;
      toggleBtn.setAttribute("aria-expanded", "true");
      inputEl.focus();
      scrollMessagesToBottom();
    }

    function closePanel() {
      isOpen = false;
      panel.hidden = true;
      toggleBtn.setAttribute("aria-expanded", "false");
    }

    function togglePanel() {
      if (isOpen) {
        closePanel();
      } else {
        openPanel();
      }
    }

    function setFindingContext(scanId, findingId, findingTitle) {
      activeScanId = scanId || currentScanId || null;
      activeFindingId = findingId || null;

      if (contextBanner && contextText) {
        contextText.textContent = "Focus: " + (findingTitle || "Selected Security Finding");
        contextBanner.style.display = "flex";
      }
      openPanel();
      inputEl.value = "How do I fix this finding (" + (findingTitle || "issue") + ") and verify the remediation?";
      updateInputState();
      inputEl.focus();
    }

    function clearFindingContext() {
      activeFindingId = null;
      if (contextBanner) {
        contextBanner.style.display = "none";
      }
    }

    function updateInputState() {
      const val = inputEl.value.trim();
      sendBtn.disabled = !val || isLoading;
      inputEl.style.height = "auto";
      inputEl.style.height = Math.min(inputEl.scrollHeight, 120) + "px";
    }

    // Safe formatting of AI markdown text without innerHTML on untrusted data
    function renderSafeMarkdown(rawText, container) {
      const codeBlockRegex = /```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g;
      let lastIndex = 0;
      let match;

      while ((match = codeBlockRegex.exec(rawText)) !== null) {
        const textBefore = rawText.slice(lastIndex, match.index);
        if (textBefore.trim()) {
          renderTextParagraphs(textBefore, container);
        }

        const lang = match[1];
        const code = match[2];
        const pre = document.createElement("pre");
        const codeEl = document.createElement("code");
        if (lang) codeEl.className = "language-" + lang;
        codeEl.textContent = code;
        pre.appendChild(codeEl);
        container.appendChild(pre);

        lastIndex = match.index + match[0].length;
      }

      const remainingText = rawText.slice(lastIndex);
      if (remainingText.trim()) {
        renderTextParagraphs(remainingText, container);
      }
    }

    function renderTextParagraphs(text, container) {
      const paras = text.split(/\n\s*\n/);
      paras.forEach(function (para) {
        const trimmed = para.trim();
        if (!trimmed) return;

        // Check for bullet list
        const lines = trimmed.split("\n");
        const isBulletList = lines.every(function (l) {
          const t = l.trim();
          return t.startsWith("- ") || t.startsWith("* ") || t.startsWith("• ");
        });

        if (isBulletList && lines.length > 0) {
          const ul = document.createElement("ul");
          lines.forEach(function (line) {
            const li = document.createElement("li");
            const clean = line.trim().replace(/^[-*•]\s+/, "");
            renderInlineCode(clean, li);
            ul.appendChild(li);
          });
          container.appendChild(ul);
        } else {
          const p = document.createElement("p");
          renderInlineCode(trimmed, p);
          container.appendChild(p);
        }
      });
    }

    function renderInlineCode(text, parent) {
      const parts = text.split(/(`[^`]+`)/g);
      parts.forEach(function (part) {
        if (part.startsWith("`") && part.endsWith("`") && part.length > 2) {
          const code = document.createElement("code");
          code.textContent = part.slice(1, -1);
          parent.appendChild(code);
        } else if (part) {
          parent.appendChild(document.createTextNode(part));
        }
      });
    }

    function appendMessage(role, text) {
      const msgWrap = document.createElement("div");
      msgWrap.className = "ai-msg ai-msg-" + role;

      const bubble = document.createElement("div");
      bubble.className = "ai-msg-bubble";

      renderSafeMarkdown(text, bubble);
      msgWrap.appendChild(bubble);

      const timeEl = document.createElement("span");
      timeEl.className = "ai-msg-time";
      const now = new Date();
      timeEl.textContent = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      msgWrap.appendChild(timeEl);

      if (role === "assistant") {
        const actions = document.createElement("div");
        actions.className = "ai-msg-actions";
        const copyBtn = document.createElement("button");
        copyBtn.className = "ai-copy-btn";
        copyBtn.type = "button";
        copyBtn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Copy';
        copyBtn.addEventListener("click", function () {
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(function () {
              copyBtn.textContent = "Copied!";
              setTimeout(function () {
                copyBtn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Copy';
              }, 2000);
            }).catch(function () {});
          }
        });
        actions.appendChild(copyBtn);
        msgWrap.appendChild(actions);
      }

      messagesEl.appendChild(msgWrap);
      scrollMessagesToBottom();
      return msgWrap;
    }

    let typingIndicatorEl = null;

    function showTypingIndicator() {
      if (typingIndicatorEl) return;
      typingIndicatorEl = document.createElement("div");
      typingIndicatorEl.className = "ai-msg ai-msg-assistant ai-typing-indicator-wrap";
      const bubble = document.createElement("div");
      bubble.className = "ai-msg-bubble ai-typing-indicator";
      bubble.innerHTML = '<span class="ai-typing-dot"></span><span class="ai-typing-dot"></span><span class="ai-typing-dot"></span>';
      typingIndicatorEl.appendChild(bubble);
      messagesEl.appendChild(typingIndicatorEl);
      scrollMessagesToBottom();
    }

    function removeTypingIndicator() {
      if (typingIndicatorEl && typingIndicatorEl.parentNode) {
        typingIndicatorEl.parentNode.removeChild(typingIndicatorEl);
      }
      typingIndicatorEl = null;
    }

    async function sendMessage(text) {
      const msg = (text || inputEl.value).trim();
      if (!msg || isLoading) return;

      if (chipsEl) chipsEl.style.display = "none";

      appendMessage("user", msg);
      inputEl.value = "";
      updateInputState();

      isLoading = true;
      sendBtn.disabled = true;
      inputEl.disabled = true;
      showTypingIndicator();

      const payload = {
        sessionId: sessionId,
        message: msg,
        scanId: activeScanId || currentScanId || null,
        findingId: activeFindingId || null,
      };

      try {
        const response = await fetch(API_BASE + "/api/chat", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Accept": "application/json",
          },
          body: JSON.stringify(payload),
        });

        const data = await response.json();
        removeTypingIndicator();

        if (response.ok && data.reply) {
          appendMessage("assistant", data.reply);
        } else if (data.unconfigured) {
          appendMessage("assistant", "⚠️ Google Gemini API key is not configured. Please add `GEMINI_API_KEY=your_key` in the `.env` file on the server to enable AI security responses.");
        } else {
          appendMessage("assistant", "⚠️ " + (data.error || "Unable to get an AI response right now. Please try again."));
        }
      } catch (err) {
        removeTypingIndicator();
        appendMessage("assistant", "⚠️ Network error: Could not connect to Nector chat service. Please ensure the server is running.");
        inputEl.value = msg; // Restore draft
      } finally {
        isLoading = false;
        inputEl.disabled = false;
        updateInputState();
        inputEl.focus();
      }
    }

    async function clearChat() {
      if (isLoading) return;
      try {
        await fetch(API_BASE + "/api/chat/clear", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sessionId: sessionId }),
        });
      } catch (e) {}

      messagesEl.innerHTML = "";
      appendMessage("assistant", "👋 Conversation cleared! What website security question can I help you with?");
      if (chipsEl) chipsEl.style.display = "flex";
      clearFindingContext();
    }

    // Event listeners
    toggleBtn.addEventListener("click", togglePanel);
    closeBtn.addEventListener("click", closePanel);
    clearBtn.addEventListener("click", clearChat);

    if (contextClearBtn) {
      contextClearBtn.addEventListener("click", clearFindingContext);
    }

    inputEl.addEventListener("input", updateInputState);

    inputEl.addEventListener("keydown", function (e) {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
      }
    });

    sendBtn.addEventListener("click", function () {
      sendMessage();
    });

    if (chipsEl) {
      chipsEl.addEventListener("click", function (e) {
        const chip = e.target.closest(".ai-chip");
        if (chip && chip.dataset.question) {
          sendMessage(chip.dataset.question);
        }
      });
    }

    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && isOpen) {
        closePanel();
      }
    });

    // Public hook for findings integration
    window.nectorAI = {
      openWithFinding: setFindingContext,
      open: openPanel,
      close: closePanel,
      toggle: togglePanel,
      send: sendMessage,
    };
  })();
})();
