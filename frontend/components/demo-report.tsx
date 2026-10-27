"use client";

import { ChevronDown, Info } from "lucide-react";
import {
  DEMO_TARGET,
  demoFindings,
  type Severity,
} from "@/lib/demo-report";
import { focusRing } from "@/lib/focus-ring";

const severityChip: Record<Severity, string> = {
  Medium: "border-amber-500/40 bg-amber-500/10 text-amber-700",
  Low: "border-ink/15 bg-ink/5 text-muted",
};

function Counts() {
  // Summary counts are calculated from the sample findings — no score is invented.
  const counts = new Map<Severity, number>();
  for (const finding of demoFindings) {
    counts.set(finding.severity, (counts.get(finding.severity) ?? 0) + 1);
  }
  return (
    <ul className="flex flex-wrap items-center gap-2" aria-label="Finding counts">
      <li className="rounded-full border border-ink/15 bg-ink/5 px-3 py-1 text-xs font-medium text-muted">
        {demoFindings.length} findings
      </li>
      {(["Medium", "Low"] as Severity[]).flatMap((severity) => {
        const count = counts.get(severity);
        if (!count) return [];
        return (
          <li
            key={severity}
            className={`rounded-full border px-3 py-1 text-xs font-medium ${severityChip[severity]}`}
          >
            {count} {severity.toLowerCase()}
          </li>
        );
      })}
    </ul>
  );
}

export function DemoReport() {
  return (
    <section
      id="demo-report"
      aria-labelledby="demo-report-heading"
      className="scroll-mt-24 px-6 py-20 sm:py-24"
    >
      <div className="mx-auto w-full max-w-3xl">
        <h2
          id="demo-report-heading"
          className="text-balance text-center text-3xl font-medium tracking-tight sm:text-4xl"
        >
          Demo report
        </h2>

        <div className="mt-10 rounded-3xl border border-ink/10 bg-white p-6 shadow-sm sm:p-10">
          {/* Prominent sample notice */}
          <p className="flex items-start gap-2 rounded-2xl border border-lavender/80 bg-lavender/40 px-4 py-3 text-sm font-medium text-ink">
            <Info className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
            Sample report — illustrative data, not a live scan.
          </p>

          {/* Target + counts */}
          <div className="mt-6 flex flex-wrap items-center justify-between gap-4">
            <p className="text-sm text-muted">
              Sample target:{" "}
              <span className="rounded-md bg-cream px-2 py-0.5 font-mono text-sm text-ink">
                {DEMO_TARGET}
              </span>
            </p>
            <Counts />
          </div>

          {/* Expandable finding cards (native details/summary: keyboard accessible) */}
          <ul className="mt-6 flex flex-col gap-4">
            {demoFindings.map((finding) => (
              <li key={finding.id}>
                <details className="group rounded-2xl border border-ink/10 bg-cream/50 transition-colors open:bg-white">
                  <summary
                    className={`flex cursor-pointer list-none items-center justify-between gap-4 rounded-2xl px-4 py-3.5 transition-colors hover:bg-ink/5 ${focusRing}`}
                  >
                    <span className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
                      <span className="text-sm font-medium text-ink sm:text-base">
                        {finding.title}
                      </span>
                      <span
                        className={`shrink-0 rounded-full border px-2.5 py-0.5 text-xs font-medium ${severityChip[finding.severity]}`}
                      >
                        {finding.severity}
                      </span>
                    </span>
                    <ChevronDown
                      className="h-4 w-4 shrink-0 text-muted transition-transform group-open:rotate-180"
                      aria-hidden
                    />
                  </summary>
                  <div className="flex flex-col gap-4 border-t border-ink/10 px-4 py-4 text-sm">
                    <div>
                      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">
                        Explanation
                      </h3>
                      <p className="mt-1 text-muted">{finding.explanation}</p>
                    </div>
                    <div>
                      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">
                        Example evidence
                      </h3>
                      <pre className="mt-1 overflow-x-auto rounded-xl bg-cream px-3 py-2 font-mono text-xs text-ink">
{finding.evidence}
                      </pre>
                      <p className="mt-1 text-xs text-muted">
                        Sample text for illustration — not captured from a live site.
                      </p>
                    </div>
                    <div>
                      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">
                        Recommended action
                      </h3>
                      <p className="mt-1 text-muted">{finding.recommendation}</p>
                    </div>
                  </div>
                </details>
              </li>
            ))}
          </ul>
        </div>

        <p className="mx-auto mt-6 max-w-md text-center text-xs text-muted sm:text-sm">
          Curious what a real scan looks like? Try the scanner once your site is
          connected — every real report comes from an actual scan.
        </p>
      </div>
    </section>
  );
}
