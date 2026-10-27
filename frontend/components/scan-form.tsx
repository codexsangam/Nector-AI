"use client";

import { useState, type FormEvent } from "react";
import { ArrowRight, ShieldCheck, TriangleAlert } from "lucide-react";
import { focusRing } from "@/lib/focus-ring";

function validateUrl(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed) return "Please enter your website URL.";
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return "Enter a valid URL, e.g. https://yourwebsite.com.";
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return "Only HTTP or HTTPS URLs are accepted.";
  }
  return null;
}

export function ScanForm() {
  const [url, setUrl] = useState("");
  const [permission, setPermission] = useState(false);
  const [urlError, setUrlError] = useState<string | null>(null);
  const [permissionError, setPermissionError] = useState<string | null>(null);
  const [ready, setReady] = useState(false);

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setReady(false);

    const nextUrlError = validateUrl(url);
    const nextPermissionError = permission
      ? null
      : "Please confirm you own this website or have permission to test it.";

    setUrlError(nextUrlError);
    setPermissionError(nextPermissionError);

    if (!nextUrlError && !nextPermissionError) {
      setReady(true);
      // No request is made in this step — the backend is not wired yet.
    }
  }

  return (
    <section id="scan" aria-labelledby="scan-heading" className="scroll-mt-24 px-6 py-20 sm:py-24">
      <div className="mx-auto w-full max-w-3xl">
        <h2
          id="scan-heading"
          className="text-balance text-center text-3xl font-medium tracking-tight sm:text-4xl"
        >
          Check your website
        </h2>

        <form
          onSubmit={handleSubmit}
          noValidate
          className="mt-10 rounded-3xl border border-ink/10 bg-white p-6 shadow-sm sm:p-10"
        >
          {/* URL field */}
          <div className="flex flex-col gap-2">
            <label htmlFor="website-url" className="text-sm font-medium text-ink">
              Website URL
            </label>
            <input
              id="website-url"
              name="website-url"
              type="text"
              inputMode="url"
              autoComplete="url"
              spellCheck={false}
              placeholder="https://yourwebsite.com"
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                if (urlError) setUrlError(null);
              }}
              aria-invalid={urlError ? true : undefined}
              aria-describedby={urlError ? "website-url-error" : undefined}
              className={`w-full rounded-full border bg-cream/60 px-5 py-3 text-sm text-ink placeholder:text-muted/60 focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ink ${
                urlError ? "border-red-500/70" : "border-ink/15"
              }`}
            />
            {urlError && (
              <p id="website-url-error" role="alert" className="flex items-start gap-1.5 text-sm text-red-600">
                <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
                {urlError}
              </p>
            )}
          </div>

          {/* Permission checkbox */}
          <div className="mt-6 flex flex-col gap-2">
            <label
              htmlFor="scan-permission"
              className="flex cursor-pointer items-start gap-3 rounded-lg text-sm text-muted"
            >
              <input
                id="scan-permission"
                name="scan-permission"
                type="checkbox"
                checked={permission}
                onChange={(e) => {
                  setPermission(e.target.checked);
                  if (permissionError) setPermissionError(null);
                }}
                aria-invalid={permissionError ? true : undefined}
                aria-describedby={permissionError ? "scan-permission-error" : undefined}
                className={`mt-0.5 h-4 w-4 shrink-0 rounded border-ink/30 accent-ink ${
                  permissionError ? "outline-2 outline-offset-2 outline-red-500" : ""
                } ${focusRing}`}
              />
              <span>
                I own this website or have permission to test it.
              </span>
            </label>
            {permissionError && (
              <p id="scan-permission-error" role="alert" className="flex items-start gap-1.5 text-sm text-red-600">
                <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
                {permissionError}
              </p>
            )}
          </div>

          {/* Submit */}
          <div className="mt-8 sm:mt-10">
            <button
              type="submit"
              className={`inline-flex w-full items-center justify-center gap-2 rounded-full bg-ink px-6 py-3 text-sm font-medium text-cream transition-colors hover:bg-ink/85 sm:w-auto sm:text-base ${focusRing}`}
            >
              Start scan
              <ArrowRight className="h-4 w-4" aria-hidden />
            </button>
          </div>

          {/* Success / status message */}
          <div aria-live="polite">
            {ready && (
              <p className="mt-6 flex items-start gap-2 rounded-2xl border border-mint/80 bg-mint/40 px-4 py-3 text-sm text-ink">
                <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
                Scanning is not connected yet. You can explore the demo report below.
              </p>
            )}
          </div>
        </form>

        <p className="mx-auto mt-6 max-w-md text-center text-xs text-muted sm:text-sm">
          Nector never scans a website without your explicit confirmation, and this form
          only validates what you enter — nothing is contacted yet.
        </p>
      </div>
    </section>
  );
}
