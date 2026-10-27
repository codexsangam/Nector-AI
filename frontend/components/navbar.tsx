"use client";

import { useEffect, useRef, useState } from "react";
import { Menu, X } from "lucide-react";
import { NectorMark } from "./nector-mark";

const navLinks = [
  { label: "How it works", href: "#how-it-works" },
  { label: "Features", href: "#features" },
  { label: "Pricing", href: "#pricing" },
];

const focusRing =
  "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ink";

export function Navbar() {
  const [open, setOpen] = useState(false);
  const menuButtonRef = useRef<HTMLButtonElement>(null);

  // Close the mobile menu with Escape and return focus to the button.
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        menuButtonRef.current?.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open]);

  return (
    <header className="sticky top-0 z-40 border-b border-ink/10 bg-cream/90 backdrop-blur-sm">
      <nav
        aria-label="Main navigation"
        className="mx-auto flex h-16 max-w-6xl items-center justify-between px-6"
      >
        {/* Left: logo + wordmark */}
        <a
          href="/"
          className={`flex items-center gap-2 rounded-lg text-lg font-semibold tracking-tight ${focusRing}`}
        >
          <NectorMark className="h-7 w-7 text-ink" />
          Nector
        </a>

        {/* Center: section links (desktop) */}
        <ul className="hidden items-center gap-8 md:flex">
          {navLinks.map((link) => (
            <li key={link.href}>
              <a
                href={link.href}
                className={`rounded-lg text-sm font-medium text-muted transition-colors hover:text-ink ${focusRing}`}
              >
                {link.label}
              </a>
            </li>
          ))}
        </ul>

        {/* Right: CTAs (desktop) */}
        <div className="hidden items-center gap-3 md:flex">
          <a
            href="#demo-report"
            className={`rounded-full border border-ink/20 bg-transparent px-4 py-2 text-sm font-medium transition-colors hover:border-ink/40 hover:bg-ink/5 ${focusRing}`}
          >
            Try demo
          </a>
          <a
            href="#scan"
            className={`rounded-full bg-ink px-4 py-2 text-sm font-medium text-cream transition-colors hover:bg-ink/85 ${focusRing}`}
          >
            Scan your website
          </a>
        </div>

        {/* Mobile menu button */}
        <button
          ref={menuButtonRef}
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          aria-controls="mobile-menu"
          aria-label={open ? "Close menu" : "Open menu"}
          className={`inline-flex h-10 w-10 items-center justify-center rounded-lg border border-ink/20 md:hidden ${focusRing}`}
        >
          {open ? (
            <X className="h-5 w-5" aria-hidden />
          ) : (
            <Menu className="h-5 w-5" aria-hidden />
          )}
        </button>
      </nav>

      {/* Mobile menu */}
      {open && (
        <div
          id="mobile-menu"
          className="border-t border-ink/10 bg-cream md:hidden"
        >
          <ul className="mx-auto flex max-w-6xl flex-col px-6 py-4">
            {navLinks.map((link) => (
              <li key={link.href}>
                <a
                  href={link.href}
                  onClick={() => setOpen(false)}
                  className={`block rounded-lg px-2 py-3 text-sm font-medium text-muted transition-colors hover:bg-ink/5 hover:text-ink ${focusRing}`}
                >
                  {link.label}
                </a>
              </li>
            ))}
          </ul>
          <div className="mx-auto flex max-w-6xl flex-col gap-3 px-6 pb-6">
            <a
              href="#demo-report"
              onClick={() => setOpen(false)}
              className={`rounded-full border border-ink/20 px-4 py-2.5 text-center text-sm font-medium transition-colors hover:bg-ink/5 ${focusRing}`}
            >
              Try demo
            </a>
            <a
              href="#scan"
              onClick={() => setOpen(false)}
              className={`rounded-full bg-ink px-4 py-2.5 text-center text-sm font-medium text-cream transition-colors hover:bg-ink/85 ${focusRing}`}
            >
              Scan your website
            </a>
          </div>
        </div>
      )}
    </header>
  );
}
