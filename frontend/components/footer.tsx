import { NectorMark } from "./nector-mark";

export function Footer() {
  return (
    <footer className="border-t border-ink/10 px-6 py-12">
      <div className="mx-auto flex max-w-6xl flex-col items-center gap-3 text-center">
        <span className="flex items-center gap-2 text-lg font-semibold tracking-tight">
          <NectorMark className="h-6 w-6 text-ink" aria-hidden />
          Nector
        </span>
        <p className="text-sm text-muted">Find risks. Understand fixes.</p>
        <p className="text-xs text-muted">
          Only test systems you are authorized to assess.
        </p>
      </div>
    </footer>
  );
}
