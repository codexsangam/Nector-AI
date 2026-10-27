/**
 * Nector logo mark — an original SVG recreation of the brand "N" mark:
 * two mirrored wave-like lobes separated by a thin diagonal slash.
 */
export function NectorMark({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 96 96"
      className={className}
      aria-hidden="true"
      focusable="false"
    >
      <g fill="currentColor">
        <path d="M15 27 C15 15 27 9 38 14 L47 19 C41.5 32 41.5 50 47 63 L47 71 C47 80 38.5 84.5 30.5 80 C20.5 74.5 15 64 15 52 Z" />
        <path d="M81 69 C81 81 69 87 58 82 L49 77 C54.5 64 54.5 46 49 33 L49 25 C49 16 57.5 11.5 65.5 16 C75.5 21.5 81 32 81 44 Z" />
      </g>
    </svg>
  );
}
