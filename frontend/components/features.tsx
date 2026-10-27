import {
  ListChecks,
  MessagesSquare,
  ArrowDownWideNarrow,
  FileDown,
} from "lucide-react";

const card = "flex h-full flex-col gap-3 rounded-2xl border border-ink/10 bg-white p-6 shadow-sm";

const plannedFeatures = [
  {
    title: "Common security checks",
    text: "Run a broad set of checks for the issues websites most often overlook.",
    icon: ListChecks,
  },
  {
    title: "Clear AI explanations",
    text: "Turn raw scanner output into plain language anyone can act on.",
    icon: MessagesSquare,
  },
  {
    title: "Prioritized findings",
    text: "See the most important risks first, ordered by severity.",
    icon: ArrowDownWideNarrow,
  },
  {
    title: "Downloadable reports",
    text: "Export results as documents you can keep or share with your team.",
    icon: FileDown,
  },
];

export function Features() {
  return (
    <section
      id="features"
      aria-labelledby="features-heading"
      className="scroll-mt-24 px-6 py-20 sm:py-24"
    >
      <div className="mx-auto w-full max-w-6xl">
        <h2
          id="features-heading"
          className="text-balance text-center text-3xl font-medium tracking-tight sm:text-4xl"
        >
          Features
        </h2>
        {/* Clearly marked as planned capabilities — none of these are implemented yet */}
        <p className="mx-auto mt-3 max-w-xl text-center text-sm text-muted sm:text-base">
          Planned capabilities — listed for transparency, not built yet.
        </p>

        <ul className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {plannedFeatures.map(({ title, text, icon: Icon }) => (
            <li key={title} className={card}>
              <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-ink/10 bg-cream">
                <Icon className="h-5 w-5 text-ink" aria-hidden />
              </div>
              <h3 className="text-base font-medium text-ink">{title}</h3>
              <p className="text-sm text-muted">{text}</p>
              <span className="mt-auto w-fit rounded-full border border-amber-500/40 bg-amber-500/10 px-2.5 py-0.5 text-xs font-medium text-amber-700">
                Planned
              </span>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
