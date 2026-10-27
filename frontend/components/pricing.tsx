import { Check, Clock } from "lucide-react";

const card =
  "flex h-full flex-col gap-4 rounded-2xl border border-ink/10 bg-white p-6 shadow-sm sm:p-8";

const plans = [
  {
    name: "Free",
    planned: ["Basic scans", "Clear reports"],
  },
  {
    name: "Pro",
    planned: ["Scheduled scans", "Scan history", "Report downloads"],
  },
];

function PlannedList({ items }: { items: string[] }) {
  return (
    <ul className="flex flex-col gap-2 text-sm text-muted">
      {items.map((item) => (
        <li key={item} className="flex items-start gap-2">
          <Check className="mt-0.5 h-4 w-4 shrink-0 text-ink" aria-hidden />
          <span>
            Planned: {item.charAt(0).toLowerCase() + item.slice(1)}
          </span>
        </li>
      ))}
    </ul>
  );
}

export function Pricing() {
  return (
    <section
      id="pricing"
      aria-labelledby="pricing-heading"
      className="scroll-mt-24 px-6 py-20 sm:py-24"
    >
      <div className="mx-auto w-full max-w-4xl">
        <h2
          id="pricing-heading"
          className="text-balance text-center text-3xl font-medium tracking-tight sm:text-4xl"
        >
          Pricing
        </h2>
        <p className="mx-auto mt-3 max-w-xl text-center text-sm text-muted sm:text-base">
          Both plans are coming soon. No prices are set and no payments are taken yet.
        </p>

        <div className="mt-10 grid gap-4 md:grid-cols-2">
          {plans.map(({ name, planned }) => (
            <div key={name} className={card}>
              <div className="flex items-center justify-between gap-3">
                <h3 className="text-xl font-medium text-ink">{name}</h3>
                <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/40 bg-amber-500/10 px-3 py-1 text-xs font-medium text-amber-700">
                  <Clock className="h-3.5 w-3.5" aria-hidden />
                  Coming soon
                </span>
              </div>
              <PlannedList items={planned} />
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
