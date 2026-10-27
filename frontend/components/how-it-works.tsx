import { Globe, ScanSearch, FlaskConical } from "lucide-react";

const card =
  "flex h-full flex-col gap-3 rounded-2xl border border-ink/10 bg-white p-6 text-left shadow-sm sm:p-8";

const steps = [
  {
    step: "Step 1",
    title: "Enter your website",
    text: "Type the address of a website you own or are allowed to test.",
    icon: Globe,
  },
  {
    step: "Step 2",
    title: "Run an authorized scan",
    text: "Confirm you have permission, and Nector checks the site for common issues.",
    icon: ScanSearch,
  },
  {
    step: "Step 3",
    title: "Understand your findings",
    text: "Get plain-language explanations and practical next steps for each risk.",
    icon: FlaskConical,
  },
];

export function HowItWorks() {
  return (
    <section
      id="how-it-works"
      aria-labelledby="how-it-works-heading"
      className="scroll-mt-24 px-6 py-20 sm:py-24"
    >
      <div className="mx-auto w-full max-w-6xl">
        <h2
          id="how-it-works-heading"
          className="text-balance text-center text-3xl font-medium tracking-tight sm:text-4xl"
        >
          How it works
        </h2>
        <p className="mx-auto mt-3 max-w-xl text-center text-sm text-muted sm:text-base">
          Three steps from a URL to a readable report.
        </p>

        <ol className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {steps.map(({ step, title, text, icon: Icon }) => (
            <li key={title} className={card}>
              <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-ink/10 bg-cream">
                <Icon className="h-5 w-5 text-ink" aria-hidden />
              </div>
              <p className="text-xs font-semibold uppercase tracking-wide text-muted">
                {step}
              </p>
              <h3 className="text-base font-medium text-ink">{title}</h3>
              <p className="text-sm text-muted">{text}</p>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}
