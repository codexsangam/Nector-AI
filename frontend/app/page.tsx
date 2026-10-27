import { ArrowRight, FileText } from "lucide-react";
import { Navbar } from "@/components/navbar";
import { ScanForm } from "@/components/scan-form";
import { DemoReport } from "@/components/demo-report";
import { HowItWorks } from "@/components/how-it-works";
import { Features } from "@/components/features";
import { Pricing } from "@/components/pricing";
import { Footer } from "@/components/footer";

const focusRing =
  "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ink";

export default function Home() {
  return (
    <>
      <Navbar />

      <main className="mx-auto flex max-w-6xl flex-col items-center px-6 pb-28 pt-16 text-center sm:pt-24">
        {/* Badge */}
        <span className="inline-flex items-center gap-2 rounded-full border border-ink/15 bg-cream px-4 py-1.5 text-xs font-medium text-muted sm:text-sm">
          Website security, made understandable
        </span>

        {/* Heading */}
        <h1 className="text-balance text-4xl font-medium leading-[1.1] tracking-tight sm:text-6xl lg:text-7xl">
          <span className="block">Find the risks.</span>
          <span className="mt-2 block">
            <span className="inline-block -rotate-1 rounded-lg bg-coral-soft px-4 py-1 text-ink sm:px-5">
              Understand the fixes.
            </span>
          </span>
        </h1>

        {/* Description */}
        <p className="max-w-2xl text-balance text-base text-muted sm:text-lg">
          Nector checks your website for common security issues and turns
          technical findings into clear explanations and practical next steps.
        </p>

        {/* CTAs */}
        <div className="flex flex-col gap-3 sm:flex-row sm:gap-4">
          <a
            href="#scan"
            className={`inline-flex items-center justify-center gap-2 rounded-full bg-ink px-6 py-3 text-sm font-medium text-cream transition-colors hover:bg-ink/85 sm:text-base ${focusRing}`}
          >
            Scan your website
            <ArrowRight className="h-4 w-4" aria-hidden />
          </a>
          <a
            href="#demo-report"
            className={`inline-flex items-center justify-center gap-2 rounded-full border border-ink/20 px-6 py-3 text-sm font-medium text-ink transition-colors hover:border-ink/40 hover:bg-ink/5 sm:text-base ${focusRing}`}
          >
            View demo report
            <FileText className="h-4 w-4" aria-hidden />
          </a>
        </div>

        {/* Fine print */}
        <p className="mt-2 text-xs text-muted sm:text-sm">
          Only scan websites you own or have permission to test.
        </p>
      </main>

      <ScanForm />

      <DemoReport />

      <HowItWorks />
      <Features />
      <Pricing />
      <Footer />
    </>
  );
}
