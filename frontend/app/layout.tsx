import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Nector — AI-powered website vulnerability tester",
  description:
    "Nector scans websites for vulnerabilities and turns security findings into simple, actionable reports.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="bg-cream font-sans text-ink antialiased">
        {/* Soft background glows: lavender upper-left, mint right */}
        <div
          aria-hidden
          className="pointer-events-none fixed inset-0 -z-10 overflow-hidden"
        >
          <div className="absolute -top-24 -left-24 h-[36rem] w-[36rem] rounded-full bg-lavender opacity-60 blur-3xl" />
          <div className="absolute top-1/3 -right-32 h-[34rem] w-[34rem] rounded-full bg-mint opacity-60 blur-3xl" />
        </div>
        {children}
      </body>
    </html>
  );
}
