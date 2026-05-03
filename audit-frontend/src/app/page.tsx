import Image from "next/image";
import Link from "next/link";

import { SiteHeader } from "@/components/SiteHeader";

export default function Home() {
  return (
    <div className="min-h-screen flex flex-col">
      <SiteHeader
        nav={[
          { href: "/onboarding", label: "Onboard" },
          { href: "/dashboard", label: "Dashboard" },
        ]}
      />
      <main className="flex-1 max-w-4xl mx-auto w-full px-4 sm:px-6 py-12 md:py-16 space-y-12">
        <section className="space-y-6">
          <p className="text-xs uppercase tracking-[0.2em] text-aws-orange font-medium">
            Autonomous audit pipeline
          </p>
          <h1 className="text-4xl md:text-5xl font-semibold tracking-tight text-white leading-tight">
            Well-Architected security &amp; cost insights
          </h1>
          <p className="text-slate-400 leading-relaxed text-lg max-w-2xl">
            Connect accounts through a read-only cross-account IAM role, execute collector-backed checks aligned with CSPM-style
            posture reviews, and review grouped findings with production-grade remediation playbooks — deterministic rules stay the source
            of truth.
          </p>
          <div className="flex flex-wrap gap-4 pt-2">
            <Link
              href="/onboarding"
              className="rounded-xl bg-aws-orange hover:bg-[var(--accent-muted)] text-aws-ink font-semibold px-6 py-3 transition-colors shadow-lg shadow-black/30"
            >
              Onboard account
            </Link>
            <Link
              href="/dashboard"
              className="rounded-xl border border-[var(--border)] hover:bg-[var(--panel)] px-6 py-3 font-medium text-slate-200 transition-colors"
            >
              Open dashboard
            </Link>
          </div>
        </section>

        <section className="grid md:grid-cols-3 gap-4">
          {[
            {
              title: "Security first",
              body: "IAM, GuardDuty, KMS, RDS, network exposure, CloudTrail integrity, and data perimeter signals collected with graceful degradation.",
            },
            {
              title: "Cost discipline",
              body: "Cost Explorer, Budgets, Trusted Advisor hooks, and EC2 waste signals (EIPs, detached EBS, stopped fleets).",
            },
            {
              title: "Operator UX",
              body: "Findings stay behind pillar → severity groups with pagination — no wall of JSON until you expand a row.",
            },
          ].map((card) => (
            <div
              key={card.title}
              className="rounded-2xl border border-[var(--border)] bg-[var(--panel)]/55 p-5 flex flex-col gap-3 shadow-xl shadow-black/20 relative overflow-hidden"
            >
              <div className="absolute -right-2 -top-2 h-16 w-16 opacity-[0.12] pointer-events-none">
                <Image
                  src="https://a0.awsstatic.com/libra-css/images/logos/aws_logo_smile_1200x630.png"
                  alt=""
                  fill
                  className="object-contain"
                  sizes="64px"
                />
              </div>
              <h2 className="font-semibold text-white relative">{card.title}</h2>
              <p className="text-sm text-slate-400 leading-relaxed flex-1 relative">{card.body}</p>
            </div>
          ))}
        </section>

        <section className="rounded-2xl border border-[var(--border)] bg-[var(--panel)]/40 p-6 md:p-8 space-y-3">
          <h2 className="font-medium text-white">Customer IAM</h2>
          <p className="text-sm text-slate-400 leading-relaxed">
            Ship the template in{" "}
            <code className="text-aws-orange/95 font-mono text-xs">policies/auditor-policy.json</code> and trust your platform principal with a scoped{" "}
            <code className="text-aws-orange/95 font-mono text-xs">sts:ExternalId</code>. No long-lived
            access keys on analyst workstations.
          </p>
        </section>
      </main>
    </div>
  );
}
