import Link from "next/link";

export default function Home() {
  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 p-8 md:p-16">
      <div className="max-w-3xl mx-auto space-y-8">
        <div>
          <p className="text-sm uppercase tracking-widest text-emerald-400/90">
            AWS Audit Platform
          </p>
          <h1 className="text-4xl font-semibold mt-2">
            Well-Architected security &amp; cost insights
          </h1>
          <p className="text-slate-400 mt-4 leading-relaxed">
            Connect an AWS account via a read-only cross-account IAM role, run
            asynchronous audits, and review findings with charts and HTML
            reports. Control plane API keys stay on the server via the Next.js
            proxy.
          </p>
        </div>
        <div className="flex flex-wrap gap-4">
          <Link
            href="/onboarding"
            className="rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-medium px-5 py-2.5 transition-colors"
          >
            Onboard account
          </Link>
          <Link
            href="/dashboard"
            className="rounded-lg border border-slate-600 hover:border-slate-400 px-5 py-2.5 transition-colors"
          >
            Dashboard
          </Link>
        </div>
        <section className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 space-y-3">
          <h2 className="font-medium text-slate-200">Customer IAM</h2>
          <p className="text-sm text-slate-400">
            Use the policy template in the repository{" "}
            <code className="text-emerald-300">policies/auditor-policy.json</code>{" "}
            and trust your platform principal with{" "}
            <code className="text-emerald-300">sts:ExternalId</code>.
          </p>
        </section>
      </div>
    </main>
  );
}
