"use client";
import Link from "next/link";
import { Shield, Zap, Lock, BarChart3, ArrowRight, CheckCircle } from "lucide-react";

export default function HomePage() {
  return (
    <div className="min-h-screen bg-slate-950">
      {/* Navbar */}
      <nav className="border-b border-slate-800 px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-8 w-8 text-blue-500" />
            <span className="text-xl font-bold text-white">APT Agents</span>
          </div>
          <div className="flex items-center gap-4">
            <Link href="/auth/login" className="text-slate-400 hover:text-white transition-colors">
              Login
            </Link>
            <Link
              href="/auth/signup"
              className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg transition-colors font-medium"
            >
              Get Started Free
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="max-w-7xl mx-auto px-6 py-24 text-center">
        <div className="inline-flex items-center gap-2 bg-blue-950 border border-blue-800 text-blue-400 text-sm px-4 py-2 rounded-full mb-8">
          <Zap className="h-4 w-4" />
          AI-Powered Security Testing
        </div>
        <h1 className="text-5xl md:text-7xl font-bold text-white mb-6 leading-tight">
          Security Testing
          <span className="text-blue-500"> Automated.</span>
          <br />
          Results <span className="text-cyan-400">Verified.</span>
        </h1>
        <p className="text-xl text-slate-400 mb-12 max-w-3xl mx-auto">
          APT Agents uses 20 specialized AI agents to find vulnerabilities in your web applications.
          Browser-verified findings. Zero false positives. Professional PDF reports.
          <strong className="text-white"> In 30 minutes, not 4 weeks.</strong>
        </p>
        <div className="flex items-center justify-center gap-4 flex-wrap">
          <Link
            href="/auth/signup"
            className="bg-blue-600 hover:bg-blue-500 text-white px-8 py-4 rounded-xl text-lg font-semibold flex items-center gap-2 transition-colors"
          >
            Start Free Scan <ArrowRight className="h-5 w-5" />
          </Link>
          <Link
            href="#how-it-works"
            className="border border-slate-700 text-slate-300 hover:text-white px-8 py-4 rounded-xl text-lg transition-colors"
          >
            See How It Works
          </Link>
        </div>
      </section>

      {/* Stats */}
      <section className="border-y border-slate-800 py-12">
        <div className="max-w-7xl mx-auto px-6 grid grid-cols-2 md:grid-cols-4 gap-8 text-center">
          {[
            { label: "Security Agents", value: "20" },
            { label: "Vulnerabilities Checked", value: "OWASP Top 10+" },
            { label: "Scan Time", value: "< 30 min" },
            { label: "False Positives", value: "~0%" },
          ].map((stat) => (
            <div key={stat.label}>
              <div className="text-3xl font-bold text-blue-400 mb-2">{stat.value}</div>
              <div className="text-slate-500 text-sm">{stat.label}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Features */}
      <section id="how-it-works" className="max-w-7xl mx-auto px-6 py-24">
        <h2 className="text-4xl font-bold text-white text-center mb-16">
          How APT Agents Works
        </h2>
        <div className="grid md:grid-cols-3 gap-8">
          {[
            {
              icon: <Lock className="h-8 w-8 text-blue-500" />,
              title: "1. Verify Ownership",
              desc: "Add a DNS TXT record to prove you own the domain. We never test without authorization.",
            },
            {
              icon: <Zap className="h-8 w-8 text-cyan-400" />,
              title: "2. AI Agents Scan",
              desc: "20 specialized AI agents crawl and test your site for SQL injection, XSS, IDOR, SSRF, and more.",
            },
            {
              icon: <BarChart3 className="h-8 w-8 text-green-400" />,
              title: "3. Verified Report",
              desc: "Every finding is browser-verified by Playwright. Get a professional PDF with CVSS scores and fixes.",
            },
          ].map((f) => (
            <div key={f.title} className="bg-slate-900 border border-slate-800 rounded-2xl p-8">
              <div className="mb-4">{f.icon}</div>
              <h3 className="text-xl font-bold text-white mb-3">{f.title}</h3>
              <p className="text-slate-400">{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Pricing */}
      <section className="max-w-7xl mx-auto px-6 py-24">
        <h2 className="text-4xl font-bold text-white text-center mb-4">Simple Pricing</h2>
        <p className="text-slate-400 text-center mb-16">10x cheaper than manual pentesting</p>
        <div className="grid md:grid-cols-3 gap-8 max-w-5xl mx-auto">
          {[
            { plan: "Starter", price: "$49", scans: "5 scans/mo", color: "border-slate-700" },
            { plan: "Business", price: "$149", scans: "20 scans/mo", color: "border-blue-500", popular: true },
            { plan: "Enterprise", price: "$499", scans: "Unlimited", color: "border-slate-700" },
          ].map((p) => (
            <div key={p.plan} className={`bg-slate-900 border-2 ${p.color} rounded-2xl p-8 relative`}>
              {p.popular && (
                <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-blue-600 text-white text-xs px-4 py-1 rounded-full">
                  Most Popular
                </div>
              )}
              <div className="text-slate-400 mb-2">{p.plan}</div>
              <div className="text-4xl font-bold text-white mb-1">{p.price}</div>
              <div className="text-slate-500 text-sm mb-6">/month</div>
              <div className="flex items-center gap-2 text-slate-300">
                <CheckCircle className="h-5 w-5 text-green-400" />
                {p.scans}
              </div>
              <Link
                href="/auth/signup"
                className={`mt-6 block text-center py-3 rounded-xl font-medium transition-colors ${
                  p.popular
                    ? "bg-blue-600 hover:bg-blue-500 text-white"
                    : "border border-slate-700 text-slate-300 hover:text-white"
                }`}
              >
                Get Started
              </Link>
            </div>
          ))}
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-slate-800 py-8 text-center text-slate-500 text-sm">
        <div className="flex items-center justify-center gap-2 mb-2">
          <Shield className="h-5 w-5 text-blue-500" />
          <span className="text-white font-medium">APT Agents</span>
        </div>
        © 2026 Anas Technology. All rights reserved.
      </footer>
    </div>
  );
}
