"use client";

import React, { useState } from "react";
import Link from "next/link";
import { 
  Shield, 
  ShieldCheck, 
  ShieldAlert, 
  Globe, 
  Zap, 
  Lock, 
  CheckCircle2, 
  FileText, 
  Sparkles, 
  Terminal, 
  ArrowRight, 
  ChevronDown, 
  GitBranch, 
  Box, 
  CloudLightning, 
  HardDrive, 
  Download, 
  Check 
} from "lucide-react";

export default function GrayStrikeHomePage() {
  const [targetDomain, setTargetDomain] = useState("elixlumi.com");
  const [isScanning, setIsScanning] = useState(false);
  const [showResults, setShowResults] = useState(false);
  const [isPatched, setIsPatched] = useState(false);

  const handleRunAudit = (e: React.FormEvent) => {
    e.preventDefault();
    setIsScanning(true);
    setShowResults(false);
    setIsPatched(false);

    setTimeout(() => {
      setIsScanning(false);
      setShowResults(true);
      const resElem = document.getElementById("live-audit-result");
      if (resElem) {
        resElem.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }, 1200);
  };

  const handleApplyFix = () => {
    setIsPatched(true);
  };

  return (
    <div className="min-h-screen bg-[#070b12] text-slate-100 font-sans selection:bg-emerald-500 selection:text-black">
      
      {/* 1. NAVBAR */}
      <nav className="sticky top-0 z-50 bg-[#0c121e]/80 backdrop-blur-md border-b border-slate-800/80 px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <Link href="/" className="flex items-center space-x-3 group">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-emerald-500 via-teal-400 to-blue-500 p-0.5 shadow-lg shadow-emerald-500/20 group-hover:scale-105 transition-all">
              <div className="w-full h-full bg-[#090d16] rounded-[10px] flex items-center justify-center">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
              </div>
            </div>
            <div className="flex flex-col">
              <span className="text-xl font-bold tracking-tight text-white flex items-center gap-1.5">
                GrayStrike <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 uppercase tracking-widest font-mono">Agentic</span>
              </span>
            </div>
          </Link>

          <div className="hidden md:flex items-center space-x-8 text-sm font-medium text-slate-400">
            <a href="#how-it-works" className="hover:text-emerald-400 transition-colors">How It Works</a>
            <a href="#connectors" className="hover:text-emerald-400 transition-colors">Universal Connectors</a>
            <a href="#pricing" className="hover:text-emerald-400 transition-colors">Pricing</a>
            <a href="#faq" className="hover:text-emerald-400 transition-colors">FAQ</a>
          </div>

          <div className="flex items-center space-x-4">
            <Link href="/auth/login" className="hidden sm:inline-flex items-center text-sm font-medium text-slate-300 hover:text-white transition">
              Sign In
            </Link>
            <Link href="/dashboard" className="inline-flex items-center gap-2 px-5 py-2.5 text-sm font-semibold text-slate-950 bg-emerald-500 hover:bg-emerald-400 rounded-xl transition shadow-lg shadow-emerald-500/25">
              <span>Open Dashboard</span>
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </nav>

      {/* 2. HERO SECTION */}
      <header className="relative pt-20 pb-28 px-6 overflow-hidden">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[350px] bg-emerald-500/10 rounded-full blur-[140px] pointer-events-none"></div>

        <div className="max-w-5xl mx-auto text-center relative z-10">
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-slate-900/90 border border-emerald-500/30 text-emerald-400 text-xs font-semibold tracking-wide uppercase mb-8 shadow-inner shadow-emerald-500/10">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
            <span>2026 Autonomous Cyber AI • SMT Proof & Auto-Patch Engine</span>
          </div>

          <h1 className="text-4xl sm:text-6xl lg:text-7xl font-extrabold tracking-tight text-white leading-[1.1] mb-6">
            Traditional Scanners Give You a 50-Page PDF. <br className="hidden sm:block"/>
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 via-teal-300 to-cyan-400">
              GrayStrike Actually Fixes Your Website.
            </span>
          </h1>

          <p className="max-w-3xl mx-auto text-lg sm:text-xl text-slate-300 font-normal leading-relaxed mb-10">
            Meet the world’s first autonomous cybersecurity agent that detects vulnerabilities with mathematical evidence—and patches them in your code, WordPress, or Cloudflare with a single click.
          </p>

          {/* Interactive Audit Input */}
          <form onSubmit={handleRunAudit} className="max-w-2xl mx-auto p-2 rounded-2xl bg-slate-900/80 border border-slate-700/80 shadow-2xl backdrop-blur-xl">
            <div className="flex flex-col sm:flex-row items-center gap-2">
              <div className="flex items-center flex-1 w-full px-4 py-2.5 bg-slate-950/80 rounded-xl border border-slate-800">
                <Globe className="w-5 h-5 text-emerald-400 mr-3 shrink-0" />
                <input 
                  type="text" 
                  value={targetDomain} 
                  onChange={(e) => setTargetDomain(e.target.value)}
                  placeholder="Enter domain (e.g. elixlumi.com)" 
                  className="w-full bg-transparent text-white placeholder-slate-500 focus:outline-none font-mono text-sm"
                />
              </div>
              <button 
                type="submit" 
                disabled={isScanning}
                className="w-full sm:w-auto px-7 py-3 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold rounded-xl flex items-center justify-center gap-2 transition hover:scale-[1.02] active:scale-[0.98] shadow-lg shadow-emerald-500/25 shrink-0"
              >
                {isScanning ? (
                  <span className="flex items-center gap-2">
                    <span className="w-4 h-4 border-2 border-black border-t-transparent rounded-full animate-spin"></span>
                    <span>Scanning...</span>
                  </span>
                ) : (
                  <span className="flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4" />
                    <span>Audit & Auto-Fix</span>
                  </span>
                )}
              </button>
            </div>
          </form>

          <div className="mt-8 flex flex-wrap items-center justify-center gap-6 sm:gap-10 text-xs sm:text-sm text-slate-400 font-medium">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>100% Non-Intrusive & Safe</span>
            </div>
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-emerald-400" />
              <span>Zero Passwords or Root Needed</span>
            </div>
            <div className="flex items-center gap-2">
              <Zap className="w-4 h-4 text-emerald-400" />
              <span>95+ Vulnerability Checks in 10s</span>
            </div>
          </div>
        </div>
      </header>

      {/* 3. LIVE SIMULATION RESULT */}
      {showResults && (
        <section id="live-audit-result" className="py-12 px-6 max-w-6xl mx-auto transition-all duration-500">
          <div className="bg-slate-900/90 border border-emerald-500/40 rounded-3xl p-6 sm:p-8 backdrop-blur-xl shadow-2xl">
            
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between pb-6 border-b border-slate-800 gap-4">
              <div>
                <div className="flex items-center gap-3">
                  <span className={`px-3 py-1 rounded-full text-xs font-mono font-bold border flex items-center gap-1.5 ${
                    isPatched 
                      ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/40" 
                      : "bg-amber-500/20 text-amber-400 border-amber-500/40"
                  }`}>
                    <span className="w-2 h-2 rounded-full bg-current animate-pulse"></span>
                    {isPatched ? "POST-PATCH GRADE: A+ (100% Secure)" : "INITIAL GRADE: C+ (Moderate Risk)"}
                  </span>
                  <span className="font-mono text-white font-bold text-lg">https://{targetDomain.replace(/^https?:\/\//, "")}</span>
                </div>
                <p className="text-xs text-slate-400 mt-1">Hostinger Cloud CDN • Node.js (Express) Detected • Let's Encrypt Active</p>
              </div>

              <div className="flex items-center gap-3">
                <button 
                  onClick={() => alert("Downloading elixlumi.com_executive_security_audit.pdf")} 
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-xl text-xs font-semibold flex items-center gap-2 border border-slate-700"
                >
                  <FileText className="w-4 h-4 text-red-400" />
                  <span>Executive PDF</span>
                </button>
                <button 
                  onClick={handleApplyFix}
                  disabled={isPatched}
                  className={`px-5 py-2 rounded-xl text-xs font-bold flex items-center gap-2 shadow-lg transition ${
                    isPatched 
                      ? "bg-slate-800 text-emerald-400 border border-emerald-500/40" 
                      : "bg-emerald-500 hover:bg-emerald-400 text-slate-950 shadow-emerald-500/20"
                  }`}
                >
                  <Sparkles className="w-4 h-4" />
                  <span>{isPatched ? "✅ Patched via GitHub Pull Request #1" : "1-Click Auto-Fix All (A+)"}</span>
                </button>
              </div>
            </div>

            {/* Findings Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
              <div className="p-4 rounded-2xl bg-slate-950/80 border border-red-500/30">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-bold text-red-400 uppercase">HIGH • CWE-942</span>
                  <span className="text-xs text-slate-500 font-mono">SEC-001</span>
                </div>
                <h4 className="text-sm font-bold text-white mt-1">Permissive CORS Wildcard (`Origin: *`)</h4>
                <p className="text-xs text-slate-400 mt-1">Top-level root permits arbitrary domains to issue cross-origin requests and read sensitive responses.</p>
                <div className="mt-2 text-[11px] font-mono text-emerald-400 bg-emerald-950/40 px-2.5 py-1 rounded border border-emerald-800/40 inline-block">
                  Auto-Fix: Origin restricted to verified domain
                </div>
              </div>

              <div className="p-4 rounded-2xl bg-slate-950/80 border border-amber-500/30">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-bold text-amber-400 uppercase">MEDIUM • CWE-1021</span>
                  <span className="text-xs text-slate-500 font-mono">SEC-002</span>
                </div>
                <h4 className="text-sm font-bold text-white mt-1">Missing Clickjacking Defense (X-Frame-Options)</h4>
                <p className="text-xs text-slate-400 mt-1">Website can be framed inside hidden malicious iframes to trick users into unintentional clicks.</p>
                <div className="mt-2 text-[11px] font-mono text-emerald-400 bg-emerald-950/40 px-2.5 py-1 rounded border border-emerald-800/40 inline-block">
                  Auto-Fix: Injected X-Frame-Options: SAMEORIGIN
                </div>
              </div>
            </div>

            {/* Code Diff Preview */}
            <div className="mt-6 p-4 rounded-2xl bg-[#090d16] border border-slate-800 font-mono text-xs overflow-x-auto text-slate-300">
              <div className="flex items-center justify-between text-slate-400 pb-2 border-b border-slate-800 mb-3">
                <span className="flex items-center gap-2 text-emerald-400 font-bold">
                  <Terminal className="w-4 h-4" />
                  <span>Synthesized Minimal-Diff Patch (Ready to Merge)</span>
                </span>
                <span className="text-[11px]">server.js</span>
              </div>
              <pre className="text-slate-300 leading-relaxed">
                <code>
                  <span className="text-red-400">- app.use(cors(&#123; origin: '*' &#125;));</span><br/>
                  <span className="text-emerald-400">+ const helmet = require('helmet');</span><br/>
                  <span className="text-emerald-400">+ app.disable('x-powered-by');</span><br/>
                  <span className="text-emerald-400">+ app.use(cors(&#123; origin: ['https://{targetDomain}'], credentials: true &#125;));</span><br/>
                  <span className="text-emerald-400">+ app.use(helmet(&#123; hsts: &#123; maxAge: 31536000, preload: true &#125;, frameguard: &#123; action: 'sameorigin' &#125; &#125;));</span>
                </code>
              </pre>
            </div>

          </div>
        </section>
      )}

      {/* 4. UNIVERSAL CONNECTORS */}
      <section id="connectors" className="py-24 px-6 max-w-7xl mx-auto border-t border-slate-800/80">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <h2 className="text-xs font-bold font-mono tracking-widest uppercase text-emerald-400 mb-3">
            Zero Infrastructure Lock-In
          </h2>
          <p className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
            How GrayStrike Connects & Fixes Any Platform
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <div className="p-7 rounded-2xl bg-slate-900/60 border border-slate-800">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2.5 rounded-xl bg-blue-500/10 text-blue-400">
                <GitBranch className="w-5 h-5" />
              </div>
              <h4 className="font-bold text-white text-base">GitHub / GitLab</h4>
            </div>
            <p className="text-slate-400 text-xs leading-relaxed">
              Official GitHub App creates an isolated branch, commits minimal-diff fixes, and submits automated Pull Requests for developer approval.
            </p>
          </div>

          <div className="p-7 rounded-2xl bg-slate-900/60 border border-slate-800">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2.5 rounded-xl bg-purple-500/10 text-purple-400">
                <Box className="w-5 h-5" />
              </div>
              <h4 className="font-bold text-white text-base">WordPress & WooCommerce</h4>
            </div>
            <p className="text-slate-400 text-xs leading-relaxed">
              No developer needed. GrayStrike WP Connector hardens `.htaccess`, injects security headers, and locks down sensitive REST endpoints.
            </p>
          </div>

          <div className="p-7 rounded-2xl bg-slate-900/60 border border-slate-800">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2.5 rounded-xl bg-amber-500/10 text-amber-400">
                <CloudLightning className="w-5 h-5" />
              </div>
              <h4 className="font-bold text-white text-base">Cloudflare Edge (Universal)</h4>
            </div>
            <p className="text-slate-400 text-xs leading-relaxed">
              Zero code changes required. Injects HTTP Response Transform Rules at the Cloudflare edge in 30 seconds for Shopify or legacy PHP apps.
            </p>
          </div>
        </div>
      </section>

      {/* 5. FOOTER */}
      <footer className="py-8 px-6 border-t border-slate-800 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-emerald-400" />
            <span className="text-slate-400 font-semibold">GrayStrike Technologies Inc.</span>
            <span>© 2026. All rights reserved.</span>
          </div>
          <div className="flex items-center gap-6">
            <Link href="/privacy" className="hover:text-slate-300">Privacy Policy</Link>
            <Link href="/terms" className="hover:text-slate-300">Terms of Service</Link>
          </div>
        </div>
      </footer>

    </div>
  );
}
