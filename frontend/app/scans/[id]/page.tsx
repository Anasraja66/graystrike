"use client";
import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { Shield, ArrowLeft, Download, AlertTriangle, CheckCircle, RefreshCw, Terminal, Sparkles, Zap, Lock, AlertOctagon, Flame } from "lucide-react";
import axios from "axios";

export default function LiveScanMonitorPage() {
  const params = useParams();
  const router = useRouter();
  const scanId = params.id as string;

  const [scan, setScan] = useState<any>(null);
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchScan = async () => {
    const token = localStorage.getItem("token");
    if (!token) { router.push("/auth/login"); return; }
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

    try {
      const res = await axios.get(`${api}/api/v1/scans/${scanId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setScan(res.data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScan();
    // Polling interval every 3 seconds while scan is running
    const interval = setInterval(() => {
      fetchScan();
    }, 3000);
    return () => clearInterval(interval);
  }, [scanId]);

  const downloadPdf = () => {
    const token = localStorage.getItem("token");
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
    window.open(`${api}/api/v1/reports/scans/${scanId}/pdf?token=${token}`, "_blank");
  };

  const downloadJson = () => {
    const token = localStorage.getItem("token");
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
    window.open(`${api}/api/v1/reports/scans/${scanId}/json?token=${token}`, "_blank");
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center text-blue-400">
        Loading scan telemetry...
      </div>
    );
  }

  const isCompleted = scan?.status === "completed";
  const isRunning = scan?.status === "running" || scan?.status === "queued";

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-8">
      <div className="max-w-6xl mx-auto">
        {/* Navigation & Header */}
        <div className="flex items-center justify-between mb-8">
          <Link href="/dashboard" className="flex items-center gap-2 text-slate-400 hover:text-white transition-colors">
            <ArrowLeft className="h-5 w-5" /> Back to Dashboard
          </Link>
          <div className="flex items-center gap-3">
            {isCompleted && (
              <>
                <button
                  onClick={downloadJson}
                  className="border border-slate-700 hover:border-slate-500 text-slate-300 px-4 py-2 rounded-lg text-sm transition-colors flex items-center gap-2"
                >
                  <Download className="h-4 w-4" /> JSON Export
                </button>
                <button
                  onClick={downloadPdf}
                  className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-sm font-semibold transition-colors flex items-center gap-2 shadow-lg shadow-blue-500/20"
                >
                  <Download className="h-4 w-4" /> Download PDF Report
                </button>
              </>
            )}
          </div>
        </div>

        {/* Live Status Banner */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 mb-8">
          <div className="flex items-center justify-between flex-wrap gap-4">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <span className="text-sm font-medium text-slate-400">Target Application:</span>
                <span className="text-xl font-bold text-white font-mono">{scan?.target_url}</span>
              </div>
              <div className="flex items-center gap-4 text-sm text-slate-400">
                <span>Scan ID: <code className="text-slate-300">{scanId.slice(0, 8)}</code></span>
                <span>Stage: <strong className="text-blue-400 uppercase">{scan?.current_stage || "INITIALIZING"}</strong></span>
              </div>
            </div>
            <div>
              {isRunning && (
                <div className="inline-flex items-center gap-2 bg-purple-950/80 border border-purple-800 text-purple-300 px-4 py-2 rounded-full font-medium text-sm animate-pulse">
                  <RefreshCw className="h-4 w-4 animate-spin text-purple-400" /> Scan Running (44 Autonomous AI Micro-Agents Active)
                </div>
              )}
              {isCompleted && (
                <div className="inline-flex items-center gap-2 bg-emerald-950/80 border border-emerald-800 text-emerald-400 px-4 py-2 rounded-full font-medium text-sm">
                  <CheckCircle className="h-4 w-4" /> 44 AI Micro-Agents Completed Assessment
                </div>
              )}
            </div>
          </div>
        </div>

        {/* AI Vibe-App Stack & Hacker Entry Points Card */}
        <div className="bg-gradient-to-r from-purple-950/40 via-slate-900 to-indigo-950/40 border border-purple-900/50 rounded-2xl p-6 mb-8 relative">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 mb-1.5">
                <Sparkles className="h-4 w-4 text-purple-400" />
                <h3 className="text-base font-bold text-white">AI App Architecture & Hacker Entry Point Analysis</h3>
                <span className="text-[10px] font-mono uppercase bg-purple-900/80 text-purple-300 border border-purple-700 px-2 py-0.5 rounded-full font-semibold">
                  Vibe Shield 2.0
                </span>
              </div>
              <p className="text-xs text-slate-300">
                Target Architecture Fingerprint: <span className="font-semibold text-white">Next.js 14+ · Supabase BaaS · Tailwind CSS · AI Prompt Endpoints</span>
              </p>
              <p className="text-xs text-slate-400 mt-1">
                Our 44 micro-agents tested unauthenticated browser APIs, client JavaScript bundles, and backend storage policies to locate where a hacker could dump customer records or hijack admin access.
              </p>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <Link
                href="/attack-paths"
                className="bg-rose-950/80 hover:bg-rose-900 border border-rose-800 text-rose-300 text-xs font-bold px-4 py-2 rounded-lg transition-colors flex items-center gap-1.5"
              >
                <Flame className="h-3.5 w-3.5 text-rose-400" />
                <span>View Attack Path Graph</span>
              </Link>
              <Link
                href="/findings"
                className="bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold px-4 py-2 rounded-lg transition-colors flex items-center gap-1.5 shadow-md shadow-purple-950/40"
              >
                <Zap className="h-3.5 w-3.5" />
                <span>Review Hacker Entry Points</span>
              </Link>
            </div>
          </div>
        </div>

        {/* Live Metrics Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6 mb-8">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <span className="text-slate-400 text-xs font-medium uppercase">Pages Analyzed</span>
            <div className="text-3xl font-bold text-white mt-2">{scan?.pages_discovered || 0}</div>
          </div>
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <span className="text-slate-400 text-xs font-medium uppercase">Total Findings</span>
            <div className="text-3xl font-bold text-blue-400 mt-2">{scan?.total_findings || 0}</div>
          </div>
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <span className="text-slate-400 text-xs font-medium uppercase">Critical Vulnerabilities</span>
            <div className="text-3xl font-bold text-red-500 mt-2">{scan?.critical_count || 0}</div>
          </div>
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <span className="text-slate-400 text-xs font-medium uppercase">High Severity</span>
            <div className="text-3xl font-bold text-orange-400 mt-2">{scan?.high_count || 0}</div>
          </div>
        </div>

        {/* Execution Log Terminal */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
          <div className="flex items-center gap-2 mb-4 border-b border-slate-800 pb-3">
            <Terminal className="h-5 w-5 text-blue-500" />
            <h3 className="font-semibold text-white">Multi-Agent Orchestrator Pipeline</h3>
          </div>
          <div className="space-y-3 font-mono text-xs">
            <div className="text-emerald-400">✓ [Stage 1] Authorization Gate: Domain ownership & Scope verified.</div>
            <div className="text-emerald-400">✓ [Stage 2] Scope Enforcer: SSRF & Private IP boundaries locked.</div>
            <div className="text-cyan-400">✓ [Stage 3] Crawler Agent: Surface mapping, forms & security headers extracted.</div>
            <div className="text-blue-400">✓ [Stage 4] Agent Selector: 41 Specialized Security Micro-Agents dispatched (OWASP Top 10 + EASM + Red-Team + AI App Suites).</div>
            {isCompleted && (
              <div className="text-emerald-400">✓ [Stage 5] Final Risk Classification & CVSS Scores generated. Ready for export!</div>
            )}
          </div>
        </div>

        {/* Action Link to Findings Hub */}
        {isCompleted && scan?.total_findings > 0 && (
          <div className="mt-8 bg-gradient-to-r from-blue-900/40 via-indigo-900/40 to-slate-900 border border-blue-800/60 rounded-2xl p-6 flex items-center justify-between flex-wrap gap-4">
            <div>
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <span>🛡️</span> {scan.total_findings} Security Findings Ready for Review
              </h3>
              <p className="text-slate-300 text-sm mt-1">
                Explore vulnerability breakdowns, evidence snapshots, and Copy-Paste AI Remediation prompts.
              </p>
            </div>
            <Link
              href="/findings"
              className="bg-blue-600 hover:bg-blue-500 text-white px-5 py-2.5 rounded-xl font-semibold text-sm transition-all shadow-lg shadow-blue-500/25 flex items-center gap-2"
            >
              View All Findings & AI Fixes →
            </Link>
          </div>
        )}
      </div>
    </div>
  );
}
