import Link from "next/link";
import { Shield, ArrowLeft, LayoutDashboard, Globe, AlertTriangle, GitFork, FileText, Search } from "lucide-react";

export default function NotFound() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col items-center justify-center p-6 selection:bg-blue-500 selection:text-white">
      {/* Background glowing gradient effects */}
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-72 h-72 bg-purple-600/10 rounded-full blur-3xl pointer-events-none" />

      <div className="max-w-xl w-full bg-slate-900/90 border border-slate-800 rounded-2xl p-8 relative shadow-2xl backdrop-blur-md text-center">
        {/* Badge & Icon */}
        <div className="inline-flex p-3 rounded-2xl bg-rose-500/10 border border-rose-500/20 text-rose-400 mb-4">
          <Shield className="h-10 w-10 text-rose-500 animate-pulse" />
        </div>

        <div className="inline-block px-3 py-1 bg-slate-800/80 border border-slate-700/60 rounded-full text-xs font-mono text-slate-400 mb-3 uppercase tracking-wider">
          HTTP 404 · Resource Unreachable
        </div>

        <h1 className="text-3xl md:text-4xl font-extrabold text-white tracking-tight mb-2">
          Target Route Not Found
        </h1>

        <p className="text-slate-400 text-sm mb-8 leading-relaxed">
          The endpoint, scan ID, or sub-path you attempted to access does not exist in the active scope or has been moved.
        </p>

        {/* Rapid Navigation Shortcuts */}
        <div className="grid grid-cols-2 gap-3 mb-8 text-left">
          <Link
            href="/dashboard"
            className="flex items-center gap-3 p-3 bg-slate-950/70 hover:bg-slate-800/80 border border-slate-800 hover:border-blue-500/50 rounded-xl transition-all group"
          >
            <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400 group-hover:text-blue-300">
              <LayoutDashboard className="h-4 w-4" />
            </div>
            <div>
              <div className="text-xs font-bold text-white group-hover:text-blue-400">Dashboard</div>
              <div className="text-[10px] text-slate-500">Security Command Center</div>
            </div>
          </Link>

          <Link
            href="/projects"
            className="flex items-center gap-3 p-3 bg-slate-950/70 hover:bg-slate-800/80 border border-slate-800 hover:border-cyan-500/50 rounded-xl transition-all group"
          >
            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 group-hover:text-cyan-300">
              <Globe className="h-4 w-4" />
            </div>
            <div>
              <div className="text-xs font-bold text-white group-hover:text-cyan-400">Targets</div>
              <div className="text-[10px] text-slate-500">Applications & Scope</div>
            </div>
          </Link>

          <Link
            href="/attack-paths"
            className="flex items-center gap-3 p-3 bg-slate-950/70 hover:bg-slate-800/80 border border-slate-800 hover:border-rose-500/50 rounded-xl transition-all group"
          >
            <div className="p-2 rounded-lg bg-rose-500/10 text-rose-400 group-hover:text-rose-300">
              <GitFork className="h-4 w-4" />
            </div>
            <div>
              <div className="text-xs font-bold text-white group-hover:text-rose-400">Attack Paths</div>
              <div className="text-[10px] text-slate-500">Multi-Stage Exploit Chains</div>
            </div>
          </Link>

          <Link
            href="/findings"
            className="flex items-center gap-3 p-3 bg-slate-950/70 hover:bg-slate-800/80 border border-slate-800 hover:border-purple-500/50 rounded-xl transition-all group"
          >
            <div className="p-2 rounded-lg bg-purple-500/10 text-purple-400 group-hover:text-purple-300">
              <AlertTriangle className="h-4 w-4" />
            </div>
            <div>
              <div className="text-xs font-bold text-white group-hover:text-purple-400">Findings</div>
              <div className="text-[10px] text-slate-500">Vulnerabilities & Fixes</div>
            </div>
          </Link>
        </div>

        {/* Primary Action Button */}
        <Link
          href="/dashboard"
          className="w-full bg-blue-600 hover:bg-blue-500 text-white font-medium py-2.5 px-4 rounded-xl flex items-center justify-center gap-2 transition-all shadow-lg shadow-blue-500/20"
        >
          <ArrowLeft className="h-4 w-4" /> Return to Security Dashboard
        </Link>
      </div>
    </div>
  );
}
