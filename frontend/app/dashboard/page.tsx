"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Shield, Plus, Globe, Scan, AlertTriangle, CheckCircle, Clock, LogOut, CreditCard, Key, Sparkles, ArrowRight, Zap, Lock, Flame, GitFork } from "lucide-react";
import axios from "axios";

export default function DashboardPage() {
  const router = useRouter();
  const [user, setUser] = useState<any>(null);
  const [projects, setProjects] = useState<any[]>([]);
  const [scans, setScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem("token");
    const userData = localStorage.getItem("user");
    if (!token) { router.push("/auth/login"); return; }
    if (userData) setUser(JSON.parse(userData));

    const headers = { Authorization: `Bearer ${token}` };
    const api = process.env.NEXT_PUBLIC_API_URL;

    Promise.all([
      axios.get(`${api}/api/v1/projects/`, { headers }),
      axios.get(`${api}/api/v1/scans/`, { headers }),
    ]).then(([p, s]) => {
      setProjects(p.data);
      setScans(s.data);
    }).catch(() => {
      localStorage.clear();
      router.push("/auth/login");
    }).finally(() => setLoading(false));
  }, []);

  const logout = () => { localStorage.clear(); router.push("/"); };

  const statusColor: Record<string, string> = {
    completed: "text-green-400",
    running: "text-blue-400",
    queued: "text-yellow-400",
    failed: "text-red-400",
    cancelled: "text-slate-400",
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="text-blue-400 text-xl">Loading...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950">
      {/* Sidebar */}
      <div className="fixed left-0 top-0 h-full w-64 bg-slate-900 border-r border-slate-800 flex flex-col">
        <div className="p-6 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Shield className="h-7 w-7 text-blue-500" />
            <span className="font-bold text-white text-lg">APT Agents</span>
          </div>
          <div className="text-slate-400 text-sm mt-1">{user?.org_name}</div>
        </div>
        <nav className="flex-1 p-4 space-y-1">
          {[
            { href: "/dashboard", icon: <Globe className="h-5 w-5" />, label: "Dashboard" },
            { href: "/projects", icon: <Globe className="h-5 w-5" />, label: "Projects" },
            { href: "/scans", icon: <Scan className="h-5 w-5" />, label: "Scans" },
            { href: "/findings", icon: <AlertTriangle className="h-5 w-5" />, label: "Findings" },
            { href: "/attack-paths", icon: <GitFork className="h-5 w-5 text-rose-400" />, label: "Attack Paths (Wiz)" },
            { href: "/attack-surface", icon: <Globe className="h-5 w-5 text-cyan-400" />, label: "Attack Surface (EASM)" },
            { href: "/reports", icon: <CheckCircle className="h-5 w-5" />, label: "Reports" },
            { href: "/settings/api-keys", icon: <Key className="h-5 w-5" />, label: "CI/CD & API Keys" },
            { href: "/settings/billing", icon: <CreditCard className="h-5 w-5" />, label: "Billing & Alerts" },
          ].map((item) => (
            <Link key={item.href} href={item.href}
              className="flex items-center gap-3 text-slate-400 hover:text-white hover:bg-slate-800 px-3 py-2.5 rounded-lg transition-colors">
              {item.icon}
              {item.label}
            </Link>
          ))}
        </nav>
        <div className="p-4 border-t border-slate-800">
          <div className="text-sm text-slate-400 mb-1">{user?.full_name}</div>
          <div className="text-xs text-slate-600">{user?.email}</div>
          <button onClick={logout}
            className="flex items-center gap-2 text-slate-400 hover:text-red-400 mt-3 text-sm transition-colors">
            <LogOut className="h-4 w-4" /> Logout
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div className="ml-64 p-8">
        <div className="flex items-center justify-between mb-8">
          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          <Link href="/projects/new"
            className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg flex items-center gap-2 transition-colors">
            <Plus className="h-5 w-5" /> New Project
          </Link>
        </div>

        {/* AI Vibe-App Hacker Entry Inspector Feature Card */}
        <div className="bg-gradient-to-r from-purple-950/70 via-indigo-950/50 to-slate-900 border border-purple-800/60 rounded-2xl p-6 mb-8 relative overflow-hidden shadow-2xl shadow-purple-950/30">
          <div className="absolute top-0 right-0 w-80 h-80 bg-purple-600/10 rounded-full blur-3xl pointer-events-none" />
          <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
            <div className="max-w-2xl">
              <div className="flex items-center gap-2 mb-2 flex-wrap">
                <span className="text-[10px] font-mono uppercase bg-purple-900/80 text-purple-200 border border-purple-600 px-2.5 py-0.5 rounded-full font-bold flex items-center gap-1">
                  <Sparkles className="h-3 w-3 text-purple-300" />
                  AI Vibe-App Hacker Inspector
                </span>
                <span className="text-xs text-slate-400 font-medium">
                  Lovable · Bolt.new · Cursor · v0 · Supabase · Next.js
                </span>
              </div>
              <h2 className="text-xl md:text-2xl font-bold text-white tracking-tight">
                Where Can a Hacker Break Into Your AI Website?
              </h2>
              <p className="text-sm text-slate-300 mt-1.5 leading-relaxed">
                AI builders make site creation fast, but frequently leave Supabase databases open and private keys exposed. 
                Our 44 autonomous agents locate where hackers can bypass your login or dump customer data, and generate ready-to-paste prompts to fill every gap.
              </p>
            </div>
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 shrink-0">
              <Link
                href="/projects/new"
                className="bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-bold px-6 py-3 rounded-xl text-sm transition-all shadow-lg shadow-purple-950/60 flex items-center justify-center gap-2"
              >
                <Zap className="h-4 w-4" />
                <span>Audit Hacker Entry Points</span>
                <ArrowRight className="h-4 w-4" />
              </Link>
              <Link
                href="/findings"
                className="bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 font-semibold px-4 py-3 rounded-xl text-sm transition-colors text-center"
              >
                View Active AI Gaps
              </Link>
            </div>
          </div>
        </div>

        {/* Wiz / Pentera Attack Path Choke Point Quick Card */}
        <div className="bg-slate-900/90 border border-slate-800 hover:border-slate-700 rounded-2xl p-5 mb-8 flex flex-col md:flex-row md:items-center justify-between gap-4 transition-all">
          <div className="flex items-center gap-4">
            <div className="p-3 bg-rose-950/60 border border-rose-800/80 rounded-xl text-rose-400">
              <Flame className="h-6 w-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-white font-bold text-base">Hacker Exploit Chains & Attack Paths</span>
                <span className="text-[10px] bg-rose-950 text-rose-300 border border-rose-800 px-2 py-0.5 rounded-full font-mono uppercase">
                  Wiz / Pentera Mode
                </span>
              </div>
              <p className="text-slate-400 text-xs mt-0.5">
                Automatically identifies the single <span className="text-emerald-400 font-semibold">Critical Choke Point</span> that cuts off 60-80% of attacker exploit routes to your database.
              </p>
            </div>
          </div>
          <Link
            href="/attack-paths"
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-white rounded-lg text-xs font-semibold flex items-center justify-center gap-2 shrink-0 transition"
          >
            <span>Open Attack Graph</span>
            <ArrowRight className="h-3.5 w-3.5 text-slate-400" />
          </Link>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-4 gap-6 mb-8">
          {[
            { label: "Projects", value: projects.length, icon: <Globe className="h-6 w-6 text-blue-400" />, color: "text-blue-400" },
            { label: "Total Scans", value: scans.length, icon: <Scan className="h-6 w-6 text-cyan-400" />, color: "text-cyan-400" },
            { label: "Critical Findings", value: scans.reduce((a: number, s: any) => a + (s.critical_count || 0), 0), icon: <AlertTriangle className="h-6 w-6 text-red-400" />, color: "text-red-400" },
            { label: "Running Scans", value: scans.filter((s: any) => s.status === "running").length, icon: <Clock className="h-6 w-6 text-yellow-400" />, color: "text-yellow-400" },
          ].map((stat) => (
            <div key={stat.label} className="bg-slate-900 border border-slate-800 rounded-xl p-6">
              <div className="flex items-center justify-between mb-4">
                <span className="text-slate-400 text-sm">{stat.label}</span>
                {stat.icon}
              </div>
              <div className={`text-3xl font-bold ${stat.color}`}>{stat.value}</div>
            </div>
          ))}
        </div>

        {/* Projects */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-white">Projects</h2>
            <Link href="/projects/new" className="text-blue-400 hover:text-blue-300 text-sm">+ Add Project</Link>
          </div>
          {projects.length === 0 ? (
            <div className="text-center py-12">
              <Globe className="h-12 w-12 text-slate-700 mx-auto mb-4" />
              <p className="text-slate-400">No projects yet.</p>
              <Link href="/projects/new" className="text-blue-400 hover:text-blue-300 text-sm mt-2 block">
                Add your first website →
              </Link>
            </div>
          ) : (
            <div className="space-y-3">
              {projects.map((p: any) => (
                <div key={p.id} className="flex items-center justify-between bg-slate-800 rounded-lg px-4 py-3">
                  <div>
                    <div className="text-white font-medium">{p.name}</div>
                    <div className="text-slate-400 text-sm">{p.base_url}</div>
                  </div>
                  <Link href={`/projects/${p.id}`} className="text-blue-400 text-sm hover:text-blue-300">
                    View →
                  </Link>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent Scans */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Recent Scans</h2>
          {scans.length === 0 ? (
            <div className="text-center py-12">
              <Scan className="h-12 w-12 text-slate-700 mx-auto mb-4" />
              <p className="text-slate-400">No scans yet. Start by adding a project.</p>
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="text-slate-500 text-sm border-b border-slate-800">
                  <th className="text-left pb-3">Target</th>
                  <th className="text-left pb-3">Status</th>
                  <th className="text-left pb-3">Findings</th>
                  <th className="text-left pb-3">Critical</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((s: any) => (
                  <tr key={s.id} className="border-b border-slate-800">
                    <td className="py-3 text-white text-sm">{s.target_url}</td>
                    <td className={`py-3 text-sm font-medium capitalize ${statusColor[s.status] || "text-slate-400"}`}>
                      {s.status}
                    </td>
                    <td className="py-3 text-slate-300 text-sm">{s.total_findings}</td>
                    <td className="py-3 text-red-400 text-sm font-bold">{s.critical_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
