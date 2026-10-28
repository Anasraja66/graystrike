"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  Shield,
  ArrowLeft,
  AlertTriangle,
  Database,
  CreditCard,
  Bot,
  ShieldAlert,
  Zap,
  ArrowRight,
  CheckCircle2,
  Copy,
  Check,
  RefreshCw,
  Layers,
  DollarSign,
  Activity,
  Flame,
  Sparkles,
  ExternalLink,
  ChevronRight,
  Lock,
  Unlock,
  Crosshair,
  GitFork
} from "lucide-react";
import axios from "axios";

export default function AttackPathsPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [scans, setScans] = useState<any[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>("workspace");
  const [graphData, setGraphData] = useState<any>(null);
  const [activeTab, setActiveTab] = useState<"chains" | "topology" | "jewels">("chains");
  const [selectedPathId, setSelectedPathId] = useState<string>("");
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const fetchAttackGraph = async (scanId: string) => {
    setLoading(true);
    const token = localStorage.getItem("token");
    if (!token) {
      router.push("/auth/login");
      return;
    }
    const headers = { Authorization: `Bearer ${token}` };
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

    try {
      let endpoint = `${api}/api/v1/reports/workspace/attack-paths`;
      if (scanId && scanId !== "workspace") {
        endpoint = `${api}/api/v1/reports/scans/${scanId}/attack-paths`;
      }
      const res = await axios.get(endpoint, { headers });
      setGraphData(res.data);
      if (res.data.paths && res.data.paths.length > 0) {
        setSelectedPathId(res.data.paths[0].id);
      }
    } catch (err) {
      console.error("Failed to load attack paths:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      router.push("/auth/login");
      return;
    }
    const headers = { Authorization: `Bearer ${token}` };
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

    // Load available scans for filter
    axios
      .get(`${api}/api/v1/scans/`, { headers })
      .then((res) => {
        setScans(res.data || []);
      })
      .catch((err) => console.error("Failed to load scans", err));

    fetchAttackGraph(selectedScanId);
  }, []);

  const handleScanChange = (scanId: string) => {
    setSelectedScanId(scanId);
    fetchAttackGraph(scanId);
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2500);
  };

  const getJewelIcon = (iconName: string) => {
    switch (iconName) {
      case "Database":
        return <Database className="h-6 w-6 text-amber-400" />;
      case "CreditCard":
        return <CreditCard className="h-6 w-6 text-emerald-400" />;
      case "Bot":
        return <Bot className="h-6 w-6 text-purple-400" />;
      case "ShieldAlert":
      default:
        return <ShieldAlert className="h-6 w-6 text-rose-400" />;
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 md:p-8">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Navigation & Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-6">
          <div className="flex items-center gap-4">
            <Link
              href="/dashboard"
              className="p-2 bg-slate-900 border border-slate-800 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
            >
              <ArrowLeft className="h-5 w-5" />
            </Link>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl md:text-3xl font-extrabold text-white tracking-tight flex items-center gap-2">
                  <Flame className="h-7 w-7 text-rose-500 animate-pulse" />
                  Attack Path & Business Risk Graph
                </h1>
                <span className="text-[11px] font-semibold bg-rose-950/80 text-rose-400 border border-rose-800/80 px-2.5 py-0.5 rounded-full uppercase tracking-wider">
                  Pentera / Wiz Style
                </span>
              </div>
              <p className="text-slate-400 text-sm mt-1">
                Visualizing multi-stage hacker exploit chains connecting perimeter bugs to Crown Jewels & financial blast radius.
              </p>
            </div>
          </div>

          {/* Scope Selector & Refresh */}
          <div className="flex items-center gap-3">
            <div className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 flex items-center gap-2 text-sm">
              <span className="text-slate-400 font-medium text-xs uppercase">Scope:</span>
              <select
                value={selectedScanId}
                onChange={(e) => handleScanChange(e.target.value)}
                className="bg-transparent text-white font-medium focus:outline-none cursor-pointer"
              >
                <option value="workspace" className="bg-slate-900 text-white">
                  🌐 All Workspace Findings (Aggregated)
                </option>
                {scans.map((s) => (
                  <option key={s.id} value={s.id} className="bg-slate-900 text-white">
                    Scan {s.id.slice(0, 8)} ({s.target_url || "Target"})
                  </option>
                ))}
              </select>
            </div>

            <button
              onClick={() => fetchAttackGraph(selectedScanId)}
              disabled={loading}
              className="p-2.5 bg-slate-900 border border-slate-800 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition flex items-center justify-center"
              title="Refresh Graph"
            >
              <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin text-blue-400" : ""}`} />
            </button>
          </div>
        </div>

        {/* Top Summary Metrics Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Attack Chains</span>
              <Activity className="h-5 w-5 text-rose-400" />
            </div>
            <div className="mt-3 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-white">
                {graphData?.summary?.total_paths ?? 0}
              </span>
              <span className="text-xs text-rose-400 font-medium">Exploit Paths</span>
            </div>
            <p className="text-xs text-slate-400 mt-1">Multi-stage chains reaching sensitive data</p>
            <div className="absolute top-0 right-0 h-1 w-full bg-gradient-to-r from-rose-500 to-amber-500" />
          </div>

          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Max Exploit Risk</span>
              <ShieldAlert className="h-5 w-5 text-amber-400" />
            </div>
            <div className="mt-3 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-white">
                {graphData?.summary?.max_risk_score ?? 0}
                <span className="text-base text-slate-500 font-normal">/100</span>
              </span>
              <span className="text-xs bg-rose-950 text-rose-400 px-2 py-0.5 rounded font-mono font-bold">
                CRITICAL
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">Highest individual chain probability</p>
            <div className="absolute top-0 right-0 h-1 w-full bg-gradient-to-r from-amber-500 to-rose-500" />
          </div>

          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Crown Jewels in Peril</span>
              <Database className="h-5 w-5 text-purple-400" />
            </div>
            <div className="mt-3 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-white">
                {graphData?.summary?.crown_jewels_at_risk ?? 0}
              </span>
              <span className="text-xs text-purple-400 font-medium">Target Assets</span>
            </div>
            <p className="text-xs text-slate-400 mt-1">DB, Stripe, LLM quota, Admin tenant</p>
            <div className="absolute top-0 right-0 h-1 w-full bg-gradient-to-r from-purple-500 to-indigo-500" />
          </div>

          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Est. Blast Radius</span>
              <DollarSign className="h-5 w-5 text-emerald-400" />
            </div>
            <div className="mt-3 flex items-baseline gap-2">
              <span className="text-2xl font-extrabold text-emerald-400">
                $105k - $400k
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">Regulatory fines + direct financial loss</p>
            <div className="absolute top-0 right-0 h-1 w-full bg-gradient-to-r from-emerald-500 to-teal-500" />
          </div>
        </div>

        {/* 🎯 Critical Choke Point Banner (Pentera / Wiz Style) */}
        {graphData?.critical_choke_point && (
          <div className="relative overflow-hidden rounded-2xl border-2 border-emerald-500/40 bg-gradient-to-r from-emerald-950/40 via-slate-900 to-slate-900 p-6 shadow-xl">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <span className="flex h-3 w-3 relative">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
                  </span>
                  <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                    <Crosshair className="h-4 w-4" />
                    High-Leverage Remediation · Critical Choke Point
                  </span>
                </div>
                <h3 className="text-xl md:text-2xl font-bold text-white flex items-center gap-2">
                  Fix &quot;{graphData.critical_choke_point.title}&quot;
                </h3>
                <p className="text-slate-300 text-sm max-w-2xl leading-relaxed">
                  {graphData.critical_choke_point.action_message} Instead of fixing all 10+ bugs individually, resolving this single choke point instantly breaks attacker access to your database and API resources.
                </p>
                <div className="flex items-center gap-3 pt-1">
                  <span className="text-xs font-mono text-slate-400 bg-slate-950/70 border border-slate-800 px-2.5 py-1 rounded">
                    Asset: {graphData.critical_choke_point.affected_asset}
                  </span>
                  <span className="text-xs font-bold bg-emerald-900/60 text-emerald-300 border border-emerald-700/60 px-2.5 py-1 rounded">
                    {graphData.critical_choke_point.risk_reduction_pct}% Risk Reduction
                  </span>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 shrink-0">
                <button
                  onClick={() =>
                    copyToClipboard(
                      `Fix security vulnerability: "${graphData.critical_choke_point.title}" on asset "${graphData.critical_choke_point.affected_asset}". Apply strict row-level security and authentication checks.`,
                      "choke_point_prompt"
                    )
                  }
                  className="px-4 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-semibold text-sm transition flex items-center justify-center gap-2 shadow-lg shadow-emerald-950/50"
                >
                  {copiedId === "choke_point_prompt" ? (
                    <>
                      <Check className="h-4 w-4 text-white" />
                      <span>Copied AI Prompt!</span>
                    </>
                  ) : (
                    <>
                      <Sparkles className="h-4 w-4 text-emerald-200" />
                      <span>Copy Fix Prompt (Lovable/Cursor)</span>
                    </>
                  )}
                </button>
                <Link
                  href="/findings"
                  className="px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg font-semibold text-sm transition flex items-center justify-center gap-2"
                >
                  <ExternalLink className="h-4 w-4 text-slate-400" />
                  <span>Inspect in Triage</span>
                </Link>
              </div>
            </div>
          </div>
        )}

        {/* View Toggle Tabs */}
        <div className="flex items-center border-b border-slate-800 gap-4">
          <button
            onClick={() => setActiveTab("chains")}
            className={`pb-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition ${
              activeTab === "chains"
                ? "border-rose-500 text-white"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <GitFork className="h-4 w-4" />
            Exploit Chains ({graphData?.paths?.length ?? 0})
          </button>
          <button
            onClick={() => setActiveTab("topology")}
            className={`pb-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition ${
              activeTab === "topology"
                ? "border-rose-500 text-white"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Layers className="h-4 w-4" />
            Graph Topology & Nodes ({graphData?.nodes?.length ?? 0})
          </button>
          <button
            onClick={() => setActiveTab("jewels")}
            className={`pb-3 text-sm font-semibold flex items-center gap-2 border-b-2 transition ${
              activeTab === "jewels"
                ? "border-rose-500 text-white"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Shield className="h-4 w-4" />
            Crown Jewels & Financial Impact (4)
          </button>
        </div>

        {/* TAB 1: Step-by-Step Exploit Chains */}
        {activeTab === "chains" && (
          <div className="space-y-6">
            {graphData?.paths && graphData.paths.length > 0 ? (
              graphData.paths.map((path: any, idx: number) => {
                const isSelected = selectedPathId === path.id;
                return (
                  <div
                    key={path.id}
                    className={`rounded-2xl border transition-all overflow-hidden ${
                      isSelected
                        ? "border-rose-500/80 bg-slate-900/95 shadow-xl shadow-rose-950/20"
                        : "border-slate-800 bg-slate-900/60 hover:border-slate-700"
                    }`}
                  >
                    {/* Chain Header */}
                    <div
                      onClick={() => setSelectedPathId(isSelected ? "" : path.id)}
                      className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 cursor-pointer"
                    >
                      <div className="flex items-start md:items-center gap-3">
                        <div className="h-9 w-9 rounded-xl bg-rose-950/80 border border-rose-800/80 flex items-center justify-center font-mono font-bold text-rose-400 text-sm shrink-0">
                          #{idx + 1}
                        </div>
                        <div>
                          <div className="flex items-center gap-2 flex-wrap">
                            <h4 className="text-lg font-bold text-white">{path.name}</h4>
                            <span className="text-[10px] uppercase font-bold bg-rose-950 text-rose-400 border border-rose-800 px-2 py-0.5 rounded">
                              Risk Score: {path.risk_score}/100
                            </span>
                            <span className="text-[10px] uppercase font-bold bg-purple-950 text-purple-400 border border-purple-800 px-2 py-0.5 rounded">
                              Target: {path.crown_jewel}
                            </span>
                          </div>
                          <p className="text-slate-400 text-xs mt-1">
                            {path.steps_count} chained steps · Choke Point ID: {path.choke_point_finding_id?.slice(0, 8)}
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center gap-3 self-end md:self-center">
                        <span className="text-xs text-slate-400 hidden sm:inline">
                          {isSelected ? "Click to collapse" : "Click to view full chain"}
                        </span>
                        <ChevronRight
                          className={`h-5 w-5 text-slate-400 transition-transform ${
                            isSelected ? "rotate-90 text-rose-400" : ""
                          }`}
                        />
                      </div>
                    </div>

                    {/* Step-by-Step Flow Cards */}
                    {isSelected && (
                      <div className="border-t border-slate-800/80 bg-slate-950/70 p-6 space-y-6">
                        <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                          Hacker Exploit Sequence (Live Attack Simulation)
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 relative">
                          {path.steps.map((st: any, sIdx: number) => {
                            const isFirst = sIdx === 0;
                            const isLast = sIdx === path.steps.length - 1;
                            return (
                              <div
                                key={st.step}
                                className={`rounded-xl p-4 border relative flex flex-col justify-between ${
                                  isLast
                                    ? "bg-rose-950/30 border-rose-800/80"
                                    : isFirst
                                    ? "bg-amber-950/20 border-amber-800/60"
                                    : "bg-slate-900 border-slate-800"
                                }`}
                              >
                                <div>
                                  <div className="flex items-center justify-between mb-2">
                                    <span
                                      className={`text-[11px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${
                                        isLast
                                          ? "bg-rose-900/60 text-rose-300"
                                          : isFirst
                                          ? "bg-amber-900/60 text-amber-300"
                                          : "bg-blue-900/60 text-blue-300"
                                      }`}
                                    >
                                      Stage {st.step}: {st.role}
                                    </span>
                                  </div>
                                  <h5 className="font-semibold text-white text-sm">{st.title}</h5>
                                  <p className="text-xs text-slate-300 mt-2 leading-relaxed">
                                    {st.action}
                                  </p>
                                </div>

                                <div className="mt-4 pt-3 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-400">
                                  <span>Node: {st.node_id?.slice(0, 16)}...</span>
                                  {isLast ? (
                                    <span className="text-rose-400 font-bold flex items-center gap-1">
                                      <Lock className="h-3 w-3" /> Compromised
                                    </span>
                                  ) : (
                                    <span className="text-amber-400 font-medium flex items-center gap-1">
                                      <Unlock className="h-3 w-3" /> Pivot Forward
                                    </span>
                                  )}
                                </div>
                              </div>
                            );
                          })}
                        </div>

                        {/* Chain Severing / Remediation Box */}
                        <div className="bg-emerald-950/30 border border-emerald-800/70 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                          <div className="space-y-1">
                            <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                              <Shield className="h-3.5 w-3.5" /> Recommended Chain Severing Action
                            </span>
                            <p className="text-sm text-slate-200">{path.remediation_summary}</p>
                          </div>
                          <button
                            onClick={() =>
                              copyToClipboard(
                                `Fix exploit chain "${path.name}": ${path.remediation_summary}`,
                                `chain_prompt_${path.id}`
                              )
                            }
                            className="px-3.5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold transition flex items-center justify-center gap-2 shrink-0"
                          >
                            {copiedId === `chain_prompt_${path.id}` ? (
                              <>
                                <Check className="h-3.5 w-3.5" />
                                <span>Copied Prompt!</span>
                              </>
                            ) : (
                              <>
                                <Copy className="h-3.5 w-3.5" />
                                <span>Copy Prompt for AI Code Fix</span>
                              </>
                            )}
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })
            ) : (
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center space-y-3">
                <CheckCircle2 className="h-12 w-12 text-emerald-400 mx-auto" />
                <h3 className="text-lg font-bold text-white">No Active Attack Chains Found</h3>
                <p className="text-slate-400 text-sm max-w-md mx-auto">
                  Your scanned target did not expose any multi-stage exploit pathways or row-level security breaches reaching core Crown Jewels.
                </p>
              </div>
            )}
          </div>
        )}

        {/* TAB 2: Topology & Nodes View */}
        {activeTab === "topology" && (
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 space-y-6">
            <div>
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Layers className="h-5 w-5 text-blue-400" />
                Exploit Graph Topology (Nodes & Directional Edges)
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Displays the mathematical attack graph connecting perimeter assets to critical infrastructure.
              </p>
            </div>

            {/* Visual Node Grid */}
            <div className="space-y-4">
              <span className="text-xs font-semibold uppercase text-slate-400 tracking-wider">
                Graph Nodes ({graphData?.nodes?.length ?? 0})
              </span>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {graphData?.nodes?.map((node: any) => {
                  const isCrown = node.type === "crown_jewel";
                  const isExploit = node.type === "exploit";
                  const isEntry = node.type === "entry";

                  return (
                    <div
                      key={node.id}
                      className={`p-4 rounded-xl border flex flex-col justify-between ${
                        isCrown
                          ? "bg-purple-950/30 border-purple-800/80"
                          : isExploit
                          ? "bg-rose-950/30 border-rose-800/80"
                          : "bg-slate-950 border-slate-800"
                      }`}
                    >
                      <div>
                        <div className="flex items-center justify-between mb-1.5">
                          <span
                            className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded ${
                              isCrown
                                ? "bg-purple-900 text-purple-300"
                                : isExploit
                                ? "bg-rose-900 text-rose-300"
                                : "bg-slate-800 text-slate-300"
                            }`}
                          >
                            {node.type}
                          </span>
                          <span className="text-xs font-mono text-slate-400">
                            {node.severity?.toUpperCase()}
                          </span>
                        </div>
                        <div className="font-semibold text-white text-sm">{node.title}</div>
                        <div className="text-xs text-slate-400 mt-1 truncate">
                          {node.affected_asset}
                        </div>
                      </div>

                      {isCrown && (
                        <div className="mt-3 pt-2 border-t border-purple-900/50 flex items-center justify-between text-xs font-semibold text-emerald-400">
                          <span>Max Loss:</span>
                          <span>{node.impact_usd}</span>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Edge Connections List */}
            <div className="space-y-4 pt-4 border-t border-slate-800">
              <span className="text-xs font-semibold uppercase text-slate-400 tracking-wider">
                Attack Vectors & Directed Edges ({graphData?.edges?.length ?? 0})
              </span>
              <div className="space-y-2">
                {graphData?.edges?.map((edge: any) => (
                  <div
                    key={edge.id}
                    className="p-3 bg-slate-950 border border-slate-800 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono"
                  >
                    <div className="flex items-center gap-2 text-slate-300">
                      <span className="text-blue-400 font-semibold">{edge.source}</span>
                      <ArrowRight className="h-3.5 w-3.5 text-rose-500 shrink-0" />
                      <span className="text-purple-400 font-semibold">{edge.target}</span>
                    </div>
                    <div className="text-slate-400 flex items-center gap-2">
                      <span className="bg-slate-900 border border-slate-800 px-2 py-0.5 rounded text-amber-300">
                        {edge.technique}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: Crown Jewels & Business Risk View */}
        {activeTab === "jewels" && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {[
              {
                id: "cj_customer_database",
                name: "Customer PII & Order Database",
                icon: "Database",
                impact_usd: "$75,000 - $250,000",
                regulatory: "GDPR / HIPAA / PCI-DSS Non-Compliance & Class-Action Lawsuits",
                description:
                  "Exfiltration of all customer profiles, email addresses, order histories, and private credentials via unauthenticated REST / GraphQL queries.",
                atRisk: graphData?.paths?.some((p: any) => p.crown_jewel.includes("Database"))
              },
              {
                id: "cj_payment_ledger",
                name: "Payment Gateway & Subscription Ledger",
                icon: "CreditCard",
                impact_usd: "$20,000 - $100,000",
                regulatory: "Stripe Merchant Suspension & Direct Financial Fraud",
                description:
                  "Forged webhook events and signature bypasses enabling unauthorized SaaS account upgrades or automated refund fraud.",
                atRisk: graphData?.paths?.some((p: any) => p.crown_jewel.includes("Payment"))
              },
              {
                id: "cj_llm_api_balance",
                name: "Cloud LLM API Budget & Prompt Secrets",
                icon: "Bot",
                impact_usd: "$10,000 - $50,000",
                regulatory: "Denial of Wallet (DoW) & Proprietary Prompt Disclosure",
                description:
                  "Automated bot depletion of OpenAI/Anthropic API quotas and leakage of proprietary system prompts and system instructions.",
                atRisk: graphData?.paths?.some((p: any) => p.crown_jewel.includes("LLM"))
              },
              {
                id: "cj_admin_portal",
                name: "Platform Administration & Tenant Console",
                icon: "ShieldAlert",
                impact_usd: "$50,000 - $150,000",
                regulatory: "Complete Multi-Tenant Data Breach & Brand Destruction",
                description:
                  "Takeover of administrative API routes and lack of role-based authorization allowing unauthorized tenant modification and backend control.",
                atRisk: graphData?.paths?.some((p: any) => p.crown_jewel.includes("Admin") || p.crown_jewel.includes("Tenant"))
              }
            ].map((jewel) => (
              <div
                key={jewel.id}
                className={`rounded-2xl border p-6 flex flex-col justify-between ${
                  jewel.atRisk
                    ? "bg-rose-950/20 border-rose-800/80 shadow-lg shadow-rose-950/20"
                    : "bg-slate-900/60 border-slate-800"
                }`}
              >
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl">
                      {getJewelIcon(jewel.icon)}
                    </div>
                    {jewel.atRisk ? (
                      <span className="text-xs font-bold uppercase tracking-wider bg-rose-950 text-rose-400 border border-rose-800 px-2.5 py-1 rounded-full flex items-center gap-1.5 animate-pulse">
                        <Flame className="h-3.5 w-3.5" /> High Risk
                      </span>
                    ) : (
                      <span className="text-xs font-bold uppercase tracking-wider bg-emerald-950 text-emerald-400 border border-emerald-800 px-2.5 py-1 rounded-full flex items-center gap-1.5">
                        <CheckCircle2 className="h-3.5 w-3.5" /> Secured
                      </span>
                    )}
                  </div>

                  <div>
                    <h4 className="text-lg font-bold text-white">{jewel.name}</h4>
                    <p className="text-slate-300 text-xs mt-2 leading-relaxed">{jewel.description}</p>
                  </div>

                  <div className="p-3 bg-slate-950/80 border border-slate-800/80 rounded-xl space-y-1.5">
                    <div className="text-[11px] font-semibold uppercase text-slate-400">
                      Compliance & Regulatory Exposure:
                    </div>
                    <div className="text-xs text-rose-300 font-medium">{jewel.regulatory}</div>
                  </div>
                </div>

                <div className="mt-6 pt-4 border-t border-slate-800 flex items-center justify-between">
                  <span className="text-xs text-slate-400">Est. Financial Blast Radius:</span>
                  <span className="text-sm font-extrabold text-emerald-400">{jewel.impact_usd}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
