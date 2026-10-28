"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  Globe,
  ArrowLeft,
  AlertTriangle,
  Shield,
  CheckCircle2,
  RefreshCw,
  ExternalLink,
  Flame,
  Layers,
  Database,
  Cloud,
  Server,
  Lock,
  Unlock,
  Activity,
  Play
} from "lucide-react";
import axios from "axios";

export default function AttackSurfacePage() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [discovering, setDiscovering] = useState(false);
  const [projects, setProjects] = useState<any[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>("workspace");
  const [surfaceData, setSurfaceData] = useState<any>(null);
  const [filterType, setFilterType] = useState<string>("all");

  const fetchSurface = async (projId: string) => {
    setLoading(true);
    const token = localStorage.getItem("token");
    if (!token) {
      router.push("/auth/login");
      return;
    }
    const headers = { Authorization: `Bearer ${token}` };
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

    try {
      let url = `${api}/api/v1/easm/workspace/assets`;
      if (projId && projId !== "workspace") {
        url = `${api}/api/v1/easm/projects/${projId}/assets`;
      }
      const res = await axios.get(url, { headers });
      setSurfaceData(res.data);
    } catch (err) {
      console.error("Failed to load attack surface:", err);
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

    // Load projects for filter
    axios
      .get(`${api}/api/v1/projects/`, { headers })
      .then((res) => setProjects(res.data || []))
      .catch((e) => console.error(e));

    fetchSurface(selectedProjectId);
  }, []);

  const handleRefresh = async () => {
    setDiscovering(true);
    await fetchSurface(selectedProjectId);
    setDiscovering(false);
  };

  const displayedAssets = (surfaceData?.assets || []).filter((a: any) => {
    if (filterType === "all") return true;
    if (filterType === "shadow") return a.is_shadow;
    if (filterType === "takeover") return a.takeover_risk;
    if (filterType === "bucket") return a.asset_type?.includes("Bucket");
    return true;
  });

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
                  <Globe className="h-7 w-7 text-cyan-400" />
                  External Attack Surface (EASM)
                </h1>
                <span className="text-[11px] font-semibold bg-cyan-950/80 text-cyan-300 border border-cyan-800 px-2.5 py-0.5 rounded-full uppercase tracking-wider">
                  Shadow Asset Discovery
                </span>
              </div>
              <p className="text-slate-400 text-sm mt-1">
                Continuous reconnaissance: mapping subdomains via Certificate Transparency logs, detecting staging leaks, and identifying dangling CNAME takeovers.
              </p>
            </div>
          </div>

          {/* Project Scope & Trigger Recon */}
          <div className="flex items-center gap-3">
            <div className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 flex items-center gap-2 text-sm">
              <span className="text-slate-400 font-medium text-xs uppercase">Scope:</span>
              <select
                value={selectedProjectId}
                onChange={(e) => {
                  setSelectedProjectId(e.target.value);
                  fetchSurface(e.target.value);
                }}
                className="bg-transparent text-white font-medium focus:outline-none cursor-pointer"
              >
                <option value="workspace" className="bg-slate-900 text-white">
                  🌐 All Workspace Projects
                </option>
                {projects.map((p) => (
                  <option key={p.id} value={p.id} className="bg-slate-900 text-white">
                    {p.name} ({p.base_url})
                  </option>
                ))}
              </select>
            </div>

            <button
              onClick={handleRefresh}
              disabled={discovering || loading}
              className="px-4 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:opacity-50 text-white font-semibold text-xs rounded-lg shadow-lg shadow-cyan-950/50 flex items-center gap-2 transition"
            >
              <RefreshCw className={`h-4 w-4 ${discovering ? "animate-spin text-white" : ""}`} />
              <span>{discovering ? "Discovering..." : "Scan Attack Surface"}</span>
            </button>
          </div>
        </div>

        {/* Top Surface Metrics Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Discovered Assets</span>
              <Server className="h-5 w-5 text-cyan-400" />
            </div>
            <div className="mt-3 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-white">
                {surfaceData?.total_assets_found ?? 0}
              </span>
              <span className="text-xs text-cyan-400 font-medium">Live Endpoints</span>
            </div>
            <p className="text-xs text-slate-400 mt-1">Subdomains, APIs, CDNs, & Buckets</p>
            <div className="absolute top-0 right-0 h-1 w-full bg-gradient-to-r from-cyan-500 to-blue-500" />
          </div>

          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Shadow / Staging Leaks</span>
              <AlertTriangle className="h-5 w-5 text-amber-400" />
            </div>
            <div className="mt-3 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-white">
                {surfaceData?.shadow_assets_count ?? 0}
              </span>
              <span className="text-xs bg-amber-950 text-amber-400 px-2 py-0.5 rounded font-mono font-bold">
                DEV LEAKS
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">Pre-production environments exposed to public</p>
            <div className="absolute top-0 right-0 h-1 w-full bg-gradient-to-r from-amber-500 to-orange-500" />
          </div>

          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Subdomain Takeovers</span>
              <Flame className="h-5 w-5 text-rose-400" />
            </div>
            <div className="mt-3 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-white">
                {surfaceData?.takeover_risks_count ?? 0}
              </span>
              <span className={`text-xs px-2 py-0.5 rounded font-mono font-bold ${
                (surfaceData?.takeover_risks_count || 0) > 0 ? "bg-rose-950 text-rose-400" : "bg-emerald-950 text-emerald-400"
              }`}>
                {(surfaceData?.takeover_risks_count || 0) > 0 ? "CRITICAL" : "SECURED"}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">Dangling DNS CNAME pointing to unclaimed hosts</p>
            <div className="absolute top-0 right-0 h-1 w-full bg-gradient-to-r from-rose-500 to-red-500" />
          </div>

          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Surface Health Status</span>
              <Activity className="h-5 w-5 text-emerald-400" />
            </div>
            <div className="mt-3 flex items-baseline gap-2">
              <span className={`text-2xl font-extrabold ${
                surfaceData?.summary?.status === "DANGER"
                  ? "text-rose-400"
                  : surfaceData?.summary?.status === "WARNING"
                  ? "text-amber-400"
                  : "text-emerald-400"
              }`}>
                {surfaceData?.summary?.status || "HEALTHY"}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">Certificate Transparency audit state</p>
            <div className="absolute top-0 right-0 h-1 w-full bg-gradient-to-r from-emerald-500 to-teal-500" />
          </div>
        </div>

        {/* Filter Pills */}
        <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
          {[
            { id: "all", label: `All Assets (${surfaceData?.total_assets_found ?? 0})` },
            { id: "shadow", label: `Shadow / Staging (${surfaceData?.shadow_assets_count ?? 0})` },
            { id: "takeover", label: `Takeover Risks (${surfaceData?.takeover_risks_count ?? 0})` },
            { id: "bucket", label: `Storage Buckets` },
          ].map((f) => (
            <button
              key={f.id}
              onClick={() => setFilterType(f.id)}
              className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition ${
                filterType === f.id
                  ? "bg-cyan-600 text-white"
                  : "bg-slate-900 border border-slate-800 text-slate-400 hover:text-white"
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>

        {/* Asset Inventory Grid */}
        {loading ? (
          <div className="text-center py-20 text-cyan-400">Discovering external attack surface...</div>
        ) : displayedAssets.length === 0 ? (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-12 text-center space-y-3">
            <CheckCircle2 className="h-12 w-12 text-emerald-400 mx-auto" />
            <h3 className="text-lg font-bold text-white">No Assets Match Selected Filter</h3>
            <p className="text-slate-400 text-sm max-w-md mx-auto">
              Click &quot;Scan Attack Surface&quot; above to query public Certificate Transparency logs and DNS records.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {displayedAssets.map((asset: any) => {
              const isShadow = asset.is_shadow;
              const isTakeover = asset.takeover_risk;

              return (
                <div
                  key={asset.hostname}
                  className={`rounded-2xl border p-5 flex flex-col justify-between transition-all ${
                    isTakeover
                      ? "bg-rose-950/30 border-rose-800/80 shadow-lg shadow-rose-950/20"
                      : isShadow
                      ? "bg-amber-950/20 border-amber-800/70"
                      : "bg-slate-900/90 border-slate-800 hover:border-slate-700"
                  }`}
                >
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span
                        className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded ${
                          isTakeover
                            ? "bg-rose-900 text-rose-300"
                            : isShadow
                            ? "bg-amber-900 text-amber-300"
                            : "bg-cyan-950 text-cyan-300 border border-cyan-800"
                        }`}
                      >
                        {asset.asset_type}
                      </span>
                      <span className="text-xs font-mono font-semibold text-emerald-400">
                        HTTP {asset.http_status}
                      </span>
                    </div>

                    <div>
                      <h4 className="font-bold text-white text-base break-all flex items-center gap-1.5">
                        <a
                          href={asset.url}
                          target="_blank"
                          rel="noreferrer"
                          className="hover:text-cyan-300 transition flex items-center gap-1"
                        >
                          {asset.hostname}
                          <ExternalLink className="h-3.5 w-3.5 opacity-60" />
                        </a>
                      </h4>
                      <p className="text-xs text-slate-400 mt-1 font-mono">
                        Server: {asset.server_banner}
                      </p>
                    </div>

                    {asset.cname && (
                      <div className="p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-400 break-all">
                        <span className="text-slate-500">CNAME: </span>
                        <span className="text-cyan-300">{asset.cname}</span>
                      </div>
                    )}

                    {isTakeover && (
                      <div className="p-3 bg-rose-950/80 border border-rose-800 rounded-xl space-y-1">
                        <div className="text-xs font-bold text-rose-300 flex items-center gap-1">
                          <Flame className="h-3.5 w-3.5 text-rose-400" />
                          Dangling CNAME Takeover Vulnerability!
                        </div>
                        <p className="text-[11px] text-rose-200">
                          This domain points to an abandoned {asset.takeover_service} instance. Anyone can register the name and impersonate your brand!
                        </p>
                      </div>
                    )}
                  </div>

                  <div className="mt-5 pt-3 border-t border-slate-800 flex items-center justify-between">
                    <span className="text-[11px] text-slate-400 font-mono">
                      {asset.discovered_at}
                    </span>
                    <Link
                      href={`/projects/new?target=${encodeURIComponent(asset.url)}`}
                      className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold rounded-lg flex items-center gap-1.5 transition"
                    >
                      <Play className="h-3 w-3 text-cyan-400 fill-current" />
                      <span>Audit Asset</span>
                    </Link>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
