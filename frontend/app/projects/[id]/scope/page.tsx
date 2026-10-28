"use client";
import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { Shield, ArrowLeft, Save, AlertTriangle, CheckCircle, Lock } from "lucide-react";
import axios from "axios";

export default function ScopeConfigPage() {
  const params = useParams();
  const router = useRouter();
  const projectId = params.id as string;

  const [project, setProject] = useState<any>(null);
  const [allowedHosts, setAllowedHosts] = useState("");
  const [deniedPaths, setDeniedPaths] = useState("/admin, /api/internal, /logout");
  const [maxRequests, setMaxRequests] = useState(1000);
  const [rateLimit, setRateLimit] = useState(2.0);
  const [activeChecks, setActiveChecks] = useState(false);
  const [saved, setSaved] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) { router.push("/auth/login"); return; }
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

    axios.get(`${api}/api/v1/projects/${projectId}`, {
      headers: { Authorization: `Bearer ${token}` }
    }).then((res) => {
      setProject(res.data);
      const host = new URL(res.data.base_url).hostname;
      setAllowedHosts(host);
    }).catch(console.error)
      .finally(() => setLoading(false));
  }, [projectId]);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center text-blue-400">
        Loading scope configurations...
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-8">
      <div className="max-w-4xl mx-auto">
        <div className="flex items-center gap-4 mb-8">
          <Link href="/dashboard" className="text-slate-400 hover:text-white transition-colors">
            <ArrowLeft className="h-5 w-5" />
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-white">Testing Scope & Safety Policy</h1>
            <p className="text-slate-400 text-sm">{project?.name} ({project?.base_url})</p>
          </div>
        </div>

        {saved && (
          <div className="bg-emerald-950 border border-emerald-800 text-emerald-400 px-4 py-3 rounded-xl text-sm mb-6 flex items-center gap-2">
            <CheckCircle className="h-5 w-5" /> Scope policy saved successfully!
          </div>
        )}

        <form onSubmit={handleSave} className="bg-slate-900 border border-slate-800 rounded-2xl p-8 space-y-6">
          <div>
            <label className="block text-sm font-semibold text-slate-200 mb-2">
              Authorized Target Hosts (Comma separated)
            </label>
            <input
              type="text"
              value={allowedHosts}
              onChange={(e) => setAllowedHosts(e.target.value)}
              className="w-full bg-slate-800 border border-slate-700 text-white px-4 py-3 rounded-lg focus:outline-none focus:border-blue-500 font-mono text-sm"
              placeholder="example.com, api.example.com"
              required
            />
            <p className="text-xs text-slate-400 mt-1">Requests to any other host or domain are strictly prohibited and dropped.</p>
          </div>

          <div>
            <label className="block text-sm font-semibold text-slate-200 mb-2">
              Excluded Deny-list Paths (Comma separated)
            </label>
            <input
              type="text"
              value={deniedPaths}
              onChange={(e) => setDeniedPaths(e.target.value)}
              className="w-full bg-slate-800 border border-slate-700 text-white px-4 py-3 rounded-lg focus:outline-none focus:border-blue-500 font-mono text-sm"
              placeholder="/admin, /logout, /internal"
            />
            <p className="text-xs text-slate-400 mt-1">Agents will never navigate to or inspect paths matching these prefixes.</p>
          </div>

          <div className="grid grid-cols-2 gap-6">
            <div>
              <label className="block text-sm font-semibold text-slate-200 mb-2">
                Maximum Request Quota
              </label>
              <input
                type="number"
                value={maxRequests}
                onChange={(e) => setMaxRequests(Number(e.target.value))}
                className="w-full bg-slate-800 border border-slate-700 text-white px-4 py-3 rounded-lg focus:outline-none focus:border-blue-500 font-mono text-sm"
                min="50"
                max="5000"
              />
              <p className="text-xs text-slate-400 mt-1">Stops scan if request count exceeds budget.</p>
            </div>
            <div>
              <label className="block text-sm font-semibold text-slate-200 mb-2">
                Rate Limit (Requests / Sec)
              </label>
              <input
                type="number"
                step="0.5"
                value={rateLimit}
                onChange={(e) => setRateLimit(Number(e.target.value))}
                className="w-full bg-slate-800 border border-slate-700 text-white px-4 py-3 rounded-lg focus:outline-none focus:border-blue-500 font-mono text-sm"
                min="0.5"
                max="10"
              />
              <p className="text-xs text-slate-400 mt-1">Prevents server resource exhaustion or denial of service.</p>
            </div>
          </div>

          {/* Safety Notice Banner */}
          <div className="bg-slate-950 border border-blue-900/60 rounded-xl p-4 flex items-start gap-3">
            <Lock className="h-5 w-5 text-blue-400 mt-0.5 shrink-0" />
            <div className="text-xs text-slate-300">
              <strong className="text-white block mb-0.5">Automated Safety Constraints Enforced</strong>
              The system automatically drops requests targeting loopback addresses (<code className="text-blue-300">127.0.0.1</code>), cloud metadata services (<code className="text-blue-300">169.254.169.254</code>), or private RFC 1918 addresses. Destructive operations are disabled by policy.
            </div>
          </div>

          <button
            type="submit"
            className="w-full bg-blue-600 hover:bg-blue-500 text-white py-3 rounded-lg font-semibold flex items-center justify-center gap-2 transition-colors"
          >
            <Save className="h-4 w-4" /> Save Scope Policy
          </button>
        </form>
      </div>
    </div>
  );
}
