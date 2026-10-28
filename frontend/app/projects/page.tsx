"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Shield, ArrowLeft, Globe, Plus, Play, Settings, ExternalLink } from "lucide-react";
import axios from "axios";

export default function ProjectsListPage() {
  const router = useRouter();
  const [projects, setProjects] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [scanningId, setScanningId] = useState<string | null>(null);

  const fetchProjects = async () => {
    const token = localStorage.getItem("token");
    if (!token) { router.push("/auth/login"); return; }
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

    try {
      const res = await axios.get(`${api}/api/v1/projects/`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setProjects(res.data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProjects();
  }, []);

  const triggerScan = async (projectId: string, baseUrl: string) => {
    const token = localStorage.getItem("token");
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
    setScanningId(projectId);

    try {
      const res = await axios.post(
        `${api}/api/v1/scans/`,
        { project_id: projectId, target_url: baseUrl },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      router.push(`/scans/${res.data.id}`);
    } catch (err: any) {
      alert(err.response?.data?.detail || "Scan initiation failed");
    } finally {
      setScanningId(null);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-8">
      <div className="max-w-6xl mx-auto">
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-4">
            <Link href="/dashboard" className="text-slate-400 hover:text-white transition-colors">
              <ArrowLeft className="h-5 w-5" />
            </Link>
            <div>
              <h1 className="text-2xl font-bold text-white">Target Applications</h1>
              <p className="text-slate-400 text-sm">Manage authorized domains, scope policies, and continuous audit schedules</p>
            </div>
          </div>
          <Link
            href="/projects/new"
            className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-sm font-semibold flex items-center gap-2 transition-colors"
          >
            <Plus className="h-4 w-4" /> Add Application
          </Link>
        </div>

        {loading ? (
          <div className="text-center py-20 text-blue-400">Loading targets...</div>
        ) : projects.length === 0 ? (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-12 text-center">
            <Globe className="h-12 w-12 text-slate-700 mx-auto mb-4" />
            <h3 className="text-lg font-bold text-white">No Registered Applications</h3>
            <p className="text-slate-400 text-sm mt-1">Register a website to configure DNS ownership and testing scope.</p>
            <Link href="/projects/new" className="mt-4 inline-block bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-medium">
              Register Web App →
            </Link>
          </div>
        ) : (
          <div className="grid md:grid-cols-2 gap-6">
            {projects.map((p) => (
              <div key={p.id} className="bg-slate-900 border border-slate-800 rounded-2xl p-6 flex flex-col justify-between">
                <div>
                  <div className="flex items-center gap-3 mb-2">
                    <Globe className="h-5 w-5 text-blue-400" />
                    <Link href={`/projects/${p.id}`} className="text-lg font-bold text-white hover:text-blue-400 transition-colors">
                      {p.name}
                    </Link>
                  </div>
                  <p className="text-xs text-slate-400 font-mono mb-4">{p.base_url}</p>
                  {p.description && (
                    <p className="text-sm text-slate-300 mb-4 line-clamp-2">{p.description}</p>
                  )}
                  <div className="flex items-center justify-between text-xs text-slate-400 mb-4 bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80">
                    <span>Continuous Audit:</span>
                    <span className="font-semibold uppercase text-blue-400">{p.scan_schedule || "manual"}</span>
                  </div>
                </div>

                <div className="flex items-center gap-3 pt-4 border-t border-slate-800">
                  <button
                    onClick={() => triggerScan(p.id, p.base_url)}
                    disabled={scanningId === p.id}
                    className="flex-1 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white py-2 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors shadow-md shadow-blue-500/20"
                  >
                    <Play className="h-3.5 w-3.5 fill-current" />
                    {scanningId === p.id ? "Launching 41 Agents..." : "Start 41-Agent Scan"}
                  </button>
                  <Link
                    href={`/projects/${p.id}`}
                    className="border border-slate-700 hover:border-slate-500 text-slate-300 p-2 rounded-lg text-xs transition-colors"
                    title="View Project Details & Telemetry"
                  >
                    <ExternalLink className="h-4 w-4" />
                  </Link>
                  <Link
                    href={`/projects/${p.id}/scope`}
                    className="border border-slate-700 hover:border-slate-500 text-slate-300 p-2 rounded-lg text-xs transition-colors"
                    title="Configure Scope Policy"
                  >
                    <Settings className="h-4 w-4" />
                  </Link>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
