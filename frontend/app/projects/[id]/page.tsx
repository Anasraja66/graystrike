"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  Globe,
  ArrowLeft,
  Settings,
  Play,
  Shield,
  AlertTriangle,
  CheckCircle2,
  Scan,
  RefreshCw,
  ExternalLink,
  Calendar,
  Layers,
  FileText
} from "lucide-react";
import axios from "axios";

export default function ProjectDetailPage() {
  const params = useParams();
  const router = useRouter();
  const projectId = params.id as string;

  const [project, setProject] = useState<any>(null);
  const [scans, setScans] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [startingScan, setStartingScan] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      router.push("/auth/login");
      return;
    }
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
    const headers = { Authorization: `Bearer ${token}` };

    Promise.all([
      axios.get(`${api}/api/v1/projects/${projectId}`, { headers }),
      axios.get(`${api}/api/v1/scans/`, { headers }),
      axios.get(`${api}/api/v1/findings/?project_id=${projectId}`, { headers }).catch(() => ({ data: [] })),
    ])
      .then(([projRes, scansRes, findingsRes]) => {
        setProject(projRes.data);
        const projScans = (scansRes.data || []).filter((s: any) => s.project_id === projectId);
        setScans(projScans);
        setFindings(findingsRes.data || []);
      })
      .catch((err) => {
        console.error("Failed to load project details:", err);
      })
      .finally(() => setLoading(false));
  }, [projectId]);

  const handleStartScan = async () => {
    setStartingScan(true);
    const token = localStorage.getItem("token");
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

    try {
      const res = await axios.post(
        `${api}/api/v1/scans/`,
        { project_id: projectId, target_url: project?.base_url },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      router.push(`/scans/${res.data.id}`);
    } catch (err: any) {
      alert("Failed to start scan: " + (err.response?.data?.detail || err.message));
      setStartingScan(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center text-blue-400">
        Loading project details...
      </div>
    );
  }

  if (!project) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center text-slate-300 gap-4">
        <AlertTriangle className="h-10 w-10 text-rose-400" />
        <h2 className="text-xl font-bold text-white">Project Not Found</h2>
        <Link href="/projects" className="text-blue-400 hover:underline">
          Return to Projects List
        </Link>
      </div>
    );
  }

  const criticalCount = findings.filter((f) => f.severity?.toLowerCase() === "critical").length;
  const highCount = findings.filter((f) => f.severity?.toLowerCase() === "high").length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 md:p-8">
      <div className="max-w-6xl mx-auto space-y-6">
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
              <div className="flex items-center gap-3">
                <h1 className="text-2xl md:text-3xl font-extrabold text-white tracking-tight flex items-center gap-2">
                  <Globe className="h-6 w-6 text-blue-400" />
                  {project.name}
                </h1>
                <span className="text-xs bg-slate-800 text-slate-300 px-2.5 py-0.5 rounded-full font-mono">
                  {project.scan_schedule || "Manual"}
                </span>
              </div>
              <a
                href={project.base_url}
                target="_blank"
                rel="noreferrer"
                className="text-slate-400 hover:text-blue-300 text-xs font-mono mt-1 inline-flex items-center gap-1 transition"
              >
                {project.base_url}
                <ExternalLink className="h-3 w-3" />
              </a>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="flex items-center gap-3 flex-wrap">
            <Link
              href={`/projects/${project.id}/scope`}
              className="px-3.5 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-200 text-xs font-semibold rounded-lg flex items-center gap-1.5 transition"
            >
              <Settings className="h-4 w-4 text-slate-400" />
              <span>Scope & DNS Policy</span>
            </Link>

            <Link
              href="/attack-surface"
              className="px-3.5 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-cyan-300 text-xs font-semibold rounded-lg flex items-center gap-1.5 transition"
            >
              <Layers className="h-4 w-4 text-cyan-400" />
              <span>Attack Surface</span>
            </Link>

            <button
              onClick={handleStartScan}
              disabled={startingScan}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-bold rounded-lg flex items-center gap-1.5 shadow-md shadow-blue-500/20 transition"
            >
              <Play className="h-3.5 w-3.5 fill-current" />
              <span>{startingScan ? "Launching 44 Agents..." : "Start Security Scan"}</span>
            </button>
          </div>
        </div>

        {/* Project Summary Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Scans Run</span>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-white">{scans.length}</span>
              <span className="text-xs text-blue-400 font-medium">Audits</span>
            </div>
            <p className="text-xs text-slate-400 mt-1">Automated LangGraph sessions</p>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Findings</span>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-white">{findings.length}</span>
              <span className="text-xs text-slate-400 font-medium">Bugs</span>
            </div>
            <p className="text-xs text-slate-400 mt-1">Across all assessment micro-agents</p>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Critical Severity</span>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-red-500">{criticalCount}</span>
              <span className="text-xs text-red-400 font-medium">Urgent</span>
            </div>
            <p className="text-xs text-slate-400 mt-1">Requires immediate remediation</p>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">High Severity</span>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-orange-400">{highCount}</span>
              <span className="text-xs text-orange-400 font-medium">High Risk</span>
            </div>
            <p className="text-xs text-slate-400 mt-1">Severe logic or configuration flaws</p>
          </div>
        </div>

        {/* Project Scans Table */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden space-y-3 p-6">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <Scan className="h-5 w-5 text-blue-400" />
              Scans History for {project.name}
            </h3>
            <button
              onClick={handleStartScan}
              disabled={startingScan}
              className="text-xs text-blue-400 hover:text-blue-300 font-semibold"
            >
              + Run New Scan
            </button>
          </div>

          {scans.length === 0 ? (
            <div className="text-center py-12 border border-dashed border-slate-800 rounded-xl">
              <Scan className="h-10 w-10 text-slate-700 mx-auto mb-2" />
              <p className="text-slate-400 text-sm">No scans conducted for this application yet.</p>
              <button
                onClick={handleStartScan}
                disabled={startingScan}
                className="mt-3 px-4 py-1.5 bg-blue-600 text-white rounded-lg text-xs font-semibold"
              >
                Run First Scan
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="bg-slate-950 text-slate-400 text-xs uppercase border-b border-slate-800">
                  <tr>
                    <th className="px-4 py-3">Scan ID</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Total Findings</th>
                    <th className="px-4 py-3">Critical</th>
                    <th className="px-4 py-3">High</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {scans.map((s) => (
                    <tr key={s.id} className="hover:bg-slate-800/40 transition">
                      <td className="px-4 py-3 font-mono text-white text-xs">{s.id.slice(0, 8)}</td>
                      <td className="px-4 py-3">
                        <span className="text-xs font-semibold uppercase px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800">
                          {s.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-slate-300 font-semibold">{s.total_findings || 0}</td>
                      <td className="px-4 py-3 text-red-400 font-bold">{s.critical_count || 0}</td>
                      <td className="px-4 py-3 text-orange-400 font-bold">{s.high_count || 0}</td>
                      <td className="px-4 py-3 text-right space-x-2">
                        <Link
                          href={`/scans/${s.id}`}
                          className="text-blue-400 hover:text-blue-300 text-xs font-semibold"
                        >
                          View Results →
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
