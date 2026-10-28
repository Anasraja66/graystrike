"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Shield, ArrowLeft, Scan as ScanIcon, Plus, ExternalLink } from "lucide-react";
import axios from "axios";

export default function ScansListPage() {
  const router = useRouter();
  const [scans, setScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) { router.push("/auth/login"); return; }
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

    axios.get(`${api}/api/v1/scans/`, {
      headers: { Authorization: `Bearer ${token}` }
    }).then((res) => setScans(res.data))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const statusColor: Record<string, string> = {
    completed: "text-emerald-400 bg-emerald-950/60 border-emerald-800",
    running: "text-blue-400 bg-blue-950/60 border-blue-800",
    queued: "text-yellow-400 bg-yellow-950/60 border-yellow-800",
    failed: "text-red-400 bg-red-950/60 border-red-800",
    cancelled: "text-slate-400 bg-slate-800 border-slate-700",
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
              <h1 className="text-2xl font-bold text-white">Security Scans</h1>
              <p className="text-slate-400 text-sm">Autonomous multi-agent penetration testing sessions</p>
            </div>
          </div>
          <Link
            href="/projects/new"
            className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-sm font-semibold flex items-center gap-2 transition-colors"
          >
            <Plus className="h-4 w-4" /> New Target
          </Link>
        </div>

        {loading ? (
          <div className="text-center py-20 text-blue-400">Loading scans...</div>
        ) : scans.length === 0 ? (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-12 text-center">
            <ScanIcon className="h-12 w-12 text-slate-700 mx-auto mb-4" />
            <h3 className="text-lg font-bold text-white">No Scans Recorded</h3>
            <p className="text-slate-400 text-sm mt-1">Add a project to initiate your first automated audit.</p>
          </div>
        ) : (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-950/80 text-slate-400 text-xs uppercase border-b border-slate-800">
                <tr>
                  <th className="px-6 py-4">Target Application</th>
                  <th className="px-6 py-4">Status</th>
                  <th className="px-6 py-4">Total Findings</th>
                  <th className="px-6 py-4">Critical</th>
                  <th className="px-6 py-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {scans.map((s) => (
                  <tr key={s.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-6 py-4 font-mono text-white">{s.target_url}</td>
                    <td className="px-6 py-4">
                      <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase border ${statusColor[s.status] || "text-slate-400"}`}>
                        {s.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-slate-300 font-semibold">{s.total_findings}</td>
                    <td className="px-6 py-4 text-red-400 font-bold">{s.critical_count}</td>
                    <td className="px-6 py-4 text-right">
                      <Link
                        href={`/scans/${s.id}`}
                        className="text-blue-400 hover:text-blue-300 text-xs font-semibold inline-flex items-center gap-1"
                      >
                        Monitor <ExternalLink className="h-3.5 w-3.5" />
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
  );
}
