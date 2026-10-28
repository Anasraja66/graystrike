"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { 
  Shield, ArrowLeft, Download, FileText, CheckCircle, Award, 
  ExternalLink, CheckCircle2, XCircle, AlertCircle, FileCode
} from "lucide-react";
import axios from "axios";

export default function ReportsPage() {
  const router = useRouter();
  const [scans, setScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [complianceModal, setComplianceModal] = useState<any | null>(null);
  const [loadingCompliance, setLoadingCompliance] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) { router.push("/auth/login"); return; }
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

    axios.get(`${api}/api/v1/scans/`, {
      headers: { Authorization: `Bearer ${token}` }
    }).then((res) => {
      setScans(res.data.filter((s: any) => s.status === "completed"));
    }).catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const downloadPdf = (scanId: string) => {
    const token = localStorage.getItem("token");
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
    window.open(`${api}/api/v1/reports/scans/${scanId}/pdf?token=${token}`, "_blank");
  };

  const downloadJson = (scanId: string) => {
    const token = localStorage.getItem("token");
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
    window.open(`${api}/api/v1/reports/scans/${scanId}/json?token=${token}`, "_blank");
  };

  const downloadSarif = (scanId: string) => {
    const token = localStorage.getItem("token");
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
    window.open(`${api}/api/v1/ci/scans/${scanId}/sarif?token=${token}`, "_blank");
  };

  const downloadCompliancePacket = (scanId: string) => {
    const token = localStorage.getItem("token");
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
    window.open(`${api}/api/v1/reports/scans/${scanId}/compliance-packet-pdf?token=${token}`, "_blank");
  };

  const openCompliance = async (scanId: string) => {
    setLoadingCompliance(true);
    const token = localStorage.getItem("token");
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

    try {
      const res = await axios.get(`${api}/api/v1/reports/scans/${scanId}/compliance`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setComplianceModal(res.data);
    } catch (e) {
      console.error(e);
      alert("Could not load compliance evaluation.");
    } finally {
      setLoadingCompliance(false);
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
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-bold text-white">Assessment & Compliance Reports</h1>
                <span className="text-[10px] bg-indigo-950 text-indigo-300 border border-indigo-800 px-2 py-0.5 rounded-full font-mono uppercase tracking-wide">
                  SOC 2 · ISO 27001 · PCI-DSS · SARIF
                </span>
              </div>
              <p className="text-slate-400 text-sm mt-0.5">
                Download executive audit PDFs, OASIS SARIF 2.1.0 deliverables, and regulatory compliance evaluations
              </p>
            </div>
          </div>
        </div>

        {/* Compliance Evaluation Modal */}
        {complianceModal && (
          <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50 overflow-y-auto">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 max-w-3xl w-full my-8 shadow-2xl">
              <div className="flex items-center justify-between pb-4 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <Award className="h-6 w-6 text-indigo-400" />
                  <h3 className="text-lg font-bold text-white">Regulatory Compliance Audit Matrix</h3>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => downloadCompliancePacket(complianceModal.scan_id)}
                    className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition shadow"
                  >
                    <Download className="h-3.5 w-3.5" />
                    <span>Download Auditor Evidence PDF</span>
                  </button>
                  <button
                    onClick={() => setComplianceModal(null)}
                    className="text-slate-400 hover:text-white text-xs font-semibold px-2.5 py-1.5 bg-slate-800 rounded-lg"
                  >
                    Close
                  </button>
                </div>
              </div>

              <div className="mt-4 space-y-4">
                {Object.values(complianceModal.frameworks).map((fw: any) => (
                  <div key={fw.framework_id} className="bg-slate-950/80 border border-slate-800 rounded-xl p-4">
                    <div className="flex items-center justify-between gap-4 mb-2">
                      <div>
                        <span className="font-bold text-white text-sm">{fw.framework_name}</span>
                        <span className="text-xs text-slate-500 block">{fw.full_name}</span>
                      </div>
                      <div className="text-right">
                        <span className={`text-xs font-bold px-2 py-0.5 rounded ${
                          fw.status === "PASSED" ? "bg-emerald-950 text-emerald-300 border border-emerald-800" :
                          fw.status === "NEEDS_REMEDIATION" ? "bg-amber-950 text-amber-300 border border-amber-800" :
                          "bg-red-950 text-red-300 border border-red-800"
                        }`}>
                          {fw.status} ({fw.compliance_score}%)
                        </span>
                        <span className="text-[10px] text-slate-400 block mt-0.5">
                          {fw.passing_controls}/{fw.total_controls} Controls Passing
                        </span>
                      </div>
                    </div>

                    {/* Progress Bar */}
                    <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden mb-3">
                      <div
                        className={`h-full ${fw.compliance_score >= 80 ? "bg-emerald-500" : fw.compliance_score >= 60 ? "bg-amber-500" : "bg-red-500"}`}
                        style={{ width: `${fw.compliance_score}%` }}
                      />
                    </div>

                    {/* Controls Checklist */}
                    <div className="space-y-1.5 pt-2 border-t border-slate-900">
                      {fw.controls.map((ctrl: any) => (
                        <div key={ctrl.control_id} className="flex items-start justify-between text-xs gap-3">
                          <span className="text-slate-300 flex items-center gap-1.5">
                            {ctrl.status === "COMPLIANT" ? (
                              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                            ) : (
                              <XCircle className="h-3.5 w-3.5 text-red-400 shrink-0" />
                            )}
                            <strong className="text-slate-400">{ctrl.control_id}:</strong> {ctrl.title}
                          </span>
                          <span className={`text-[10px] font-mono shrink-0 ${ctrl.status === "COMPLIANT" ? "text-emerald-400" : "text-red-400"}`}>
                            {ctrl.status === "COMPLIANT" ? "PASS" : `${ctrl.violations_count} violation(s)`}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {loading ? (
          <div className="text-center py-20 text-blue-400">Loading reports...</div>
        ) : scans.length === 0 ? (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-12 text-center">
            <FileText className="h-12 w-12 text-slate-700 mx-auto mb-4" />
            <h3 className="text-lg font-bold text-white">No Reports Generated Yet</h3>
            <p className="text-slate-400 text-sm mt-1">Completed scans automatically produce downloadable reports here.</p>
          </div>
        ) : (
          <div className="space-y-4">
            {scans.map((s) => (
              <div key={s.id} className="bg-slate-900 border border-slate-800 rounded-xl p-6 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <FileText className="h-5 w-5 text-blue-400" />
                    <span className="font-semibold text-white">{s.target_url}</span>
                  </div>
                  <div className="flex items-center gap-3 text-xs text-slate-400 mt-2 flex-wrap">
                    <span>Scan ID: <code className="text-slate-300">{s.id.slice(0, 8)}</code></span>
                    <span>Total Findings: <strong className="text-white">{s.total_findings}</strong></span>
                    {s.critical_count > 0 && (
                      <span className="text-red-400 font-bold">Critical: {s.critical_count}</span>
                    )}
                    {s.high_count > 0 && (
                      <span className="text-orange-400 font-bold">High: {s.high_count}</span>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-2 flex-wrap">
                  {/* Auditor Evidence PDF */}
                  <button
                    onClick={() => downloadCompliancePacket(s.id)}
                    className="border border-emerald-800/80 bg-emerald-950/40 hover:bg-emerald-900/60 text-emerald-300 px-3 py-2 rounded-lg text-xs font-semibold transition-colors flex items-center gap-1.5 shadow-sm"
                    title="Download SOC 2 / ISO 27001 / PCI-DSS Auditor Evidence Packet"
                  >
                    <Award className="h-3.5 w-3.5 text-emerald-400" /> Auditor Evidence PDF
                  </button>

                  {/* Compliance Matrix Button */}
                  <button
                    onClick={() => openCompliance(s.id)}
                    disabled={loadingCompliance}
                    className="border border-indigo-900 bg-indigo-950/40 hover:bg-indigo-900/60 text-indigo-300 px-3 py-2 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5"
                    title="View SOC 2, ISO 27001, PCI-DSS compliance scores"
                  >
                    <Award className="h-3.5 w-3.5 text-indigo-400" /> Compliance Matrix
                  </button>

                  {/* SARIF Button for GitHub */}
                  <button
                    onClick={() => downloadSarif(s.id)}
                    className="border border-purple-900/80 bg-purple-950/30 hover:bg-purple-900/50 text-purple-300 px-3 py-2 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5"
                    title="Download SARIF 2.1.0 for GitHub Code Scanning"
                  >
                    <FileCode className="h-3.5 w-3.5 text-purple-400" /> SARIF 2.1
                  </button>

                  {/* JSON Button */}
                  <button
                    onClick={() => downloadJson(s.id)}
                    className="border border-slate-700 hover:border-slate-500 text-slate-300 px-3 py-2 rounded-lg text-xs transition-colors flex items-center gap-1.5"
                  >
                    <Download className="h-3.5 w-3.5" /> JSON
                  </button>

                  {/* PDF Report */}
                  <button
                    onClick={() => downloadPdf(s.id)}
                    className="bg-blue-600 hover:bg-blue-500 text-white px-3.5 py-2 rounded-lg text-xs font-semibold transition-colors flex items-center gap-1.5 shadow-md shadow-blue-500/20"
                  >
                    <Download className="h-3.5 w-3.5" /> Executive PDF
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
