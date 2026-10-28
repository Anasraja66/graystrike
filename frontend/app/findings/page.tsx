"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { 
  Shield, ArrowLeft, AlertTriangle, Filter, CheckCircle, ExternalLink, 
  Copy, Check, RefreshCw, Clock, History, AlertCircle, CheckCircle2, XCircle, Sparkles,
  GitPullRequest, Code2, X, Terminal, FlaskConical
} from "lucide-react";
import axios from "axios";

export default function FindingsPage() {
  const router = useRouter();
  const [findings, setFindings] = useState<any[]>([]);
  const [filterSeverity, setFilterSeverity] = useState<string>("");
  const [filterStatus, setFilterStatus] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  
  // Retest state
  const [retestingId, setRetestingId] = useState<string | null>(null);
  const [retestModalData, setRetestModalData] = useState<any | null>(null);
  const [statusUpdatingId, setStatusUpdatingId] = useState<string | null>(null);

  // Auto-Fix PR state
  const [autoFixLoadingId, setAutoFixLoadingId] = useState<string | null>(null);
  const [autoFixModalData, setAutoFixModalData] = useState<{
    findingId: string;
    findingTitle: string;
    patch: {
      title: string;
      target_file: string;
      patch_code: string;
      instructions: string;
    };
    pull_request_url?: string | null;
    pull_request_number?: number | null;
    branch_name?: string | null;
  } | null>(null);
  const [githubRepo, setGithubRepo] = useState<string>("");
  const [githubToken, setGithubToken] = useState<string>("");
  const [baseBranch, setBaseBranch] = useState<string>("main");
  const [creatingPr, setCreatingPr] = useState<boolean>(false);
  const [patchCopied, setPatchCopied] = useState<boolean>(false);
  const [aiAppOnly, setAiAppOnly] = useState<boolean>(false);

  // QA Regression Test Modal State
  const [regressionLoadingId, setRegressionLoadingId] = useState<string | null>(null);
  const [regressionModalData, setRegressionModalData] = useState<any | null>(null);
  const [activeTestTab, setActiveTestTab] = useState<"typescript_jest" | "python_pytest" | "playwright_e2e" | "safe_curl_verification">("typescript_jest");
  const [testCopied, setTestCopied] = useState<boolean>(false);

  const isAiAppFinding = (f: any) => {
    const t = (f.title || "").toLowerCase();
    const c = (f.category || "").toLowerCase();
    const a = (f.affected_asset || "").toLowerCase();
    const cwe = (f.cwe_id || "").toLowerCase();
    return (
      t.includes("supabase") || t.includes("secret") || t.includes("llm") ||
      t.includes("chat") || t.includes("webhook") || t.includes("bucket") ||
      t.includes("storage") || t.includes("admin") || c.includes("supabase") ||
      cwe.includes("cwe-1426") || cwe.includes("cwe-798") || cwe.includes("cwe-284") ||
      cwe.includes("cwe-345") || cwe.includes("cwe-552") || a.includes("supabase") ||
      a.includes("/api/chat") || a.includes("/api/ai") || a.includes("webhook")
    );
  };

  const displayedFindings = findings.filter(f => !aiAppOnly || isAiAppFinding(f));

  const handleCopyPrompt = (id: string, promptText: string) => {
    navigator.clipboard.writeText(promptText);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2500);
  };

  const fetchFindings = async () => {
    const token = localStorage.getItem("token");
    if (!token) { router.push("/auth/login"); return; }
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

    try {
      const params = new URLSearchParams();
      if (filterSeverity) params.append("severity", filterSeverity);
      if (filterStatus) params.append("status", filterStatus);

      const url = `${api}/api/v1/findings/?${params.toString()}`;
      const res = await axios.get(url, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setFindings(res.data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, [filterSeverity, filterStatus]);

  const handleStatusChange = async (findingId: string, newStatus: string) => {
    const token = localStorage.getItem("token");
    if (!token) return;
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
    setStatusUpdatingId(findingId);

    try {
      await axios.patch(`${api}/api/v1/findings/${findingId}/status`, 
        { status: newStatus },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      await fetchFindings();
    } catch (e) {
      console.error("Status update failed:", e);
    } finally {
      setStatusUpdatingId(null);
    }
  };

  const handleRetest = async (findingId: string) => {
    const token = localStorage.getItem("token");
    if (!token) return;
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
    setRetestingId(findingId);

    try {
      const res = await axios.post(`${api}/api/v1/findings/${findingId}/retest`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setRetestModalData(res.data);
      await fetchFindings();
    } catch (e: any) {
      console.error("Retest failed:", e);
      alert("Retest probe failed: " + (e.response?.data?.detail || e.message));
    } finally {
      setRetestingId(null);
    }
  };

  const handleOpenAutoFix = async (finding: any) => {
    const token = localStorage.getItem("token");
    if (!token) return;
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
    setAutoFixLoadingId(finding.id);

    try {
      const res = await axios.post(
        `${api}/api/v1/findings/${finding.id}/auto-fix`,
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setAutoFixModalData({
        findingId: finding.id,
        findingTitle: finding.title,
        patch: res.data.patch,
        pull_request_url: res.data.pull_request_url,
      });
    } catch (e: any) {
      console.error("Auto-fix generation failed:", e);
      alert("Failed to generate code patch: " + (e.response?.data?.detail || e.message));
    } finally {
      setAutoFixLoadingId(null);
    }
  };

  const handleCreatePr = async () => {
    if (!autoFixModalData) return;
    if (!githubRepo.trim() || !githubToken.trim()) {
      alert("Please enter both GitHub Repository (e.g. owner/repo) and Personal Access Token.");
      return;
    }

    const token = localStorage.getItem("token");
    if (!token) return;
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
    setCreatingPr(true);

    try {
      const res = await axios.post(
        `${api}/api/v1/findings/${autoFixModalData.findingId}/auto-fix`,
        {
          github_repo: githubRepo.trim(),
          github_token: githubToken.trim(),
          base_branch: baseBranch.trim() || "main",
        },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      setAutoFixModalData((prev) => prev ? {
        ...prev,
        pull_request_url: res.data.pull_request_url,
        pull_request_number: res.data.pull_request_number,
        branch_name: res.data.branch_name,
      } : null);
    } catch (e: any) {
      console.error("Failed to create PR:", e);
      alert("GitHub PR creation error: " + (e.response?.data?.detail || e.message));
    } finally {
      setCreatingPr(false);
    }
  };

  const handleCopyPatch = (patchCode: string) => {
    navigator.clipboard.writeText(patchCode);
    setPatchCopied(true);
    setTimeout(() => setPatchCopied(false), 2000);
  };

  const handleOpenRegressionTests = async (f: any) => {
    setRegressionLoadingId(f.id);
    const token = localStorage.getItem("token");
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
    try {
      const res = await axios.get(`${api}/api/v1/findings/${f.id}/regression-tests`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setRegressionModalData({ finding: f, tests: res.data });
      setActiveTestTab("typescript_jest");
    } catch (err: any) {
      alert("Failed to load regression tests: " + (err.response?.data?.detail || err.message));
    } finally {
      setRegressionLoadingId(null);
    }
  };

  const handleCopyTestCode = (code: string) => {
    navigator.clipboard.writeText(code);
    setTestCopied(true);
    setTimeout(() => setTestCopied(false), 2000);
  };

  const severityBadge = (sev: string) => {
    switch (sev?.toLowerCase()) {
      case "critical": return "bg-red-950 text-red-400 border-red-800";
      case "high": return "bg-orange-950 text-orange-400 border-orange-800";
      case "medium": return "bg-yellow-950 text-yellow-400 border-yellow-800";
      case "low": return "bg-blue-950 text-blue-400 border-blue-800";
      default: return "bg-slate-800 text-slate-400 border-slate-700";
    }
  };

  const statusBadge = (st: string) => {
    const s = st?.toLowerCase();
    switch (s) {
      case "resolved":
        return "bg-emerald-950/80 text-emerald-300 border-emerald-700/80";
      case "regression_detected":
        return "bg-red-950 text-red-300 border-red-600 animate-pulse font-bold";
      case "ready_retest":
        return "bg-purple-950/80 text-purple-300 border-purple-700";
      case "in_progress":
        return "bg-amber-950/80 text-amber-300 border-amber-700";
      case "triaged":
        return "bg-blue-950/80 text-blue-300 border-blue-700";
      case "false_positive":
        return "bg-slate-800 text-slate-400 border-slate-700";
      default:
        return "bg-slate-900 text-slate-300 border-slate-800";
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
          <div className="flex items-center gap-4">
            <Link href="/dashboard" className="text-slate-400 hover:text-white transition-colors">
              <ArrowLeft className="h-5 w-5" />
            </Link>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-bold text-white">Vulnerability Findings & Verification</h1>
                <span className="text-[10px] bg-blue-950 text-blue-300 border border-blue-800 px-2 py-0.5 rounded-full font-mono uppercase tracking-wide">
                  Evidence Engine 2.0
                </span>
              </div>
              <p className="text-slate-400 text-sm mt-0.5">
                Targeted retests, automated regression checks, and AI remediation prompts
              </p>
            </div>
          </div>

          {/* Filters */}
          <div className="flex flex-wrap items-center gap-3">
            {/* Status Filter */}
            <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-sm">
              <Filter className="h-4 w-4 text-slate-400" />
              <select
                value={filterStatus}
                onChange={(e) => setFilterStatus(e.target.value)}
                className="bg-transparent text-white focus:outline-none"
              >
                <option value="" className="bg-slate-900">All Statuses</option>
                <option value="open" className="bg-slate-900">Open</option>
                <option value="triaged" className="bg-slate-900">Triaged</option>
                <option value="in_progress" className="bg-slate-900">In Progress</option>
                <option value="ready_retest" className="bg-slate-900">Ready for Retest</option>
                <option value="resolved" className="bg-slate-900">Resolved (Fixed)</option>
                <option value="regression_detected" className="bg-slate-900">🚨 Regression Detected</option>
                <option value="false_positive" className="bg-slate-900">False Positive</option>
              </select>
            </div>

            {/* Severity Filter */}
            <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-sm">
              <select
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
                className="bg-transparent text-white focus:outline-none"
              >
                <option value="" className="bg-slate-900">All Severities</option>
                <option value="critical" className="bg-slate-900">Critical</option>
                <option value="high" className="bg-slate-900">High</option>
                <option value="medium" className="bg-slate-900">Medium</option>
                <option value="low" className="bg-slate-900">Low</option>
              </select>
            </div>

            {/* AI App Mode Filter Toggle */}
            <button
              onClick={() => setAiAppOnly(!aiAppOnly)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold transition-all border ${
                aiAppOnly
                  ? "bg-gradient-to-r from-purple-900 to-indigo-900 text-purple-200 border-purple-500 shadow-md shadow-purple-950/50"
                  : "bg-slate-900 text-slate-400 border-slate-800 hover:text-white"
              }`}
              title="Filter exclusively for AI-generated / Vibe-coded vulnerabilities (Supabase RLS, Leaked API Keys, AI Endpoints, Unsigned Webhooks)"
            >
              <Sparkles className={`h-3.5 w-3.5 ${aiAppOnly ? "text-purple-300 animate-pulse" : "text-slate-500"}`} />
              <span>AI App / Vibe Shield</span>
            </button>
          </div>
        </div>

        {/* Retest Result Modal / Alert Banner */}
        {retestModalData && (
          <div className="mb-6 bg-slate-900 border-2 rounded-2xl p-6 shadow-2xl relative transition-all"
            style={{
              borderColor: retestModalData.is_fixed ? "rgba(16, 185, 129, 0.7)" : "rgba(239, 68, 68, 0.7)"
            }}
          >
            <div className="flex items-start justify-between gap-4">
              <div className="flex items-start gap-3">
                {retestModalData.is_fixed ? (
                  <CheckCircle2 className="h-6 w-6 text-emerald-400 shrink-0 mt-0.5" />
                ) : (
                  <XCircle className="h-6 w-6 text-red-400 shrink-0 mt-0.5" />
                )}
                <div>
                  <h3 className="text-lg font-bold text-white flex items-center gap-2">
                    {retestModalData.is_fixed ? (
                      <span className="text-emerald-400">Fix Confirmed & Verified! 🎉</span>
                    ) : (
                      <span className="text-red-400">Retest Failed — Vulnerability Still Active ⚠️</span>
                    )}
                    <span className="text-xs font-mono font-normal text-slate-400">
                      ({retestModalData.tested_at})
                    </span>
                  </h3>
                  <p className="text-sm text-slate-300 mt-1">
                    {retestModalData.notes}
                  </p>
                  
                  {/* Before / After Evidence Comparison */}
                  <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-slate-950/80 p-3 rounded-lg border border-slate-800">
                      <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1">
                        Previous Evidence (Before Fix)
                      </span>
                      <p className="text-xs font-mono text-slate-300 line-clamp-3">
                        {retestModalData.previous_evidence || "Initial scan detection"}
                      </p>
                    </div>
                    <div className="bg-slate-950/80 p-3 rounded-lg border border-slate-800">
                      <span className="text-[10px] font-bold text-blue-400 uppercase tracking-wider block mb-1">
                        Live Retest Verification (After Fix)
                      </span>
                      <p className="text-xs font-mono text-emerald-300">
                        {retestModalData.new_evidence}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
              <button
                onClick={() => setRetestModalData(null)}
                className="text-slate-400 hover:text-white text-xs font-semibold px-2.5 py-1 bg-slate-800 rounded"
              >
                Dismiss
              </button>
            </div>
          </div>
        )}

        {/* Auto-Fix PR Modal */}
        {autoFixModalData && (
          <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 overflow-y-auto">
            <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-3xl w-full p-6 shadow-2xl space-y-5 my-8">
              {/* Header */}
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 bg-gradient-to-br from-indigo-600 to-purple-600 rounded-xl text-white shadow-lg shadow-indigo-900/30">
                    <GitPullRequest className="h-6 w-6" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="text-xl font-bold text-white">Auto-Fix & Pull Request Agent</h3>
                      <span className="text-[10px] font-mono uppercase bg-indigo-950 text-indigo-300 border border-indigo-800 px-2 py-0.5 rounded-full">
                        Automated Patch
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Finding: <span className="text-slate-200 font-semibold">{autoFixModalData.findingTitle}</span>
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setAutoFixModalData(null)}
                  className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>

              {/* Instructions banner */}
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5 flex items-center gap-3 text-xs text-slate-300">
                <Sparkles className="h-4 w-4 text-indigo-400 shrink-0" />
                <span>{autoFixModalData.patch.instructions}</span>
              </div>

              {/* Code Patch Box */}
              <div>
                <div className="flex items-center justify-between bg-slate-950 px-4 py-2 rounded-t-xl border border-b-0 border-slate-800">
                  <div className="flex items-center gap-2">
                    <Code2 className="h-4 w-4 text-indigo-400" />
                    <span className="text-xs font-mono font-bold text-slate-200">
                      {autoFixModalData.patch.target_file}
                    </span>
                  </div>
                  <button
                    onClick={() => handleCopyPatch(autoFixModalData.patch.patch_code)}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
                  >
                    {patchCopied ? (
                      <>
                        <Check className="h-3.5 w-3.5 text-emerald-400" />
                        <span className="text-emerald-400 font-semibold">Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="h-3.5 w-3.5 text-slate-400" />
                        <span>Copy Code</span>
                      </>
                    )}
                  </button>
                </div>
                <pre className="bg-slate-950 text-emerald-300 text-xs font-mono p-4 rounded-b-xl border border-slate-800 overflow-x-auto max-h-64 select-all leading-relaxed">
                  <code>{autoFixModalData.patch.patch_code}</code>
                </pre>
              </div>

              {/* PR Result or PR Creation Form */}
              {autoFixModalData.pull_request_url ? (
                <div className="bg-emerald-950/40 border border-emerald-800/80 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                      <CheckCircle2 className="h-5 w-5" />
                      <span>Pull Request #{autoFixModalData.pull_request_number} Created Successfully!</span>
                    </div>
                    <p className="text-xs text-slate-300 mt-1">
                      Branch: <code className="text-emerald-300 font-mono">{autoFixModalData.branch_name}</code>
                    </p>
                  </div>
                  <a
                    href={autoFixModalData.pull_request_url}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1.5 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold rounded-lg shadow transition-colors shrink-0"
                  >
                    <span>View PR on GitHub</span>
                    <ExternalLink className="h-3.5 w-3.5" />
                  </a>
                </div>
              ) : (
                <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-4 space-y-3">
                  <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                    <Terminal className="h-4 w-4 text-purple-400" />
                    Open Automated GitHub Pull Request (1-Click)
                  </h4>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                    <div>
                      <label className="block text-slate-400 mb-1 font-medium">GitHub Repository</label>
                      <input
                        type="text"
                        placeholder="owner/repo (e.g. acme/web-app)"
                        value={githubRepo}
                        onChange={(e) => setGithubRepo(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1 font-medium">Base Branch</label>
                      <input
                        type="text"
                        placeholder="main"
                        value={baseBranch}
                        onChange={(e) => setBaseBranch(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                  </div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1 font-medium">
                      GitHub Personal Access Token (PAT) <span className="text-[10px] text-slate-500">(Requires `repo` scope)</span>
                    </label>
                    <input
                      type="password"
                      placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                      value={githubToken}
                      onChange={(e) => setGithubToken(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white placeholder-slate-500 text-xs focus:outline-none focus:border-indigo-500 font-mono"
                    />
                  </div>
                  <div className="flex justify-end pt-2">
                    <button
                      onClick={handleCreatePr}
                      disabled={creatingPr || !githubRepo || !githubToken}
                      className="inline-flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-bold rounded-lg shadow-lg shadow-indigo-950/50 transition-all"
                    >
                      {creatingPr ? (
                        <>
                          <RefreshCw className="h-4 w-4 animate-spin" />
                          <span>Creating Branch & Opening PR...</span>
                        </>
                      ) : (
                        <>
                          <GitPullRequest className="h-4 w-4" />
                          <span>Submit Remediation PR</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* QA Regression Test Modal */}
        {regressionModalData && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
            <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-3xl w-full p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto">
              {/* Header */}
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-3 bg-emerald-950/80 border border-emerald-800 rounded-xl text-emerald-400">
                    <FlaskConical className="h-6 w-6" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="text-xl font-bold text-white">Automated QA & CI/CD Regression Tests</h3>
                      <span className="text-[10px] font-mono uppercase bg-emerald-950 text-emerald-300 border border-emerald-800 px-2 py-0.5 rounded-full font-semibold">
                        Zero-Regression Shield
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Finding: <span className="text-slate-200 font-semibold">{regressionModalData.finding.title}</span>
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setRegressionModalData(null)}
                  className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>

              {/* Explanatory banner */}
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5 flex items-center gap-3 text-xs text-slate-300">
                <Shield className="h-4 w-4 text-emerald-400 shrink-0" />
                <span>
                  Commit this defensive test to your repository. It automatically executes in GitHub Actions / CI to ensure this security vulnerability is never reintroduced.
                </span>
              </div>

              {/* Framework Selector Tabs */}
              <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
                {[
                  { id: "typescript_jest", label: "TypeScript (Vitest / Jest)" },
                  { id: "python_pytest", label: "Python (Pytest)" },
                  { id: "playwright_e2e", label: "Playwright E2E" },
                  { id: "safe_curl_verification", label: "Terminal cURL Probe" },
                ].map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTestTab(tab.id as any)}
                    className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition ${
                      activeTestTab === tab.id
                        ? "bg-emerald-600 text-white"
                        : "bg-slate-800/80 text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              {/* Test Content Box */}
              {regressionModalData.tests?.test_frameworks?.[activeTestTab] && (
                <div>
                  <div className="flex items-center justify-between bg-slate-950 px-4 py-2 rounded-t-xl border border-b-0 border-slate-800">
                    <div className="flex items-center gap-2">
                      <Code2 className="h-4 w-4 text-emerald-400" />
                      <span className="text-xs font-mono font-bold text-slate-200">
                        {regressionModalData.tests.test_frameworks[activeTestTab].filename || "Terminal Diagnostic Probe"}
                      </span>
                    </div>
                    <button
                      onClick={() =>
                        handleCopyTestCode(
                          regressionModalData.tests.test_frameworks[activeTestTab].code ||
                            regressionModalData.tests.test_frameworks[activeTestTab].command
                        )
                      }
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
                    >
                      {testCopied ? (
                        <>
                          <Check className="h-3.5 w-3.5 text-emerald-400" />
                          <span className="text-emerald-400 font-semibold">Copied!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="h-3.5 w-3.5 text-slate-400" />
                          <span>Copy Code</span>
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="bg-slate-950 text-emerald-300 text-xs font-mono p-4 rounded-b-xl border border-slate-800 overflow-x-auto max-h-72 select-all leading-relaxed">
                    <code>
                      {regressionModalData.tests.test_frameworks[activeTestTab].code ||
                        regressionModalData.tests.test_frameworks[activeTestTab].command}
                    </code>
                  </pre>
                  <div className="mt-2 text-xs text-slate-400 flex items-center justify-between">
                    <span>{regressionModalData.tests.test_frameworks[activeTestTab].description}</span>
                    {regressionModalData.tests.test_frameworks[activeTestTab].expected_status && (
                      <span className="text-emerald-400 font-mono font-semibold">
                        Expected: {regressionModalData.tests.test_frameworks[activeTestTab].expected_status}
                      </span>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Findings List */}
        {loading ? (
          <div className="text-center py-20 text-blue-400">Loading findings...</div>
        ) : displayedFindings.length === 0 ? (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-12 text-center">
            <CheckCircle className="h-12 w-12 text-emerald-500 mx-auto mb-4" />
            <h3 className="text-lg font-bold text-white">No Vulnerabilities Match Filters</h3>
            <p className="text-slate-400 text-sm mt-1">
              {aiAppOnly ? "No AI-app specific vulnerabilities found on this target." : "Try resetting severity or status filters."}
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {displayedFindings.map((f) => (
                  <div 
                    key={f.id} 
                    className={`bg-slate-900 border rounded-xl p-6 transition-all ${
                      f.status === "regression_detected" 
                        ? "border-red-600/80 shadow-lg shadow-red-950/40" 
                        : f.status === "resolved"
                        ? "border-emerald-900/60 opacity-90"
                        : "border-slate-800 hover:border-slate-700"
                    }`}
                  >
                    <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
                      <div className="flex-1">
                        {/* Top Badges */}
                        <div className="flex items-center gap-3 mb-2 flex-wrap">
                          <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase border ${severityBadge(f.severity)}`}>
                            {f.severity}
                          </span>
                          
                          {/* Lifecycle Status Badge */}
                          <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase border ${statusBadge(f.status)}`}>
                            {f.status === "regression_detected" ? "🚨 REGRESSION DETECTED" : f.status}
                          </span>

                          {/* AI App Specialized Badge */}
                          {isAiAppFinding(f) && (
                            <span className="text-[10px] font-mono bg-purple-950 text-purple-300 border border-purple-800 px-2 py-0.5 rounded-full flex items-center gap-1 font-semibold">
                              <Sparkles className="h-3 w-3 text-purple-400" />
                              AI App Vulnerability
                            </span>
                          )}

                          {f.cwe_id && (
                            <span className="text-xs font-mono bg-slate-800 text-slate-300 px-2 py-0.5 rounded">
                              {f.cwe_id}
                            </span>
                          )}
                          {f.owasp_ref && (
                            <span className="text-xs font-mono bg-blue-950/60 text-blue-300 px-2 py-0.5 rounded border border-blue-900">
                              {f.owasp_ref}
                            </span>
                          )}
                      
                      {/* Confidence Score */}
                      <span className="text-xs text-slate-400 font-mono">
                        Confidence: {(f.confidence * 100).toFixed(0)}%
                      </span>

                      {/* Retest status badge */}
                      {f.retest_status && f.retest_status !== "untested" && (
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                          f.retest_status === "fixed_verified" 
                            ? "bg-emerald-950 text-emerald-400 border border-emerald-800" 
                            : "bg-amber-950 text-amber-400 border border-amber-800"
                        }`}>
                          Retest: {f.retest_status}
                        </span>
                      )}
                    </div>

                    {/* Title & Asset */}
                    <h3 className="text-lg font-semibold text-white">{f.title}</h3>
                    <p className="text-sm text-slate-400 mt-1 font-mono break-all">{f.affected_asset}</p>

                    {/* Provenance & Deduplication Timeline */}
                    <div className="flex items-center gap-4 mt-2 text-xs text-slate-500 font-mono">
                      {f.first_seen_at && (
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" /> First seen: {new Date(f.first_seen_at).toLocaleDateString()}
                        </span>
                      )}
                      {f.last_seen_at && (
                        <span className="flex items-center gap-1">
                          <History className="h-3 w-3" /> Last scanned: {new Date(f.last_seen_at).toLocaleDateString()}
                        </span>
                      )}
                      {f.fingerprint && (
                        <span className="text-[10px] text-slate-600 truncate max-w-[140px]" title={`Fingerprint: ${f.fingerprint}`}>
                          FP: {f.fingerprint.slice(0, 10)}...
                        </span>
                      )}
                    </div>

                    {/* Evidence Summary */}
                    {f.evidence_summary && (
                      <p className="text-sm text-slate-300 mt-3 bg-slate-950/60 p-3 rounded border border-slate-800/80">
                        {f.evidence_summary}
                      </p>
                    )}

                    {/* Retest Notes if available */}
                    {f.retest_notes && (
                      <div className="mt-2.5 text-xs bg-slate-950/80 p-2.5 rounded border border-blue-900/40 text-blue-200">
                        <span className="font-bold text-blue-400">Retest History:</span> {f.retest_notes}
                      </div>
                    )}

                    {/* Hacker Entry Simulation Box */}
                    <div className="mt-3.5 bg-slate-950/90 border border-red-900/40 rounded-xl p-3.5 relative overflow-hidden">
                      <div className="flex items-center gap-2 mb-2">
                        <span className="p-1 bg-red-950 text-red-400 border border-red-800 rounded">
                          <AlertTriangle className="h-3.5 w-3.5" />
                        </span>
                        <span className="text-xs font-bold text-red-300 uppercase tracking-wide">
                          Hacker Entry Simulation (How They Attack This Gap)
                        </span>
                      </div>
                      
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 my-2 text-xs">
                        <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
                          <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-0.5">
                            1. Where Hacker Enters
                          </span>
                          <span className="font-mono text-slate-200 break-all text-[11px]">
                            {f.affected_asset || "Public frontend / API"}
                          </span>
                        </div>
                        <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
                          <span className="text-[10px] font-bold text-orange-400 uppercase tracking-wider block mb-0.5">
                            2. Exploit Action
                          </span>
                          <span className="text-slate-200 text-[11px] line-clamp-3">
                            {f.technical_explanation || "Hacker queries unauthenticated REST endpoint or extracts exposed frontend keys."}
                          </span>
                        </div>
                        <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
                          <span className="text-[10px] font-bold text-red-400 uppercase tracking-wider block mb-0.5">
                            3. Hacker Danger
                          </span>
                          <span className="text-red-200 text-[11px] line-clamp-3">
                            {f.business_impact || "Direct access to internal tables, customer data theft, or account compromise."}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Business Impact */}
                    {f.business_impact && (
                      <div className="mt-3 bg-red-950/30 border border-red-900/50 rounded-lg p-3">
                        <span className="text-xs font-bold text-red-400 uppercase tracking-wide">🚨 Business Risk:</span>
                        <p className="text-xs text-red-200 mt-1 font-medium">{f.business_impact}</p>
                      </div>
                    )}

                    {/* Remediation Steps */}
                    {f.remediation_steps && (
                      <div className="mt-3">
                        <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wide">Remediation:</span>
                        <p className="text-xs text-slate-300 mt-1">{f.remediation_steps}</p>
                      </div>
                    )}

                    {/* AI Fix Prompt Box (Fill Gap in Lovable / Claude) */}
                    {f.ai_fix_prompt && (
                      <div className="mt-3.5 bg-gradient-to-r from-purple-950/40 to-indigo-950/40 border border-purple-800/60 rounded-xl p-3.5">
                        <div className="flex items-center justify-between gap-2 mb-2 flex-wrap">
                          <span className="text-xs font-bold text-purple-300 flex items-center gap-1.5">
                            <Sparkles className="h-3.5 w-3.5 text-purple-400" />
                            ⚡ Fill Gap in Lovable / Claude / Cursor <span className="text-[10px] text-purple-400 font-normal">(1-Click Copy-Paste)</span>
                          </span>
                          <button
                            onClick={() => handleCopyPrompt(f.id, f.ai_fix_prompt)}
                            className="inline-flex items-center gap-1.5 px-3 py-1 text-xs font-bold rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white shadow-md shadow-purple-950/50 transition-all"
                          >
                            {copiedId === f.id ? (
                              <>
                                <Check className="h-3.5 w-3.5 text-emerald-300" />
                                <span>Copied Prompt!</span>
                              </>
                            ) : (
                              <>
                                <Copy className="h-3.5 w-3.5" />
                                <span>Copy Lovable Fix Prompt</span>
                              </>
                            )}
                          </button>
                        </div>
                        <p className="text-xs text-purple-100 font-mono bg-slate-950/80 p-3 rounded-lg border border-purple-900/60 break-all select-all leading-relaxed">
                          {f.ai_fix_prompt}
                        </p>
                      </div>
                    )}
                  </div>

                  {/* Actions Right Side Column */}
                  <div className="flex lg:flex-col items-center lg:items-end justify-between gap-3 shrink-0 pt-2 lg:pt-0 border-t lg:border-t-0 border-slate-800">
                    
                    {/* QA Regression Test Button */}
                    <button
                      onClick={() => handleOpenRegressionTests(f)}
                      disabled={regressionLoadingId === f.id}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-emerald-950/90 hover:bg-emerald-900 border border-emerald-800 text-emerald-300 text-xs font-semibold rounded-lg shadow transition-colors"
                      title="Get ready-to-commit TypeScript, Pytest, or Playwright defensive regression tests"
                    >
                      {regressionLoadingId === f.id ? (
                        <RefreshCw className="h-3.5 w-3.5 animate-spin text-emerald-400" />
                      ) : (
                        <FlaskConical className="h-3.5 w-3.5 text-emerald-400" />
                      )}
                      <span>{regressionLoadingId === f.id ? "Loading..." : "QA Regression Test"}</span>
                    </button>

                    {/* Auto-Fix PR Button */}
                    <button
                      onClick={() => handleOpenAutoFix(f)}
                      disabled={autoFixLoadingId === f.id}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 disabled:opacity-50 text-white text-xs font-semibold rounded-lg shadow-md shadow-indigo-950/40 transition-all"
                      title="Generate automated code fix patch and create 1-click Pull Request"
                    >
                      {autoFixLoadingId === f.id ? (
                        <RefreshCw className="h-3.5 w-3.5 animate-spin text-indigo-200" />
                      ) : (
                        <GitPullRequest className="h-3.5 w-3.5 text-indigo-200" />
                      )}
                      <span>{autoFixLoadingId === f.id ? "Generating..." : "Auto-Fix PR"}</span>
                    </button>

                    {/* Retest Fix Button */}
                    <button
                      onClick={() => handleRetest(f.id)}
                      disabled={retestingId === f.id}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 text-white text-xs font-semibold rounded-lg shadow transition-colors"
                      title="Run automated targeted probe to verify if vulnerability is resolved"
                    >
                      <RefreshCw className={`h-3.5 w-3.5 ${retestingId === f.id ? "animate-spin text-blue-300" : ""}`} />
                      <span>{retestingId === f.id ? "Retesting..." : "Retest Fix"}</span>
                    </button>

                    {/* Status Triage Selector */}
                    <div className="flex items-center gap-1.5">
                      <span className="text-[11px] text-slate-400 font-medium">Status:</span>
                      <select
                        value={f.status}
                        disabled={statusUpdatingId === f.id}
                        onChange={(e) => handleStatusChange(f.id, e.target.value)}
                        className="bg-slate-800 border border-slate-700 text-xs text-slate-200 rounded px-2 py-1 focus:outline-none focus:border-blue-500"
                      >
                        <option value="open">Open</option>
                        <option value="triaged">Triaged</option>
                        <option value="in_progress">In Progress</option>
                        <option value="ready_retest">Ready for Retest</option>
                        <option value="resolved">Resolved</option>
                        <option value="false_positive">False Positive</option>
                        <option value="accepted_risk">Accepted Risk</option>
                      </select>
                    </div>

                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
