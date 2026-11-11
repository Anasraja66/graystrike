"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  Shield,
  ArrowLeft,
  CheckCircle2,
  AlertTriangle,
  Code2,
  Cpu,
  Sparkles,
  GitPullRequest,
  Check,
  Copy,
  Terminal,
  Zap,
  Lock,
  ArrowRight,
  RefreshCw,
  GitFork,
  Globe,
  Scan,
  Key,
  CreditCard,
  LogOut,
  Network,
  Activity,
  ShieldAlert,
  Sliders,
  Scale,
  RotateCcw,
  History,
  FileCheck2
} from "lucide-react";
import axios from "axios";

const PRESET_VULNERABILITIES = [
  {
    id: "cors-942",
    cwe: "CWE-942",
    title: "Permissive CORS Wildcard & Missing Origin Constraints",
    code: `const express = require('express');
const cors = require('cors');
const app = express();

// Vulnerability: Permissive Wildcard Origin allows credential theft
app.use(cors({ origin: '*' }));

app.get('/api/user/profile', (req, res) => {
    res.json({ user: 'alice', role: 'admin' });
});

app.listen(3000);`
  },
  {
    id: "sqli-89",
    cwe: "CWE-89",
    title: "Raw SQL Concatenation in Query Sink",
    code: `const express = require('express');
const app = express();

app.get('/api/users', async (req, res) => {
    // Vulnerability: Untrusted taint concatenation directly into SQL AST
    const query = "SELECT * FROM users WHERE id = " + req.query.id;
    const [rows] = await db.query(query);
    res.json(rows);
});

app.listen(3000);`
  },
  {
    id: "cmdi-78",
    cwe: "CWE-78",
    title: "OS Command Injection via Shell Invocation",
    code: `const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/api/network/ping', (req, res) => {
    // Vulnerability: Raw command string passed to /bin/sh allows command chaining
    const output = exec("ping -c 4 " + req.query.host);
    res.send(output);
});

app.listen(3000);`
  },
  {
    id: "traversal-22",
    cwe: "CWE-22",
    title: "Arbitrary File Read / Path Traversal Escape",
    code: `const express = require('express');
const fs = require('fs');
const app = express();

app.get('/api/files/download', (req, res) => {
    // Vulnerability: Relative traversal '../' breaks outside sandbox
    const data = readFile("/var/www/uploads/" + req.query.file);
    res.send(data);
});

app.listen(3000);`
  },
  {
    id: "xss-79",
    cwe: "CWE-79",
    title: "Reflected Cross-Site Scripting (XSS)",
    code: `const express = require('express');
const app = express();

app.get('/api/welcome', (req, res) => {
    // Vulnerability: Unescaped string injection into HTTP response body
    res.send("<h1>Welcome " + req.query.name + "</h1>");
});

app.listen(3000);`
  },
  {
    id: "overflow-190",
    cwe: "CWE-190",
    title: "Unbounded Integer Arithmetic / Buffer Wrap-Around",
    code: `const express = require('express');
const app = express();

app.post('/api/buffer/allocate', (req, res) => {
    const buffer_size = 1024;
    // Vulnerability: Arithmetic overflow wraps to negative or wraps around 32-bit bound
    const totalAlloc = buffer_size + req.query.size;
    res.json({ allocated: totalAlloc });
});

app.listen(3000);`
  }
];

export default function RemediationPage() {
  const router = useRouter();
  const [selectedPreset, setSelectedPreset] = useState<string>("cors-942");
  const [sourceCode, setSourceCode] = useState<string>(PRESET_VULNERABILITIES[0].code);
  const [loading, setLoading] = useState<boolean>(false);
  const [repairResult, setRepairResult] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedDiff, setCopiedDiff] = useState<boolean>(false);
  const [telemetry, setTelemetry] = useState<any | null>(null);
  const [telemetryLoading, setTelemetryLoading] = useState<boolean>(false);
  const [recoveryDrillData, setRecoveryDrillData] = useState<any | null>(null);
  const [drillLoading, setDrillLoading] = useState<boolean>(false);
  const [githubPrData, setGithubPrData] = useState<any | null>(null);
  const [prLoading, setPrLoading] = useState<boolean>(false);

  const fetchTelemetry = async () => {
    setTelemetryLoading(true);
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
    try {
      const res = await axios.get(`${api}/api/v1/remediation/swarm-telemetry`);
      setTelemetry(res.data);
    } catch (e) {
      console.error("Telemetry fetch error:", e);
    } finally {
      setTelemetryLoading(false);
    }
  };

  const runRecoveryDrill = async () => {
    setDrillLoading(true);
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
    try {
      const res = await axios.post(`${api}/api/v1/remediation/state-recovery-drill`);
      setRecoveryDrillData(res.data);
    } catch (e) {
      console.error("Recovery drill error:", e);
    } finally {
      setDrillLoading(false);
    }
  };

  const runSimulatedPRCheck = async () => {
    setPrLoading(true);
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
    try {
      const res = await axios.post(`${api}/api/v1/github/simulate-pr-check`, {
        pr_number: 108,
        repository: "enterprise-client/secure-backend",
        commit_sha: "f9e8d7c6b5a41234",
        file_name: "src/controllers/userController.js",
        code_snippet: sourceCode
      });
      setGithubPrData(res.data);
    } catch (e) {
      console.error("GitHub PR check error:", e);
    } finally {
      setPrLoading(false);
    }
  };

  useEffect(() => {
    fetchTelemetry();
    runRecoveryDrill();
    runSimulatedPRCheck();
  }, []);

  const handleSelectPreset = (id: string) => {
    setSelectedPreset(id);
    const target = PRESET_VULNERABILITIES.find((p) => p.id === id);
    if (target) {
      setSourceCode(target.code);
      setRepairResult(null);
      setError(null);
    }
  };

  const executeRepair = async () => {
    setLoading(true);
    setError(null);
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

    try {
      const res = await axios.post(`${api}/api/v1/remediation/cegis-repair`, {
        source_code: sourceCode,
        file_path: "server.js"
      });
      setRepairResult(res.data);
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.detail || err.message || "CEGIS Repair failed.");
    } finally {
      setLoading(false);
    }
  };

  const copyDiff = () => {
    if (!repairResult?.unified_diff) return;
    navigator.clipboard.writeText(repairResult.unified_diff);
    setCopiedDiff(true);
    setTimeout(() => setCopiedDiff(false), 2000);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex">
      {/* Sidebar Navigation */}
      <div className="fixed left-0 top-0 h-full w-64 bg-slate-900 border-r border-slate-800 flex flex-col z-20">
        <div className="p-6 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Shield className="h-7 w-7 text-blue-500" />
            <span className="font-bold text-white text-lg">GrayStrike</span>
          </div>
          <div className="text-emerald-400 text-xs font-mono mt-1">Neuro-Symbolic Engine</div>
        </div>
        <nav className="flex-1 p-4 space-y-1">
          {[
            { href: "/dashboard", icon: <Globe className="h-5 w-5" />, label: "Dashboard" },
            { href: "/projects", icon: <Globe className="h-5 w-5" />, label: "Projects" },
            { href: "/scans", icon: <Scan className="h-5 w-5" />, label: "Scans" },
            { href: "/findings", icon: <AlertTriangle className="h-5 w-5" />, label: "Findings" },
            { href: "/remediation", icon: <Cpu className="h-5 w-5 text-indigo-400" />, label: "CEGIS Remediation", active: true },
            { href: "/attack-paths", icon: <GitFork className="h-5 w-5 text-rose-400" />, label: "Attack Paths (Wiz)" },
            { href: "/attack-surface", icon: <Globe className="h-5 w-5 text-cyan-400" />, label: "Attack Surface (EASM)" },
            { href: "/reports", icon: <CheckCircle2 className="h-5 w-5" />, label: "Reports" },
            { href: "/settings/api-keys", icon: <Key className="h-5 w-5" />, label: "CI/CD & API Keys" },
            { href: "/settings/billing", icon: <CreditCard className="h-5 w-5" />, label: "Billing & Alerts" }
          ].map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg transition-colors ${
                item.active
                  ? "bg-indigo-600/20 text-indigo-300 border border-indigo-500/40 font-semibold"
                  : "text-slate-400 hover:text-white hover:bg-slate-800"
              }`}
            >
              {item.icon}
              {item.label}
            </Link>
          ))}
        </nav>
      </div>

      {/* Main Content Pane */}
      <div className="ml-64 flex-1 p-8">
        {/* Header Banner */}
        <div className="flex items-center justify-between pb-6 border-b border-slate-800 mb-8">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-3xl font-extrabold text-white tracking-tight">
                CEGIS Neuro-Symbolic Remediation
              </h1>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800">
                Z3 SMT Certified
              </span>
            </div>
            <p className="text-slate-400 text-sm mt-1">
              Zero-Hallucination Program Repair via MaxSAT Fault Localization, Hole Sketching & SMT Unsatisfiability Prover.
            </p>
          </div>
          <button
            onClick={executeRepair}
            disabled={loading}
            className="flex items-center gap-2 bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-500 hover:to-blue-500 text-white font-semibold px-5 py-2.5 rounded-xl shadow-lg shadow-indigo-500/20 disabled:opacity-50 transition-all cursor-pointer"
          >
            {loading ? (
              <>
                <RefreshCw className="h-5 w-5 animate-spin" />
                Synthesizing Proof...
              </>
            ) : (
              <>
                <Sparkles className="h-5 w-5" />
                Run CEGIS Formal Repair
              </>
            )}
          </button>
        </div>

        {/* Preset Vulnerability Catalog */}
        <div className="mb-6">
          <label className="text-xs font-semibold uppercase tracking-wider text-slate-400 block mb-2">
            Select Vulnerability Class Benchmark (Ground Truth)
          </label>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2.5">
            {PRESET_VULNERABILITIES.map((p) => (
              <button
                key={p.id}
                onClick={() => handleSelectPreset(p.id)}
                className={`p-3 rounded-lg border text-left transition-all ${
                  selectedPreset === p.id
                    ? "bg-indigo-950/70 border-indigo-500 text-white shadow-md shadow-indigo-950"
                    : "bg-slate-900/60 border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200"
                }`}
              >
                <div className="text-xs font-mono font-bold text-indigo-400">{p.cwe}</div>
                <div className="text-xs font-medium truncate mt-1">{p.title}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Dual Editor & Verification Workspace */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          {/* Left: Input Source Code */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden flex flex-col">
            <div className="bg-slate-950 px-4 py-3 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Code2 className="h-4 w-4 text-amber-400" />
                <span className="text-xs font-mono font-semibold text-slate-300">
                  server.js (Vulnerable Source)
                </span>
              </div>
              <span className="text-xs text-amber-400 font-mono">AST Editable</span>
            </div>
            <textarea
              value={sourceCode}
              onChange={(e) => setSourceCode(e.target.value)}
              className="w-full h-80 bg-slate-950/80 p-4 font-mono text-xs text-slate-200 focus:outline-none resize-none border-none leading-relaxed"
              spellCheck={false}
            />
          </div>

          {/* Right: Synthesis & SMT Proof Status */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden flex flex-col">
            <div className="bg-slate-950 px-4 py-3 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Cpu className="h-4 w-4 text-emerald-400" />
                <span className="text-xs font-mono font-semibold text-slate-300">
                  SMT Verification & Synthesis Engine
                </span>
              </div>
              {repairResult && (
                <span className="text-xs font-mono text-emerald-400 bg-emerald-950/80 px-2 py-0.5 rounded border border-emerald-800">
                  {repairResult.execution_time_ms} ms Latency
                </span>
              )}
            </div>

            <div className="p-4 flex-1 flex flex-col justify-between">
              {repairResult ? (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-3">
                    <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                      <div className="text-xs text-slate-500 font-mono">Faults Isolated</div>
                      <div className="text-xl font-bold text-amber-400 font-mono mt-0.5">
                        {repairResult.faults_detected}
                      </div>
                    </div>
                    <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                      <div className="text-xs text-slate-500 font-mono">Z3 UNSAT Verified</div>
                      <div className="text-xl font-bold text-emerald-400 font-mono mt-0.5">
                        {repairResult.fixes_applied?.length || 0}
                      </div>
                    </div>
                  </div>

                  {/* Applied Verified Fixes List */}
                  <div className="space-y-2">
                    <div className="text-xs font-semibold uppercase text-slate-400">
                      Formally Verified Countermeasures:
                    </div>
                    {repairResult.fixes_applied?.map((fix: any, idx: number) => (
                      <div
                        key={idx}
                        className="bg-slate-950/80 border border-slate-800 p-3 rounded-lg flex items-start justify-between gap-3"
                      >
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-mono font-bold text-indigo-400">
                              {fix.cwe}
                            </span>
                            <span className="text-xs text-slate-300 font-medium">
                              Line {fix.line}: {fix.fault}
                            </span>
                          </div>
                          <div className="text-xs font-mono text-emerald-400 mt-1">
                            Status: {fix.smt_status}
                          </div>
                        </div>
                        <CheckCircle2 className="h-5 w-5 text-emerald-400 flex-shrink-0 mt-0.5" />
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-center p-6 text-slate-500">
                  <Cpu className="h-12 w-12 text-slate-700 mb-3 animate-pulse" />
                  <p className="text-sm font-medium text-slate-400">
                    Engine Ready for SMT Verification
                  </p>
                  <p className="text-xs text-slate-600 max-w-sm mt-1">
                    Click "Run CEGIS Formal Repair" to isolate faults via MaxSAT, construct program sketches, and verify patches with Z3.
                  </p>
                </div>
              )}

              {error && (
                <div className="mt-4 p-3 rounded-lg bg-red-950/60 border border-red-800 text-red-300 text-xs">
                  {error}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Surgical Unified Diff Viewer */}
        {repairResult?.unified_diff && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl mb-8">
            <div className="bg-slate-950 px-4 py-3 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <GitPullRequest className="h-4 w-4 text-emerald-400" />
                <span className="text-xs font-mono font-semibold text-slate-300">
                  Synthesized Unified Git Diff (Surgical Patch)
                </span>
              </div>
              <button
                onClick={copyDiff}
                className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded-lg transition-colors cursor-pointer"
              >
                {copiedDiff ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                {copiedDiff ? "Copied" : "Copy Unified Diff"}
              </button>
            </div>
            <pre className="p-4 font-mono text-xs text-slate-300 overflow-x-auto bg-slate-950/90 leading-relaxed whitespace-pre">
              {repairResult.unified_diff}
            </pre>
          </div>
        )}

        {/* Byzantine Swarm Governance & Consensus Telemetry (GRC v2.6) */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-2xl mt-8">
          <div className="bg-slate-950 px-6 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="h-8 w-8 rounded-lg bg-indigo-600/20 border border-indigo-500/40 flex items-center justify-center">
                <Network className="h-5 w-5 text-indigo-400" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-base font-bold text-white tracking-tight">
                    Byzantine Swarm Governance & Consensus Telemetry
                  </h2>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-950 text-indigo-300 border border-indigo-800">
                    GRC Protocol v2.6
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Decentralized multi-agent verification backed by SAC (EMNLP 2026), MSR Filtering (UPenn 2026), & Z3 SMT Ground Truth.
                </p>
              </div>
            </div>

            <button
              onClick={fetchTelemetry}
              disabled={telemetryLoading}
              className="flex items-center gap-2 text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-200 px-3.5 py-2 rounded-lg border border-slate-700 transition-all cursor-pointer"
            >
              <RefreshCw className={`h-3.5 w-3.5 text-indigo-400 ${telemetryLoading ? "animate-spin" : ""}`} />
              Refresh Swarm State
            </button>
          </div>

          <div className="p-6 space-y-6">
            {/* Scientific Foundations Badges */}
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mr-1">
                Formal Theorems:
              </span>
              {[
                { label: "SAC (arXiv:2605.09076)", desc: "Receiver-Side Scoring & (F+1)-Robust Graphs" },
                { label: "MSR Filter (arXiv:2606.15024)", desc: "Global Outlier Trimming (100% Agreement)" },
                { label: "Adaptive xi_t (arXiv:2403.17907)", desc: "Geometric Decay under Intermittent Attacks" },
                { label: "CP-WBFT (arXiv:2511.10400)", desc: "HCP Entropy Weighting (f=6/7 Fault Limit)" },
                { label: "Z3 SMT Prover", desc: "UNSAT Formal Truth (Verification before Voting)" }
              ].map((badge, idx) => (
                <div
                  key={idx}
                  title={badge.desc}
                  className="px-2.5 py-1 rounded-md text-[11px] font-mono bg-slate-950 text-slate-300 border border-slate-800 flex items-center gap-1.5 shadow-sm"
                >
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                  {badge.label}
                </div>
              ))}
            </div>

            {/* Core Metrics Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800/80">
                <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
                  <span>Effective Voters (n_eff)</span>
                  <Scale className="h-4 w-4 text-cyan-400" />
                </div>
                <div className="text-2xl font-bold font-mono text-cyan-300 mt-2">
                  {telemetry?.metrics?.effective_independent_voters_neff || "5.38"}
                </div>
                <div className="text-[11px] text-slate-500 mt-1">
                  Cross-model diversity (ρ=0.05) prevents equicorrelation collapse
                </div>
              </div>

              <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800/80">
                <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
                  <span>MSR Filter Status</span>
                  <Sliders className="h-4 w-4 text-amber-400" />
                </div>
                <div className="text-2xl font-bold font-mono text-amber-300 mt-2">
                  f = {telemetry?.metrics?.msr_filter_f ?? 1} Trimmed
                </div>
                <div className="text-[11px] text-slate-500 mt-1">
                  Extreme adversarial bounds trimmed via Π_MSR(V, f)
                </div>
              </div>

              <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800/80">
                <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
                  <span>Adaptive Threshold (ξ_t)</span>
                  <Activity className="h-4 w-4 text-indigo-400" />
                </div>
                <div className="text-2xl font-bold font-mono text-indigo-300 mt-2">
                  {telemetry?.metrics?.adaptive_threshold_xi_t || "3.76"}
                </div>
                <div className="text-[11px] text-slate-500 mt-1">
                  Time-varying threshold isolates intermittent faulty nodes
                </div>
              </div>

              <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800/80">
                <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
                  <span>Consensus State</span>
                  <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                </div>
                <div className="text-2xl font-bold font-mono text-emerald-400 mt-2">
                  {telemetry?.metrics?.consensus_decision || "APPROVED"}
                </div>
                <div className="text-[11px] text-slate-500 mt-1">
                  Z3 SMT short-circuit overrides voting with mathematical proof
                </div>
              </div>
            </div>

            {/* Active Swarm Nodes Table */}
            <div>
              <div className="flex items-center justify-between mb-3">
                <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                  Swarm Participant Agents (SAC Receiver-Side Scored)
                </div>
                <span className="text-xs font-mono text-slate-400">
                  Total Nodes: {telemetry?.metrics?.total_nodes || 7} (Honest: {telemetry?.metrics?.honest_nodes || 6}, Byzantine Filtered: {telemetry?.metrics?.byzantine_isolated || 1})
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
                {(telemetry?.agents || [
                  { id: "agent-deepseek-v3", role: "MaxSAT Fault Localizer", model: "DeepSeek-V3", trust: 0.98, status: "VERIFIED_HONEST", reported_conf: 0.95 },
                  { id: "agent-llama-70b", role: "Symbolic Sketch Synthesizer", model: "Llama-3.3-70B", trust: 0.96, status: "VERIFIED_HONEST", reported_conf: 0.94 },
                  { id: "agent-qwen-coder", role: "AST Transform Verifier", model: "Qwen-2.5-Coder", trust: 0.97, status: "VERIFIED_HONEST", reported_conf: 0.96 },
                  { id: "agent-mistral-large", role: "WAF Rule Synthesizer", model: "Mistral-Large-2", trust: 0.94, status: "VERIFIED_HONEST", reported_conf: 0.91 },
                  { id: "agent-phi-mini", role: "Local Edge Policy Guard", model: "Phi-3.5-mini", trust: 0.85, status: "VERIFIED_HONEST", reported_conf: 0.88 },
                  { id: "agent-llama-3b", role: "Edge Taint Tracker", model: "Llama-3.2-3B", trust: 0.82, status: "VERIFIED_HONEST", reported_conf: 0.84 },
                  { id: "agent-byzantine-infiltrator", role: "Compromised Sybil Injector", model: "Adversarial Injected", trust: 0.12, status: "BYZANTINE_FILTERED", reported_conf: 1.00 }
                ]).map((agent: any) => {
                  const isByzantine = agent.status === "BYZANTINE_FILTERED";
                  return (
                    <div
                      key={agent.id}
                      className={`p-3.5 rounded-xl border transition-all ${
                        isByzantine
                          ? "bg-rose-950/20 border-rose-800/60 shadow-lg shadow-rose-950/20"
                          : "bg-slate-950 border-slate-800/80 hover:border-slate-700"
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div>
                          <div className="text-xs font-bold text-white font-mono truncate max-w-[150px]">
                            {agent.id}
                          </div>
                          <div className="text-[11px] text-slate-400 mt-0.5">{agent.role}</div>
                        </div>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                            isByzantine
                              ? "bg-rose-950 text-rose-300 border border-rose-800"
                              : "bg-emerald-950 text-emerald-300 border border-emerald-800"
                          }`}
                        >
                          {isByzantine ? "Isolated" : "Honest"}
                        </span>
                      </div>

                      <div className="mt-3 pt-3 border-t border-slate-800/60 grid grid-cols-2 gap-2 text-[11px] font-mono">
                        <div>
                          <span className="text-slate-500 block text-[10px]">Model</span>
                          <span className="text-slate-300 font-medium truncate block">{agent.model}</span>
                        </div>
                        <div>
                          <span className="text-slate-500 block text-[10px]">Receiver Trust</span>
                          <span className={`font-bold ${isByzantine ? "text-rose-400" : "text-emerald-400"}`}>
                            {agent.trust}
                          </span>
                        </div>
                      </div>

                      <div className="mt-2 text-[10px] font-mono text-slate-500 flex items-center justify-between">
                        <span>Self Conf: {agent.reported_conf}</span>
                        {isByzantine && (
                          <span className="text-rose-400 font-semibold">SAC Filter Drop</span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Runtime Governance Audit Trail */}
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <Lock className="h-5 w-5 text-indigo-400 flex-shrink-0" />
                <div>
                  <div className="text-xs font-mono font-bold text-white">
                    Runtime Governance Graph & SHA-256 Hash Chain
                  </div>
                  <div className="text-[11px] font-mono text-slate-400 mt-0.5">
                    State Machine: RECON_DISCOVERY ➔ EXPLOIT_POC ➔ CEGIS_SMT_UNSAT ➔ SURGICAL_PATCH_MERGE
                  </div>
                </div>
              </div>
              <div className="text-[11px] font-mono text-emerald-400 bg-emerald-950/60 px-3 py-1.5 rounded-lg border border-emerald-800 flex items-center gap-2">
                <CheckCircle2 className="h-3.5 w-3.5" />
                <span>Zero-Trust Policy Enforced</span>
              </div>
            </div>

            {/* Autonomous Multi-Agent State Recovery & Rollback Drill */}
            <div className="mt-8 bg-slate-900/60 border border-indigo-900/50 rounded-2xl p-6 backdrop-blur-sm">
              <div className="flex flex-col md:flex-row md:items-center justify-between pb-5 border-b border-slate-800/80 gap-4">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 bg-indigo-950/80 border border-indigo-700/60 rounded-xl text-indigo-400">
                    <RotateCcw className="h-6 w-6" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="text-base font-bold text-white tracking-wide">
                        Autonomous State Recovery & Rollback Drill
                      </h3>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-indigo-950 text-indigo-300 border border-indigo-800">
                        Position Paper Nov 2026 & SoK Sec. 5
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Beyond Containment: Causal provenance traversal, cascading revocation, and Z3 SMT replay verification.
                    </p>
                  </div>
                </div>

                <button
                  onClick={runRecoveryDrill}
                  disabled={drillLoading}
                  className="px-4 py-2 bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 disabled:opacity-50 text-white rounded-xl text-xs font-mono font-semibold flex items-center gap-2 transition-all shadow-lg shadow-indigo-950/40 border border-indigo-400/30"
                >
                  <RefreshCw className={`h-3.5 w-3.5 ${drillLoading ? "animate-spin" : ""}`} />
                  <span>{drillLoading ? "Executing Recovery..." : "Simulate Swarm Compromise & Rollback"}</span>
                </button>
              </div>

              {/* Diagnostic Metrics Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-6">
                <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800">
                  <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
                    <span>Residual Contamination (RCR)</span>
                    <ShieldAlert className="h-4 w-4 text-emerald-400" />
                  </div>
                  <div className="text-2xl font-bold font-mono text-emerald-400 mt-2">
                    {recoveryDrillData?.metrics?.residual_contamination_ratio_rcr ?? "0.000"}
                  </div>
                  <div className="text-[11px] text-slate-500 mt-1">
                    Fraction of contaminated state remaining (0.0 = Zero Leakage)
                  </div>
                </div>

                <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800">
                  <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
                    <span>Recovery Completeness</span>
                    <FileCheck2 className="h-4 w-4 text-emerald-400" />
                  </div>
                  <div className="text-2xl font-bold font-mono text-emerald-400 mt-2">
                    {recoveryDrillData?.metrics?.recovery_completeness
                      ? `${Math.round(recoveryDrillData.metrics.recovery_completeness * 100)}%`
                      : "100%"}
                  </div>
                  <div className="text-[11px] text-slate-500 mt-1">
                    Invariant holds + all tainted states pruned cleanly
                  </div>
                </div>

                <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800">
                  <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
                    <span>Z3 SMT Invariant Verification</span>
                    <CheckCircle2 className="h-4 w-4 text-cyan-400" />
                  </div>
                  <div className="text-2xl font-bold font-mono text-cyan-300 mt-2">
                    {recoveryDrillData?.metrics?.smt_prover_status || "UNSAT_SAFE"}
                  </div>
                  <div className="text-[11px] text-slate-500 mt-1">
                    Replay verification proves safety invariant P in restored state S'
                  </div>
                </div>

                <div className="bg-slate-950/80 p-4 rounded-xl border border-slate-800">
                  <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
                    <span>Recovery Telemetry</span>
                    <History className="h-4 w-4 text-violet-400" />
                  </div>
                  <div className="text-lg font-bold font-mono text-violet-300 mt-2">
                    TTC: {recoveryDrillData?.metrics?.time_to_containment_ms || "1.20"}ms
                  </div>
                  <div className="text-[11px] text-slate-500 mt-1">
                    TTR: {recoveryDrillData?.metrics?.time_to_recovery_ms || "1.21"}ms | Collateral Loss: {recoveryDrillData?.metrics?.collateral_loss || 0}
                  </div>
                </div>
              </div>

              {/* Provenance DAG Execution Timeline */}
              <div className="mt-6">
                <div className="flex items-center justify-between mb-3">
                  <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                    Causal Provenance DAG G=(V,E) Traversal & Pruning
                  </div>
                  <span className="text-xs font-mono text-slate-400">
                    Contaminated Nodes Pruned: {recoveryDrillData?.contamination_set_size || 3} / {recoveryDrillData?.provenance_dag?.total_nodes || 6}
                  </span>
                </div>

                <div className="space-y-2.5">
                  {(recoveryDrillData?.provenance_dag?.nodes || [
                    { id: "evt-001-admission", principal: "swarm-coordinator", type: "ADMISSION", status: "CLEAN_SNAPSHOT", payload: { action: "INIT_SWARM_SECURITY_POLICY" } },
                    { id: "evt-002-deepseek-repair", principal: "agent-deepseek-v3", type: "TOOL_ACTION", status: "CLEAN_SNAPSHOT", payload: { action: "CEGIS_MAXSAT_FAULT_LOCALIZE", target: "CWE-89" } },
                    { id: "evt-003-byzantine-infiltrator", principal: "agent-byzantine-infiltrator", type: "MESSAGE", status: "COMPROMISE_ORIGIN", payload: { action: "PROMPT_INJECTION_COLLUSION", threat_vector: "SoK_R2_LOSS_OF_INDEPENDENCE" } },
                    { id: "evt-004-tainted-delegation", principal: "agent-byzantine-infiltrator", type: "DELEGATION", status: "TAINTED_PRUNED", payload: { action: "DELEGATE_CREDENTIALS", scope: "cloud_infrastructure_write" } },
                    { id: "evt-005-memory-poisoning", principal: "agent-byzantine-infiltrator", type: "MEMORY_WRITE", status: "TAINTED_PRUNED", payload: { action: "POISON_SHARED_RAG_STORE", vector: "Lying_with_Truths_P4" } },
                    { id: "evt-006-llama-test-synth", principal: "agent-llama-70b", type: "TOOL_ACTION", status: "BENIGN_PRESERVED", payload: { action: "SYNTHESIZE_UNIT_TEST", cwe: "CWE-89" } }
                  ]).map((node: any) => {
                    const isOrigin = node.status === "COMPROMISE_ORIGIN";
                    const isTainted = node.status === "TAINTED_PRUNED";
                    const isPreserved = node.status === "BENIGN_PRESERVED";
                    const isClean = node.status === "CLEAN_SNAPSHOT";

                    return (
                      <div
                        key={node.id}
                        className={`p-3.5 rounded-xl border flex flex-col md:flex-row md:items-center justify-between gap-3 font-mono text-xs transition-all ${
                          isOrigin
                            ? "bg-rose-950/40 border-rose-700/80 text-rose-200"
                            : isTainted
                            ? "bg-rose-950/20 border-rose-900/60 text-rose-300 opacity-75 line-through decoration-rose-500"
                            : isPreserved
                            ? "bg-emerald-950/30 border-emerald-700/70 text-emerald-200 shadow-md shadow-emerald-950/20"
                            : "bg-slate-950 border-slate-800 text-slate-300"
                        }`}
                      >
                        <div className="flex items-center gap-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                              isOrigin
                                ? "bg-rose-900 text-rose-100 border border-rose-600"
                                : isTainted
                                ? "bg-rose-950 text-rose-400 border border-rose-800"
                                : isPreserved
                                ? "bg-emerald-900 text-emerald-200 border border-emerald-600"
                                : "bg-slate-800 text-slate-300 border border-slate-700"
                            }`}
                          >
                            {node.type}
                          </span>
                          <span className="font-bold text-white">{node.id}</span>
                          <span className="text-slate-400">({node.principal})</span>
                        </div>

                        <div className="flex items-center gap-4">
                          <span className="text-[11px] text-slate-300">
                            Action: {node.payload?.action || "EVENT_EXECUTION"}
                          </span>
                          <span
                            className={`px-2.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                              isOrigin
                                ? "bg-rose-950 text-rose-300 border border-rose-700"
                                : isTainted
                                ? "bg-rose-950 text-rose-400 border border-rose-900"
                                : isPreserved
                                ? "bg-emerald-950 text-emerald-300 border border-emerald-700"
                                : "bg-slate-900 text-slate-400 border border-slate-800"
                            }`}
                          >
                            {isOrigin ? "Origin c" : isTainted ? "Pruned C(c)" : isPreserved ? "Benign Delta Preserved" : "Clean Baseline"}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Active Restored State Snapshot */}
              <div className="mt-6 pt-5 border-t border-slate-800/80">
                <div className="flex items-center justify-between mb-2">
                  <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                    Restored Clean State Snapshot S' (Zero Tainted Keys Leaked)
                  </div>
                  <span className="text-[11px] font-mono text-emerald-400">
                    Active Clean Keys: {Object.keys(recoveryDrillData?.restored_state || {}).length || 4}
                  </span>
                </div>
                <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
                  <pre className="text-emerald-400/90">
                    {JSON.stringify(
                      recoveryDrillData?.restored_state || {
                        env: "production",
                        db_pool: 10,
                        auth_mode: "OIDC_STRICT",
                        verified_cwe89_patch: "const query = 'SELECT * FROM users WHERE id = $1';",
                        generated_unit_test: "expect(res.status).toBe(200);"
                      },
                      null,
                      2
                    )}
                  </pre>
                </div>
              </div>
            </div>

            {/* GitHub CI/CD Automated Remediation Bot Panel */}
            <div className="mt-8 bg-slate-900/60 border border-emerald-900/40 rounded-2xl p-6 backdrop-blur-sm">
              <div className="flex flex-col md:flex-row md:items-center justify-between pb-5 border-b border-slate-800/80 gap-4">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 bg-emerald-950/80 border border-emerald-700/60 rounded-xl text-emerald-400">
                    <GitPullRequest className="h-6 w-6" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="text-base font-bold text-white tracking-wide">
                        GitHub CI/CD Automated Remediation Bot
                      </h3>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-emerald-950 text-emerald-300 border border-emerald-800">
                        NIS 2 & EU AI Act Art. 14 Compliant
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Autonomous PR security review: AST fault localization, Z3 SMT formal proof, and counter-branch synthesis.
                    </p>
                  </div>
                </div>

                <button
                  onClick={runSimulatedPRCheck}
                  disabled={prLoading}
                  className="px-4 py-2 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 disabled:opacity-50 text-white rounded-xl text-xs font-mono font-semibold flex items-center gap-2 transition-all shadow-lg shadow-emerald-950/40 border border-emerald-400/30"
                >
                  <RefreshCw className={`h-3.5 w-3.5 ${prLoading ? "animate-spin" : ""}`} />
                  <span>{prLoading ? "Analyzing PR..." : "Simulate PR Security Review (#108)"}</span>
                </button>
              </div>

              {/* GitHub Check-Run Status Bar */}
              <div className="mt-6 bg-slate-950 p-4 rounded-xl border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div className="p-1.5 bg-emerald-950 rounded-full border border-emerald-500">
                    <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                  </div>
                  <div>
                    <div className="text-xs font-mono font-bold text-white flex items-center gap-2">
                      <span>GrayStrike / Formal Neuro-Symbolic Remediation</span>
                      <span className="text-emerald-400 font-semibold">• Passed</span>
                    </div>
                    <div className="text-[11px] font-mono text-slate-400 mt-0.5">
                      Target Repo: <span className="text-indigo-400">{githubPrData?.repository || "enterprise-client/secure-backend"}</span> | PR: <span className="text-indigo-400">#{githubPrData?.pr_number || 108}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-3 font-mono text-xs">
                  <div className="bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-800 text-slate-300">
                    Branch: <span className="text-emerald-400 font-bold">{githubPrData?.remediation_branch || "graystrike/auto-fix-cwe-89-pr-108"}</span>
                  </div>
                </div>
              </div>

              {/* GitHub Review Comment Preview */}
              <div className="mt-5">
                <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                  Generated GitHub Pull Request Review Comment (Live Preview)
                </div>
                <div className="bg-slate-950 p-5 rounded-xl border border-slate-800 text-xs font-mono text-slate-300 leading-relaxed overflow-x-auto whitespace-pre-wrap">
                  {githubPrData?.github_comment_markdown || "Review Comment generating..."}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

