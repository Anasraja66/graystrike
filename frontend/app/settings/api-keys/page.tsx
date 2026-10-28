"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { 
  Shield, ArrowLeft, Key, Plus, Trash2, Copy, Check, AlertTriangle, 
  Terminal, ExternalLink, CheckCircle2, Clock, Calendar
} from "lucide-react";
import axios from "axios";

export default function ApiKeysPage() {
  const router = useRouter();
  const [keys, setKeys] = useState<any[]>([]);
  const [projects, setProjects] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  
  // Modal states
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [keyName, setKeyName] = useState("GitHub Actions CI Gate");
  const [selectedProject, setSelectedProject] = useState("");
  const [expiresInDays, setExpiresInDays] = useState(90);
  const [creating, setCreating] = useState(false);
  
  // Newly generated secret modal
  const [createdSecret, setCreatedSecret] = useState<string | null>(null);
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [copiedYaml, setCopiedYaml] = useState(false);

  const fetchKeysAndProjects = async () => {
    const token = localStorage.getItem("token");
    if (!token) { router.push("/auth/login"); return; }
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
    const headers = { Authorization: `Bearer ${token}` };

    try {
      const [keysRes, projRes] = await Promise.all([
        axios.get(`${api}/api/v1/ci/keys`, { headers }),
        axios.get(`${api}/api/v1/projects/`, { headers })
      ]);
      setKeys(keysRes.data);
      setProjects(projRes.data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchKeysAndProjects();
  }, []);

  const handleCreateKey = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    const token = localStorage.getItem("token");
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

    try {
      const res = await axios.post(`${api}/api/v1/ci/keys`, {
        name: keyName,
        project_id: selectedProject || null,
        expires_in_days: expiresInDays > 0 ? expiresInDays : null
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });

      setCreatedSecret(res.data.secret_key);
      setShowCreateModal(false);
      await fetchKeysAndProjects();
    } catch (err: any) {
      alert("Failed to create API key: " + (err.response?.data?.detail || err.message));
    } finally {
      setCreating(false);
    }
  };

  const handleRevokeKey = async (keyId: string) => {
    if (!confirm("Are you sure you want to revoke this API key immediately? Any GitHub Actions workflows using it will stop working.")) {
      return;
    }
    const token = localStorage.getItem("token");
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

    try {
      await axios.delete(`${api}/api/v1/ci/keys/${keyId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      await fetchKeysAndProjects();
    } catch (e: any) {
      alert("Failed to revoke key: " + (e.response?.data?.detail || e.message));
    }
  };

  const copyToClipboard = (text: string, setter: (val: boolean) => void) => {
    navigator.clipboard.writeText(text);
    setter(true);
    setTimeout(() => setter(false), 2500);
  };

  const sampleYaml = `name: "APT Security Gate"
on: [pull_request, workflow_dispatch]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Anas-Technology/apt-agents@v1
        with:
          api_key: \${{ secrets.APT_API_KEY }}
          project_id: "${projects[0]?.id || 'YOUR_PROJECT_UUID'}"
          fail_on: "high"`;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-8">
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-4">
            <Link href="/dashboard" className="text-slate-400 hover:text-white transition-colors">
              <ArrowLeft className="h-5 w-5" />
            </Link>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-bold text-white">CI/CD & API Keys</h1>
                <span className="text-[10px] bg-blue-950 text-blue-300 border border-blue-800 px-2 py-0.5 rounded-full font-mono uppercase tracking-wide">
                  Machine Access
                </span>
              </div>
              <p className="text-slate-400 text-sm mt-0.5">
                Manage machine-to-machine credentials for GitHub Actions, GitLab CI, and CLI security gates
              </p>
            </div>
          </div>
          <button
            onClick={() => setShowCreateModal(true)}
            className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg flex items-center gap-2 text-sm font-semibold transition-colors"
          >
            <Plus className="h-4 w-4" /> Generate New Key
          </button>
        </div>

        {/* Modal: Reveal Secret Key */}
        {createdSecret && (
          <div className="mb-8 bg-slate-900 border-2 border-emerald-500/80 rounded-2xl p-6 shadow-2xl relative">
            <div className="flex items-start gap-4">
              <CheckCircle2 className="h-6 w-6 text-emerald-400 shrink-0 mt-0.5" />
              <div className="flex-1">
                <h3 className="text-lg font-bold text-white">API Key Generated Successfully! 🎉</h3>
                <p className="text-xs text-amber-300 mt-1 flex items-center gap-1.5 font-medium">
                  <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                  Save this key now! For security reasons, it will never be displayed again.
                </p>
                <div className="mt-3 flex items-center gap-2 bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-xs text-emerald-300 select-all break-all">
                  <span className="flex-1">{createdSecret}</span>
                  <button
                    onClick={() => copyToClipboard(createdSecret, setCopiedSecret)}
                    className="shrink-0 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded font-sans text-xs font-semibold flex items-center gap-1"
                  >
                    {copiedSecret ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                    <span>{copiedSecret ? "Copied" : "Copy Key"}</span>
                  </button>
                </div>
              </div>
              <button
                onClick={() => setCreatedSecret(null)}
                className="text-slate-400 hover:text-white text-xs px-2.5 py-1 bg-slate-800 rounded font-semibold"
              >
                Dismiss
              </button>
            </div>
          </div>
        )}

        {/* Modal: Create Key Form */}
        {showCreateModal && (
          <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 max-w-md w-full shadow-2xl">
              <h3 className="text-lg font-bold text-white flex items-center gap-2 mb-4">
                <Key className="h-5 w-5 text-blue-400" /> Generate CI/CD API Key
              </h3>
              <form onSubmit={handleCreateKey} className="space-y-4">
                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1">Key Description / Name</label>
                  <input
                    type="text"
                    value={keyName}
                    onChange={(e) => setKeyName(e.target.value)}
                    required
                    placeholder="e.g. GitHub Actions - Production Repo"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1">Project Scope (Optional)</label>
                  <select
                    value={selectedProject}
                    onChange={(e) => setSelectedProject(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
                  >
                    <option value="">All Projects in Organization</option>
                    {projects.map((p) => (
                      <option key={p.id} value={p.id}>{p.name} ({p.base_url})</option>
                    ))}
                  </select>
                  <p className="text-[11px] text-slate-500 mt-1">Restrict this key to scan only a specific project.</p>
                </div>

                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1">Expiration</label>
                  <select
                    value={expiresInDays}
                    onChange={(e) => setExpiresInDays(Number(e.target.value))}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
                  >
                    <option value={30}>30 Days</option>
                    <option value={90}>90 Days (Recommended)</option>
                    <option value={180}>180 Days</option>
                    <option value={365}>1 Year</option>
                    <option value={0}>Never Expires</option>
                  </select>
                </div>

                <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
                  <button
                    type="button"
                    onClick={() => setShowCreateModal(false)}
                    className="px-4 py-2 text-xs font-semibold text-slate-400 hover:text-white"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={creating}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg transition-colors"
                  >
                    {creating ? "Generating..." : "Generate Key"}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* Active Keys List */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 mb-8">
          <h2 className="text-base font-bold text-white mb-4 flex items-center gap-2">
            <Key className="h-4 w-4 text-blue-400" /> Active API Keys
          </h2>

          {loading ? (
            <div className="text-center py-8 text-blue-400 text-sm">Loading keys...</div>
          ) : keys.length === 0 ? (
            <div className="text-center py-8 text-slate-500 text-sm">
              No API keys generated yet. Click "Generate New Key" to create your first credential.
            </div>
          ) : (
            <div className="divide-y divide-slate-800">
              {keys.map((k) => (
                <div key={k.id} className="py-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-3">
                      <span className="font-semibold text-white text-sm">{k.name}</span>
                      <span className="font-mono text-xs bg-slate-950 px-2 py-0.5 rounded border border-slate-800 text-blue-300">
                        {k.key_prefix}
                      </span>
                    </div>
                    <div className="flex items-center gap-4 text-xs text-slate-500 mt-1 font-mono">
                      <span className="flex items-center gap-1">
                        <Calendar className="h-3 w-3" /> Created: {new Date(k.created_at).toLocaleDateString()}
                      </span>
                      {k.last_used_at ? (
                        <span className="flex items-center gap-1 text-emerald-400">
                          <Clock className="h-3 w-3" /> Last used: {new Date(k.last_used_at).toLocaleDateString()}
                        </span>
                      ) : (
                        <span className="text-slate-600">Never used</span>
                      )}
                      {k.expires_at && (
                        <span>Expires: {new Date(k.expires_at).toLocaleDateString()}</span>
                      )}
                    </div>
                  </div>
                  <button
                    onClick={() => handleRevokeKey(k.id)}
                    className="text-red-400 hover:text-red-300 hover:bg-red-950/40 p-2 rounded-lg border border-red-900/40 transition-colors inline-flex items-center gap-1 text-xs font-semibold self-start md:self-auto"
                    title="Revoke key immediately"
                  >
                    <Trash2 className="h-3.5 w-3.5" /> Revoke
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* GitHub Actions Integration Quickstart */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <Terminal className="h-4 w-4 text-purple-400" /> GitHub Actions Quickstart YAML
            </h2>
            <button
              onClick={() => copyToClipboard(sampleYaml, setCopiedYaml)}
              className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded font-semibold flex items-center gap-1.5"
            >
              {copiedYaml ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
              <span>{copiedYaml ? "Copied" : "Copy YAML"}</span>
            </button>
          </div>
          <p className="text-xs text-slate-400 mb-3">
            Copy and paste this workflow into <code className="text-blue-300 font-mono">.github/workflows/apt-security-gate.yml</code> in your repository.
            Save your generated key as a repository secret named <code className="text-amber-300 font-mono">APT_API_KEY</code>.
          </p>
          <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-xs font-mono text-indigo-200 overflow-x-auto">
            {sampleYaml}
          </pre>
        </div>
      </div>
    </div>
  );
}
