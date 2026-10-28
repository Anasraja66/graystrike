"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Shield, ArrowLeft, CreditCard, Bell, Check, Zap, AlertCircle, RefreshCw } from "lucide-react";
import axios from "axios";

export default function BillingAndAlertsPage() {
  const router = useRouter();
  const [billing, setBilling] = useState<any>(null);
  const [slackUrl, setSlackUrl] = useState("");
  const [discordUrl, setDiscordUrl] = useState("");
  const [savingWebhooks, setSavingWebhooks] = useState(false);
  const [upgrading, setUpgrading] = useState<string | null>(null);
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchBilling = async () => {
    const token = localStorage.getItem("token");
    if (!token) { router.push("/auth/login"); return; }
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

    try {
      const res = await axios.get(`${api}/api/v1/billing/status`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setBilling(res.data);
      if (res.data.slack_webhook_configured) setSlackUrl("https://hooks.slack.com/services/configured");
      if (res.data.discord_webhook_configured) setDiscordUrl("https://discord.com/api/webhooks/configured");
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBilling();
  }, []);

  const handleUpgrade = async (planKey: string) => {
    setUpgrading(planKey);
    setMessage(null);
    const token = localStorage.getItem("token");
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

    try {
      const res = await axios.post(`${api}/api/v1/billing/upgrade`, { target_plan: planKey }, {
        headers: { Authorization: `Bearer ${token}` }
      });

      if (res.data.checkout_url) {
        window.location.href = res.data.checkout_url;
      } else {
        setMessage({ type: "success", text: res.data.message || `Upgraded to ${planKey.toUpperCase()} plan!` });
        await fetchBilling();
      }
    } catch (err: any) {
      setMessage({ type: "error", text: err.response?.data?.detail || "Upgrade request failed." });
    } finally {
      setUpgrading(null);
    }
  };

  const handleSaveWebhooks = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingWebhooks(true);
    setMessage(null);
    const token = localStorage.getItem("token");
    const api = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

    try {
      const res = await axios.post(`${api}/api/v1/billing/notifications`, {
        slack_webhook_url: slackUrl.includes("configured") ? undefined : slackUrl,
        discord_webhook_url: discordUrl.includes("configured") ? undefined : discordUrl
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });

      setMessage({ type: "success", text: "Alert webhooks saved! Critical vulnerabilities will trigger instant alerts." });
      await fetchBilling();
    } catch (err: any) {
      setMessage({ type: "error", text: "Failed to update webhook URLs." });
    } finally {
      setSavingWebhooks(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center text-blue-400">
        Loading billing & alerting status...
      </div>
    );
  }

  const currentPlan = billing?.current_plan?.toLowerCase() || "free";

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-8">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-4">
            <Link href="/dashboard" className="text-slate-400 hover:text-white transition-colors">
              <ArrowLeft className="h-5 w-5" />
            </Link>
            <div>
              <h1 className="text-2xl font-bold text-white flex items-center gap-2">
                <CreditCard className="h-6 w-6 text-blue-500" /> Subscription & Alerts
              </h1>
              <p className="text-slate-400 text-sm">Manage SaaS tiers, payment quotas, and real-time Slack/Discord alerts</p>
            </div>
          </div>
          <div className="px-3.5 py-1.5 rounded-full bg-blue-950/80 border border-blue-800 text-blue-400 text-sm font-semibold uppercase tracking-wide">
            Active Plan: {currentPlan}
          </div>
        </div>

        {/* Status Message */}
        {message && (
          <div className={`mb-6 p-4 rounded-xl border flex items-center gap-3 text-sm ${
            message.type === "success" ? "bg-emerald-950/50 border-emerald-800 text-emerald-300" : "bg-red-950/50 border-red-800 text-red-300"
          }`}>
            <AlertCircle className="h-5 w-5 shrink-0" />
            <span>{message.text}</span>
          </div>
        )}

        {/* Pricing Tiers Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
          {billing?.available_tiers?.map((tier: any) => {
            const isCurrent = currentPlan === tier.tier.toLowerCase();
            return (
              <div
                key={tier.tier}
                className={`bg-slate-900 border rounded-2xl p-6 flex flex-col justify-between transition-all ${
                  isCurrent ? "border-blue-500 ring-2 ring-blue-500/20 shadow-xl shadow-blue-500/10" : "border-slate-800 hover:border-slate-700"
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="text-lg font-bold text-white">{tier.name}</h3>
                    {isCurrent && (
                      <span className="text-[10px] uppercase font-bold bg-blue-600 text-white px-2 py-0.5 rounded-full">
                        Current
                      </span>
                    )}
                  </div>
                  <div className="flex items-baseline gap-1 my-4">
                    <span className="text-4xl font-extrabold text-white">${tier.price_usd}</span>
                    <span className="text-slate-400 text-sm">/ month</span>
                  </div>
                  <ul className="space-y-2.5 my-6 text-sm text-slate-300">
                    {tier.features.map((f: string, idx: number) => (
                      <li key={idx} className="flex items-center gap-2">
                        <Check className="h-4 w-4 text-emerald-400 shrink-0" />
                        <span>{f}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <button
                  disabled={isCurrent || upgrading === tier.tier}
                  onClick={() => handleUpgrade(tier.tier)}
                  className={`w-full py-2.5 rounded-xl font-semibold text-sm transition-all flex items-center justify-center gap-2 ${
                    isCurrent
                      ? "bg-slate-800 text-slate-500 cursor-not-allowed"
                      : "bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-500/25"
                  }`}
                >
                  {upgrading === tier.tier ? (
                    <RefreshCw className="h-4 w-4 animate-spin" />
                  ) : isCurrent ? (
                    "Active Plan"
                  ) : (
                    <>
                      <Zap className="h-4 w-4" /> Upgrade to {tier.tier.toUpperCase()}
                    </>
                  )}
                </button>
              </div>
            );
          })}
        </div>

        {/* Webhook Notifications Section */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
          <div className="flex items-center gap-3 mb-4 border-b border-slate-800 pb-4">
            <Bell className="h-5 w-5 text-indigo-400" />
            <div>
              <h2 className="text-lg font-bold text-white">Instant Team Alerts (Slack & Discord)</h2>
              <p className="text-slate-400 text-xs mt-0.5">
                Automatically post critical vulnerability alerts directly to your development team channel when scans finish.
              </p>
            </div>
          </div>

          <form onSubmit={handleSaveWebhooks} className="space-y-4 max-w-2xl">
            <div>
              <label className="block text-xs font-semibold uppercase text-slate-300 mb-1.5">
                Slack Incoming Webhook URL
              </label>
              <input
                type="url"
                value={slackUrl}
                onChange={(e) => setSlackUrl(e.target.value)}
                placeholder="https://hooks.slack.com/services/T.../B.../..."
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold uppercase text-slate-300 mb-1.5">
                Discord Webhook URL
              </label>
              <input
                type="url"
                value={discordUrl}
                onChange={(e) => setDiscordUrl(e.target.value)}
                placeholder="https://discord.com/api/webhooks/..."
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-blue-500"
              />
            </div>

            <button
              type="submit"
              disabled={savingWebhooks}
              className="bg-indigo-600 hover:bg-indigo-500 text-white px-5 py-2 rounded-xl text-sm font-semibold transition-colors flex items-center gap-2"
            >
              {savingWebhooks ? <RefreshCw className="h-4 w-4 animate-spin" /> : "Save Webhook Integrations"}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
