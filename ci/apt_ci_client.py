#!/usr/bin/env python3
"""
APT Agents — Production GitHub Actions CI/CD Security Gate Client
Executes authorized scans, enforces idempotency, polls for status, evaluates security gate thresholds,
detects regressions, publishes GitHub Check Runs and PR comments, redacts sensitive tokens,
and outputs GitHub Step Summaries.
"""
import os
import sys
import time
import json
import re
from typing import Dict, Any, Optional

try:
    import httpx
except ImportError:
    import urllib.request
    import urllib.error
    httpx = None


class APTCIClient:
    def __init__(
        self,
        api_url: str,
        api_key: str,
        project_id: str,
        target_url: Optional[str] = None,
        fail_on: str = "high",
        fail_on_regression_only: bool = False,
        allow_initial_baseline: bool = True,
        timeout_seconds: int = 600,
        poll_interval: int = 5,
        step_summary_file: Optional[str] = None,
        github_output_file: Optional[str] = None
    ):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key.strip()
        self.project_id = project_id.strip()
        self.target_url = target_url.strip() if target_url else None
        self.fail_on = fail_on.strip().lower()
        self.fail_on_regression_only = fail_on_regression_only
        self.allow_initial_baseline = allow_initial_baseline
        self.timeout_seconds = timeout_seconds
        self.poll_interval = max(2, poll_interval)
        self.step_summary_file = step_summary_file or os.getenv("GITHUB_STEP_SUMMARY")
        self.github_output_file = github_output_file or os.getenv("GITHUB_OUTPUT")

    def _headers(self) -> Dict[str, str]:
        return {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
            "User-Agent": "APT-Agents-GitHub-Action/1.0"
        }

    def _request(self, method: str, endpoint: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """HTTP helper supporting both httpx and standard urllib."""
        url = f"{self.api_url}{endpoint}"
        
        if httpx:
            with httpx.Client(timeout=30.0) as client:
                resp = client.request(method, url, headers=self._headers(), json=data)
                if resp.status_code >= 400:
                    try:
                        err_body = resp.json().get("detail", resp.text)
                    except Exception:
                        err_body = resp.text
                    raise RuntimeError(f"API request failed [{resp.status_code}]: {err_body}")
                return resp.json() if resp.content else {}
        else:
            req_data = json.dumps(data).encode("utf-8") if data else None
            req = urllib.request.Request(url, data=req_data, headers=self._headers(), method=method)
            try:
                with urllib.request.urlopen(req, timeout=30.0) as resp:
                    raw = resp.read().decode("utf-8")
                    return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as err:
                err_text = err.read().decode("utf-8")
                raise RuntimeError(f"API request failed [{err.code}]: {err_text}")

    def trigger_scan(self) -> Dict[str, Any]:
        """Trigger scan with branch and PR context, supporting idempotency."""
        payload = {
            "project_id": self.project_id,
            "target_url": self.target_url,
            "branch": os.getenv("GITHUB_REF_NAME", "main"),
            "commit_sha": os.getenv("GITHUB_SHA"),
            "pull_request_number": self._extract_pr_number(),
            "ci_provider": "github_actions"
        }
        print(f"🔒 [APT CI] Triggering security assessment for Project: {self.project_id}")
        if self.target_url:
            print(f"🎯 [APT CI] Scoped Target URL: {self.target_url}")
        
        resp = self._request("POST", "/api/v1/ci/scan", payload)
        if resp.get("idempotent_reused"):
            print(f"🔁 [APT CI] Idempotency: Reusing active scan for commit {payload['commit_sha']}")
        return resp

    def _extract_pr_number(self) -> Optional[int]:
        ref = os.getenv("GITHUB_REF", "")
        m = re.match(r"refs/pull/(\d+)/", ref)
        return int(m.group(1)) if m else None

    def poll_scan(self, scan_id: str) -> Dict[str, Any]:
        """Poll scan until completed, failed, cancelled, or timed out."""
        start_time = time.time()
        print(f"⏳ [APT CI] Scan in progress (ID: {scan_id}). Polling status every {self.poll_interval}s...")

        while True:
            elapsed = int(time.time() - start_time)
            if elapsed > self.timeout_seconds:
                print(f"⏱️ [APT CI] Scan timeout exceeded ({self.timeout_seconds}s). Cancelling scan...")
                try:
                    self._request("POST", f"/api/v1/scans/{scan_id}/cancel")
                except Exception as e:
                    print(f"⚠️ [APT CI] Could not cancel scan: {e}")
                raise TimeoutError(f"APT Agents scan {scan_id} exceeded maximum timeout of {self.timeout_seconds} seconds.")

            scan_data = self._request("GET", f"/api/v1/scans/{scan_id}")
            status = scan_data.get("status", "").lower()
            stage = scan_data.get("current_stage", "in_progress")
            findings_count = scan_data.get("total_findings", 0)

            print(f"📊 [APT CI] Elapsed: {elapsed}s | Status: {status.upper()} | Stage: {stage} | Findings: {findings_count}")

            if status in ["completed", "failed", "cancelled"]:
                return scan_data

            time.sleep(self.poll_interval)

    def evaluate_gate(self, scan_id: str) -> Dict[str, Any]:
        """Query security gate evaluation and regression breakdown."""
        params = (
            f"?fail_on={self.fail_on}"
            f"&fail_on_regression_only={str(self.fail_on_regression_only).lower()}"
            f"&allow_initial_baseline={str(self.allow_initial_baseline).lower()}"
        )
        return self._request("GET", f"/api/v1/ci/scans/{scan_id}/summary{params}")

    def write_step_summary(self, markdown_text: str):
        """Append markdown summary to GitHub Step Summary file."""
        if not self.step_summary_file:
            print(markdown_text)
            return

        try:
            with open(self.step_summary_file, "a", encoding="utf-8") as f:
                f.write("\n" + markdown_text + "\n")
            print(f"📝 [APT CI] Wrote security report to GITHUB_STEP_SUMMARY")
        except Exception as e:
            print(f"⚠️ [APT CI] Could not write to GITHUB_STEP_SUMMARY: {e}")
            print(markdown_text)

    def set_github_output(self, key: str, value: str):
        """Set step output for downstream GitHub Actions jobs."""
        if not self.github_output_file:
            return
        try:
            with open(self.github_output_file, "a", encoding="utf-8") as f:
                f.write(f"{key}={value}\n")
        except Exception as e:
            print(f"⚠️ [APT CI] Could not write output {key}: {e}")

    def publish_github_check_run(self, title: str, summary_md: str, conclusion: str):
        """Publishes official GitHub Check Run if GITHUB_TOKEN and repository context exist."""
        github_token = os.getenv("GITHUB_TOKEN")
        repo = os.getenv("GITHUB_REPOSITORY")
        sha = os.getenv("GITHUB_SHA")

        if not (github_token and repo and sha):
            return

        url = f"https://api.github.com/repos/{repo}/check-runs"
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "APT-Agents-CI"
        }
        payload = {
            "name": "APT Agents Security Gate",
            "head_sha": sha,
            "status": "completed",
            "conclusion": conclusion,  # "success" or "failure"
            "output": {
                "title": title,
                "summary": summary_md[:65535]
            }
        }
        try:
            if httpx:
                with httpx.Client(timeout=10.0) as client:
                    client.post(url, headers=headers, json=payload)
            print(f"📊 [APT CI] Published official GitHub Check Run ({conclusion})")
        except Exception as e:
            print(f"⚠️ [APT CI] Could not publish GitHub Check Run: {e}")

    def post_pr_comment(self, summary_md: str):
        """Posts summary comment to PR if GITHUB_TOKEN and PR number exist."""
        github_token = os.getenv("GITHUB_TOKEN")
        repo = os.getenv("GITHUB_REPOSITORY")
        pr_num = self._extract_pr_number()

        if not (github_token and repo and pr_num):
            return

        url = f"https://api.github.com/repos/{repo}/issues/{pr_num}/comments"
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "APT-Agents-CI"
        }
        payload = {"body": summary_md}
        try:
            if httpx:
                with httpx.Client(timeout=10.0) as client:
                    client.post(url, headers=headers, json=payload)
            print(f"💬 [APT CI] Posted summary comment to PR #{pr_num}")
        except Exception as e:
            print(f"⚠️ [APT CI] Could not post PR comment: {e}")

    def download_sarif(self, scan_id: str, output_path: str = "results.sarif"):
        """Downloads SARIF v2.1.0 report and saves to disk for GitHub Code Scanning."""
        try:
            sarif_data = self._request("GET", f"/api/v1/ci/scans/{scan_id}/sarif")
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(sarif_data, f, indent=2)
            print(f"📄 [APT CI] Exported OASIS SARIF 2.1.0 report: {output_path}")
        except Exception as e:
            print(f"⚠️ [APT CI] Could not download SARIF report: {e}")

    def run(self) -> int:
        """Main execution flow. Returns 0 on gate pass, 1 on gate failure, error, or incomplete scan."""
        try:
            # 1. Trigger scan
            scan_resp = self.trigger_scan()
            scan_id = scan_resp["scan_id"]
            self.set_github_output("scan_id", scan_id)

            # 2. Poll until terminal state
            scan_data = self.poll_scan(scan_id)
            final_status = scan_data.get("status", "").lower()

            # FAIL-SAFE: Failed or Cancelled Scan
            if final_status in ["failed", "cancelled"]:
                err_msg = f"Scan ended in state: '{final_status.upper()}'. Halting workflow without passing."
                print(f"❌ [APT CI] {err_msg}")
                md = f"### ❌ APT Agents Scan Failed\nScan ID `{scan_id}` ended in state `{final_status.upper()}`. Scan was not completed."
                self.write_step_summary(md)
                self.set_github_output("gate_passed", "false")
                self.publish_github_check_run("Scan Failed", md, "failure")
                self.post_pr_comment(md)
                return 1

            # 3. Evaluate Gate & Regressions
            eval_data = self.evaluate_gate(scan_id)
            gate_passed = eval_data.get("gate_passed", False)
            summary_md = eval_data.get("summary_markdown", "")
            eval_status = eval_data.get("status", "")

            # 4. Download SARIF for GitHub Code Scanning tab
            self.download_sarif(scan_id, "results.sarif")

            # FAIL-SAFE: Incomplete Scan check
            if eval_status == "incomplete" or not gate_passed:
                self.write_step_summary(summary_md)
                self.set_github_output("gate_passed", "false")
                self.publish_github_check_run("Security Gate Failed", summary_md, "failure")
                self.post_pr_comment(summary_md)
                print(f"🚨 [APT CI] Security Gate FAILED: {eval_data.get('reason')}")
                return 1

            # Passed
            self.write_step_summary(summary_md)
            self.set_github_output("gate_passed", "true")
            self.set_github_output("new_findings_count", str(eval_data.get("new_findings_count", 0)))
            self.set_github_output("regressions_count", str(eval_data.get("regression_findings_count", 0)))
            self.publish_github_check_run("Security Gate Passed", summary_md, "success")
            self.post_pr_comment(summary_md)

            print(f"🎉 [APT CI] Security Gate PASSED: {eval_data.get('reason')}")
            return 0

        except Exception as exc:
            err_msg = f"APT Agents CI Execution Error: {str(exc)}"
            print(f"💥 [APT CI] {err_msg}", file=sys.stderr)
            md = f"### ❌ APT Agents Workflow Error\n`{err_msg}`"
            self.write_step_summary(md)
            self.set_github_output("gate_passed", "false")
            self.publish_github_check_run("Workflow Error", md, "failure")
            return 1


def main():
    api_url = os.getenv("APT_API_URL") or "http://127.0.0.1:8000"
    api_key = os.getenv("APT_API_KEY")
    project_id = os.getenv("APT_PROJECT_ID")
    target_url = os.getenv("APT_TARGET_URL") or None
    fail_on = os.getenv("APT_FAIL_ON", "high")
    fail_on_reg_only = os.getenv("APT_FAIL_ON_REGRESSION_ONLY", "false").lower() in ["true", "1", "yes"]
    allow_init_baseline = os.getenv("APT_ALLOW_INITIAL_BASELINE", "true").lower() in ["true", "1", "yes"]
    timeout_sec = int(os.getenv("APT_SCAN_TIMEOUT", "600"))
    poll_sec = int(os.getenv("APT_POLL_INTERVAL", "5"))

    if not api_key:
        print("❌ [APT CI Error] Missing required environment variable: APT_API_KEY", file=sys.stderr)
        sys.exit(1)

    if not project_id:
        print("❌ [APT CI Error] Missing required environment variable: APT_PROJECT_ID", file=sys.stderr)
        sys.exit(1)

    client = APTCIClient(
        api_url=api_url,
        api_key=api_key,
        project_id=project_id,
        target_url=target_url,
        fail_on=fail_on,
        fail_on_regression_only=fail_on_reg_only,
        allow_initial_baseline=allow_init_baseline,
        timeout_seconds=timeout_sec,
        poll_interval=poll_sec
    )

    exit_code = client.run()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
