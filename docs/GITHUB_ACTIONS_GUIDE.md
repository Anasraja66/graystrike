# APT Agents GitHub Actions CI/CD Integration Guide

Integrate autonomous AI penetration testing, regression detection, and automated security gates into your pull request workflows.

---

## ⚡ Quickstart

### 1. Generate a CI/CD API Key
1. In the APT Agents dashboard, navigate to **Settings ➔ API Keys** (or call `POST /api/v1/ci/keys`).
2. Generate an API Key (e.g. `apt_live_...`).
3. Store this key in your GitHub repository's secrets:
   - Go to your repository on GitHub ➔ **Settings ➔ Secrets and variables ➔ Actions**.
   - Click **New repository secret**.
   - Name: `APT_API_KEY`
   - Value: `<paste your apt_live_... key>`

### 2. Configure Repository Variables
In the same settings page, click on the **Variables** tab and add:
- `APT_PROJECT_ID`: The UUID of your project in APT Agents (found in project settings or URL).
- `APT_API_URL` *(Optional, default: `https://api.aptagents.io`)*: Your API instance base URL.

### 3. Add Workflow to Repository
Create `.github/workflows/apt-security-gate.yml` in your repository:

```yaml
name: "APT Agents Security Gate"

on:
  pull_request:
    branches: [ "main", "master" ]
    types: [ opened, synchronize, reopened ]
  workflow_dispatch:
    inputs:
      target_url:
        description: "Target preview URL (must belong to authorized project scope)"
        required: false
      fail_on:
        description: "Severity threshold that blocks build (critical, high, medium, low, none)"
        required: false
        default: "high"

concurrency:
  group: apt-security-gate-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

permissions:
  contents: read
  pull-requests: write
  checks: write

jobs:
  security-gate:
    name: "Autonomous Security & Regression Assessment"
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run APT Agents Security Gate
        id: apt_scan
        uses: ./.github/actions/apt-scan
        with:
          api_url: ${{ vars.APT_API_URL || 'https://api.aptagents.io' }}
          api_key: ${{ secrets.APT_API_KEY }}
          project_id: ${{ vars.APT_PROJECT_ID }}
          target_url: ${{ github.event.inputs.target_url || '' }}
          fail_on: ${{ github.event.inputs.fail_on || 'high' }}
          fail_on_regression_only: "false"
          timeout_seconds: 600
          poll_interval: 5

      - name: Gate Summary
        run: |
          echo "Scan ID: ${{ steps.apt_scan.outputs.scan_id }}"
          echo "Gate Passed: ${{ steps.apt_scan.outputs.gate_passed }}"
          echo "New Findings: ${{ steps.apt_scan.outputs.new_findings_count }}"
          echo "Regressions: ${{ steps.apt_scan.outputs.regressions_count }}"
```

---

## 🛠️ Inputs Reference

| Input | Description | Default | Required |
| :--- | :--- | :--- | :--- |
| `api_key` | Secret machine-to-machine API credential (`apt_live_...`). | — | **Yes** |
| `project_id` | Registered Project UUID in APT Agents. | — | **Yes** |
| `api_url` | APT Agents API Base URL. | `https://api.aptagents.io` | No |
| `target_url` | Isolated PR preview or staging URL to test. Must match project domain. | `""` (Project base) | No |
| `fail_on` | Minimum severity threshold to block the build (`critical`, `high`, `medium`, `low`, `none`). | `high` | No |
| `fail_on_regression_only`| If `true`, only blocks if **new** findings or **regressions** occur. | `false` | No |
| `timeout_seconds` | Maximum scan duration before aborting. | `600` | No |
| `poll_interval` | Polling interval in seconds. | `5` | No |

---

## 📤 Outputs Reference

| Output | Type | Description |
| :--- | :--- | :--- |
| `scan_id` | `string` | Unique UUID of the executed security scan. |
| `gate_passed` | `boolean` | `true` if all security thresholds met; `false` if blocked. |
| `new_findings_count` | `number` | Total number of newly introduced vulnerabilities in this PR. |
| `regressions_count` | `number` | Total number of regressions (previously fixed bugs that reappeared). |

---

## 🩺 Troubleshooting Guide

### 1. `Error [401]: Invalid or revoked API Key`
- **Cause:** `APT_API_KEY` is missing or has expired.
- **Fix:** Verify GitHub Secrets contains a valid `apt_live_...` token.

### 2. `Error [400]: Scope Violation: Target '...' is outside authorized scope`
- **Cause:** The `target_url` supplied does not match the project's base domain or verified domain.
- **Fix:** APT Agents strictly forbids scanning untrusted or external URLs from PR inputs to prevent SSRF and unauthorized testing. Ensure the preview deployment is on an authorized domain (e.g. `pr-12.staging.example.com` when project is `example.com`).

### 3. `Scan Timeout Exceeded`
- **Cause:** Target application is slow or network crawler exceeded `timeout_seconds`.
- **Fix:** Increase `timeout_seconds: 900` or configure crawler rate limits in project scope policies.

### 4. `Security Gate Failed: High threshold violated`
- **Cause:** One or more findings met or exceeded the `fail_on` threshold.
- **Fix:** Review the **GitHub Step Summary** tab in the workflow run. Copy the **AI Fix Prompt** from the finding into Claude, Cursor, or Lovable to apply the patch, then retest with `git push`.
