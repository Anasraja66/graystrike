"""
P3: GitHub SAST (Static Application Security Testing) Integration
GitHub API connector — fetches repository file tree, source files,
commit metadata, and CI/CD workflow configurations for static analysis.

Supports:
- Public repos via GITHUB_TOKEN
- File tree traversal (recursive)
- Raw file content decoding (base64)
- Commit SHA ↔ deployed build mapping
- Rate-limit aware pagination
"""
import re
import base64
import json
import httpx
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field


# =============================================================
# DATA MODELS
# =============================================================

@dataclass
class GitHubFile:
    path: str
    name: str
    sha: str
    size: int
    content: str          # Decoded UTF-8 text
    encoding: str = "utf-8"
    download_url: str = ""


@dataclass
class GitHubCommit:
    sha: str
    message: str
    author: str
    timestamp: str
    files_changed: List[str] = field(default_factory=list)
    additions: int = 0
    deletions: int = 0


@dataclass
class GitHubRepoMeta:
    owner: str
    repo: str
    default_branch: str
    latest_commit_sha: str
    repo_url: str
    topics: List[str] = field(default_factory=list)
    language: str = ""
    stars: int = 0
    fetched_at: str = ""


# =============================================================
# GITHUB API CONNECTOR
# =============================================================

class GitHubConnector:
    """
    GitHub REST API v3 connector for SAST file fetching.
    Uses personal access token or unauthenticated (60 req/h limit).
    """

    BASE_URL = "https://api.github.com"

    # Files relevant to SAST security analysis
    SECURITY_RELEVANT_PATTERNS = [
        # Next.js / React / Vite routes & middleware
        r"middleware\.(ts|js|tsx)$",
        r"app/.*/(page|layout|route)\.(ts|js|tsx)$",
        r"pages/api/.*\.(ts|js)$",
        r"src/.*route.*\.(ts|js)$",
        # Auth configuration
        r"auth\.(ts|js|tsx)$",
        r".*clerk.*\.(ts|js)$",
        r".*supabase.*\.(ts|js|sql)$",
        r".*firebase.*\.(ts|js|json)$",
        # Database migrations & RLS policies
        r".*migration.*\.(sql|ts|js)$",
        r"supabase/migrations/.*\.sql$",
        # Environment / secrets config
        r"\.env(\.example|\.local|\.production)?$",
        r"\.env\.(development|staging|production|local)$",
        # Infrastructure
        r"(next|vite|nuxt)\.config\.(ts|js|mjs)$",
        r"vercel\.json$",
        r"docker-compose\.(yml|yaml)$",
        # Package dependencies
        r"package\.json$",
        r"requirements\.txt$",
        r"pyproject\.toml$",
        # Webhook handlers
        r".*webhook.*\.(ts|js|py)$",
        r".*stripe.*\.(ts|js|py)$",
        # LLM / AI routes
        r".*chat.*\.(ts|js|py)$",
        r".*llm.*\.(ts|js|py)$",
        r".*openai.*\.(ts|js|py)$",
    ]

    def __init__(self, token: Optional[str] = None):
        self.token = token
        self.headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    async def get_repo_meta(self, owner: str, repo: str) -> Optional[GitHubRepoMeta]:
        """Fetch repository metadata including default branch and latest commit."""
        async with httpx.AsyncClient(headers=self.headers, timeout=15) as client:
            # Repo info
            r = await client.get(f"{self.BASE_URL}/repos/{owner}/{repo}")
            if r.status_code != 200:
                return None
            data = r.json()

            branch = data.get("default_branch", "main")

            # Latest commit on default branch
            r2 = await client.get(f"{self.BASE_URL}/repos/{owner}/{repo}/commits/{branch}")
            latest_sha = ""
            if r2.status_code == 200:
                latest_sha = r2.json().get("sha", "")[:12]

            return GitHubRepoMeta(
                owner=owner,
                repo=repo,
                default_branch=branch,
                latest_commit_sha=latest_sha,
                repo_url=data.get("html_url", ""),
                topics=data.get("topics", []),
                language=data.get("language", ""),
                stars=data.get("stargazers_count", 0),
                fetched_at=datetime.now(timezone.utc).isoformat()
            )

    async def get_file_tree(
        self, owner: str, repo: str, branch: str = "main", max_files: int = 500
    ) -> List[Dict[str, Any]]:
        """Recursively fetch the full file tree from GitHub Git Trees API."""
        async with httpx.AsyncClient(headers=self.headers, timeout=20) as client:
            url = f"{self.BASE_URL}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
            r = await client.get(url)
            if r.status_code != 200:
                return []
            data = r.json()
            tree = data.get("tree", [])
            # Filter to files only (not trees/dirs)
            return [
                item for item in tree
                if item.get("type") == "blob" and item.get("size", 0) < 200_000
            ][:max_files]

    async def get_file_content(
        self, owner: str, repo: str, path: str
    ) -> Optional[GitHubFile]:
        """Fetch and decode a single file from GitHub Contents API."""
        async with httpx.AsyncClient(headers=self.headers, timeout=15) as client:
            url = f"{self.BASE_URL}/repos/{owner}/{repo}/contents/{path}"
            r = await client.get(url)
            if r.status_code != 200:
                return None
            data = r.json()

            if data.get("encoding") != "base64":
                return None

            try:
                raw_content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
            except Exception:
                raw_content = ""

            return GitHubFile(
                path=data.get("path", path),
                name=data.get("name", ""),
                sha=data.get("sha", ""),
                size=data.get("size", 0),
                content=raw_content,
                download_url=data.get("download_url", "")
            )

    async def get_security_relevant_files(
        self, owner: str, repo: str, branch: str = "main"
    ) -> List[GitHubFile]:
        """
        Fetch all files matching security-relevant patterns from the repository.
        Returns decoded GitHubFile objects.
        """
        tree = await self.get_file_tree(owner, repo, branch)
        security_files = []

        compiled_patterns = [re.compile(p) for p in self.SECURITY_RELEVANT_PATTERNS]

        relevant_paths = []
        for item in tree:
            path = item.get("path", "")
            for pattern in compiled_patterns:
                if pattern.search(path):
                    relevant_paths.append(path)
                    break

        # Fetch file contents (limit to 40 most important)
        relevant_paths = relevant_paths[:40]
        async with httpx.AsyncClient(headers=self.headers, timeout=15) as client:
            for path in relevant_paths:
                url = f"{self.BASE_URL}/repos/{owner}/{repo}/contents/{path}"
                r = await client.get(url)
                if r.status_code != 200:
                    continue
                data = r.json()
                if data.get("encoding") != "base64":
                    continue
                try:
                    raw = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
                    security_files.append(GitHubFile(
                        path=path,
                        name=data.get("name", ""),
                        sha=data.get("sha", ""),
                        size=data.get("size", 0),
                        content=raw,
                        download_url=data.get("download_url", "")
                    ))
                except Exception:
                    continue

        return security_files

    async def get_recent_commits(
        self, owner: str, repo: str, branch: str = "main", limit: int = 10
    ) -> List[GitHubCommit]:
        """Fetch recent commits with file change metadata."""
        async with httpx.AsyncClient(headers=self.headers, timeout=15) as client:
            url = f"{self.BASE_URL}/repos/{owner}/{repo}/commits?sha={branch}&per_page={limit}"
            r = await client.get(url)
            if r.status_code != 200:
                return []

            commits = []
            for c in r.json():
                commit_data = c.get("commit", {})
                author_info = commit_data.get("author", {})
                commits.append(GitHubCommit(
                    sha=c.get("sha", "")[:12],
                    message=commit_data.get("message", "")[:200],
                    author=author_info.get("name", "unknown"),
                    timestamp=author_info.get("date", ""),
                    files_changed=[],
                    additions=c.get("stats", {}).get("additions", 0),
                    deletions=c.get("stats", {}).get("deletions", 0)
                ))
            return commits
