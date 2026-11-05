"""
History Miner (HAFix Heuristic) for GrayStrike
Inspired by HAFixAgent (Shi et al., Queen's University, arXiv:2511.01047, 2025).

Mines version control history to enrich vulnerability analysis and patch generation:
1. Executes `git blame` to locate the single bug-introducing commit (SZZ principle).
2. Extracts file-level diff (`fl_diff`) to reveal the developer's original intent.
3. Extracts function before-and-after pair (`fn_pair`).
4. Implements the blameless fallback strategy (searches preceding 5 lines for insertion bugs).
"""
import os
import subprocess
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List


@dataclass
class GitHistoryContext:
    available: bool
    commit_hash: Optional[str] = None
    author: Optional[str] = None
    author_date: Optional[str] = None
    commit_summary: Optional[str] = None
    fl_diff: Optional[str] = None
    fn_pair_before: Optional[str] = None
    fn_pair_after: Optional[str] = None
    heuristic_used: str = "none"
    is_blameless_fallback: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "commit_hash": self.commit_hash,
            "author": self.author,
            "author_date": self.author_date,
            "commit_summary": self.commit_summary,
            "fl_diff": self.fl_diff,
            "fn_pair_before": self.fn_pair_before,
            "fn_pair_after": self.fn_pair_after,
            "heuristic_used": self.heuristic_used,
            "is_blameless_fallback": self.is_blameless_fallback,
            "details": self.details,
        }


class GitHistoryMiner:
    """
    Extracts version control historical context for vulnerability locations
    using Git blame and diff mining heuristics.
    """

    def __init__(self, repo_path: str = "."):
        self.repo_path = os.path.abspath(repo_path)

    def _run_git(self, args: List[str]) -> Optional[str]:
        try:
            res = subprocess.run(
                ["git"] + args,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            if res.returncode == 0:
                return res.stdout
            return None
        except Exception:
            return None

    def mine_line_history(
        self,
        file_path: str,
        line_number: int,
        fallback_window: int = 5
    ) -> GitHistoryContext:
        """
        Mines the blame commit and historical diff for a specific file and line.
        Applies HAFix blameless fallback if the target line is not directly blameable.
        """
        rel_path = file_path
        if os.path.isabs(file_path):
            try:
                rel_path = os.path.relpath(file_path, self.repo_path)
            except ValueError:
                rel_path = file_path

        # Step 1: Attempt direct blame on target line
        blame_info = self._execute_blame(rel_path, line_number)
        is_fallback = False

        # Step 2: Blameless fallback if direct blame failed (e.g., newly inserted line)
        if not blame_info and line_number > 1:
            for offset in range(1, fallback_window + 1):
                candidate_line = line_number - offset
                if candidate_line < 1:
                    break
                blame_info = self._execute_blame(rel_path, candidate_line)
                if blame_info:
                    is_fallback = True
                    break

        if not blame_info:
            return GitHistoryContext(
                available=False,
                heuristic_used="none",
                details={"reason": f"No git blame found for {rel_path}:{line_number}"}
            )

        commit_hash = blame_info.get("commit_hash")
        author = blame_info.get("author")
        author_date = blame_info.get("author_date")
        summary = blame_info.get("summary")

        # Step 3: Extract fl_diff (File-Level Diff from that commit)
        fl_diff = None
        if commit_hash and not commit_hash.startswith("0000000"):
            raw_diff = self._run_git(["show", commit_hash, "--", rel_path])
            if raw_diff:
                # Truncate exceptionally large diffs for LLM prompt economy
                lines = raw_diff.splitlines()
                if len(lines) > 60:
                    fl_diff = "\n".join(lines[:60]) + "\n... [truncated for prompt economy]"
                else:
                    fl_diff = raw_diff

        # Step 4: Extract fn_pair (Before & after hunk snapshot)
        fn_before, fn_after = self._extract_fn_pair(rel_path, commit_hash, line_number)

        return GitHistoryContext(
            available=True,
            commit_hash=commit_hash,
            author=author,
            author_date=author_date,
            commit_summary=summary,
            fl_diff=fl_diff,
            fn_pair_before=fn_before,
            fn_pair_after=fn_after,
            heuristic_used="fl_diff+fn_pair",
            is_blameless_fallback=is_fallback,
            details={
                "target_file": rel_path,
                "target_line": line_number,
                "commit_hash": commit_hash
            }
        )

    def _execute_blame(self, rel_path: str, line_number: int) -> Optional[Dict[str, str]]:
        output = self._run_git(["blame", "-L", f"{line_number},{line_number}", "--porcelain", rel_path])
        if not output:
            return None

        lines = output.splitlines()
        if not lines:
            return None

        header_parts = lines[0].split()
        commit_hash = header_parts[0] if header_parts else None

        info: Dict[str, str] = {"commit_hash": commit_hash or "unknown"}
        for line in lines[1:]:
            if line.startswith("author "):
                info["author"] = line[len("author "):].strip()
            elif line.startswith("author-time "):
                info["author_date"] = line[len("author-time "):].strip()
            elif line.startswith("summary "):
                info["summary"] = line[len("summary "):].strip()

        return info

    def _extract_fn_pair(
        self,
        rel_path: str,
        commit_hash: Optional[str],
        line_number: int
    ) -> tuple[Optional[str], Optional[str]]:
        if not commit_hash or commit_hash.startswith("0000000"):
            return None, None

        # Try to read the file at parent commit (commit^) and at commit
        before_content = self._run_git(["show", f"{commit_hash}^:{rel_path}"])
        after_content = self._run_git(["show", f"{commit_hash}:{rel_path}"])

        before_snippet = None
        after_snippet = None

        if before_content:
            before_lines = before_content.splitlines()
            start = max(0, line_number - 8)
            end = min(len(before_lines), line_number + 8)
            before_snippet = "\n".join(before_lines[start:end])

        if after_content:
            after_lines = after_content.splitlines()
            start = max(0, line_number - 8)
            end = min(len(after_lines), line_number + 8)
            after_snippet = "\n".join(after_lines[start:end])

        return before_snippet, after_snippet
