"""
API Clients for GitHub Forensics Evidence Collection.

Clients for fetching data from various OSINT sources:
- GitHubClient: GitHub REST API (unauthenticated, 60 req/hr)
- WaybackClient: Wayback Machine CDX API
- GHArchiveClient: GH Archive BigQuery
- GitClient: Local git operations
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Protocol, runtime_checkable

from ._schema import EvidenceSource


@runtime_checkable
class SourceClient(Protocol):
    """Protocol for source clients."""

    @property
    def source(self) -> EvidenceSource: ...


class GitHubClient:
    """Client for GitHub REST API (unauthenticated OSINT).

    Rate limits: 60 requests/hour unauthenticated.
    All public repository data is accessible without authentication.
    """

    BASE_URL = "https://api.github.com"

    def __init__(self):
        self._session: Any = None

    @property
    def source(self) -> EvidenceSource:
        return EvidenceSource.GITHUB

    def _get_session(self) -> Any:
        if self._session is None:
            import requests

            self._session = requests.Session()
            self._session.headers.update({"Accept": "application/vnd.github+json"})
        return self._session

    def get_commit(self, owner: str, repo: str, sha: str) -> dict[str, Any]:
        """Fetch commit from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/commits/{sha}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_issue(self, owner: str, repo: str, number: int) -> dict[str, Any]:
        """Fetch issue from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/issues/{number}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_pull_request(self, owner: str, repo: str, number: int) -> dict[str, Any]:
        """Fetch PR from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/pulls/{number}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_file(self, owner: str, repo: str, path: str, ref: str = "HEAD") -> dict[str, Any]:
        """Fetch file content from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/contents/{path}"
        params = {"ref": ref}
        resp = session.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

    def get_branch(self, owner: str, repo: str, branch: str) -> dict[str, Any]:
        """Fetch branch from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/branches/{branch}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_tag(self, owner: str, repo: str, tag: str) -> dict[str, Any]:
        """Fetch tag from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/git/refs/tags/{tag}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_release(self, owner: str, repo: str, tag: str) -> dict[str, Any]:
        """Fetch release by tag from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/releases/tags/{tag}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_forks(self, owner: str, repo: str, per_page: int = 100) -> list[dict[str, Any]]:
        """Fetch forks from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/forks"
        params = {"per_page": per_page}
        resp = session.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

    def get_repo(self, owner: str, repo: str) -> dict[str, Any]:
        """Fetch repository info from GitHub API."""
        session = self._get_session()
        url = f"{self.BASE_URL}/repos/{owner}/{repo}"
        resp = session.get(url)
        resp.raise_for_status()
        return resp.json()


class WaybackClient:
    """Client for Wayback Machine CDX API."""

    CDX_URL = "https://web.archive.org/cdx/search/cdx"
    AVAILABILITY_URL = "https://archive.org/wayback/available"
    ARCHIVE_URL = "https://web.archive.org/web"

    def __init__(self):
        self._session: Any = None

    @property
    def source(self) -> EvidenceSource:
        return EvidenceSource.WAYBACK

    def _get_session(self) -> Any:
        if self._session is None:
            import requests

            self._session = requests.Session()
        return self._session

    def search_cdx(
        self,
        url: str,
        match_type: str = "exact",
        from_date: str | None = None,
        to_date: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, str]]:
        """Search CDX API for archived snapshots."""
        session = self._get_session()
        params: dict[str, Any] = {
            "url": url,
            "output": "json",
            "matchType": match_type,
            "filter": "statuscode:200",
            "limit": limit,
        }
        if from_date:
            params["from"] = from_date
        if to_date:
            params["to"] = to_date

        resp = session.get(self.CDX_URL, params=params)
        resp.raise_for_status()
        data = resp.json()

        if len(data) <= 1:
            return []

        headers = data[0]
        return [dict(zip(headers, row)) for row in data[1:]]

    def get_snapshot(self, url: str, timestamp: str) -> str | None:
        """Fetch archived page content."""
        session = self._get_session()
        archive_url = f"{self.ARCHIVE_URL}/{timestamp}/{url}"
        resp = session.get(archive_url)
        if resp.status_code == 200:
            return resp.text
        return None


class GHArchiveClient:
    """Client for GH Archive BigQuery queries."""

    def __init__(self, credentials_path: str | None = None, project_id: str | None = None):
        self.credentials_path = credentials_path
        self.project_id = project_id
        self._client: Any = None

    @property
    def source(self) -> EvidenceSource:
        return EvidenceSource.GHARCHIVE

    def _get_client(self) -> Any:
        if self._client is None:
            from google.cloud import bigquery
            from google.oauth2 import service_account

            credentials = None
            project = self.project_id

            # First, try explicit credentials path
            if self.credentials_path:
                credentials = service_account.Credentials.from_service_account_file(
                    self.credentials_path, scopes=["https://www.googleapis.com/auth/bigquery"]
                )
                project = credentials.project_id
            else:
                # Check GOOGLE_APPLICATION_CREDENTIALS - could be path or JSON content
                creds_env = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
                if creds_env:
                    # Strip surrounding quotes if present (shell quoting)
                    creds_env = creds_env.strip()
                    if creds_env.startswith("'") and creds_env.endswith("'"):
                        creds_env = creds_env[1:-1]
                    elif creds_env.startswith('"') and creds_env.endswith('"'):
                        creds_env = creds_env[1:-1]

                    # If it starts with '{', treat as JSON content
                    if creds_env.startswith("{"):
                        creds_info = json.loads(creds_env)
                        credentials = service_account.Credentials.from_service_account_info(
                            creds_info, scopes=["https://www.googleapis.com/auth/bigquery"]
                        )
                        project = creds_info.get("project_id", project)
                    elif os.path.exists(creds_env):
                        # It's a file path
                        credentials = service_account.Credentials.from_service_account_file(
                            creds_env, scopes=["https://www.googleapis.com/auth/bigquery"]
                        )
                        project = credentials.project_id

            if credentials:
                self._client = bigquery.Client(credentials=credentials, project=project)
            else:
                # Fall back to default credentials
                self._client = bigquery.Client(project=project)

        return self._client

    def query_events(
        self,
        repo: str | None = None,
        actor: str | None = None,
        event_type: str | None = None,
        from_date: str = "",
        to_date: str | None = None,
    ) -> list[dict[str, Any]]:
        """Query GH Archive for events."""
        client = self._get_client()

        # Build table reference - use daily table
        # from_date is YYYYMMDDHHMM format (12 digits), extract day part
        day = from_date[:8]
        table = f"`githubarchive.day.{day}`"

        # Build WHERE clauses
        clauses = []

        # Filter by hour and minute using created_at timestamp
        hour = int(from_date[8:10])
        minute = int(from_date[10:12])
        clauses.append(f"EXTRACT(HOUR FROM created_at) = {hour}")
        clauses.append(f"EXTRACT(MINUTE FROM created_at) = {minute}")

        if repo:
            clauses.append(f"repo.name = '{repo}'")
        if actor:
            clauses.append(f"actor.login = '{actor}'")
        if event_type:
            clauses.append(f"type = '{event_type}'")

        where = " AND ".join(clauses) if clauses else "1=1"

        query = f"""
        SELECT
            type,
            created_at,
            actor.login as actor_login,
            actor.id as actor_id,
            repo.name as repo_name,
            repo.id as repo_id,
            payload
        FROM {table}
        WHERE {where}
        ORDER BY created_at
        LIMIT 1000
        """

        results = client.query(query)
        return [dict(row) for row in results]


class GitClient:
    """Client for local git operations."""

    def __init__(self, repo_path: str = "."):
        self.repo_path = repo_path

    @property
    def source(self) -> EvidenceSource:
        return EvidenceSource.GIT

    def _run(self, *args: str) -> str:
        result = subprocess.run(
            ["git", "-C", self.repo_path, *args],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()

    def get_commit(self, sha: str) -> dict[str, Any]:
        """Get commit info from local git."""
        format_str = "%H%n%an%n%ae%n%aI%n%cn%n%ce%n%cI%n%P%n%B"
        output = self._run("show", "-s", f"--format={format_str}", sha)
        lines = output.split("\n")

        return {
            "sha": lines[0],
            "author_name": lines[1],
            "author_email": lines[2],
            "author_date": lines[3],
            "committer_name": lines[4],
            "committer_email": lines[5],
            "committer_date": lines[6],
            "parents": lines[7].split() if lines[7] else [],
            "message": "\n".join(lines[8:]),
        }

    def get_commit_files(self, sha: str) -> list[dict[str, Any]]:
        """Get files changed in a commit."""
        output = self._run("diff-tree", "--no-commit-id", "--name-status", "-r", sha)
        files = []
        for line in output.split("\n"):
            if line:
                parts = line.split("\t")
                status_map = {"A": "added", "M": "modified", "D": "removed", "R": "renamed"}
                files.append({"status": status_map.get(parts[0][0], "modified"), "filename": parts[-1]})
        return files

    def get_log(
        self,
        ref: str = "HEAD",
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get commit log."""
        args = ["log", f"--max-count={limit}", "--format=%H|%an|%ae|%aI|%s", ref]
        if since:
            args.append(f"--since={since}")
        if until:
            args.append(f"--until={until}")

        output = self._run(*args)
        commits = []
        for line in output.split("\n"):
            if line:
                parts = line.split("|", 4)
                commits.append(
                    {
                        "sha": parts[0],
                        "author_name": parts[1],
                        "author_email": parts[2],
                        "author_date": parts[3],
                        "message": parts[4] if len(parts) > 4 else "",
                    }
                )
        return commits
