"""
GH Archive Event Parsers.

Functions for parsing GH Archive BigQuery rows into Evidence objects.
Each parser extracts structured data from raw GH Archive JSON payloads.

These are the same functions as in _creation.py but extracted here for:
1. Better testability (unit test parsers in isolation)
2. Clearer separation of concerns
3. Easier maintenance

The original functions in _creation.py are kept for backward compatibility.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from ._schema import (
    CommitInPush,
    CreateEvent,
    EvidenceSource,
    ForkEvent,
    GitHubActor,
    GitHubRepository,
    IssueAction,
    IssueCommentEvent,
    IssueEvent,
    PRAction,
    PullRequestEvent,
    PushEvent,
    RefType,
    VerificationInfo,
    WatchEvent,
)


def _parse_datetime(dt_str: Any) -> datetime:
    """Parse datetime from various formats."""
    if dt_str is None:
        return datetime.now(timezone.utc)
    if isinstance(dt_str, datetime):
        return dt_str

    # Handle string formats
    if isinstance(dt_str, str):
        # ISO format with Z
        if dt_str.endswith("Z"):
            dt_str = dt_str[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(dt_str)
        except ValueError:
            pass

        # Try common formats
        formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S %Z",
            "%Y-%m-%d %H:%M:%S",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(dt_str, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue

    return datetime.now(timezone.utc)


def _generate_evidence_id(prefix: str, *parts: str) -> str:
    """Generate a deterministic evidence ID."""
    content = ":".join(parts)
    hash_val = hashlib.sha256(content.encode()).hexdigest()[:12]
    return f"{prefix}-{hash_val}"


def _make_actor(login: str, actor_id: int | None = None) -> GitHubActor:
    """Create GitHubActor from components."""
    return GitHubActor(login=login, id=actor_id)


def _make_repo(repo_name: str) -> GitHubRepository:
    """Create GitHubRepository from full name."""
    parts = repo_name.split("/", 1)
    if len(parts) == 2:
        return GitHubRepository(owner=parts[0], name=parts[1], full_name=repo_name)
    return GitHubRepository(owner="unknown", name=repo_name, full_name=repo_name)


class _RowContext:
    """Extracted common data from a GH Archive row."""

    __slots__ = ("row", "payload", "when", "who", "repository", "verification")

    def __init__(self, row: dict[str, Any]):
        self.row = row
        self.payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
        self.when = _parse_datetime(row.get("created_at"))
        self.who = _make_actor(row.get("actor_login", "unknown"), row.get("actor_id"))
        self.repository = _make_repo(row.get("repo_name", "unknown/unknown"))
        self.verification = VerificationInfo(
            source=EvidenceSource.GHARCHIVE,
            bigquery_table="githubarchive.day.*",
        )


# =============================================================================
# EVENT PARSERS
# =============================================================================


def parse_push_event(row: dict[str, Any]) -> PushEvent:
    """Parse GH Archive PushEvent into PushEvent evidence."""
    ctx = _RowContext(row)
    payload = ctx.payload

    commits = []
    for c in payload.get("commits", []):
        author = c.get("author", {})
        commits.append(
            CommitInPush(
                sha=c.get("sha", ""),
                message=c.get("message", ""),
                author_name=author.get("name", ""),
                author_email=author.get("email", ""),
            )
        )

    before_sha = payload.get("before", "0" * 40)
    after_sha = payload.get("head", payload.get("after", "0" * 40))
    size = int(payload.get("size", len(commits)))
    is_force_push = size == 0 and before_sha != "0" * 40
    ref = payload.get("ref", "")

    return PushEvent(
        evidence_id=_generate_evidence_id("push", ctx.repository.full_name, after_sha),
        when=ctx.when,
        who=ctx.who,
        what=f"Pushed {size} commit(s) to {ref}",
        repository=ctx.repository,
        verification=VerificationInfo(
            source=EvidenceSource.GHARCHIVE,
            bigquery_table="githubarchive.day.*",
            query=f"actor.login='{ctx.who.login}' AND repo.name='{ctx.repository.full_name}'",
        ),
        ref=ref,
        before_sha=before_sha,
        after_sha=after_sha,
        size=size,
        commits=commits,
        is_force_push=is_force_push,
    )


def parse_issue_event(row: dict[str, Any]) -> IssueEvent:
    """Parse GH Archive IssuesEvent into IssueEvent evidence."""
    ctx = _RowContext(row)
    issue = ctx.payload.get("issue", {})

    action_str = ctx.payload.get("action", "opened")
    action_map = {
        "opened": IssueAction.OPENED,
        "closed": IssueAction.CLOSED,
        "reopened": IssueAction.REOPENED,
        "deleted": IssueAction.DELETED,
    }
    action = action_map.get(action_str, IssueAction.OPENED)
    issue_number = issue.get("number", 0)

    return IssueEvent(
        evidence_id=_generate_evidence_id("issue", ctx.repository.full_name, str(issue_number), action_str),
        when=ctx.when,
        who=ctx.who,
        what=f"Issue #{issue_number} {action_str}",
        repository=ctx.repository,
        verification=ctx.verification,
        action=action,
        issue_number=issue_number,
        issue_title=issue.get("title", ""),
        issue_body=issue.get("body"),
    )


def parse_create_event(row: dict[str, Any]) -> CreateEvent:
    """Parse GH Archive CreateEvent into CreateEvent evidence."""
    ctx = _RowContext(row)

    ref_type_str = ctx.payload.get("ref_type", "branch")
    ref_type_map = {"branch": RefType.BRANCH, "tag": RefType.TAG, "repository": RefType.REPOSITORY}
    ref_type = ref_type_map.get(ref_type_str, RefType.BRANCH)
    ref_name = ctx.payload.get("ref", "")

    return CreateEvent(
        evidence_id=_generate_evidence_id("create", ctx.repository.full_name, ref_type_str, ref_name),
        when=ctx.when,
        who=ctx.who,
        what=f"Created {ref_type_str} '{ref_name}'",
        repository=ctx.repository,
        verification=ctx.verification,
        ref_type=ref_type,
        ref_name=ref_name,
    )


def parse_pull_request_event(row: dict[str, Any]) -> PullRequestEvent:
    """Parse GH Archive PullRequestEvent into PullRequestEvent evidence."""
    ctx = _RowContext(row)
    pr = ctx.payload.get("pull_request", {})

    action_str = ctx.payload.get("action", "opened")
    action_map = {"opened": PRAction.OPENED, "closed": PRAction.CLOSED, "reopened": PRAction.REOPENED}
    action = action_map.get(action_str, PRAction.OPENED)
    if action_str == "closed" and pr.get("merged"):
        action = PRAction.MERGED

    pr_number = pr.get("number", 0)

    return PullRequestEvent(
        evidence_id=_generate_evidence_id("pr", ctx.repository.full_name, str(pr_number), action_str),
        when=ctx.when,
        who=ctx.who,
        what=f"PR #{pr_number} {action_str}",
        repository=ctx.repository,
        verification=ctx.verification,
        action=action,
        pr_number=pr_number,
        pr_title=pr.get("title", ""),
        pr_body=pr.get("body"),
        head_sha=pr.get("head", {}).get("sha"),
        merged=pr.get("merged", False),
    )


def parse_issue_comment_event(row: dict[str, Any]) -> IssueCommentEvent:
    """Parse GH Archive IssueCommentEvent into IssueCommentEvent evidence."""
    ctx = _RowContext(row)
    issue = ctx.payload.get("issue", {})
    comment = ctx.payload.get("comment", {})
    comment_id = comment.get("id", 0)

    return IssueCommentEvent(
        evidence_id=_generate_evidence_id("comment", ctx.repository.full_name, str(comment_id)),
        when=ctx.when,
        who=ctx.who,
        what=f"Comment on issue #{issue.get('number')}",
        repository=ctx.repository,
        verification=ctx.verification,
        action=ctx.payload.get("action", "created"),
        issue_number=issue.get("number", 0),
        comment_id=comment_id,
        comment_body=comment.get("body", ""),
    )


def parse_watch_event(row: dict[str, Any]) -> WatchEvent:
    """Parse GH Archive WatchEvent into WatchEvent evidence."""
    ctx = _RowContext(row)
    action = ctx.payload.get("action", "started")

    return WatchEvent(
        evidence_id=_generate_evidence_id("watch", ctx.repository.full_name, ctx.who.login),
        when=ctx.when,
        who=ctx.who,
        what=f"User {ctx.who.login} starred repository",
        repository=ctx.repository,
        verification=ctx.verification,
        action=action,
    )


def parse_fork_event(row: dict[str, Any]) -> ForkEvent:
    """Parse GH Archive ForkEvent into ForkEvent evidence."""
    ctx = _RowContext(row)
    forkee = ctx.payload.get("forkee", {})
    fork_full_name = forkee.get("full_name", f"{ctx.who.login}/{ctx.repository.name}")

    return ForkEvent(
        evidence_id=_generate_evidence_id("fork", ctx.repository.full_name, fork_full_name),
        when=ctx.when,
        who=ctx.who,
        what=f"Forked to {fork_full_name}",
        repository=ctx.repository,
        verification=ctx.verification,
        forkee_full_name=fork_full_name,
    )


# =============================================================================
# DISPATCHER
# =============================================================================

_PARSERS = {
    "PushEvent": parse_push_event,
    "IssuesEvent": parse_issue_event,
    "CreateEvent": parse_create_event,
    "PullRequestEvent": parse_pull_request_event,
    "IssueCommentEvent": parse_issue_comment_event,
    "WatchEvent": parse_watch_event,
    "ForkEvent": parse_fork_event,
}


def parse_gharchive_event(row: dict[str, Any]) -> Any:
    """Parse any GH Archive event by dispatching to appropriate parser."""
    event_type = row.get("type", "")
    parser = _PARSERS.get(event_type)
    if parser is None:
        supported = ", ".join(_PARSERS.keys())
        raise ValueError(f"Unsupported GH Archive event type: {event_type}. Supported: {supported}")
    return parser(row)
