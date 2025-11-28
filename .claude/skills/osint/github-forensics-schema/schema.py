"""
GitHub Forensics Verifiable Evidence Schema

Strictly defines verifiable GitHub forensic evidence that can be confirmed
through public sources: GitHub API, GH Archive (BigQuery), Git, and Wayback Machine.

All evidence types are designed to be independently verifiable - no guesses.

EVIDENCE CATEGORIES:
1. GitHub Archive Events - Real-time events recorded in BigQuery (PushEvent contains commits)
2. GitHub API Observations - Point-in-time queries to GitHub API
3. Wayback Snapshots - Point-in-time archived web pages
4. Git Observations - Local git repository queries

Every piece of evidence answers: WHEN, WHO, WHAT
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, Field, HttpUrl


# =============================================================================
# ENUMS - Evidence Sources and Types
# =============================================================================


class EvidenceSource(str, Enum):
    """Source from which evidence was obtained and can be verified."""

    GITHUB_API = "github_api"  # GitHub REST/GraphQL API (point-in-time observation)
    GITHUB_WEB = "github_web"  # GitHub web interface (commit pages, etc.)
    GHARCHIVE = "gharchive"  # GH Archive via BigQuery (immutable event stream)
    WAYBACK = "wayback"  # Internet Archive Wayback Machine (point-in-time snapshot)
    GIT_LOCAL = "git_local"  # Local git repository operations


class EventType(str, Enum):
    """GitHub event types as recorded in GH Archive."""

    PUSH = "PushEvent"
    PULL_REQUEST = "PullRequestEvent"
    PULL_REQUEST_REVIEW = "PullRequestReviewEvent"
    PULL_REQUEST_REVIEW_COMMENT = "PullRequestReviewCommentEvent"
    ISSUES = "IssuesEvent"
    ISSUE_COMMENT = "IssueCommentEvent"
    CREATE = "CreateEvent"
    DELETE = "DeleteEvent"
    FORK = "ForkEvent"
    WATCH = "WatchEvent"
    RELEASE = "ReleaseEvent"
    MEMBER = "MemberEvent"
    PUBLIC = "PublicEvent"
    WORKFLOW_RUN = "WorkflowRunEvent"
    WORKFLOW_JOB = "WorkflowJobEvent"
    CHECK_RUN = "CheckRunEvent"
    CHECK_SUITE = "CheckSuiteEvent"


class RefType(str, Enum):
    """Git reference types for create/delete events."""

    BRANCH = "branch"
    TAG = "tag"
    REPOSITORY = "repository"


class PRAction(str, Enum):
    """Pull request actions."""

    OPENED = "opened"
    CLOSED = "closed"
    REOPENED = "reopened"
    EDITED = "edited"
    ASSIGNED = "assigned"
    UNASSIGNED = "unassigned"
    LABELED = "labeled"
    UNLABELED = "unlabeled"
    SYNCHRONIZE = "synchronize"
    REVIEW_REQUESTED = "review_requested"


class IssueAction(str, Enum):
    """Issue actions."""

    OPENED = "opened"
    CLOSED = "closed"
    REOPENED = "reopened"
    EDITED = "edited"
    ASSIGNED = "assigned"
    UNASSIGNED = "unassigned"
    LABELED = "labeled"
    UNLABELED = "unlabeled"
    TRANSFERRED = "transferred"
    DELETED = "deleted"


class WorkflowConclusion(str, Enum):
    """Workflow run conclusions."""

    SUCCESS = "success"
    FAILURE = "failure"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"
    TIMED_OUT = "timed_out"
    ACTION_REQUIRED = "action_required"
    NEUTRAL = "neutral"
    STALE = "stale"


# =============================================================================
# BASE MODELS - Common Fields
# =============================================================================


class VerificationInfo(BaseModel):
    """Information required to independently verify evidence."""

    source: EvidenceSource = Field(
        ..., description="Primary source for verification"
    )
    verified_at: datetime | None = Field(
        default=None, description="When this evidence was verified"
    )
    verification_url: HttpUrl | None = Field(
        default=None, description="Direct URL to verify this evidence"
    )
    bigquery_table: str | None = Field(
        default=None,
        description="BigQuery table for GH Archive verification (e.g., githubarchive.day.20250713)",
    )
    verification_query: str | None = Field(
        default=None, description="SQL query to reproduce GH Archive evidence"
    )


class GitHubActor(BaseModel):
    """GitHub user/actor information - the WHO."""

    login: str = Field(..., description="GitHub username")
    id: int | None = Field(default=None, description="GitHub user ID (stable)")
    avatar_url: HttpUrl | None = Field(default=None, description="Avatar URL")
    is_bot: bool = Field(
        default=False, description="Whether this is a bot/automation account"
    )


class GitHubRepository(BaseModel):
    """GitHub repository reference - part of WHERE/WHAT."""

    owner: str = Field(..., description="Repository owner (user or org)")
    name: str = Field(..., description="Repository name")
    full_name: str = Field(..., description="Full name (owner/name)")
    id: int | None = Field(default=None, description="GitHub repository ID")
    is_fork: bool = Field(default=False, description="Whether this is a fork")
    parent_full_name: str | None = Field(
        default=None, description="Parent repo if this is a fork"
    )


class EvidenceBase(BaseModel):
    """
    Base class for all verifiable evidence.

    Every evidence piece MUST answer:
    - WHEN: timestamp of the event/observation
    - WHO: actor who performed the action (where applicable)
    - WHAT: description of what happened
    """

    evidence_id: str = Field(
        ..., description="Unique identifier for this evidence piece"
    )

    # WHEN - temporal anchor
    when: datetime = Field(
        ..., description="When this event occurred or observation was made (UTC)"
    )

    # WHAT - summary of the evidence
    what: str = Field(
        ..., description="Brief description of what this evidence shows"
    )

    # Verification
    verification: VerificationInfo = Field(
        ..., description="How to verify this evidence"
    )

    notes: str | None = Field(
        default=None, description="Investigator notes on this evidence"
    )


# =============================================================================
# GITHUB ARCHIVE EVENTS - Immutable event stream from BigQuery
#
# These are EVENTS - something happened at a specific time.
# Commits are delivered via PushEvent, not as separate events.
# =============================================================================


class GitHubEventBase(EvidenceBase):
    """
    Base class for all GH Archive events.

    Events are immutable records from GitHub's event stream.
    All events have: WHEN (created_at), WHO (actor), WHAT (type + payload)
    """

    # WHO performed the action
    actor: GitHubActor = Field(..., description="Who performed this action")

    # WHERE it happened
    repository: GitHubRepository = Field(..., description="Target repository")


class PushEventCommit(BaseModel):
    """
    Individual commit within a PushEvent.

    NOTE: This is NOT a separate event - commits come embedded in PushEvents.
    To get full commit details, use GitHub API with the SHA.
    """

    sha: str = Field(..., description="Commit SHA (use to fetch full details via API)")
    message: str = Field(..., description="Commit message")
    author_name: str = Field(..., description="Author name from git")
    author_email: str = Field(..., description="Author email from git")
    distinct: bool = Field(
        default=True, description="Whether commit is distinct to this push"
    )


class PushEvent(GitHubEventBase):
    """
    PushEvent from GH Archive - someone pushed commits to a repository.

    WHEN: created_at timestamp
    WHO: actor.login (the pusher)
    WHAT: Pushed N commits to {ref}, moving from {before} to {after}

    IMPORTANT: Commits are embedded here, not separate events.
    Force pushes have size=0 and empty commits array.

    Verifiable via BigQuery:
    SELECT * FROM `githubarchive.day.YYYYMMDD`
    WHERE type = 'PushEvent' AND repo.name = '{repo}'
    """

    evidence_type: Literal["push_event"] = "push_event"

    # WHAT happened
    ref: str = Field(..., description="Git ref pushed to (e.g., refs/heads/main)")
    before_sha: str = Field(
        ..., description="SHA before push - use to detect force-pushed commits"
    )
    after_sha: str = Field(..., description="SHA after push (new HEAD)")
    size: int = Field(..., description="Number of commits in push (0 = force push)")
    commits: list[PushEventCommit] = Field(
        default_factory=list,
        description="Commits in this push (empty for force push)"
    )
    is_force_push: bool = Field(
        default=False,
        description="True if size=0, indicating history was rewritten",
    )


class PullRequestEvent(GitHubEventBase):
    """
    PullRequestEvent from GH Archive - PR opened, closed, merged, etc.

    WHEN: created_at timestamp
    WHO: actor.login (who performed the action)
    WHAT: {action} PR #{number} "{title}"

    Recovers deleted PRs including title, body, and merge status.
    """

    evidence_type: Literal["pull_request_event"] = "pull_request_event"

    # WHAT happened
    action: PRAction = Field(..., description="What happened to the PR")
    pr_number: int = Field(..., description="Pull request number")
    pr_title: str = Field(..., description="PR title")
    pr_body: str | None = Field(default=None, description="PR body/description")
    head_sha: str | None = Field(default=None, description="Head commit SHA")
    base_sha: str | None = Field(default=None, description="Base commit SHA")
    head_ref: str | None = Field(default=None, description="Head branch name")
    base_ref: str | None = Field(default=None, description="Base branch name")
    merged: bool = Field(default=False, description="Whether PR was merged")
    merged_by: GitHubActor | None = Field(
        default=None, description="Who merged the PR"
    )
    merge_commit_sha: str | None = Field(
        default=None, description="Merge commit SHA if merged"
    )

    # Recovery metadata
    is_deleted_from_github: bool = Field(
        default=False,
        description="PR no longer exists on GitHub (recovered from archive)",
    )


class IssueEvent(GitHubEventBase):
    """
    IssuesEvent from GH Archive - issue opened, closed, etc.

    WHEN: created_at timestamp
    WHO: actor.login (who performed the action)
    WHAT: {action} issue #{number} "{title}"

    Recovers deleted issues including title and body text.
    """

    evidence_type: Literal["issue_event"] = "issue_event"

    # WHAT happened
    action: IssueAction = Field(..., description="What happened to the issue")
    issue_number: int = Field(..., description="Issue number")
    issue_title: str = Field(..., description="Issue title")
    issue_body: str | None = Field(default=None, description="Issue body text")
    labels: list[str] = Field(default_factory=list, description="Issue labels")

    # Recovery metadata
    is_deleted_from_github: bool = Field(
        default=False,
        description="Issue no longer exists on GitHub (recovered from archive)",
    )


class IssueCommentEvent(GitHubEventBase):
    """
    IssueCommentEvent from GH Archive - comment on issue or PR.

    WHEN: created_at timestamp
    WHO: actor.login (comment author)
    WHAT: {action} comment on #{issue_number}

    Preserves comment text even if deleted from GitHub.
    """

    evidence_type: Literal["issue_comment_event"] = "issue_comment_event"

    # WHAT happened
    action: Literal["created", "edited", "deleted"] = Field(
        ..., description="What happened to the comment"
    )
    issue_number: int = Field(..., description="Parent issue/PR number")
    comment_id: int = Field(..., description="Comment ID")
    comment_body: str = Field(..., description="Comment text content")
    is_on_pull_request: bool = Field(
        default=False, description="Whether comment is on a PR vs issue"
    )


class CreateEvent(GitHubEventBase):
    """
    CreateEvent from GH Archive - branch, tag, or repository created.

    WHEN: created_at timestamp
    WHO: actor.login (creator)
    WHAT: Created {ref_type} "{ref_name}"
    """

    evidence_type: Literal["create_event"] = "create_event"

    # WHAT was created
    ref_type: RefType = Field(..., description="Type: branch, tag, or repository")
    ref_name: str = Field(..., description="Name of the branch/tag")
    default_branch: str | None = Field(
        default=None, description="Default branch (for repository creation)"
    )


class DeleteEvent(GitHubEventBase):
    """
    DeleteEvent from GH Archive - branch or tag deleted.

    WHEN: created_at timestamp
    WHO: actor.login (deleter)
    WHAT: Deleted {ref_type} "{ref_name}"
    """

    evidence_type: Literal["delete_event"] = "delete_event"

    # WHAT was deleted
    ref_type: RefType = Field(..., description="Type: branch or tag")
    ref_name: str = Field(..., description="Name of the deleted branch/tag")


class ForkEvent(GitHubEventBase):
    """
    ForkEvent from GH Archive - repository forked.

    WHEN: created_at timestamp
    WHO: actor.login (forker)
    WHAT: Forked {source} to {fork}

    Records fork relationships even after parent/fork deletion.
    """

    evidence_type: Literal["fork_event"] = "fork_event"

    # WHAT happened (repository field is the source)
    fork_repository: GitHubRepository = Field(
        ..., description="Newly created fork"
    )


class WorkflowRunEvent(GitHubEventBase):
    """
    WorkflowRunEvent from GH Archive - GitHub Actions workflow execution.

    WHEN: created_at timestamp
    WHO: actor.login (triggering user/bot)
    WHAT: Workflow "{name}" {action} on {head_sha}

    CRITICAL for distinguishing legitimate workflow execution
    from direct API abuse with stolen tokens. Absence of WorkflowRunEvent
    during a suspicious commit = direct API attack, not workflow.
    """

    evidence_type: Literal["workflow_run_event"] = "workflow_run_event"

    # WHAT happened
    action: Literal["requested", "completed", "in_progress"] = Field(
        ..., description="Workflow run lifecycle stage"
    )
    workflow_name: str = Field(..., description="Workflow name")
    workflow_path: str | None = Field(
        default=None, description="Path to workflow file (.github/workflows/...)"
    )
    head_sha: str = Field(..., description="Commit SHA being processed")
    head_branch: str | None = Field(default=None, description="Branch name")
    conclusion: WorkflowConclusion | None = Field(
        default=None, description="Run conclusion (for completed events)"
    )
    run_id: int | None = Field(default=None, description="Workflow run ID")


class ReleaseEvent(GitHubEventBase):
    """
    ReleaseEvent from GH Archive - release published/created/etc.

    WHEN: created_at timestamp
    WHO: actor.login (release author)
    WHAT: {action} release "{tag_name}"
    """

    evidence_type: Literal["release_event"] = "release_event"

    # WHAT happened
    action: Literal["published", "created", "edited", "deleted", "prereleased", "released"] = Field(
        ..., description="Release action"
    )
    tag_name: str = Field(..., description="Release tag name")
    release_name: str | None = Field(default=None, description="Release title")
    release_body: str | None = Field(
        default=None, description="Release description/notes"
    )
    prerelease: bool = Field(default=False, description="Whether prerelease")
    draft: bool = Field(default=False, description="Whether draft")
    target_commitish: str | None = Field(
        default=None, description="Target branch/commit"
    )


class WatchEvent(GitHubEventBase):
    """
    WatchEvent from GH Archive - repository starred.

    WHEN: created_at timestamp
    WHO: actor.login (who starred)
    WHAT: Starred {repository}

    Can indicate reconnaissance activity when correlated with other events.
    """

    evidence_type: Literal["watch_event"] = "watch_event"
    action: Literal["started"] = Field(default="started", description="Always 'started'")


class MemberEvent(GitHubEventBase):
    """
    MemberEvent from GH Archive - collaborator added/removed.

    WHEN: created_at timestamp
    WHO: actor.login (who made the change)
    WHAT: {action} member {member.login} with {permission}
    """

    evidence_type: Literal["member_event"] = "member_event"

    # WHAT happened
    action: Literal["added", "removed", "edited"] = Field(
        ..., description="Member action"
    )
    member: GitHubActor = Field(..., description="Affected member")
    permission: str | None = Field(
        default=None, description="Permission level granted"
    )


class PublicEvent(GitHubEventBase):
    """
    PublicEvent from GH Archive - repository made public.

    WHEN: created_at timestamp
    WHO: actor.login (who made it public)
    WHAT: Made {repository} public
    """

    evidence_type: Literal["public_event"] = "public_event"


# =============================================================================
# GITHUB API OBSERVATIONS - Point-in-time queries
#
# These are OBSERVATIONS - we queried the API and saw this state.
# Not events, but current/historical state retrieved on demand.
# =============================================================================


class CommitAuthor(BaseModel):
    """Git commit author/committer information."""

    name: str = Field(..., description="Name from git commit")
    email: str = Field(..., description="Email from git commit")
    date: datetime = Field(..., description="Author/commit date (UTC)")


class CommitSignature(BaseModel):
    """GPG/SSH signature verification details."""

    verified: bool = Field(..., description="Whether signature is valid")
    reason: str | None = Field(
        default=None, description="Verification reason/status"
    )
    signature: str | None = Field(default=None, description="Raw signature")
    payload: str | None = Field(default=None, description="Signed payload")


class CommitFileChange(BaseModel):
    """File changed in a commit."""

    filename: str = Field(..., description="Path to file")
    status: Literal["added", "modified", "removed", "renamed", "copied"] = Field(
        ..., description="Change type"
    )
    additions: int = Field(default=0, description="Lines added")
    deletions: int = Field(default=0, description="Lines deleted")
    patch: str | None = Field(
        default=None, description="Unified diff patch for this file"
    )
    previous_filename: str | None = Field(
        default=None, description="Previous filename if renamed"
    )


class CommitObservation(EvidenceBase):
    """
    Observation of a commit via GitHub API, web, or git.

    NOT an event - commits are delivered via PushEvent in GH Archive.
    This is for when you query a specific commit directly.

    WHEN: when the commit was authored (author.date)
    WHO: author (wrote code) and committer (created commit object)
    WHAT: Commit {sha} with message "{message}"

    Verifiable via:
    - GitHub API: GET /repos/{owner}/{repo}/commits/{sha}
    - GitHub Web: https://github.com/{owner}/{repo}/commit/{sha}
    - GitHub Patch: https://github.com/{owner}/{repo}/commit/{sha}.patch
    - Git: git show {sha}
    """

    evidence_type: Literal["commit_observation"] = "commit_observation"

    # WHERE
    repository: GitHubRepository = Field(..., description="Repository containing commit")

    # WHAT - the commit itself
    sha: Annotated[str, Field(min_length=40, max_length=40)] = Field(
        ..., description="Full 40-character commit SHA"
    )
    short_sha: Annotated[str, Field(min_length=7, max_length=8)] = Field(
        ..., description="Short SHA (7-8 chars)"
    )
    message: str = Field(..., description="Full commit message")

    # WHO
    author: CommitAuthor = Field(..., description="Who wrote the code")
    committer: CommitAuthor = Field(..., description="Who created the commit object")

    # Additional details
    signature: CommitSignature | None = Field(
        default=None, description="Signature verification if signed"
    )
    parents: list[str] = Field(
        default_factory=list, description="Parent commit SHAs"
    )
    files: list[CommitFileChange] = Field(
        default_factory=list, description="Files changed in this commit"
    )
    is_merge: bool = Field(
        default=False, description="Whether this is a merge commit"
    )

    # Recovery context
    is_dangling: bool = Field(
        default=False,
        description="Commit is not on any branch (orphaned/force-pushed)",
    )
    recovered_via: Literal["api", "web", "patch", "git_fetch"] | None = Field(
        default=None, description="How this orphaned commit was accessed"
    )


class ForcesPushedCommitReference(EvidenceBase):
    """
    Reference to a commit that was force-pushed over.

    Derived from PushEvent with size=0 in GH Archive.
    The before_sha points to a commit that's no longer on any branch
    but remains accessible on GitHub.

    WHEN: when the force push occurred
    WHO: pusher (actor from PushEvent)
    WHAT: Force push replaced {deleted_sha} with {replaced_by_sha} on {branch}
    """

    evidence_type: Literal["force_pushed_commit_ref"] = "force_pushed_commit_ref"

    # WHERE
    repository: GitHubRepository = Field(..., description="Repository")

    # WHO
    pusher: GitHubActor = Field(..., description="Who performed the force push")

    # WHAT
    branch: str = Field(..., description="Branch that was force-pushed")
    deleted_sha: Annotated[str, Field(min_length=40, max_length=40)] = Field(
        ..., description="SHA of the overwritten commit (from PushEvent.before)"
    )
    replaced_by_sha: Annotated[str, Field(min_length=40, max_length=40)] = Field(
        ..., description="SHA that replaced it (from PushEvent.after)"
    )

    # Recovery status
    source_push_event_id: str | None = Field(
        default=None, description="ID of the PushEvent this was derived from"
    )
    commit_recovered: bool = Field(
        default=False, description="Whether full commit was fetched via API"
    )
    recovered_commit: CommitObservation | None = Field(
        default=None, description="Full commit details if recovered"
    )


# =============================================================================
# WAYBACK MACHINE SNAPSHOTS - Point-in-time archived web pages
#
# These are SNAPSHOTS - the Wayback Machine crawled a URL at time T
# and captured what it saw. Not events, but frozen observations.
# =============================================================================


class WaybackSnapshot(BaseModel):
    """
    A single Wayback Machine snapshot - a frozen observation of a URL.

    WHEN: timestamp (archive capture time, not content time)
    WHAT: The URL content as it appeared at capture time
    """

    timestamp: str = Field(
        ..., description="Archive timestamp (YYYYMMDDHHMMSS)"
    )
    captured_at: datetime = Field(
        ..., description="When Wayback Machine captured this (parsed from timestamp)"
    )
    original_url: HttpUrl = Field(..., description="Original URL that was archived")
    archive_url: HttpUrl = Field(
        ..., description="Full archive.org URL to access snapshot"
    )
    status_code: int = Field(..., description="HTTP status code at capture time")
    mime_type: str | None = Field(default=None, description="Content MIME type")
    digest: str | None = Field(default=None, description="Content digest/hash")


class WaybackObservation(EvidenceBase):
    """
    Collection of Wayback snapshots for a GitHub URL.

    WHEN: range of capture times (earliest to latest)
    WHAT: Archived snapshots of {content_type} at {original_url}

    Verifiable via CDX API:
    https://web.archive.org/cdx/search/cdx?url={url}&output=json
    """

    evidence_type: Literal["wayback_observation"] = "wayback_observation"

    # WHERE (if applicable)
    repository: GitHubRepository | None = Field(
        default=None, description="Associated repository if applicable"
    )

    # WHAT was observed
    content_type: Literal[
        "repository_homepage",
        "issue",
        "pull_request",
        "wiki",
        "file_blob",
        "directory_tree",
        "commits_list",
        "release",
        "network_members",
        "user_profile",
        "other",
    ] = Field(..., description="Type of GitHub content archived")

    original_url: HttpUrl = Field(..., description="The URL being tracked")

    # Snapshot data
    snapshots: list[WaybackSnapshot] = Field(
        ..., description="All available snapshots"
    )
    latest_snapshot: WaybackSnapshot = Field(
        ..., description="Most recent snapshot"
    )
    earliest_snapshot: WaybackSnapshot = Field(
        ..., description="Earliest snapshot"
    )
    total_snapshots: int = Field(..., description="Total snapshot count")


class RecoveredIssueContent(EvidenceBase):
    """
    Issue/PR content recovered from Wayback snapshot.

    WHEN: snapshot capture time
    WHO: author_login (from parsed page)
    WHAT: Recovered content of issue/PR #{number}

    Use when content no longer exists on GitHub or GH Archive.
    """

    evidence_type: Literal["recovered_issue_content"] = "recovered_issue_content"

    # WHERE
    repository: GitHubRepository = Field(..., description="Repository")

    # WHAT was recovered
    issue_number: int = Field(..., description="Issue/PR number")
    is_pull_request: bool = Field(default=False, description="PR vs issue")
    title: str | None = Field(default=None, description="Recovered title")
    body: str | None = Field(default=None, description="Recovered body text")

    # WHO (from parsed content)
    author_login: str | None = Field(default=None, description="Author username")

    # Additional recovered data
    comments: list[str] = Field(
        default_factory=list, description="Recovered comment texts"
    )
    labels: list[str] = Field(default_factory=list, description="Labels")
    state: Literal["open", "closed", "merged", "unknown"] | None = Field(
        default=None, description="State at snapshot time"
    )

    # Source
    source_snapshot: WaybackSnapshot = Field(
        ..., description="Wayback snapshot this was extracted from"
    )


class RecoveredFileContent(EvidenceBase):
    """
    File content recovered from Wayback snapshot.

    WHEN: snapshot capture time
    WHAT: Content of {file_path} as of snapshot time

    Use when repository is deleted but files were archived.
    """

    evidence_type: Literal["recovered_file_content"] = "recovered_file_content"

    # WHERE
    repository: GitHubRepository = Field(..., description="Repository")

    # WHAT was recovered
    file_path: str = Field(..., description="Path to file in repository")
    branch: str | None = Field(default=None, description="Branch name if known")
    content: str = Field(..., description="Recovered file content")
    content_hash: str | None = Field(
        default=None, description="SHA256 hash of recovered content"
    )

    # Source
    source_snapshot: WaybackSnapshot = Field(
        ..., description="Wayback snapshot this was extracted from"
    )


class RecoveredWikiContent(EvidenceBase):
    """
    Wiki page content recovered from Wayback snapshot.

    WHEN: snapshot capture time
    WHAT: Content of wiki page "{page_name}"
    """

    evidence_type: Literal["recovered_wiki_content"] = "recovered_wiki_content"

    # WHERE
    repository: GitHubRepository = Field(..., description="Repository")

    # WHAT was recovered
    page_name: str = Field(..., description="Wiki page name")
    content: str = Field(..., description="Recovered wiki content")

    # Source
    source_snapshot: WaybackSnapshot = Field(
        ..., description="Wayback snapshot this was extracted from"
    )


class RecoveredForkList(EvidenceBase):
    """
    Fork list recovered from archived network/members page.

    WHEN: snapshot capture time
    WHAT: List of forks as of snapshot time

    Useful for finding surviving forks of deleted repositories.
    """

    evidence_type: Literal["recovered_fork_list"] = "recovered_fork_list"

    # WHERE
    repository: GitHubRepository = Field(
        ..., description="Parent repository (possibly deleted)"
    )

    # WHAT was recovered
    forks: list[str] = Field(..., description="Fork full names (owner/repo)")
    forks_verified_existing: list[str] = Field(
        default_factory=list,
        description="Forks confirmed to still exist on GitHub",
    )

    # Source
    source_snapshot: WaybackSnapshot = Field(
        ..., description="Wayback snapshot this was extracted from"
    )


# =============================================================================
# TIMELINE & INVESTIGATION CONTAINERS
# =============================================================================


# Type alias for GH Archive events
GitHubArchiveEvent = (
    PushEvent
    | PullRequestEvent
    | IssueEvent
    | IssueCommentEvent
    | CreateEvent
    | DeleteEvent
    | ForkEvent
    | WorkflowRunEvent
    | ReleaseEvent
    | WatchEvent
    | MemberEvent
    | PublicEvent
)

# Type alias for observations (point-in-time queries)
Observation = (
    CommitObservation
    | ForcesPushedCommitReference
    | WaybackObservation
    | RecoveredIssueContent
    | RecoveredFileContent
    | RecoveredWikiContent
    | RecoveredForkList
)

# All evidence types
AnyEvidence = GitHubArchiveEvent | Observation


class TimelineEntry(BaseModel):
    """
    A single entry in an investigation timeline.

    Links evidence to chronological sequence with analysis.
    """

    timestamp: datetime = Field(..., description="When this occurred (UTC)")
    evidence: AnyEvidence = Field(..., description="The evidence")

    # Categorization
    significance: Literal["critical", "high", "medium", "low", "info"] = Field(
        default="info", description="Importance to investigation"
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Tags (e.g., 'initial_access', 'persistence', 'exfil')",
    )

    # Analysis
    analysis_notes: str | None = Field(
        default=None, description="Investigator analysis"
    )
    related_evidence_ids: list[str] = Field(
        default_factory=list, description="IDs of related evidence"
    )


class ActorProfile(BaseModel):
    """
    Profile of an actor involved in an investigation.

    Aggregates all evidence for a specific GitHub account.
    """

    actor: GitHubActor = Field(..., description="The GitHub actor")

    # WHEN active
    first_seen: datetime = Field(..., description="Earliest activity (UTC)")
    last_seen: datetime = Field(..., description="Most recent activity (UTC)")

    # WHAT they did
    repositories_touched: list[str] = Field(
        default_factory=list, description="Repositories interacted with"
    )
    event_count: int = Field(default=0, description="Total events")
    event_types: list[EventType] = Field(
        default_factory=list, description="Types of events performed"
    )

    # Account metadata
    is_automation: bool = Field(
        default=False, description="Appears to be automation account"
    )
    account_created: datetime | None = Field(
        default=None, description="Account creation date if known"
    )
    account_deleted: bool = Field(
        default=False, description="Account is now deleted"
    )

    # Links to evidence
    evidence_ids: list[str] = Field(
        default_factory=list, description="Evidence IDs involving this actor"
    )
    notes: str | None = Field(default=None, description="Investigator notes")


class IOC(BaseModel):
    """
    Indicator of Compromise from evidence.

    Only IOCs that are verifiable from collected evidence.
    """

    ioc_type: Literal[
        "commit_sha",
        "file_path",
        "email",
        "username",
        "ip_address",
        "domain",
        "api_key_pattern",
        "secret_pattern",
        "repository",
        "tag_name",
        "branch_name",
        "workflow_name",
        "other",
    ] = Field(..., description="Type of IOC")
    value: str = Field(..., description="The IOC value")
    context: str = Field(..., description="Where this IOC was found")
    evidence_id: str = Field(..., description="Source evidence ID")
    confidence: Literal["confirmed", "high", "medium", "low"] = Field(
        default="medium", description="Confidence level"
    )
    first_seen: datetime | None = Field(default=None, description="First seen")
    last_seen: datetime | None = Field(default=None, description="Last seen")


class Investigation(BaseModel):
    """
    Complete GitHub forensics investigation container.
    """

    investigation_id: str = Field(..., description="Unique ID")
    title: str = Field(..., description="Investigation title")
    description: str = Field(..., description="Summary")
    created_at: datetime = Field(..., description="Start time")
    updated_at: datetime = Field(..., description="Last update")
    status: Literal["active", "completed", "archived"] = Field(default="active")

    # Scope
    target_repositories: list[GitHubRepository] = Field(default_factory=list)
    target_actors: list[str] = Field(default_factory=list)
    time_range_start: datetime | None = Field(default=None)
    time_range_end: datetime | None = Field(default=None)

    # Evidence
    evidence: list[AnyEvidence] = Field(default_factory=list)
    timeline: list[TimelineEntry] = Field(default_factory=list)
    actors: list[ActorProfile] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)

    # Analysis
    findings: str | None = Field(default=None)
    recommendations: list[str] = Field(default_factory=list)

    # Verification metadata
    bigquery_queries_used: list[str] = Field(default_factory=list)
    wayback_urls_checked: list[str] = Field(default_factory=list)
    github_api_calls: int = Field(default=0)
