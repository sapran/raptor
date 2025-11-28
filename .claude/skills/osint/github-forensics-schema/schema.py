"""
GitHub Forensics Verifiable Evidence Schema

Strictly defines verifiable GitHub forensic evidence.

EVIDENCE TYPES:
1. Event    - Something happened (when, who, what)
             Sources: GH Archive, git log
2. Content  - Something we found (when_found, who?, what, where_found, found_by)
             Sources: GH Archive, GitHub API, Wayback
3. IOC      - Indicator of Compromise (same as content)
             Sources: Security blogs, extracted from content

All evidence is independently verifiable - no guesses.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, Field, HttpUrl


# =============================================================================
# ENUMS
# =============================================================================


class EvidenceSource(str, Enum):
    """Where evidence was obtained from."""

    GHARCHIVE = "gharchive"  # GH Archive via BigQuery
    GIT_LOG = "git_log"  # Local git log/show
    GITHUB_API = "github_api"  # GitHub REST/GraphQL API
    GITHUB_WEB = "github_web"  # GitHub web interface
    WAYBACK = "wayback"  # Internet Archive Wayback Machine
    SECURITY_BLOG = "security_blog"  # Security research blogs/reports


class EventType(str, Enum):
    """GitHub event types from GH Archive."""

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
    """Git reference types."""

    BRANCH = "branch"
    TAG = "tag"
    REPOSITORY = "repository"


class PRAction(str, Enum):
    """Pull request actions."""

    OPENED = "opened"
    CLOSED = "closed"
    REOPENED = "reopened"
    EDITED = "edited"
    SYNCHRONIZE = "synchronize"
    MERGED = "merged"


class IssueAction(str, Enum):
    """Issue actions."""

    OPENED = "opened"
    CLOSED = "closed"
    REOPENED = "reopened"
    EDITED = "edited"
    DELETED = "deleted"


class WorkflowConclusion(str, Enum):
    """Workflow run conclusions."""

    SUCCESS = "success"
    FAILURE = "failure"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"
    TIMED_OUT = "timed_out"


class IOCType(str, Enum):
    """Types of Indicators of Compromise."""

    COMMIT_SHA = "commit_sha"
    FILE_PATH = "file_path"
    EMAIL = "email"
    USERNAME = "username"
    REPOSITORY = "repository"
    TAG_NAME = "tag_name"
    BRANCH_NAME = "branch_name"
    WORKFLOW_NAME = "workflow_name"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    API_KEY = "api_key"
    SECRET = "secret"
    URL = "url"
    OTHER = "other"


# =============================================================================
# COMMON MODELS
# =============================================================================


class GitHubActor(BaseModel):
    """GitHub user/actor - the WHO."""

    login: str = Field(..., description="GitHub username")
    id: int | None = Field(default=None, description="GitHub user ID")
    is_bot: bool = Field(default=False, description="Is automation account")


class GitHubRepository(BaseModel):
    """GitHub repository reference."""

    owner: str = Field(..., description="Repository owner")
    name: str = Field(..., description="Repository name")
    full_name: str = Field(..., description="Full name (owner/name)")
    id: int | None = Field(default=None, description="Repository ID")


class VerificationInfo(BaseModel):
    """How to independently verify this evidence."""

    source: EvidenceSource = Field(..., description="Primary source")
    url: HttpUrl | None = Field(default=None, description="Direct verification URL")
    bigquery_table: str | None = Field(
        default=None, description="GH Archive table (e.g., githubarchive.day.20250713)"
    )
    query: str | None = Field(default=None, description="SQL/API query to reproduce")
    verified_at: datetime | None = Field(default=None, description="When verified")


# =============================================================================
# EVENT - Something that happened
#
# Has: when, who, what
# Sources: GH Archive, git log
# =============================================================================


class Event(BaseModel):
    """
    Base class for events - something that happened.

    WHEN: When it happened
    WHO: Who did it
    WHAT: What they did
    """

    evidence_id: str = Field(..., description="Unique evidence ID")

    # WHEN
    when: datetime = Field(..., description="When this happened (UTC)")

    # WHO
    who: GitHubActor = Field(..., description="Who performed the action")

    # WHAT
    what: str = Field(..., description="What happened (brief description)")

    # WHERE
    repository: GitHubRepository = Field(..., description="Target repository")

    # Verification
    verification: VerificationInfo = Field(..., description="How to verify")

    notes: str | None = Field(default=None, description="Investigator notes")


# -----------------------------------------------------------------------------
# GH Archive Events
# -----------------------------------------------------------------------------


class CommitInPush(BaseModel):
    """Commit embedded in a PushEvent."""

    sha: str = Field(..., description="Commit SHA")
    message: str = Field(..., description="Commit message")
    author_name: str = Field(..., description="Author name")
    author_email: str = Field(..., description="Author email")


class PushEvent(Event):
    """
    PushEvent - someone pushed commits.

    WHEN: Push timestamp
    WHO: Pusher
    WHAT: Pushed N commits to {ref}
    """

    event_type: Literal["push"] = "push"

    ref: str = Field(..., description="Git ref (e.g., refs/heads/main)")
    before_sha: str = Field(..., description="SHA before push")
    after_sha: str = Field(..., description="SHA after push")
    size: int = Field(..., description="Number of commits (0 = force push)")
    commits: list[CommitInPush] = Field(default_factory=list)
    is_force_push: bool = Field(default=False, description="True if size=0")


class PullRequestEvent(Event):
    """PullRequestEvent - PR action occurred."""

    event_type: Literal["pull_request"] = "pull_request"

    action: PRAction = Field(..., description="PR action")
    pr_number: int = Field(..., description="PR number")
    pr_title: str = Field(..., description="PR title")
    pr_body: str | None = Field(default=None)
    head_sha: str | None = Field(default=None)
    base_ref: str | None = Field(default=None)
    merged: bool = Field(default=False)
    merge_commit_sha: str | None = Field(default=None)


class IssueEvent(Event):
    """IssuesEvent - issue action occurred."""

    event_type: Literal["issue"] = "issue"

    action: IssueAction = Field(..., description="Issue action")
    issue_number: int = Field(..., description="Issue number")
    issue_title: str = Field(..., description="Issue title")
    issue_body: str | None = Field(default=None)
    labels: list[str] = Field(default_factory=list)


class IssueCommentEvent(Event):
    """IssueCommentEvent - comment on issue/PR."""

    event_type: Literal["issue_comment"] = "issue_comment"

    action: Literal["created", "edited", "deleted"] = Field(...)
    issue_number: int = Field(..., description="Parent issue/PR number")
    comment_id: int = Field(..., description="Comment ID")
    comment_body: str = Field(..., description="Comment text")


class CreateEvent(Event):
    """CreateEvent - branch/tag/repo created."""

    event_type: Literal["create"] = "create"

    ref_type: RefType = Field(..., description="What was created")
    ref_name: str = Field(..., description="Name of branch/tag")


class DeleteEvent(Event):
    """DeleteEvent - branch/tag deleted."""

    event_type: Literal["delete"] = "delete"

    ref_type: RefType = Field(..., description="What was deleted")
    ref_name: str = Field(..., description="Name of branch/tag")


class ForkEvent(Event):
    """ForkEvent - repository forked."""

    event_type: Literal["fork"] = "fork"

    fork_full_name: str = Field(..., description="New fork (owner/repo)")


class WorkflowRunEvent(Event):
    """
    WorkflowRunEvent - GitHub Actions execution.

    CRITICAL: Absence of this during suspicious commit = direct API attack.
    """

    event_type: Literal["workflow_run"] = "workflow_run"

    action: Literal["requested", "completed", "in_progress"] = Field(...)
    workflow_name: str = Field(..., description="Workflow name")
    workflow_path: str | None = Field(default=None)
    head_sha: str = Field(..., description="Commit being processed")
    head_branch: str | None = Field(default=None)
    conclusion: WorkflowConclusion | None = Field(default=None)
    run_id: int | None = Field(default=None)


class ReleaseEvent(Event):
    """ReleaseEvent - release published."""

    event_type: Literal["release"] = "release"

    action: Literal["published", "created", "edited", "deleted"] = Field(...)
    tag_name: str = Field(..., description="Release tag")
    release_name: str | None = Field(default=None)
    release_body: str | None = Field(default=None)
    prerelease: bool = Field(default=False)


class WatchEvent(Event):
    """WatchEvent - repo starred (recon indicator)."""

    event_type: Literal["watch"] = "watch"


class MemberEvent(Event):
    """MemberEvent - collaborator added/removed."""

    event_type: Literal["member"] = "member"

    action: Literal["added", "removed"] = Field(...)
    member: GitHubActor = Field(..., description="Affected member")
    permission: str | None = Field(default=None)


class PublicEvent(Event):
    """PublicEvent - repo made public."""

    event_type: Literal["public"] = "public"


# Type alias for all events
AnyEvent = (
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


# =============================================================================
# CONTENT - Something we found/recovered
#
# Has: when_found, who (optional), what, where_found, found_by
# Sources: GH Archive, GitHub API, Wayback
# =============================================================================


class Content(BaseModel):
    """
    Base class for content - something we found/recovered.

    WHEN_FOUND: When we discovered this content
    WHO: Who created it (if known)
    WHAT: What the content is
    WHERE_FOUND: Source location
    FOUND_BY: How we found it
    """

    evidence_id: str = Field(..., description="Unique evidence ID")

    # WHEN
    when_found: datetime = Field(..., description="When we found this (UTC)")
    content_timestamp: datetime | None = Field(
        default=None, description="When content was created (if known)"
    )

    # WHO (optional - not always known)
    who: GitHubActor | None = Field(default=None, description="Content creator")

    # WHAT
    what: str = Field(..., description="What this content is")

    # WHERE
    where_found: str = Field(..., description="Source location (URL, path, etc.)")
    repository: GitHubRepository | None = Field(default=None)

    # FOUND BY
    found_by: EvidenceSource = Field(..., description="How we found this")

    # Verification
    verification: VerificationInfo = Field(..., description="How to verify")

    notes: str | None = Field(default=None)


# -----------------------------------------------------------------------------
# Commit Content (from API/web/git)
# -----------------------------------------------------------------------------


class CommitAuthor(BaseModel):
    """Git commit author/committer."""

    name: str
    email: str
    date: datetime


class CommitFileChange(BaseModel):
    """File changed in a commit."""

    filename: str
    status: Literal["added", "modified", "removed", "renamed"]
    additions: int = 0
    deletions: int = 0
    patch: str | None = None


class CommitContent(Content):
    """
    Full commit details recovered from API/web/git.

    Not an event - use PushEvent for when commits were pushed.
    """

    content_type: Literal["commit"] = "commit"

    sha: Annotated[str, Field(min_length=40, max_length=40)] = Field(
        ..., description="Full 40-char SHA"
    )
    message: str = Field(..., description="Commit message")
    author: CommitAuthor = Field(..., description="Who wrote the code")
    committer: CommitAuthor = Field(..., description="Who created commit object")
    parents: list[str] = Field(default_factory=list)
    files: list[CommitFileChange] = Field(default_factory=list)
    signature_verified: bool | None = Field(default=None)

    # Recovery context
    is_dangling: bool = Field(
        default=False, description="Not on any branch (force-pushed over)"
    )


class ForcePushedCommitRef(Content):
    """
    Reference to a commit that was force-pushed over.

    Derived from PushEvent with size=0. The before_sha points to
    a commit no longer on any branch but still accessible.
    """

    content_type: Literal["force_pushed_commit"] = "force_pushed_commit"

    deleted_sha: str = Field(..., description="SHA that was overwritten")
    replaced_by_sha: str = Field(..., description="SHA that replaced it")
    branch: str = Field(..., description="Branch that was force-pushed")
    pusher: GitHubActor = Field(..., description="Who force-pushed")
    push_event_id: str | None = Field(default=None, description="Source PushEvent ID")

    # Recovery
    commit_recovered: bool = Field(default=False)
    recovered_commit: CommitContent | None = Field(default=None)


# -----------------------------------------------------------------------------
# Wayback Content (from archive.org snapshots)
# -----------------------------------------------------------------------------


class WaybackSnapshot(BaseModel):
    """Single Wayback Machine snapshot."""

    timestamp: str = Field(..., description="YYYYMMDDHHMMSS")
    captured_at: datetime = Field(..., description="Capture time")
    archive_url: HttpUrl = Field(..., description="archive.org URL")
    original_url: HttpUrl = Field(..., description="Original URL")
    status_code: int = Field(default=200)
    digest: str | None = Field(default=None, description="Content hash")


class WaybackContent(Content):
    """Collection of Wayback snapshots for a URL."""

    content_type: Literal["wayback_snapshots"] = "wayback_snapshots"

    original_url: HttpUrl = Field(..., description="URL being tracked")
    snapshots: list[WaybackSnapshot] = Field(...)
    total_snapshots: int = Field(...)
    earliest: WaybackSnapshot = Field(...)
    latest: WaybackSnapshot = Field(...)


class RecoveredIssue(Content):
    """Issue/PR content recovered from Wayback or GH Archive."""

    content_type: Literal["recovered_issue"] = "recovered_issue"

    issue_number: int
    is_pull_request: bool = False
    title: str | None = None
    body: str | None = None
    state: Literal["open", "closed", "merged", "unknown"] | None = None
    labels: list[str] = Field(default_factory=list)
    comments: list[str] = Field(default_factory=list)

    source_snapshot: WaybackSnapshot | None = Field(
        default=None, description="Wayback source if from archive"
    )


class RecoveredFile(Content):
    """File content recovered from Wayback."""

    content_type: Literal["recovered_file"] = "recovered_file"

    file_path: str
    branch: str | None = None
    content: str
    content_hash: str | None = None

    source_snapshot: WaybackSnapshot


class RecoveredWiki(Content):
    """Wiki page recovered from Wayback."""

    content_type: Literal["recovered_wiki"] = "recovered_wiki"

    page_name: str
    content: str

    source_snapshot: WaybackSnapshot


class RecoveredForks(Content):
    """Fork list recovered from Wayback network page."""

    content_type: Literal["recovered_forks"] = "recovered_forks"

    forks: list[str] = Field(..., description="Fork full names")
    forks_still_exist: list[str] = Field(default_factory=list)

    source_snapshot: WaybackSnapshot


# Type alias for all content
AnyContent = (
    CommitContent
    | ForcePushedCommitRef
    | WaybackContent
    | RecoveredIssue
    | RecoveredFile
    | RecoveredWiki
    | RecoveredForks
)


# =============================================================================
# IOC - Indicator of Compromise
#
# Same structure as Content
# Sources: Security blogs, extracted from content
# =============================================================================


class IOC(BaseModel):
    """
    Indicator of Compromise.

    Same structure as Content - something we found that indicates compromise.
    Sources: Security blogs, extracted from events/content.
    """

    evidence_id: str = Field(..., description="Unique evidence ID")

    # WHEN
    when_found: datetime = Field(..., description="When we found this")
    first_seen: datetime | None = Field(default=None, description="First observation")
    last_seen: datetime | None = Field(default=None, description="Last observation")

    # WHO (optional)
    who: GitHubActor | None = Field(default=None, description="Associated actor")

    # WHAT
    ioc_type: IOCType = Field(..., description="Type of IOC")
    value: str = Field(..., description="The IOC value")
    what: str = Field(..., description="Context/description")

    # WHERE
    where_found: str = Field(..., description="Source (URL, evidence ID, etc.)")
    repository: GitHubRepository | None = Field(default=None)

    # FOUND BY
    found_by: EvidenceSource = Field(..., description="How we found this")
    extracted_from: str | None = Field(
        default=None, description="Evidence ID this was extracted from"
    )

    # Confidence
    confidence: Literal["confirmed", "high", "medium", "low"] = Field(default="medium")

    # Verification
    verification: VerificationInfo | None = Field(default=None)

    notes: str | None = Field(default=None)


# =============================================================================
# INVESTIGATION CONTAINERS
# =============================================================================


# All evidence types
AnyEvidence = AnyEvent | AnyContent | IOC


class TimelineEntry(BaseModel):
    """Single entry in investigation timeline."""

    timestamp: datetime = Field(..., description="When this occurred")
    evidence: AnyEvidence = Field(..., description="The evidence")
    significance: Literal["critical", "high", "medium", "low", "info"] = "info"
    tags: list[str] = Field(default_factory=list)
    analysis: str | None = Field(default=None)
    related_ids: list[str] = Field(default_factory=list)


class ActorProfile(BaseModel):
    """Profile of an actor in investigation."""

    actor: GitHubActor
    first_seen: datetime
    last_seen: datetime
    repositories: list[str] = Field(default_factory=list)
    event_count: int = 0
    event_types: list[EventType] = Field(default_factory=list)
    is_automation: bool = False
    account_deleted: bool = False
    evidence_ids: list[str] = Field(default_factory=list)
    notes: str | None = None


class Investigation(BaseModel):
    """Complete investigation container."""

    investigation_id: str
    title: str
    description: str
    created_at: datetime
    updated_at: datetime
    status: Literal["active", "completed", "archived"] = "active"

    # Scope
    target_repositories: list[GitHubRepository] = Field(default_factory=list)
    target_actors: list[str] = Field(default_factory=list)
    time_start: datetime | None = None
    time_end: datetime | None = None

    # Evidence
    events: list[AnyEvent] = Field(default_factory=list)
    content: list[AnyContent] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)

    # Analysis
    timeline: list[TimelineEntry] = Field(default_factory=list)
    actors: list[ActorProfile] = Field(default_factory=list)
    findings: str | None = None
    recommendations: list[str] = Field(default_factory=list)

    # Verification metadata
    queries_used: list[str] = Field(default_factory=list)
    urls_checked: list[str] = Field(default_factory=list)
