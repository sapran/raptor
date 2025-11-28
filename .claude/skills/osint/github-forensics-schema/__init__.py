"""
GitHub Forensics Verifiable Evidence Schema

Pydantic models for verifiable GitHub forensic evidence.
All evidence types can be independently verified through:
- GitHub API (point-in-time observations)
- GH Archive/BigQuery (immutable event stream)
- Wayback Machine (point-in-time snapshots)
- Git (local repository queries)

Every evidence piece answers: WHEN, WHO, WHAT
"""

from .schema import (
    # Enums
    EvidenceSource,
    EventType,
    RefType,
    PRAction,
    IssueAction,
    WorkflowConclusion,
    # Base types
    VerificationInfo,
    GitHubActor,
    GitHubRepository,
    EvidenceBase,
    GitHubEventBase,
    # GH Archive Events (commits come via PushEvent)
    PushEventCommit,
    PushEvent,
    PullRequestEvent,
    IssueEvent,
    IssueCommentEvent,
    CreateEvent,
    DeleteEvent,
    ForkEvent,
    WorkflowRunEvent,
    ReleaseEvent,
    WatchEvent,
    MemberEvent,
    PublicEvent,
    # API Observations (point-in-time queries)
    CommitAuthor,
    CommitSignature,
    CommitFileChange,
    CommitObservation,
    ForcesPushedCommitReference,
    # Wayback Snapshots (point-in-time archived pages)
    WaybackSnapshot,
    WaybackObservation,
    RecoveredIssueContent,
    RecoveredFileContent,
    RecoveredWikiContent,
    RecoveredForkList,
    # Investigation containers
    TimelineEntry,
    ActorProfile,
    IOC,
    Investigation,
    # Type aliases
    GitHubArchiveEvent,
    Observation,
    AnyEvidence,
)

__all__ = [
    # Enums
    "EvidenceSource",
    "EventType",
    "RefType",
    "PRAction",
    "IssueAction",
    "WorkflowConclusion",
    # Base types
    "VerificationInfo",
    "GitHubActor",
    "GitHubRepository",
    "EvidenceBase",
    "GitHubEventBase",
    # GH Archive Events
    "PushEventCommit",
    "PushEvent",
    "PullRequestEvent",
    "IssueEvent",
    "IssueCommentEvent",
    "CreateEvent",
    "DeleteEvent",
    "ForkEvent",
    "WorkflowRunEvent",
    "ReleaseEvent",
    "WatchEvent",
    "MemberEvent",
    "PublicEvent",
    # API Observations
    "CommitAuthor",
    "CommitSignature",
    "CommitFileChange",
    "CommitObservation",
    "ForcesPushedCommitReference",
    # Wayback Snapshots
    "WaybackSnapshot",
    "WaybackObservation",
    "RecoveredIssueContent",
    "RecoveredFileContent",
    "RecoveredWikiContent",
    "RecoveredForkList",
    # Investigation containers
    "TimelineEntry",
    "ActorProfile",
    "IOC",
    "Investigation",
    # Type aliases
    "GitHubArchiveEvent",
    "Observation",
    "AnyEvidence",
]
