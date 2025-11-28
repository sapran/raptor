"""
GitHub Forensics Verifiable Evidence Schema

Three evidence types:
1. Event   - Something happened (when, who, what)
             Sources: GH Archive, git log
2. Content - Something we found (when_found, who?, what, where_found, found_by)
             Sources: GH Archive, GitHub API, Wayback
3. IOC     - Indicator of Compromise (same as content)
             Sources: Security blogs, extracted from content
"""

from .schema import (
    # Enums
    EvidenceSource,
    EventType,
    RefType,
    PRAction,
    IssueAction,
    WorkflowConclusion,
    IOCType,
    # Common
    GitHubActor,
    GitHubRepository,
    VerificationInfo,
    # Events (when, who, what)
    Event,
    CommitInPush,
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
    AnyEvent,
    # Content (when_found, who?, what, where_found, found_by)
    Content,
    CommitAuthor,
    CommitFileChange,
    CommitContent,
    ForcePushedCommitRef,
    WaybackSnapshot,
    WaybackContent,
    RecoveredIssue,
    RecoveredFile,
    RecoveredWiki,
    RecoveredForks,
    AnyContent,
    # IOC
    IOC,
    # Investigation
    AnyEvidence,
    TimelineEntry,
    ActorProfile,
    Investigation,
)

__all__ = [
    # Enums
    "EvidenceSource",
    "EventType",
    "RefType",
    "PRAction",
    "IssueAction",
    "WorkflowConclusion",
    "IOCType",
    # Common
    "GitHubActor",
    "GitHubRepository",
    "VerificationInfo",
    # Events
    "Event",
    "CommitInPush",
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
    "AnyEvent",
    # Content
    "Content",
    "CommitAuthor",
    "CommitFileChange",
    "CommitContent",
    "ForcePushedCommitRef",
    "WaybackSnapshot",
    "WaybackContent",
    "RecoveredIssue",
    "RecoveredFile",
    "RecoveredWiki",
    "RecoveredForks",
    "AnyContent",
    # IOC
    "IOC",
    # Investigation
    "AnyEvidence",
    "TimelineEntry",
    "ActorProfile",
    "Investigation",
]
