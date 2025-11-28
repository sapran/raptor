---
name: github-forensics-schema
description: Pydantic schema for verifiable GitHub forensic evidence. Three types - Event (when/who/what), Content (when_found/who?/what/where_found/found_by), IOC (same as content). All independently verifiable.
version: 2.0
author: mbrg
tags:
  - github
  - forensics
  - schema
  - pydantic
  - osint
  - evidence
---

# GitHub Forensics Verifiable Evidence Schema

Three evidence types, each independently verifiable:

| Type | Fields | Sources |
|------|--------|---------|
| **Event** | when, who, what | GH Archive, git log |
| **Content** | when_found, who?, what, where_found, found_by | GH Archive, GitHub API, Wayback |
| **IOC** | same as content | Security blogs, extracted from content |

## Event - Something Happened

```python
class Event(BaseModel):
    when: datetime          # When it happened
    who: GitHubActor        # Who did it
    what: str               # What they did
    repository: GitHubRepository
    verification: VerificationInfo
```

### Event Types (from GH Archive / git log)

| Type | What |
|------|------|
| `PushEvent` | Pushed commits (commits embedded here, not separate events) |
| `PullRequestEvent` | PR opened/closed/merged |
| `IssueEvent` | Issue opened/closed |
| `IssueCommentEvent` | Comment on issue/PR |
| `CreateEvent` | Branch/tag/repo created |
| `DeleteEvent` | Branch/tag deleted |
| `ForkEvent` | Repo forked |
| `WorkflowRunEvent` | GitHub Actions (absence = API attack) |
| `ReleaseEvent` | Release published |
| `WatchEvent` | Repo starred (recon indicator) |
| `MemberEvent` | Collaborator added/removed |
| `PublicEvent` | Repo made public |

### Example: PushEvent

```python
PushEvent(
    evidence_id="push-001",
    when=datetime(2025, 7, 13, 20, 30, 24),
    who=GitHubActor(login="attacker"),
    what="Pushed 1 commit to refs/heads/main",
    repository=GitHubRepository(owner="org", name="repo", full_name="org/repo"),
    verification=VerificationInfo(
        source=EvidenceSource.GHARCHIVE,
        bigquery_table="githubarchive.day.20250713",
        query="SELECT * FROM ... WHERE type='PushEvent'"
    ),
    ref="refs/heads/main",
    before_sha="abc123...",
    after_sha="def456...",
    size=1,
    commits=[CommitInPush(sha="def456...", message="backdoor", ...)],
    is_force_push=False
)
```

## Content - Something We Found

```python
class Content(BaseModel):
    when_found: datetime       # When we discovered it
    content_timestamp: datetime | None  # When content was created
    who: GitHubActor | None    # Creator (if known)
    what: str                  # What the content is
    where_found: str           # Source location
    found_by: EvidenceSource   # How we found it
    verification: VerificationInfo
```

### Content Types

| Type | Source | What |
|------|--------|------|
| `CommitContent` | GitHub API/web/git | Full commit details |
| `ForcePushedCommitRef` | GH Archive PushEvent | Reference to overwritten commit |
| `WaybackContent` | Wayback CDX | Collection of snapshots |
| `RecoveredIssue` | Wayback/GH Archive | Issue/PR text |
| `RecoveredFile` | Wayback | File content |
| `RecoveredWiki` | Wayback | Wiki page |
| `RecoveredForks` | Wayback | Fork list |

### Example: CommitContent

```python
CommitContent(
    evidence_id="commit-001",
    when_found=datetime.utcnow(),
    content_timestamp=datetime(2025, 7, 13, 20, 30, 24),
    who=GitHubActor(login="attacker"),
    what="Commit def456 containing backdoor",
    where_found="https://github.com/org/repo/commit/def456...",
    found_by=EvidenceSource.GITHUB_API,
    repository=GitHubRepository(...),
    verification=VerificationInfo(
        source=EvidenceSource.GITHUB_API,
        url="https://github.com/org/repo/commit/def456..."
    ),
    sha="def456789...",  # Full 40-char
    message="Add feature",
    author=CommitAuthor(name="Attacker", email="...", date=...),
    committer=CommitAuthor(...),
    files=[CommitFileChange(filename="backdoor.py", status="added")],
    is_dangling=True  # Force-pushed over
)
```

## IOC - Indicator of Compromise

Same structure as Content. For indicators extracted from events/content or from security blogs.

```python
class IOC(BaseModel):
    when_found: datetime
    first_seen: datetime | None
    last_seen: datetime | None
    who: GitHubActor | None    # Associated actor
    ioc_type: IOCType          # commit_sha, email, username, etc.
    value: str                 # The IOC value
    what: str                  # Context
    where_found: str           # Source
    found_by: EvidenceSource
    extracted_from: str | None  # Evidence ID if extracted
    confidence: Literal["confirmed", "high", "medium", "low"]
```

### IOC Types

`commit_sha`, `file_path`, `email`, `username`, `repository`, `tag_name`, `branch_name`, `workflow_name`, `ip_address`, `domain`, `api_key`, `secret`, `url`, `other`

### Example: IOC from Security Blog

```python
IOC(
    evidence_id="ioc-001",
    when_found=datetime.utcnow(),
    first_seen=datetime(2025, 7, 13),
    ioc_type=IOCType.COMMIT_SHA,
    value="678851bbe9776228f55e0460e66a6167ac2a1685",
    what="Malicious commit in Amazon Q attack",
    where_found="https://security-blog.example.com/amazon-q-analysis",
    found_by=EvidenceSource.SECURITY_BLOG,
    repository=GitHubRepository(owner="aws", name="aws-toolkit-vscode", full_name="aws/aws-toolkit-vscode"),
    confidence="confirmed"
)
```

## Investigation Container

```python
class Investigation(BaseModel):
    investigation_id: str
    title: str
    description: str

    # Evidence (separated by type)
    events: list[AnyEvent]      # Things that happened
    content: list[AnyContent]   # Things we found
    iocs: list[IOC]             # Indicators

    # Analysis
    timeline: list[TimelineEntry]
    actors: list[ActorProfile]
    findings: str | None
    recommendations: list[str]
```

## Sources Summary

| Source | Used For |
|--------|----------|
| `GHARCHIVE` | Events, force-push detection, deleted PR/issue recovery |
| `GIT_LOG` | Local events from git history |
| `GITHUB_API` | Commit content, current state |
| `GITHUB_WEB` | Commit patches, dangling commits |
| `WAYBACK` | Deleted content recovery |
| `SECURITY_BLOG` | External IOCs |

## Related Skills

- **github-archive**: Query GH Archive for events
- **github-commit-recovery**: Recover commits using SHAs
- **github-wayback-recovery**: Recover deleted content
