---
name: github-forensics-schema
description: Pydantic schema for verifiable GitHub forensic evidence. Defines strict types for all evidence that can be independently verified via GitHub API, GH Archive (BigQuery), Git, or Wayback Machine. Every evidence piece answers WHEN, WHO, WHAT.
version: 1.1
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

**Purpose**: Strict Pydantic schema defining all verifiable GitHub forensic evidence. Every evidence piece answers **WHEN**, **WHO**, **WHAT** and can be independently verified.

## When to Use This Skill

- Building GitHub security investigations with structured evidence
- Collecting IOCs from GitHub-related incidents
- Creating reproducible forensic reports with verifiable claims
- Integrating multiple evidence sources (GH Archive, Wayback, GitHub API)
- Establishing attribution and timeline with provable data

## Core Principles

**All Evidence Answers WHEN, WHO, WHAT**:
```python
class EvidenceBase(BaseModel):
    when: datetime      # Temporal anchor
    what: str           # What this evidence shows
    verification: ...   # How to verify it
```

**Evidence Categories**:

| Category | Source | Nature | Example |
|----------|--------|--------|---------|
| **GH Archive Events** | BigQuery | Immutable event stream | PushEvent, IssueEvent |
| **API Observations** | GitHub API | Point-in-time query | CommitObservation |
| **Wayback Snapshots** | archive.org | Point-in-time capture | WaybackObservation |

**Key Distinction**:
- **Events** = Something happened (immutable, from GH Archive)
- **Observations** = We looked and saw this (point-in-time, from API/Wayback)
- **Commits come via PushEvent** - there is no separate "CommitEvent" in GH Archive

## Schema Structure

### GH Archive Events (Immutable)

Events are recorded in GitHub's event stream and queryable via BigQuery.

| Type | GH Archive Event | WHEN/WHO/WHAT |
|------|------------------|---------------|
| `PushEvent` | `PushEvent` | When pushed / Who pushed / Commits + before/after SHA |
| `PullRequestEvent` | `PullRequestEvent` | When / Who acted / Action + PR details |
| `IssueEvent` | `IssuesEvent` | When / Who acted / Action + issue details |
| `IssueCommentEvent` | `IssueCommentEvent` | When / Who commented / Comment body |
| `CreateEvent` | `CreateEvent` | When / Who created / Branch/tag/repo created |
| `DeleteEvent` | `DeleteEvent` | When / Who deleted / Branch/tag deleted |
| `ForkEvent` | `ForkEvent` | When / Who forked / Source → Fork |
| `WorkflowRunEvent` | `WorkflowRunEvent` | When / Who triggered / Workflow + conclusion |
| `ReleaseEvent` | `ReleaseEvent` | When / Who released / Tag + release notes |
| `WatchEvent` | `WatchEvent` | When / Who starred / Repository |
| `MemberEvent` | `MemberEvent` | When / Who changed / Member + permission |
| `PublicEvent` | `PublicEvent` | When / Who / Made repo public |

### API Observations (Point-in-Time)

Observations from querying GitHub API directly.

| Type | Description | WHEN/WHO/WHAT |
|------|-------------|---------------|
| `CommitObservation` | Full commit details | Author date / Author+Committer / SHA + message + files |
| `ForcePushedCommitReference` | Recovered from PushEvent size=0 | Force push time / Pusher / Deleted SHA → Replaced SHA |

### Wayback Snapshots (Point-in-Time)

Archived web pages from Internet Archive.

| Type | Description | WHEN/WHO/WHAT |
|------|-------------|---------------|
| `WaybackSnapshot` | Single archived page | Capture time / N/A / URL content at capture |
| `WaybackObservation` | Collection of snapshots | Time range / N/A / All snapshots for URL |
| `RecoveredIssueContent` | Issue/PR from snapshot | Capture time / Author / Title + body |
| `RecoveredFileContent` | File from snapshot | Capture time / N/A / File content |
| `RecoveredWikiContent` | Wiki from snapshot | Capture time / N/A / Wiki content |
| `RecoveredForkList` | Forks from network page | Capture time / N/A / Fork list |

## Evidence Examples

### PushEvent (Commits come here!)

```python
PushEvent(
    evidence_id="push-001",
    when=datetime(2025, 7, 13, 20, 30, 24),
    what="Pushed 3 commits to refs/heads/main",
    actor=GitHubActor(login="developer"),
    repository=GitHubRepository(owner="org", name="repo", full_name="org/repo"),
    verification=VerificationInfo(
        source=EvidenceSource.GHARCHIVE,
        bigquery_table="githubarchive.day.20250713",
        verification_query="SELECT * FROM ... WHERE type='PushEvent'"
    ),
    ref="refs/heads/main",
    before_sha="abc123...",  # SHA before push
    after_sha="def456...",   # New HEAD
    size=3,
    commits=[
        PushEventCommit(sha="...", message="Add feature", author_name="Dev", author_email="..."),
        # ...
    ],
    is_force_push=False
)
```

### Force Push Detection (size=0)

```python
# Force push = size=0 in PushEvent
# before_sha points to the "deleted" commit
PushEvent(
    when=datetime(2025, 7, 13, 20, 30, 24),
    what="Force push replaced abc123 with def456",
    actor=GitHubActor(login="developer"),
    before_sha="abc123...",  # This commit was force-pushed over
    after_sha="def456...",   # Replaced with this
    size=0,                  # Zero commits = force push
    commits=[],
    is_force_push=True
)
```

### CommitObservation (Direct API query)

```python
CommitObservation(
    evidence_id="commit-001",
    when=datetime(2025, 7, 13, 20, 30, 24),  # author.date
    what="Commit abc123 with message 'Add backdoor'",
    verification=VerificationInfo(
        source=EvidenceSource.GITHUB_API,
        verification_url="https://github.com/org/repo/commit/abc123..."
    ),
    repository=GitHubRepository(...),
    sha="abc123def456...",  # Full 40-char SHA required
    short_sha="abc123d",
    message="Add backdoor",
    author=CommitAuthor(name="Attacker", email="...", date=datetime(...)),
    committer=CommitAuthor(...),
    files=[CommitFileChange(filename="src/evil.py", status="added", ...)],
    is_dangling=True,          # Not on any branch
    recovered_via="api"        # How we got it
)
```

### WaybackObservation

```python
WaybackObservation(
    evidence_id="wayback-001",
    when=datetime(2023, 6, 15, 14, 23, 11),  # Capture time
    what="Archived snapshots of github.com/deleted/repo",
    verification=VerificationInfo(
        source=EvidenceSource.WAYBACK,
        verification_url="https://web.archive.org/cdx/search/cdx?url=github.com/deleted/repo"
    ),
    content_type="repository_homepage",
    original_url="https://github.com/deleted/repo",
    snapshots=[...],
    latest_snapshot=WaybackSnapshot(
        timestamp="20230615142311",
        captured_at=datetime(2023, 6, 15, 14, 23, 11),
        original_url="https://github.com/deleted/repo",
        archive_url="https://web.archive.org/web/20230615142311/https://github.com/deleted/repo",
        status_code=200
    ),
    earliest_snapshot=...,
    total_snapshots=5
)
```

### Workflow Absence Detection

```python
# CRITICAL: No WorkflowRunEvent during suspicious commit = Direct API attack
# Query GH Archive for WorkflowRunEvent in time window around malicious commit
# Empty results = Token stolen and used directly, not via workflow
```

## Type Aliases

```python
# All GH Archive event types
GitHubArchiveEvent = PushEvent | PullRequestEvent | IssueEvent | ...

# All point-in-time observations
Observation = CommitObservation | WaybackObservation | ...

# Everything
AnyEvidence = GitHubArchiveEvent | Observation
```

## IOC Types

| IOC Type | Example | Found In |
|----------|---------|----------|
| `commit_sha` | `678851bbe9...` | PushEvent, CommitObservation |
| `username` | `lkmanka58` | GitHubActor |
| `email` | `attacker@evil.com` | CommitAuthor |
| `repository` | `lkmanka58/code_whisperer` | GitHubRepository |
| `tag_name` | `stability` | CreateEvent, ReleaseEvent |
| `branch_name` | `feature/backdoor` | PushEvent, CreateEvent |
| `workflow_name` | `deploy-automation` | WorkflowRunEvent |
| `file_path` | `.env`, `config.json` | CommitFileChange |
| `api_key_pattern` | `ghp_...`, `AKIA...` | Recovered content |

## Related Skills

- **github-archive**: Query GH Archive to populate event types
- **github-commit-recovery**: Recover commits using SHAs from PushEvent
- **github-wayback-recovery**: Recover deleted content for Wayback observations

## Usage Notes

1. **Commits are NOT events** - they come embedded in `PushEvent`
2. **Use `CommitObservation`** only for direct API/web queries
3. **Force push detection**: `PushEvent.size == 0`
4. **Wayback = snapshots**, not events - they capture what existed at crawl time
5. **Always include verification info** with BigQuery query or URL
