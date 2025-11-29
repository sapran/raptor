---
name: gh-evidence-kit
description: Generate, export, load, and verify forensic evidence from GitHub sources. Use when creating verifiable evidence objects from GitHub API, GH Archive, Wayback Machine, or security vendor reports. Handles evidence storage, querying, and re-verification against original sources.
version: 1.0
author: mbrg
tags:
  - github
  - forensics
  - osint
  - evidence
  - verification
---

# GH Evidence Kit

**Purpose**: Create, store, and verify forensic evidence from GitHub-related public sources.

## When to Use This Skill

- Creating verifiable evidence objects from GitHub activity
- Exporting evidence collections to JSON for sharing/archival
- Loading and re-verifying previously collected evidence
- Recovering deleted GitHub content (issues, PRs, commits) from GH Archive
- Tracking IOCs (Indicators of Compromise) with source verification

## Quick Start

```python
from src import EvidenceFactory, EvidenceStore

# Create factory
factory = EvidenceFactory()

# Create evidence from GitHub API
commit = factory.commit("aws", "aws-toolkit-vscode", "678851bbe9776228f55e0460e66a6167ac2a1685")
pr = factory.pull_request("aws", "aws-toolkit-vscode", 7710)

# Store and export
store = EvidenceStore()
store.add(commit)
store.add(pr)
store.save("evidence.json")

# Verify all evidence
is_valid, errors = store.verify_all()
```

## API Reference

### EvidenceFactory

Creates verified evidence objects from public sources.

| Method | Source | Returns |
|--------|--------|---------|
| `factory.commit(owner, repo, sha)` | GitHub API | CommitObservation |
| `factory.issue(owner, repo, number)` | GitHub API | IssueObservation |
| `factory.pull_request(owner, repo, number)` | GitHub API | IssueObservation |
| `factory.file(owner, repo, path, ref)` | GitHub API | FileObservation |
| `factory.branch(owner, repo, branch_name)` | GitHub API | BranchObservation |
| `factory.tag(owner, repo, tag_name)` | GitHub API | TagObservation |
| `factory.release(owner, repo, tag_name)` | GitHub API | ReleaseObservation |
| `factory.forks(owner, repo)` | GitHub API | list[ForkObservation] |
| `factory.wayback_snapshots(url)` | Wayback | SnapshotObservation |
| `factory.events_from_gharchive(timestamp, repo)` | BigQuery | list[Event] |
| `factory.ioc(ioc_type, value, source_url)` | Vendor URL | IOC |
| `factory.article(url, title, ...)` | - | ArticleObservation |

### Recovery Methods (GH Archive)

Recover deleted content from GH Archive BigQuery:

```python
# Requires BigQuery credentials
factory = EvidenceFactory(gharchive_credentials="path/to/creds.json")

deleted_issue = factory.recover_issue("aws/aws-toolkit-vscode", 123, "2025-07-13T20:30:24Z")
deleted_pr = factory.recover_pr("aws/aws-toolkit-vscode", 7710, "2025-07-13T20:30:24Z")
deleted_commit = factory.recover_commit("aws/aws-toolkit-vscode", "678851b", "2025-07-13T20:30:24Z")
force_pushed = factory.recover_force_push("aws/aws-toolkit-vscode", "2025-07-13T20:30:24Z")
```

### EvidenceStore

Store, query, and export evidence collections.

```python
store = EvidenceStore()

# Add evidence
store.add(commit)
store.add_all([pr, issue, ioc])

# Query
commits = store.filter(observation_type="commit")
recent = store.filter(after=datetime(2025, 7, 1))
from_github = store.filter(source="github")
repo_events = store.filter(repo="aws/aws-toolkit-vscode")

# Export/Import
store.save("evidence.json")
store = EvidenceStore.load("evidence.json")

# Verify all against sources
is_valid, errors = store.verify_all()
```

### Loading Evidence from JSON

```python
from src import load_evidence_from_json
import json

with open("evidence.json") as f:
    data = json.load(f)

for item in data:
    evidence = load_evidence_from_json(item)
    is_valid, errors = evidence.verify()
```

## Evidence Types

### Events (from GH Archive)

| Type | Description |
|------|-------------|
| PushEvent | Commits pushed |
| PullRequestEvent | PR opened/closed/merged |
| IssueEvent | Issue opened/closed |
| IssueCommentEvent | Comment on issue/PR |
| CreateEvent | Branch/tag created |
| DeleteEvent | Branch/tag deleted |
| ForkEvent | Repository forked |
| WorkflowRunEvent | GitHub Actions run |
| ReleaseEvent | Release published |

### Observations (from GitHub API, Wayback, Vendors)

| Type | Description |
|------|-------------|
| CommitObservation | Commit metadata and files |
| IssueObservation | Issue or PR |
| FileObservation | File content at ref |
| BranchObservation | Branch HEAD |
| TagObservation | Tag target |
| ReleaseObservation | Release metadata |
| ForkObservation | Fork relationship |
| SnapshotObservation | Wayback snapshots |
| IOC | Indicator of Compromise |
| ArticleObservation | Security report/blog |

## IOC Types

```python
from src import IOCType

factory.ioc(IOCType.COMMIT_SHA, "678851b...", "https://vendor.com/report")
factory.ioc(IOCType.FILE_PATH, "malicious.py", "https://vendor.com/report")
factory.ioc(IOCType.EMAIL, "attacker@example.com", "https://vendor.com/report")
```

Available: `COMMIT_SHA`, `FILE_PATH`, `FILE_HASH`, `CODE_SNIPPET`, `EMAIL`, `USERNAME`, `REPOSITORY`, `TAG_NAME`, `BRANCH_NAME`, `WORKFLOW_NAME`, `IP_ADDRESS`, `DOMAIN`, `URL`, `API_KEY`, `SECRET`

## Requirements

```bash
pip install -r requirements.txt
```

- `pydantic` - Schema validation
- `requests` - HTTP client
- `google-cloud-bigquery` - GH Archive queries (optional)
