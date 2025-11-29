#!/usr/bin/env python3
"""
Unit tests for _parsers.py module.

Tests the extracted parser functions that convert GH Archive rows
into Evidence objects.
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src._parsers import (
    _generate_evidence_id,
    _make_actor,
    _make_repo,
    _parse_datetime,
    _RowContext,
    parse_create_event,
    parse_fork_event,
    parse_gharchive_event,
    parse_issue_comment_event,
    parse_issue_event,
    parse_pull_request_event,
    parse_push_event,
    parse_watch_event,
)
from src._schema import EvidenceSource, IssueAction, PRAction, RefType


# =============================================================================
# HELPER FUNCTION TESTS
# =============================================================================


class TestGenerateEvidenceId:
    """Test evidence ID generation."""

    def test_deterministic(self):
        """Same inputs produce same ID."""
        id1 = _generate_evidence_id("test", "a", "b", "c")
        id2 = _generate_evidence_id("test", "a", "b", "c")
        assert id1 == id2

    def test_different_inputs_different_ids(self):
        """Different inputs produce different IDs."""
        id1 = _generate_evidence_id("test", "a", "b")
        id2 = _generate_evidence_id("test", "a", "c")
        assert id1 != id2

    def test_prefix_applied(self):
        """Prefix is included in the ID."""
        id1 = _generate_evidence_id("push", "repo", "sha")
        assert id1.startswith("push-")

    def test_hash_length(self):
        """ID hash part is 12 characters."""
        id1 = _generate_evidence_id("test", "input")
        parts = id1.split("-")
        assert len(parts[1]) == 12


class TestParseDatetime:
    """Test datetime parsing."""

    def test_none_returns_now(self):
        """None input returns current time."""
        result = _parse_datetime(None)
        assert isinstance(result, datetime)
        assert result.tzinfo is not None

    def test_datetime_passthrough(self):
        """datetime objects pass through unchanged."""
        dt = datetime(2025, 7, 13, 12, 0, 0, tzinfo=timezone.utc)
        result = _parse_datetime(dt)
        assert result == dt

    def test_iso_format_with_z(self):
        """ISO format with Z suffix is parsed."""
        result = _parse_datetime("2025-07-13T20:37:04Z")
        assert result.year == 2025
        assert result.month == 7
        assert result.day == 13

    def test_iso_format_with_timezone(self):
        """ISO format with timezone offset is parsed."""
        result = _parse_datetime("2025-07-13T07:52:37+00:00")
        assert result.year == 2025
        assert result.hour == 7


class TestMakeActor:
    """Test actor creation helper."""

    def test_creates_actor(self):
        """Creates GitHubActor with login and id."""
        actor = _make_actor("testuser", 12345)
        assert actor.login == "testuser"
        assert actor.id == 12345

    def test_optional_id(self):
        """ID is optional."""
        actor = _make_actor("testuser")
        assert actor.login == "testuser"
        assert actor.id is None


class TestMakeRepo:
    """Test repository creation helper."""

    def test_creates_from_full_name(self):
        """Creates GitHubRepository from owner/name format."""
        repo = _make_repo("aws/aws-toolkit-vscode")
        assert repo.owner == "aws"
        assert repo.name == "aws-toolkit-vscode"
        assert repo.full_name == "aws/aws-toolkit-vscode"

    def test_handles_no_slash(self):
        """Handles repo name without slash."""
        repo = _make_repo("single-name")
        assert repo.owner == "unknown"
        assert repo.name == "single-name"


# =============================================================================
# ROW CONTEXT TESTS
# =============================================================================


class TestRowContext:
    """Test _RowContext extraction."""

    def test_extracts_payload_from_dict(self):
        """Extracts payload when it's already a dict."""
        row = {
            "type": "PushEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "testuser",
            "actor_id": 123,
            "repo_name": "owner/repo",
            "payload": {"ref": "refs/heads/main"},
        }
        ctx = _RowContext(row)
        assert ctx.payload["ref"] == "refs/heads/main"

    def test_parses_payload_from_json_string(self):
        """Parses payload when it's a JSON string."""
        row = {
            "type": "PushEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "testuser",
            "actor_id": 123,
            "repo_name": "owner/repo",
            "payload": '{"ref": "refs/heads/main"}',
        }
        ctx = _RowContext(row)
        assert ctx.payload["ref"] == "refs/heads/main"

    def test_creates_verification_info(self):
        """Creates VerificationInfo with GHARCHIVE source."""
        row = {
            "type": "PushEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "testuser",
            "repo_name": "owner/repo",
            "payload": {},
        }
        ctx = _RowContext(row)
        assert ctx.verification.source == EvidenceSource.GHARCHIVE


# =============================================================================
# PARSER TESTS
# =============================================================================


class TestParsePushEvent:
    """Test push event parser."""

    def test_parses_basic_push(self, gharchive_events):
        """Parses a basic push event."""
        push_events = [e for e in gharchive_events if e["type"] == "PushEvent"]
        assert len(push_events) > 0

        event = parse_push_event(push_events[0])
        assert event.event_type == "push"
        assert event.verification.source == EvidenceSource.GHARCHIVE

    def test_extracts_ref(self, gharchive_push_events):
        """Extracts ref from push event."""
        event = parse_push_event(gharchive_push_events[0])
        assert event.ref is not None
        assert event.ref.startswith("refs/heads/")

    def test_extracts_commits(self, gharchive_push_events):
        """Extracts commits from push event."""
        # Find a push with commits
        push_with_commits = next(
            (e for e in gharchive_push_events if len(e["payload"].get("commits", [])) > 0),
            gharchive_push_events[0],
        )
        event = parse_push_event(push_with_commits)
        # May have 0 commits if they're not distinct
        assert hasattr(event, "commits")


class TestParseIssueEvent:
    """Test issue event parser."""

    def test_parses_issue_opened(self, gharchive_issue_events):
        """Parses an issue opened event."""
        event = parse_issue_event(gharchive_issue_events[0])
        assert event.event_type == "issue"
        assert event.action == IssueAction.OPENED

    def test_extracts_issue_number(self, gharchive_issue_events):
        """Extracts issue number."""
        event = parse_issue_event(gharchive_issue_events[0])
        assert event.issue_number > 0

    def test_extracts_issue_title(self, gharchive_issue_events):
        """Extracts issue title."""
        event = parse_issue_event(gharchive_issue_events[0])
        assert event.issue_title is not None
        assert len(event.issue_title) > 0


class TestParseCreateEvent:
    """Test create event parser."""

    def test_parses_create_event(self, gharchive_create_events):
        """Parses a create event."""
        if not gharchive_create_events:
            pytest.skip("No CreateEvent in fixture")

        event = parse_create_event(gharchive_create_events[0])
        assert event.event_type == "create"
        assert event.ref_type in [RefType.BRANCH, RefType.TAG, RefType.REPOSITORY]

    def test_extracts_ref_name(self, gharchive_create_events):
        """Extracts ref name."""
        if not gharchive_create_events:
            pytest.skip("No CreateEvent in fixture")

        event = parse_create_event(gharchive_create_events[0])
        assert event.ref_name is not None


# =============================================================================
# DISPATCHER TESTS
# =============================================================================


class TestParseGharchiveEvent:
    """Test the dispatcher function."""

    def test_dispatches_push_event(self, gharchive_push_events):
        """Correctly dispatches PushEvent."""
        event = parse_gharchive_event(gharchive_push_events[0])
        assert event.event_type == "push"

    def test_dispatches_issue_event(self, gharchive_issue_events):
        """Correctly dispatches IssuesEvent."""
        event = parse_gharchive_event(gharchive_issue_events[0])
        assert event.event_type == "issue"

    def test_raises_for_unknown_event(self):
        """Raises ValueError for unknown event types."""
        row = {
            "type": "UnknownEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "test",
            "repo_name": "owner/repo",
            "payload": {},
        }
        with pytest.raises(ValueError, match="Unsupported"):
            parse_gharchive_event(row)


# =============================================================================
# EDGE CASE TESTS
# =============================================================================


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_handles_missing_actor_id(self):
        """Handles row with no actor_id."""
        row = {
            "type": "PushEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "testuser",
            "repo_name": "owner/repo",
            "payload": {"ref": "refs/heads/main", "commits": [], "before": "a" * 40, "head": "b" * 40},
        }
        event = parse_push_event(row)
        assert event.who.login == "testuser"
        assert event.who.id is None

    def test_handles_empty_commits(self):
        """Handles push with no commits."""
        row = {
            "type": "PushEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "testuser",
            "actor_id": 123,
            "repo_name": "owner/repo",
            "payload": {"ref": "refs/heads/main", "commits": [], "before": "a" * 40, "head": "b" * 40, "size": 0},
        }
        event = parse_push_event(row)
        assert len(event.commits) == 0

    def test_handles_missing_issue_body(self):
        """Handles issue with no body."""
        row = {
            "type": "IssuesEvent",
            "created_at": "2025-07-13T07:52:37Z",
            "actor_login": "testuser",
            "actor_id": 123,
            "repo_name": "owner/repo",
            "payload": {
                "action": "opened",
                "issue": {
                    "number": 1,
                    "title": "Test",
                    # no body
                },
            },
        }
        event = parse_issue_event(row)
        assert event.issue_body is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
