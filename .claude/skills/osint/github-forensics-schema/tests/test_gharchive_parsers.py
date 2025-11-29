#!/usr/bin/env python3
"""
Unit tests for GHArchive event parsing functions.

These tests use fixture data to verify parsing logic without network calls.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src._creation import (
    create_push_event_from_gharchive,
    create_issue_event_from_gharchive,
    create_create_event_from_gharchive,
    create_event_from_gharchive,
)
from src._schema import EvidenceSource


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> list | dict:
    """Load a fixture file."""
    with open(FIXTURES_DIR / name) as f:
        return json.load(f)


@pytest.fixture
def gharchive_events() -> list[dict]:
    """Load GH Archive fixture data."""
    return load_fixture("gharchive_july13_2025.json")


# =============================================================================
# PUSH EVENT PARSING
# =============================================================================


class TestPushEventParsing:
    """Test push event parsing from GH Archive data."""

    def test_parse_push_event_basic(self, gharchive_events):
        """Parse a basic push event."""
        push_events = [e for e in gharchive_events if e["type"] == "PushEvent"]
        assert len(push_events) > 0

        row = push_events[0]
        event = create_push_event_from_gharchive(row)

        assert event.event_type == "push"
        assert event.verification.source == EvidenceSource.GHARCHIVE
        assert event.ref == row["payload"]["ref"]

    def test_push_event_extracts_commits(self, gharchive_events):
        """Push event correctly extracts commit information."""
        # Find push with commits
        push_with_commits = next(
            e for e in gharchive_events
            if e["type"] == "PushEvent" and len(e["payload"]["commits"]) > 0
        )

        event = create_push_event_from_gharchive(push_with_commits)

        assert len(event.commits) > 0
        assert event.commits[0].sha is not None
        assert event.commits[0].message is not None

    def test_push_event_generates_evidence_id(self, gharchive_events):
        """Push event generates unique evidence ID."""
        push_event = next(e for e in gharchive_events if e["type"] == "PushEvent")
        event = create_push_event_from_gharchive(push_event)

        assert event.evidence_id is not None
        assert event.evidence_id.startswith("push-")

    def test_push_event_has_who_field(self, gharchive_events):
        """Push event extracts who (actor) information."""
        push_event = next(e for e in gharchive_events if e["type"] == "PushEvent")
        event = create_push_event_from_gharchive(push_event)

        assert event.who.login == push_event["actor_login"]

    def test_push_event_has_repository(self, gharchive_events):
        """Push event extracts repository information."""
        push_event = next(e for e in gharchive_events if e["type"] == "PushEvent")
        event = create_push_event_from_gharchive(push_event)

        assert event.repository.full_name == push_event["repo_name"]


# =============================================================================
# ISSUE EVENT PARSING
# =============================================================================


class TestIssueEventParsing:
    """Test issue event parsing from GH Archive data."""

    def test_parse_issue_event_basic(self, gharchive_events):
        """Parse a basic issue event."""
        issue_events = [e for e in gharchive_events if e["type"] == "IssuesEvent"]
        assert len(issue_events) > 0

        row = issue_events[0]
        event = create_issue_event_from_gharchive(row)

        assert event.event_type == "issue"
        assert event.verification.source == EvidenceSource.GHARCHIVE
        assert event.issue_number == row["payload"]["issue"]["number"]

    def test_issue_event_extracts_title(self, gharchive_events):
        """Issue event extracts the issue title."""
        issue_event = next(e for e in gharchive_events if e["type"] == "IssuesEvent")
        event = create_issue_event_from_gharchive(issue_event)

        expected_title = issue_event["payload"]["issue"]["title"]
        assert event.issue_title == expected_title

    def test_issue_event_extracts_action(self, gharchive_events):
        """Issue event extracts the action (opened, closed, etc)."""
        issue_event = next(e for e in gharchive_events if e["type"] == "IssuesEvent")
        event = create_issue_event_from_gharchive(issue_event)

        assert event.action == issue_event["payload"]["action"]

    def test_issue_event_extracts_body(self, gharchive_events):
        """Issue event extracts the issue body."""
        issue_event = next(
            e for e in gharchive_events
            if e["type"] == "IssuesEvent" and e["payload"]["issue"].get("body")
        )
        event = create_issue_event_from_gharchive(issue_event)

        assert event.issue_body is not None
        assert len(event.issue_body) > 0


# =============================================================================
# CREATE EVENT PARSING
# =============================================================================


class TestCreateEventParsing:
    """Test create event (branch/tag creation) parsing."""

    def test_parse_create_event_basic(self, gharchive_events):
        """Parse a basic create event."""
        create_events = [e for e in gharchive_events if e["type"] == "CreateEvent"]

        if len(create_events) == 0:
            pytest.skip("No CreateEvent in fixture")

        row = create_events[0]
        event = create_create_event_from_gharchive(row)

        assert event.event_type == "create"
        assert event.verification.source == EvidenceSource.GHARCHIVE

    def test_create_event_extracts_ref_type(self, gharchive_events):
        """Create event extracts ref type (branch, tag)."""
        create_event = next(
            (e for e in gharchive_events if e["type"] == "CreateEvent"),
            None
        )

        if create_event is None:
            pytest.skip("No CreateEvent in fixture")

        event = create_create_event_from_gharchive(create_event)

        assert event.ref_type in ["branch", "tag", "repository"]
        assert event.ref_name is not None


# =============================================================================
# DISPATCHER FUNCTION
# =============================================================================


class TestEventDispatcher:
    """Test the create_event_from_gharchive dispatcher."""

    def test_dispatcher_handles_push_event(self, gharchive_events):
        """Dispatcher correctly routes PushEvent."""
        push_event = next(e for e in gharchive_events if e["type"] == "PushEvent")
        event = create_event_from_gharchive(push_event)

        assert event.event_type == "push"

    def test_dispatcher_handles_issue_event(self, gharchive_events):
        """Dispatcher correctly routes IssuesEvent."""
        issue_event = next(e for e in gharchive_events if e["type"] == "IssuesEvent")
        event = create_event_from_gharchive(issue_event)

        assert event.event_type == "issue"

    def test_dispatcher_handles_create_event(self, gharchive_events):
        """Dispatcher correctly routes CreateEvent."""
        create_event = next(
            (e for e in gharchive_events if e["type"] == "CreateEvent"),
            None
        )

        if create_event is None:
            pytest.skip("No CreateEvent in fixture")

        event = create_event_from_gharchive(create_event)
        assert event.event_type == "create"

    def test_dispatcher_raises_for_unknown_event(self):
        """Dispatcher raises error for unknown event type."""
        unknown_event = {
            "type": "UnknownEventType",
            "created_at": "2025-07-13T07:52:37+00:00",
            "actor_login": "test",
            "actor_id": 123,
            "repo_name": "test/repo",
            "repo_id": 456,
            "payload": {},
        }

        with pytest.raises(ValueError, match="Unsupported.*event.*type"):
            create_event_from_gharchive(unknown_event)


# =============================================================================
# EVIDENCE ID GENERATION
# =============================================================================


class TestEvidenceIdGeneration:
    """Test that evidence IDs are generated correctly."""

    def test_same_event_produces_same_id(self, gharchive_events):
        """Parsing the same event twice produces the same evidence ID."""
        push_event = next(e for e in gharchive_events if e["type"] == "PushEvent")

        event1 = create_push_event_from_gharchive(push_event)
        event2 = create_push_event_from_gharchive(push_event)

        assert event1.evidence_id == event2.evidence_id

    def test_different_events_produce_different_ids(self, gharchive_events):
        """Different events produce different evidence IDs."""
        push_events = [e for e in gharchive_events if e["type"] == "PushEvent"]
        assert len(push_events) >= 2

        event1 = create_push_event_from_gharchive(push_events[0])
        event2 = create_push_event_from_gharchive(push_events[1])

        assert event1.evidence_id != event2.evidence_id


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
