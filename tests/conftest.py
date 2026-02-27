"""Shared fixtures for IR-Agent tests."""

import os

# MUST set env vars BEFORE any app import so pydantic-settings picks them up.
os.environ["ENVIRONMENT"] = "testing"
os.environ["LLM_API_KEY"] = ""
os.environ["BETTER_STACK_SOURCE_TOKEN"] = ""
os.environ["MY_API_TOKEN"] = ""  # disable auth in tests
os.environ["CORS_ORIGINS"] = "*"

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="session")
def client():
    """FastAPI TestClient (no real server needed)."""
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def sample_event():
    """A sample security event for testing."""
    return {
        "timestamp": "2024-01-15T08:37:00Z",
        "event_id": 4688,
        "hostname": "WS-USER01",
        "event_type": "process_creation",
        "process_name": "cmd.exe",
        "command_line": "cmd.exe /c vssadmin delete shadows /all /quiet",
        "parent_image": "outlook.exe",
        "user": "john.doe",
        "channel": "Security",
    }


@pytest.fixture()
def benign_event():
    """A benign event for testing."""
    return {
        "timestamp": "2024-01-15T09:00:00Z",
        "event_id": 4624,
        "hostname": "WS-USER01",
        "event_type": "logon",
        "process_name": "explorer.exe",
        "command_line": "",
        "user": "john.doe",
        "channel": "Security",
    }
