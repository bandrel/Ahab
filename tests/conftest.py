"""Shared fixtures and automatic test markers for ahab test suite."""

from unittest.mock import MagicMock

import pytest
import requests

from ahab import DockerAPI


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Auto-apply 'unit' or 'integration' markers based on file location."""
    for item in items:
        if "test_integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        elif not any(item.iter_markers(name="integration")):
            item.add_marker(pytest.mark.unit)


@pytest.fixture
def mock_api():
    """A fully-mocked DockerAPI instance (no real HTTP)."""
    return MagicMock(spec=DockerAPI)


@pytest.fixture
def docker_api_with_mock_session():
    """A real DockerAPI with its session replaced by a mock.

    Use this to test method-level branch logic (status codes, JSON parsing)
    without making real HTTP requests.
    """
    api = DockerAPI("http://10.0.0.1:2375")
    api.session = MagicMock(spec=requests.Session)
    return api
