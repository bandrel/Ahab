"""Integration tests against a live Docker daemon.

Auto-marked as 'integration' by conftest.py. Requires a Docker daemon
accessible via TCP (e.g. Docker-in-Docker on localhost:2375).

Set AHAB_TEST_DOCKER_URL to override the default endpoint.
"""

import contextlib
import os

import pytest
import requests

from ahab import DockerAPI

DOCKER_URL = os.environ.get("AHAB_TEST_DOCKER_URL", "http://localhost:2375")


@pytest.fixture(scope="module")
def live_api():
    """Module-scoped real DockerAPI; skips if Docker is unreachable."""
    api = DockerAPI(DOCKER_URL)
    try:
        if not api.ping():
            pytest.skip(f"Docker API at {DOCKER_URL} requires authentication")
    except requests.exceptions.ConnectionError:
        pytest.skip(f"Docker API at {DOCKER_URL} is not reachable")
    return api


@pytest.fixture
def cleanup_container(live_api):
    """Yields a list to collect container IDs; stops/removes them on teardown."""
    container_ids: list[str] = []
    yield container_ids
    for cid in container_ids:
        with contextlib.suppress(Exception):
            live_api.stop_container(cid, timeout=3)
        with contextlib.suppress(Exception):
            live_api.remove_container(cid, force=True)


class TestLiveDockerAPI:
    def test_ping(self, live_api):
        assert live_api.ping() is True

    def test_version(self, live_api):
        ver = live_api.version()
        assert "Version" in ver
        assert "ApiVersion" in ver

    def test_info(self, live_api):
        info = live_api.info()
        assert "ID" in info or "ServerVersion" in info

    def test_list_images(self, live_api):
        images = live_api.list_images()
        assert isinstance(images, list)

    def test_list_networks(self, live_api):
        networks = live_api.list_networks()
        assert isinstance(networks, list)
        assert len(networks) > 0

    def test_list_containers(self, live_api):
        containers = live_api.list_containers(all=True)
        assert isinstance(containers, list)


class TestLiveContainerLifecycle:
    def test_create_start_inspect_stop_remove(self, live_api, cleanup_container):
        config = {
            "Image": "alpine:latest",
            "Cmd": ["sleep", "30"],
            "Tty": False,
            "HostConfig": {},
        }
        container_id = live_api.create_container(config)
        cleanup_container.append(container_id)

        live_api.start_container(container_id)

        data = live_api.inspect_container(container_id)
        assert data["State"]["Running"] is True

        live_api.stop_container(container_id, timeout=3)

        data = live_api.inspect_container(container_id)
        assert data["State"]["Running"] is False

        live_api.remove_container(container_id)
        cleanup_container.clear()

    def test_exec_run(self, live_api, cleanup_container):
        config = {
            "Image": "alpine:latest",
            "Cmd": ["sleep", "30"],
            "Tty": False,
            "HostConfig": {},
        }
        container_id = live_api.create_container(config)
        cleanup_container.append(container_id)

        live_api.start_container(container_id)

        output = live_api.exec_run(container_id, "echo hello")
        assert "hello" in output
