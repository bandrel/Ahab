"""Tests for DockerAPI methods using a real object with mocked HTTP session."""

import json

import pytest
import requests


def _mock_response(status_code=200, json_data=None, text="", iter_lines=None, iter_content=None, stream=False):
    """Build a mock requests.Response with the given attributes."""
    resp = requests.Response()
    resp.status_code = status_code
    if json_data is not None:
        resp._content = json.dumps(json_data).encode()
    elif text:
        resp._content = text.encode()
    else:
        resp._content = b""
    if iter_lines is not None:
        resp.iter_lines = lambda: iter(iter_lines)
    if iter_content is not None:
        resp.iter_content = lambda chunk_size=4096: iter(iter_content)
    return resp


class TestDockerAPIPing:
    def test_200_returns_true(self, docker_api_with_mock_session):
        api = docker_api_with_mock_session
        api.session.get.return_value = _mock_response(200)
        assert api.ping() is True

    def test_401_returns_false(self, docker_api_with_mock_session):
        api = docker_api_with_mock_session
        api.session.get.return_value = _mock_response(401)
        assert api.ping() is False

    def test_403_returns_false(self, docker_api_with_mock_session):
        api = docker_api_with_mock_session
        api.session.get.return_value = _mock_response(403)
        assert api.ping() is False

    def test_500_raises(self, docker_api_with_mock_session):
        api = docker_api_with_mock_session
        api.session.get.return_value = _mock_response(500)
        with pytest.raises(requests.exceptions.HTTPError):
            api.ping()


class TestDockerAPIVersion:
    def test_returns_parsed_json(self, docker_api_with_mock_session):
        api = docker_api_with_mock_session
        version_data = {"Version": "24.0.0", "ApiVersion": "1.43"}
        api.session.get.return_value = _mock_response(200, json_data=version_data)
        result = api.version()
        assert result["Version"] == "24.0.0"
        assert result["ApiVersion"] == "1.43"


class TestDockerAPIPullImage:
    def test_streaming_status(self, docker_api_with_mock_session, capsys):
        api = docker_api_with_mock_session
        lines = [
            json.dumps({"status": "Pulling from library/ubuntu"}).encode(),
            json.dumps({"status": "Downloading"}).encode(),
            json.dumps({"status": "Pull complete"}).encode(),
        ]
        api.session.post.return_value = _mock_response(200, iter_lines=lines)
        api.pull_image("ubuntu", "latest")
        out = capsys.readouterr().out
        assert "Pulling from library/ubuntu" in out

    def test_error_in_stream_raises(self, docker_api_with_mock_session):
        api = docker_api_with_mock_session
        lines = [
            json.dumps({"error": "manifest not found"}).encode(),
        ]
        api.session.post.return_value = _mock_response(200, iter_lines=lines)
        with pytest.raises(RuntimeError, match="manifest not found"):
            api.pull_image("ubuntu", "nonexistent")

    def test_json_decode_error_silenced(self, docker_api_with_mock_session):
        api = docker_api_with_mock_session
        lines = [b"not json at all", json.dumps({"status": "done"}).encode()]
        api.session.post.return_value = _mock_response(200, iter_lines=lines)
        api.pull_image("ubuntu", "latest")


class TestDockerAPIStartContainer:
    def test_304_already_running(self, docker_api_with_mock_session, capsys):
        api = docker_api_with_mock_session
        api.session.post.return_value = _mock_response(304)
        api.start_container("abc123")
        out = capsys.readouterr().out
        assert "already running" in out

    def test_204_success(self, docker_api_with_mock_session):
        api = docker_api_with_mock_session
        api.session.post.return_value = _mock_response(204)
        api.start_container("abc123")


class TestDockerAPIStopContainer:
    def test_304_already_stopped(self, docker_api_with_mock_session):
        api = docker_api_with_mock_session
        api.session.post.return_value = _mock_response(304)
        api.stop_container("abc123")

    def test_204_success(self, docker_api_with_mock_session):
        api = docker_api_with_mock_session
        api.session.post.return_value = _mock_response(204)
        api.stop_container("abc123")


class TestDockerAPIExecStart:
    def test_detach_returns_empty_string(self, docker_api_with_mock_session):
        api = docker_api_with_mock_session
        api.session.post.return_value = _mock_response(200)
        result = api.exec_start("exec123", detach=True)
        assert result == ""

    def test_stream_returns_response(self, docker_api_with_mock_session):
        api = docker_api_with_mock_session
        resp = _mock_response(200)
        api.session.post.return_value = resp
        result = api.exec_start("exec123", stream=True)
        assert result is resp

    def test_normal_returns_text(self, docker_api_with_mock_session):
        api = docker_api_with_mock_session
        api.session.post.return_value = _mock_response(200, text="hello world")
        result = api.exec_start("exec123")
        assert result == "hello world"
