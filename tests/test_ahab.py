"""Tests for ahab - pure logic and mocked network tests."""

import io
import tarfile
from unittest.mock import MagicMock, patch

import pytest

from ahab import (
    DockerAPI,
    categorize_images,
    discover_api,
    format_size,
    get_container_networks,
    make_tar,
    parse_args,
)

# ---------------------------------------------------------------------------
# Pure logic tests
# ---------------------------------------------------------------------------


class TestFormatSize:
    def test_none_returns_question_mark(self):
        assert format_size(None) == "?"

    def test_bytes(self):
        assert format_size(512) == "512.0 B"

    def test_kilobytes(self):
        assert format_size(2048) == "2.0 KB"

    def test_megabytes(self):
        assert format_size(5 * 1024 * 1024) == "5.0 MB"

    def test_gigabytes(self):
        assert format_size(3 * 1024**3) == "3.0 GB"

    def test_terabytes(self):
        assert format_size(2 * 1024**4) == "2.0 TB"

    def test_zero(self):
        assert format_size(0) == "0.0 B"


class TestCategorizeImages:
    def test_empty_list(self):
        preferred, acceptable, deprioritized = categorize_images([])
        assert preferred == []
        assert acceptable == []
        assert deprioritized == []

    def test_preferred_ubuntu(self):
        images = [{"RepoTags": ["ubuntu:latest"], "Id": "sha256:abc123"}]
        preferred, acceptable, deprioritized = categorize_images(images)
        assert len(preferred) == 1
        assert len(acceptable) == 0
        assert len(deprioritized) == 0

    def test_preferred_debian(self):
        images = [{"RepoTags": ["debian:bullseye"], "Id": "sha256:def456"}]
        preferred, acceptable, deprioritized = categorize_images(images)
        assert len(preferred) == 1

    def test_deprioritized_alpine(self):
        images = [{"RepoTags": ["alpine:3.18"], "Id": "sha256:ghi789"}]
        preferred, acceptable, deprioritized = categorize_images(images)
        assert len(deprioritized) == 1
        assert len(preferred) == 0

    def test_deprioritized_nixos(self):
        images = [{"RepoTags": ["nixos/nix:latest"], "Id": "sha256:jkl012"}]
        preferred, acceptable, deprioritized = categorize_images(images)
        assert len(deprioritized) == 1

    def test_acceptable_other(self):
        images = [{"RepoTags": ["nginx:latest"], "Id": "sha256:mno345"}]
        preferred, acceptable, deprioritized = categorize_images(images)
        assert len(acceptable) == 1
        assert len(preferred) == 0
        assert len(deprioritized) == 0

    def test_no_tags(self):
        images = [{"RepoTags": None, "Id": "sha256:pqr678"}]
        preferred, acceptable, deprioritized = categorize_images(images)
        assert len(acceptable) == 1

    def test_mixed(self):
        images = [
            {"RepoTags": ["ubuntu:22.04"], "Id": "sha256:a"},
            {"RepoTags": ["alpine:3.18"], "Id": "sha256:b"},
            {"RepoTags": ["nginx:latest"], "Id": "sha256:c"},
            {"RepoTags": ["debian:bookworm"], "Id": "sha256:d"},
        ]
        preferred, acceptable, deprioritized = categorize_images(images)
        assert len(preferred) == 2
        assert len(acceptable) == 1
        assert len(deprioritized) == 1


class TestMakeTar:
    def test_creates_valid_tar(self):
        data = b"hello world"
        tar_bytes = make_tar("test.txt", data, mode=0o644)

        buf = io.BytesIO(tar_bytes)
        with tarfile.open(fileobj=buf, mode="r") as tar:
            members = tar.getmembers()
            assert len(members) == 1
            assert members[0].name == "test.txt"
            assert members[0].size == len(data)
            assert members[0].mode == 0o644

            extracted = tar.extractfile(members[0])
            assert extracted is not None
            assert extracted.read() == data

    def test_default_mode_is_executable(self):
        tar_bytes = make_tar("binary", b"\x00\x01\x02")
        buf = io.BytesIO(tar_bytes)
        with tarfile.open(fileobj=buf, mode="r") as tar:
            assert tar.getmembers()[0].mode == 0o755

    def test_empty_data(self):
        tar_bytes = make_tar("empty", b"")
        buf = io.BytesIO(tar_bytes)
        with tarfile.open(fileobj=buf, mode="r") as tar:
            assert tar.getmembers()[0].size == 0


class TestGetContainerNetworks:
    def test_single_network(self):
        inspect_data = {
            "NetworkSettings": {
                "Networks": {
                    "bridge": {"IPAddress": "172.17.0.2"},
                }
            }
        }
        result = get_container_networks(inspect_data)
        assert result == {"bridge": "172.17.0.2"}

    def test_multiple_networks(self):
        inspect_data = {
            "NetworkSettings": {
                "Networks": {
                    "bridge": {"IPAddress": "172.17.0.2"},
                    "custom": {"IPAddress": "10.0.0.5"},
                }
            }
        }
        result = get_container_networks(inspect_data)
        assert result == {"bridge": "172.17.0.2", "custom": "10.0.0.5"}

    def test_no_ip(self):
        inspect_data = {
            "NetworkSettings": {
                "Networks": {
                    "bridge": {"IPAddress": ""},
                }
            }
        }
        result = get_container_networks(inspect_data)
        assert result == {}

    def test_empty_networks(self):
        inspect_data = {"NetworkSettings": {"Networks": {}}}
        result = get_container_networks(inspect_data)
        assert result == {}

    def test_missing_network_settings(self):
        result = get_container_networks({})
        assert result == {}


class TestParseArgs:
    def test_target_required(self):
        with pytest.raises(SystemExit):
            parse_args([])

    def test_target_only(self):
        args = parse_args(["--target", "10.0.0.1"])
        assert args.target == "10.0.0.1"
        assert args.proxy is None
        assert args.port is None

    def test_all_args(self):
        args = parse_args(
            [
                "--target",
                "10.0.0.1",
                "--proxy",
                "socks5h://127.0.0.1:1080",
                "--port",
                "2375",
            ]
        )
        assert args.target == "10.0.0.1"
        assert args.proxy == "socks5h://127.0.0.1:1080"
        assert args.port == 2375


class TestDockerAPIUrlConstruction:
    def test_url_construction(self):
        api = DockerAPI("http://10.0.0.1:2375")
        assert api._url("/_ping") == "http://10.0.0.1:2375/_ping"
        assert api._url("/version") == "http://10.0.0.1:2375/version"

    def test_trailing_slash_stripped(self):
        api = DockerAPI("http://10.0.0.1:2375/")
        assert api._url("/_ping") == "http://10.0.0.1:2375/_ping"

    def test_no_proxy(self):
        api = DockerAPI("http://10.0.0.1:2375")
        assert api.session.proxies == {}

    def test_with_proxy(self):
        api = DockerAPI("http://10.0.0.1:2375", proxy_url="socks5h://127.0.0.1:1080")
        assert api.session.proxies["http"] == "socks5h://127.0.0.1:1080"
        assert api.session.proxies["https"] == "socks5h://127.0.0.1:1080"


# ---------------------------------------------------------------------------
# Mocked network tests
# ---------------------------------------------------------------------------


class TestDiscoverApi:
    @patch("ahab.DockerAPI")
    def test_success_on_first_port(self, mock_api_cls):
        mock_api = MagicMock()
        mock_api.ping.return_value = True
        mock_api.version.return_value = {
            "Version": "24.0.0",
            "ApiVersion": "1.43",
            "Os": "linux",
            "Arch": "amd64",
        }
        mock_api_cls.return_value = mock_api

        result = discover_api("10.0.0.1")
        assert result is mock_api
        mock_api_cls.assert_called_once_with("http://10.0.0.1:2375", None)

    @patch("ahab.DockerAPI")
    def test_auth_required_tries_next_port(self, mock_api_cls):
        mock_api_2375 = MagicMock()
        mock_api_2375.ping.return_value = False

        mock_api_2376 = MagicMock()
        mock_api_2376.ping.return_value = True
        mock_api_2376.version.return_value = {
            "Version": "24.0.0",
            "ApiVersion": "1.43",
            "Os": "linux",
            "Arch": "amd64",
        }
        mock_api_cls.side_effect = [mock_api_2375, mock_api_2376]

        result = discover_api("10.0.0.1")
        assert result is mock_api_2376

    @patch("ahab.DockerAPI")
    def test_unreachable_returns_none(self, mock_api_cls):
        import requests

        mock_api = MagicMock()
        mock_api.ping.side_effect = requests.exceptions.ConnectionError()
        mock_api_cls.return_value = mock_api

        result = discover_api("10.0.0.1")
        assert result is None

    @patch("ahab.DockerAPI")
    def test_override_port(self, mock_api_cls):
        mock_api = MagicMock()
        mock_api.ping.return_value = True
        mock_api.version.return_value = {
            "Version": "24.0.0",
            "ApiVersion": "1.43",
            "Os": "linux",
            "Arch": "amd64",
        }
        mock_api_cls.return_value = mock_api

        result = discover_api("10.0.0.1", override_port=9999)
        assert result is mock_api
        mock_api_cls.assert_called_once_with("http://10.0.0.1:9999", None)

    @patch("ahab.DockerAPI")
    def test_override_port_2376_uses_https(self, mock_api_cls):
        mock_api = MagicMock()
        mock_api.ping.return_value = True
        mock_api.version.return_value = {"Version": "24.0.0", "ApiVersion": "1.43", "Os": "linux", "Arch": "amd64"}
        mock_api_cls.return_value = mock_api

        discover_api("10.0.0.1", override_port=2376)
        mock_api_cls.assert_called_once_with("https://10.0.0.1:2376", None)

    @patch("ahab.DockerAPI")
    def test_proxy_passed_through(self, mock_api_cls):
        mock_api = MagicMock()
        mock_api.ping.return_value = True
        mock_api.version.return_value = {"Version": "24.0.0", "ApiVersion": "1.43", "Os": "linux", "Arch": "amd64"}
        mock_api_cls.return_value = mock_api

        discover_api("10.0.0.1", proxy_url="socks5h://127.0.0.1:1080")
        mock_api_cls.assert_called_once_with("http://10.0.0.1:2375", "socks5h://127.0.0.1:1080")
