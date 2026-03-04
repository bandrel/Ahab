"""Tests for ahab - pure logic, mocked network, and command handler tests."""

import io
import tarfile
from unittest.mock import MagicMock, mock_open, patch

import pytest
import requests

from ahab import (
    DockerAPI,
    categorize_images,
    cmd_containers,
    cmd_deploy,
    cmd_exec,
    cmd_help,
    cmd_images,
    cmd_inspect,
    cmd_netcheck,
    cmd_rm,
    cmd_shell,
    cmd_ssh_keys,
    deploy_binary,
    deploy_container,
    discover_api,
    display_images,
    display_networks,
    display_registry_config,
    format_size,
    get_container_networks,
    interactive_shell,
    make_tar,
    parse_args,
    setup_ssh,
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


# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_api():
    return MagicMock(spec=DockerAPI)


# ---------------------------------------------------------------------------
# Display function tests
# ---------------------------------------------------------------------------


class TestDisplayImages:
    def test_prints_all_sections(self, capsys):
        preferred = [{"RepoTags": ["ubuntu:22.04"], "Id": "sha256:aabbccddee11", "Size": 77000000}]
        acceptable = [{"RepoTags": ["nginx:latest"], "Id": "sha256:112233445566", "Size": 140000000}]
        deprioritized = [{"RepoTags": ["alpine:3.18"], "Id": "sha256:ffeeddccbbaa", "Size": 5000000}]

        result = display_images(preferred, acceptable, deprioritized)
        out = capsys.readouterr().out

        assert "Preferred (Ubuntu/Debian)" in out
        assert "Other" in out
        assert "Deprioritized (Alpine/NixOS)" in out
        assert "ubuntu:22.04" in out
        assert "nginx:latest" in out
        assert "alpine:3.18" in out
        assert len(result) == 3

    def test_empty_inputs_produce_no_output(self, capsys):
        result = display_images([], [], [])
        out = capsys.readouterr().out
        assert out == ""
        assert result == []

    def test_untagged_images_show_placeholder(self, capsys):
        imgs = [{"RepoTags": None, "Id": "sha256:aabbccddee11", "Size": 1000}]
        display_images([], imgs, [])
        out = capsys.readouterr().out
        assert "<untagged>" in out


class TestDisplayRegistryConfig:
    def test_prints_mirrors_and_registries(self, mock_api, capsys):
        mock_api.info.return_value = {
            "RegistryConfig": {
                "Mirrors": ["https://mirror.example.com/"],
                "IndexConfigs": {
                    "docker.io": {"Official": True, "Secure": True},
                    "registry.local": {"Official": False, "Secure": False},
                },
                "InsecureRegistryCIDRs": ["10.0.0.0/8"],
            }
        }
        display_registry_config(mock_api)
        out = capsys.readouterr().out

        assert "mirror.example.com" in out
        assert "docker.io" in out
        assert "official" in out
        assert "INSECURE" in out
        assert "10.0.0.0/8" in out

    def test_handles_empty_config(self, mock_api, capsys):
        mock_api.info.return_value = {"RegistryConfig": {}}
        display_registry_config(mock_api)
        out = capsys.readouterr().out
        assert "none" in out

    def test_api_error_prints_warning(self, mock_api, capsys):
        mock_api.info.side_effect = requests.exceptions.ConnectionError("refused")
        display_registry_config(mock_api)
        err = capsys.readouterr().err
        assert "Could not retrieve daemon info" in err


class TestDisplayNetworks:
    def test_prints_network_table(self, mock_api, capsys):
        mock_api.list_networks.return_value = [
            {
                "Name": "bridge",
                "Driver": "bridge",
                "Scope": "local",
                "Id": "abc123def456789012",
                "IPAM": {"Config": [{"Subnet": "172.17.0.0/16", "Gateway": "172.17.0.1"}]},
                "Containers": {"c1": {}},
            }
        ]
        display_networks(mock_api)
        out = capsys.readouterr().out

        assert "bridge" in out
        assert "172.17.0.0/16" in out
        assert "gw 172.17.0.1" in out

    def test_handles_empty_network_list(self, mock_api, capsys):
        mock_api.list_networks.return_value = []
        display_networks(mock_api)
        out = capsys.readouterr().out
        assert "Docker Networks" in out

    def test_api_error_prints_warning(self, mock_api, capsys):
        mock_api.list_networks.side_effect = requests.exceptions.ConnectionError("refused")
        display_networks(mock_api)
        err = capsys.readouterr().err
        assert "Could not retrieve networks" in err


# ---------------------------------------------------------------------------
# Deployment function tests
# ---------------------------------------------------------------------------


class TestDeployContainer:
    @patch("ahab.time.sleep")
    def test_success(self, _sleep, mock_api):
        mock_api.create_container.return_value = "abcdef123456789000"
        mock_api.inspect_container.return_value = {"State": {"Running": True}}

        cid, data = deploy_container(mock_api, "ubuntu:22.04")

        assert cid == "abcdef123456789000"
        assert data["State"]["Running"] is True
        mock_api.create_container.assert_called_once()
        config = mock_api.create_container.call_args[0][0]
        assert config["Cmd"] == ["/bin/sh", "-c", "while true; do sleep 3600; done"]
        assert "ExposedPorts" not in config

    @patch("ahab.time.sleep")
    def test_with_host_port(self, _sleep, mock_api):
        mock_api.create_container.return_value = "abcdef123456789000"
        mock_api.inspect_container.return_value = {"State": {"Running": True}}

        deploy_container(mock_api, "ubuntu:22.04", host_port=2222)

        config = mock_api.create_container.call_args[0][0]
        assert "22/tcp" in config["ExposedPorts"]
        assert config["HostConfig"]["PortBindings"]["22/tcp"] == [{"HostPort": "2222"}]

    @patch("ahab.time.sleep")
    def test_container_not_running_returns_none(self, _sleep, mock_api):
        mock_api.create_container.return_value = "abcdef123456789000"
        mock_api.inspect_container.return_value = {"State": {"Running": False, "Status": "exited"}}

        cid, data = deploy_container(mock_api, "ubuntu:22.04")

        assert cid is None
        assert data is None


class TestSetupSsh:
    def test_installs_and_configures_ssh(self, mock_api):
        mock_api.exec_stream.return_value = "done"
        mock_api.exec_run.return_value = ""

        with patch("builtins.open", mock_open(read_data=b"ssh-rsa AAAA...")):
            setup_ssh(mock_api, "container123", "/tmp/key.pub")

        mock_api.exec_stream.assert_called_once()
        assert "openssh-server" in mock_api.exec_stream.call_args[0][1]
        assert mock_api.exec_run.call_count == 3
        mock_api.upload_archive.assert_called_once()

    def test_warns_on_apt_errors(self, mock_api, capsys):
        mock_api.exec_stream.return_value = "E: Unable to locate package"
        mock_api.exec_run.return_value = ""

        with patch("builtins.open", mock_open(read_data=b"ssh-rsa AAAA...")):
            setup_ssh(mock_api, "container123", "/tmp/key.pub")

        err = capsys.readouterr().err
        assert "apt-get reported errors" in err


class TestDeployBinary:
    def test_uploads_and_runs(self, mock_api):
        mock_api.exec_run.return_value = ""

        with patch("builtins.open", mock_open(read_data=b"\x7fELFbinary")):
            deploy_binary(mock_api, "container123", "/opt/payloads/implant")

        mock_api.upload_archive.assert_called_once()
        tar_path = mock_api.upload_archive.call_args[0][1]
        assert tar_path == "/tmp"

        mock_api.exec_run.assert_called_once()
        run_cmd = mock_api.exec_run.call_args[0][1]
        assert "implant" in run_cmd
        assert mock_api.exec_run.call_args[1]["detach"] is True


# ---------------------------------------------------------------------------
# Command handler tests
# ---------------------------------------------------------------------------


class TestCmdHelp:
    def test_prints_help_text(self, mock_api, capsys):
        cmd_help(mock_api, [])
        out = capsys.readouterr().out
        assert "containers" in out
        assert "deploy" in out
        assert "ssh-keys" in out
        assert "shell" in out


class TestCmdContainers:
    def test_renders_container_table(self, mock_api, capsys):
        mock_api.list_containers.return_value = [
            {
                "Id": "abcdef123456789000",
                "Image": "ubuntu:22.04",
                "Status": "Up 5 hours",
                "NetworkSettings": {
                    "Networks": {"bridge": {"IPAddress": "172.17.0.2"}},
                },
            }
        ]
        cmd_containers(mock_api, [])
        out = capsys.readouterr().out

        assert "abcdef123456" in out
        assert "ubuntu:22.04" in out
        assert "Up 5 hours" in out
        assert "172.17.0.2" in out

    def test_no_containers(self, mock_api, capsys):
        mock_api.list_containers.return_value = []
        cmd_containers(mock_api, [])
        out = capsys.readouterr().out
        assert "No containers found" in out

    def test_api_error(self, mock_api, capsys):
        mock_api.list_containers.side_effect = requests.exceptions.ConnectionError("refused")
        cmd_containers(mock_api, [])
        err = capsys.readouterr().err
        assert "Failed to list containers" in err


class TestCmdImages:
    def test_lists_categorized_images(self, mock_api, capsys):
        mock_api.list_images.return_value = [
            {"RepoTags": ["ubuntu:22.04"], "Id": "sha256:aabb", "Size": 77000000},
        ]
        cmd_images(mock_api, [])
        out = capsys.readouterr().out
        assert "1 image(s)" in out
        assert "ubuntu:22.04" in out

    def test_empty_image_list(self, mock_api, capsys):
        mock_api.list_images.return_value = []
        cmd_images(mock_api, [])
        out = capsys.readouterr().out
        assert "0 image(s)" in out


class TestCmdInspect:
    def test_prints_container_details(self, mock_api, capsys):
        mock_api.inspect_container.return_value = {
            "Id": "abcdef123456789000",
            "Name": "/my_container",
            "Config": {"Image": "ubuntu:22.04"},
            "State": {"Status": "running", "StartedAt": "2024-01-01T00:00:00Z", "Pid": 12345},
            "NetworkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.2"}}},
            "Mounts": [{"Source": "/", "Destination": "/host", "RW": True}],
            "HostConfig": {"Privileged": True},
        }
        cmd_inspect(mock_api, ["abcdef123456"])
        out = capsys.readouterr().out

        assert "abcdef123456" in out
        assert "my_container" in out
        assert "ubuntu:22.04" in out
        assert "running" in out
        assert "172.17.0.2" in out

    def test_404_prints_not_found(self, mock_api, capsys):
        resp = MagicMock()
        resp.status_code = 404
        mock_api.inspect_container.side_effect = requests.exceptions.HTTPError(response=resp)
        cmd_inspect(mock_api, ["deadbeef"])
        err = capsys.readouterr().err
        assert "Container not found" in err

    def test_missing_args(self, mock_api, capsys):
        cmd_inspect(mock_api, [])
        err = capsys.readouterr().err
        assert "Usage" in err


class TestCmdShell:
    def test_calls_exec_stream(self, mock_api, capsys):
        mock_api.exec_stream.return_value = "hello world\n"
        cmd_shell(mock_api, ["abcdef123456", "echo", "hello", "world"])
        mock_api.exec_stream.assert_called_once_with("abcdef123456", "echo hello world")

    def test_404_handled(self, mock_api, capsys):
        resp = MagicMock()
        resp.status_code = 404
        mock_api.exec_stream.side_effect = requests.exceptions.HTTPError(response=resp)
        cmd_shell(mock_api, ["deadbeef", "ls"])
        err = capsys.readouterr().err
        assert "Container not found" in err

    def test_missing_args(self, mock_api, capsys):
        cmd_shell(mock_api, ["container_only"])
        err = capsys.readouterr().err
        assert "Usage" in err


class TestCmdNetcheck:
    def test_runs_all_checks(self, mock_api, capsys):
        mock_api.inspect_container.return_value = {"State": {"Running": True}}
        mock_api.exec_run.side_effect = [
            "nameserver 8.8.8.8\n---\n142.250.80.46 google.com",
            "204",
            "1 packets transmitted, 1 received",
            "default via 172.17.0.1 dev eth0",
        ]
        cmd_netcheck(mock_api, ["abcdef123456"])
        out = capsys.readouterr().out

        assert "DNS resolution works" in out
        assert "HTTP connectivity works" in out
        assert "ICMP ping works" in out

    def test_404_handled(self, mock_api, capsys):
        resp = MagicMock()
        resp.status_code = 404
        mock_api.inspect_container.side_effect = requests.exceptions.HTTPError(response=resp)
        cmd_netcheck(mock_api, ["deadbeef"])
        err = capsys.readouterr().err
        assert "Container not found" in err


class TestCmdDeploy:
    @patch("ahab.time.sleep")
    def test_image_found_locally(self, _sleep, mock_api, capsys):
        mock_api.list_images.return_value = [
            {"RepoTags": ["ubuntu:22.04"], "Id": "sha256:aabb"},
        ]
        mock_api.create_container.return_value = "abcdef123456789000"
        mock_api.inspect_container.return_value = {
            "State": {"Running": True},
            "NetworkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.2"}}},
        }

        cmd_deploy(mock_api, ["ubuntu:22.04", "-p", "2222"])
        out = capsys.readouterr().out

        assert "abcdef123456" in out
        mock_api.pull_image.assert_not_called()

    @patch("ahab.time.sleep")
    @patch("builtins.input", side_effect=["", "y"])
    def test_image_not_found_user_pulls(self, _input, _sleep, mock_api, capsys):
        mock_api.list_images.return_value = []
        mock_api.create_container.return_value = "abcdef123456789000"
        mock_api.inspect_container.return_value = {
            "State": {"Running": True},
            "NetworkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.2"}}},
        }

        cmd_deploy(mock_api, ["ubuntu:22.04"])
        mock_api.pull_image.assert_called_once_with("ubuntu", "22.04")

    @patch("builtins.input", side_effect=["", "n"])
    def test_image_not_found_user_declines(self, _input, mock_api, capsys):
        mock_api.list_images.return_value = []
        cmd_deploy(mock_api, ["ubuntu:22.04"])
        out = capsys.readouterr().out
        assert "cancelled" in out.lower()

    @patch("ahab.time.sleep")
    def test_p_flag_parsed(self, _sleep, mock_api, capsys):
        mock_api.list_images.return_value = [
            {"RepoTags": ["ubuntu:22.04"], "Id": "sha256:aabb"},
        ]
        mock_api.create_container.return_value = "abcdef123456789000"
        mock_api.inspect_container.return_value = {
            "State": {"Running": True},
            "NetworkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.2"}}},
        }

        cmd_deploy(mock_api, ["-p", "4444", "ubuntu:22.04"])
        config = mock_api.create_container.call_args[0][0]
        assert config["HostConfig"]["PortBindings"]["22/tcp"] == [{"HostPort": "4444"}]


class TestCmdSshKeys:
    @patch("ahab.generate_ssh_keypair", return_value=("/tmp/key", "/tmp/key.pub"))
    @patch("builtins.open", mock_open(read_data=b"ssh-rsa AAAA..."))
    def test_auto_generates_keypair(self, mock_keygen, mock_api, capsys):
        mock_api.exec_stream.return_value = "done"
        mock_api.exec_run.return_value = ""
        mock_api.inspect_container.return_value = {
            "NetworkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.2"}}},
            "HostConfig": {"PortBindings": {}},
        }
        mock_api.base_url = "http://10.0.0.1:2375"

        cmd_ssh_keys(mock_api, ["abcdef123456"])
        mock_keygen.assert_called_once()

    @patch("os.path.isfile", return_value=True)
    @patch("builtins.open", mock_open(read_data=b"ssh-rsa AAAA..."))
    def test_uses_provided_key_path(self, _isfile, mock_api, capsys):
        mock_api.exec_stream.return_value = "done"
        mock_api.exec_run.return_value = ""
        mock_api.inspect_container.return_value = {
            "NetworkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.2"}}},
            "HostConfig": {"PortBindings": {}},
        }
        mock_api.base_url = "http://10.0.0.1:2375"

        cmd_ssh_keys(mock_api, ["abcdef123456", "/tmp/my_key.pub"])
        out = capsys.readouterr().out
        assert "SSH ready" in out

    def test_missing_args(self, mock_api, capsys):
        cmd_ssh_keys(mock_api, [])
        err = capsys.readouterr().err
        assert "Usage" in err


class TestCmdExec:
    @patch("os.path.isfile", return_value=True)
    @patch("builtins.open", mock_open(read_data=b"\x7fELFbinary"))
    def test_uploads_and_runs(self, _isfile, mock_api, capsys):
        mock_api.exec_run.return_value = ""
        cmd_exec(mock_api, ["abcdef123456", "/opt/implant"])
        mock_api.upload_archive.assert_called_once()
        out = capsys.readouterr().out
        assert "implant" in out

    @patch("os.path.isfile", return_value=False)
    def test_file_not_found(self, _isfile, mock_api, capsys):
        cmd_exec(mock_api, ["abcdef123456", "/nonexistent"])
        err = capsys.readouterr().err
        assert "Binary not found" in err

    def test_missing_args(self, mock_api, capsys):
        cmd_exec(mock_api, ["container_only"])
        err = capsys.readouterr().err
        assert "Usage" in err


class TestCmdRm:
    @patch("builtins.input", return_value="y")
    def test_user_confirms_removal(self, _input, mock_api, capsys):
        mock_api.inspect_container.return_value = {
            "Id": "abcdef123456789000",
            "Config": {"Image": "ubuntu:22.04"},
        }
        cmd_rm(mock_api, ["abcdef123456"])
        mock_api.stop_container.assert_called_once()
        mock_api.remove_container.assert_called_once()
        out = capsys.readouterr().out
        assert "removed" in out

    @patch("builtins.input", return_value="n")
    def test_user_declines_removal(self, _input, mock_api, capsys):
        mock_api.inspect_container.return_value = {
            "Id": "abcdef123456789000",
            "Config": {"Image": "ubuntu:22.04"},
        }
        cmd_rm(mock_api, ["abcdef123456"])
        mock_api.stop_container.assert_not_called()
        mock_api.remove_container.assert_not_called()

    def test_404_handled(self, mock_api, capsys):
        resp = MagicMock()
        resp.status_code = 404
        mock_api.inspect_container.side_effect = requests.exceptions.HTTPError(response=resp)
        cmd_rm(mock_api, ["deadbeef"])
        err = capsys.readouterr().err
        assert "Container not found" in err


class TestInteractiveShell:
    @patch("builtins.input", side_effect=["help", "exit"])
    @patch("ahab._setup_completer")
    def test_dispatches_known_commands(self, _completer, _input, mock_api, capsys):
        interactive_shell(mock_api, "10.0.0.1")
        out = capsys.readouterr().out
        assert "commands:" in out

    @patch("builtins.input", side_effect=["bogus", "quit"])
    @patch("ahab._setup_completer")
    def test_unknown_command_prints_warning(self, _completer, _input, mock_api, capsys):
        interactive_shell(mock_api, "10.0.0.1")
        err = capsys.readouterr().err
        assert "Unknown command" in err

    @patch("builtins.input", side_effect=["exit"])
    @patch("ahab._setup_completer")
    def test_exit_breaks_loop(self, _completer, _input, mock_api, capsys):
        interactive_shell(mock_api, "10.0.0.1")
        out = capsys.readouterr().out
        assert "Exiting" in out
