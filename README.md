# Ahab

Interactive Docker Remote API exploitation tool for authorized pentesting.

![image](https://user-images.githubusercontent.com/3598052/208483570-18969205-eec8-4c70-ab3d-b5b97aa4d249.png)

## Features

- Connects to unauthenticated Docker APIs (ports 2375/2376 with auto-discovery)
- Optional SOCKS5 proxy support for pivoting through tunnels
- Deploys privileged containers with host filesystem mounted read-write
- SSH key deployment and sshd setup inside containers
- Binary upload and background execution
- Interactive shell with tab completion
- Image categorization (prefers Ubuntu/Debian for payload compatibility)
- Network enumeration and connectivity testing

## Installation

Requires Python 3.11+.

```bash
# Install with uv
uv pip install .

# With SOCKS5 proxy support
uv pip install ".[proxy]"

# Development dependencies
uv pip install ".[dev]"
```

## Usage

```bash
# Direct connection
ahab --target 10.0.0.1

# Through a SOCKS5 proxy
ahab --target 10.0.0.1 --proxy socks5h://127.0.0.1:1080

# Specify a non-standard port
ahab --target 10.0.0.1 --port 4243
```

## Interactive Commands

| Command | Description |
|---------|-------------|
| `containers` | List all containers (running + stopped) |
| `images` | List available images (categorized) |
| `registries` | Show registry configuration |
| `networks` | Show Docker networks |
| `deploy <image> [-p <port>]` | Deploy a privileged container |
| `inspect <container_id>` | Show detailed container info |
| `ssh-keys <container_id> [key_path]` | Push SSH keys (auto-generates if no path) |
| `exec <container_id> <binary_path>` | Upload and execute a binary (detached) |
| `shell <container_id> <command>` | Execute a command inside a container |
| `netcheck <container_id>` | Test internet connectivity from container |
| `rm <container_id>` | Stop and remove a container |
| `help` | Show available commands |
| `exit` / `quit` | Exit the shell |

## Development

```bash
# Run tests
pytest -q tests/

# Lint
ruff check ahab.py

# Format check
ruff format --check ahab.py
```
