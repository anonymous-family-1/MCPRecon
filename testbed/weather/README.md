# Weather MCP Server

This is the testbed weather server used in the experiment.

**Overview**
- `server.py` runs the weather server in stdio mode.
- `http-weather-server.py` runs the weather server in HTTP (ASGI) mode.

**Quick Start (HTTP Mode)**
1. Ensure `uv` is installed.
2. Clone and enter the repo:

```bash
git clone <repo-url>
cd MCPRecon/testbed/weather
```

3. Install dependencies:

```bash
uv sync
```

4. Run the HTTP server:

```bash
python http-weather-server.py
```

It listens on `http://127.0.0.1:8000`.

**Codex Configuration**
Edit `~/.codex/config.toml`.

HTTP server:

```toml
[mcp_servers.HttpWeatherServer]
url = "http://127.0.0.1:8000/mcp"
```

Stdio server:

```toml
[mcp_servers.StdioWeatherServer]
command = "<repo-dir>/testbed/weather/.venv/bin/python"
args = ["<repo-dir>/testbed/weather/server.py"]
```

Example:

```toml
[mcp_servers.StdioWeatherServer]
command = "/home/alex/sample-project/MCPRecon/testbed/weather/.venv/bin/python"
args = ["/home/alex/sample-project/MCPRecon/testbed/weather/server.py"]
```

**VS Code Copilot Configuration**
Create `mcp.json` in the folder you open in VS Code.

```json
{
  "servers": {
    "weatherhttp": {
      "url": "http://localhost:8000/mcp"
    },
    "weatherstdio": {
      "command": "<repo-dir>/testbed/weather/.venv/bin/python",
      "args": ["<repo-dir>/testbed/weather/server.py"],
      "env": {},
      "cwd": "<your-workspace-dir>"
    }
  }
}
```

Example:

```json
{
  "servers": {
    "weatherhttp": {
      "url": "http://localhost:8000/mcp"
    },
    "weatherstdio": {
      "command": "/home/alex/sample-project/MCPRecon/testbed/weather/.venv/bin/python",
      "args": ["/home/alex/sample-project/MCPRecon/testbed/weather/server.py"],
      "env": {},
      "cwd": "/home/alex/sample-project"
    }
  }
}
```
