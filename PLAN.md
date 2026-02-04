# vibefs — Vibe File Server

A simple, secure file preview service designed for AI agents to share files with users via time-limited URLs.

## Concept

Agents often need to show files to users. vibefs provides a lightweight web server where files must be explicitly authorized before they can be accessed, with automatic expiration.

## Architecture

- **Single-file core**: All logic lives in one Python file (`vibefs.py`) for maximum portability
- **CLI**: click-based, subcommands for serving and authorizing
- **Web**: Bottle (zero-dependency micro framework)
- **Storage**: SQLite (Python built-in), stores authorization records

## Commands

```
vibefs allow <path> [--ttl 3600]                # Authorize a file, auto-start daemon if needed, output access URL
vibefs revoke <token>                           # Revoke access to a file
vibefs list                                     # List currently authorized files
vibefs serve [--port 8080] [--host 0.0.0.0]    # Manually start server in foreground (for debugging)
vibefs stop                                     # Manually stop the daemon
vibefs status                                   # Check if daemon is running
```

## URL Format

```
http://localhost:8080/f/{short_hash}/{filename}
```

- `short_hash`: 6-8 char random token, not derived from path (no path leakage)
- `filename`: original filename for readability (e.g. `report.txt`)
- Full filesystem path is never exposed

## Flow

1. Agent runs `vibefs allow /home/user/projects/output/report.txt`
2. vibefs generates a short token, stores `{token, filepath, filename, created_at, expires_at}` in SQLite
3. Checks if daemon is running (via PID file):
   - Not running → fork a background daemon process that starts the Bottle server
   - Already running → skip
4. Outputs: `http://localhost:8080/f/a3b7c2/report.txt`
5. User clicks link → vibefs checks token in SQLite:
   - Valid & not expired → read file, return content with appropriate content-type
   - Expired → show "This file is no longer available" page
   - Unknown token → 404
6. Default TTL: 1 hour, configurable via `--ttl` (seconds)

## Daemon Architecture

The server runs as an implicit, on-demand daemon — no manual `serve` required.

### Auto-start
- `allow` command checks PID file (`~/.vibefs/vibefs.pid`) to see if daemon is alive
- If not running, forks a background daemon process (double-fork or `subprocess` detach)
- Daemon writes its PID to the PID file on startup

### Auto-stop (self-cleanup)
- Daemon runs a background check every 60 seconds
- On each check: query SQLite for any non-expired authorizations
- If ALL authorizations have expired → daemon exits gracefully, removes PID file
- This ensures the server only runs when there are active files to serve

### State directory: `~/.vibefs/`
- `~/.vibefs/vibefs.db` — SQLite database (always use this path, not cwd)
- `~/.vibefs/vibefs.pid` — PID file for daemon liveness check
- `~/.vibefs/vibefs.log` — daemon log output (stdout/stderr redirect)

### PID file liveness check
- Read PID from file → `os.kill(pid, 0)` to check if process is alive
- If PID file exists but process is dead → stale PID file, clean up and restart

## File Format Support

- **Phase 1**: Plain text files (text/plain)
- **Future**: Markdown rendering, images, PDFs, syntax highlighting, etc.

## Dependencies

- `click` — CLI framework
- `bottle` — Web framework
- Everything else is Python stdlib (sqlite3, hashlib, os, etc.)

## Project Structure

```
vibefs/
├── PLAN.md          # This file
├── vibefs.py        # All core logic (single file)
├── pyproject.toml   # Project metadata, dependencies & entry point
├── uv.lock          # Lock file (auto-generated)
└── README.md        # Usage documentation
```

## Packaging & Tooling

Single-file core, but proper Python packaging practices:

- **uv** as package manager (`uv init`, `uv add`, `uv run`)
- **pyproject.toml** for metadata, dependencies, and CLI entry point
- Entry point via `[project.scripts]`: `vibefs = "vibefs:cli"`
- Install with `uv pip install -e .` or run directly with `uv run vibefs`
- No `src/` layout — `vibefs.py` sits at project root, keeps it flat and simple

## Design Principles

- **Portable**: Single Python file, minimal dependencies
- **Proper packaging**: uv + pyproject.toml, installable as a real Python package
- **Secure by default**: Nothing is accessible until explicitly allowed
- **Ephemeral**: Authorizations expire automatically
- **Agent-friendly**: CLI output is clean and parseable
