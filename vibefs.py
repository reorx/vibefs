"""vibefs — Vibe File Server

A simple, secure file preview service designed for AI agents to share files
with users via time-limited URLs.
"""

import atexit
import mimetypes
import os
import secrets
import signal
import sqlite3
import subprocess
import sys
import threading
import time

import bottle
import click

# --- Constants ---

DEFAULT_PORT = 17173
DEFAULT_HOST = '0.0.0.0'
DEFAULT_TTL = 3600  # 1 hour
TOKEN_LENGTH = 4  # bytes, produces 8 hex chars
CLEANUP_INTERVAL = 60  # seconds between auto-stop checks

# --- State Directory ---

STATE_DIR = os.path.expanduser('~/.vibefs')
DB_PATH = os.path.join(STATE_DIR, 'vibefs.db')
PID_PATH = os.path.join(STATE_DIR, 'vibefs.pid')
LOG_PATH = os.path.join(STATE_DIR, 'vibefs.log')


def ensure_state_dir():
    os.makedirs(STATE_DIR, exist_ok=True)


# --- Database ---


def get_db_path():
    return os.environ.get('VIBEFS_DB', DB_PATH)


def get_db():
    db = sqlite3.connect(get_db_path())
    db.row_factory = sqlite3.Row
    db.execute("""
        CREATE TABLE IF NOT EXISTS authorizations (
            token TEXT PRIMARY KEY,
            filepath TEXT NOT NULL,
            filename TEXT NOT NULL,
            created_at REAL NOT NULL,
            expires_at REAL NOT NULL
        )
    """)
    db.commit()
    return db


def add_authorization(filepath, ttl):
    """Add an authorization record and return (token, filename)."""
    abs_path = os.path.abspath(filepath)
    if not os.path.isfile(abs_path):
        raise FileNotFoundError(f'File not found: {abs_path}')

    token = secrets.token_hex(TOKEN_LENGTH)
    filename = os.path.basename(abs_path)
    now = time.time()

    db = get_db()
    db.execute(
        'INSERT INTO authorizations (token, filepath, filename, created_at, expires_at) VALUES (?, ?, ?, ?, ?)',
        (token, abs_path, filename, now, now + ttl),
    )
    db.commit()
    db.close()
    return token, filename


def remove_authorization(token):
    """Remove an authorization record. Returns True if it existed."""
    db = get_db()
    cursor = db.execute('DELETE FROM authorizations WHERE token = ?', (token,))
    db.commit()
    deleted = cursor.rowcount > 0
    db.close()
    return deleted


def list_authorizations():
    """Return all authorization records."""
    db = get_db()
    rows = db.execute(
        'SELECT token, filepath, filename, created_at, expires_at FROM authorizations ORDER BY created_at DESC'
    ).fetchall()
    db.close()
    return rows


def lookup_authorization(token):
    """Look up a token. Returns (row, status) where status is 'valid', 'expired', or 'not_found'."""
    db = get_db()
    row = db.execute(
        'SELECT token, filepath, filename, created_at, expires_at FROM authorizations WHERE token = ?',
        (token,),
    ).fetchone()
    db.close()

    if row is None:
        return None, 'not_found'
    if time.time() > row['expires_at']:
        return row, 'expired'
    return row, 'valid'


def has_active_authorizations():
    """Check if there are any non-expired authorizations."""
    db = get_db()
    row = db.execute(
        'SELECT COUNT(*) as cnt FROM authorizations WHERE expires_at > ?',
        (time.time(),),
    ).fetchone()
    db.close()
    return row['cnt'] > 0


# --- PID File Management ---


def read_pid():
    """Read PID from file. Returns int or None."""
    if not os.path.exists(PID_PATH):
        return None
    with open(PID_PATH) as f:
        content = f.read().strip()
    if not content:
        return None
    return int(content)


def write_pid():
    """Write current process PID to file."""
    ensure_state_dir()
    with open(PID_PATH, 'w') as f:
        f.write(str(os.getpid()))


def remove_pid():
    """Remove PID file if it exists."""
    if os.path.exists(PID_PATH):
        os.remove(PID_PATH)


def is_daemon_running():
    """Check if daemon is alive via PID file. Cleans stale PID files."""
    pid = read_pid()
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        # Process doesn't exist — stale PID file
        remove_pid()
        return False
    except PermissionError:
        # Process exists but we can't signal it (different user) — treat as running
        return True


# --- Daemon ---


def start_daemon(port, host):
    """Fork a background daemon process running 'vibefs serve'."""
    ensure_state_dir()
    log_file = open(LOG_PATH, 'a')
    proc = subprocess.Popen(
        [sys.executable, '-m', 'vibefs', 'serve', '--port', str(port), '--host', host],
        stdout=log_file,
        stderr=log_file,
        start_new_session=True,
    )
    log_file.close()
    # Give it a moment to start and write PID
    time.sleep(0.3)
    if proc.poll() is not None:
        click.echo('Warning: daemon process exited immediately, check ~/.vibefs/vibefs.log', err=True)
    else:
        click.echo(f'Daemon started (pid {proc.pid})', err=True)


def stop_daemon():
    """Send SIGTERM to the daemon. Returns True if signal was sent."""
    pid = read_pid()
    if pid is None:
        return False
    try:
        os.kill(pid, signal.SIGTERM)
        return True
    except ProcessLookupError:
        remove_pid()
        return False


# --- Auto-stop Timer ---


def start_cleanup_timer():
    """Start a background thread that exits the server when all authorizations expire."""

    def check_loop():
        while True:
            time.sleep(CLEANUP_INTERVAL)
            if not has_active_authorizations():
                click.echo('All authorizations expired, shutting down.', err=True)
                remove_pid()
                os._exit(0)

    t = threading.Thread(target=check_loop, daemon=True)
    t.start()


# --- Web Server (Bottle) ---

app = bottle.Bottle()


@app.route('/f/<token>/<filename>')
def serve_file(token, filename):
    row, status = lookup_authorization(token)

    if status == 'not_found':
        bottle.abort(404, 'Not found')

    if status == 'expired':
        return bottle.template(EXPIRED_TEMPLATE, filename=row['filename'])

    filepath = row['filepath']
    if not os.path.isfile(filepath):
        bottle.abort(404, 'File no longer exists on disk')

    content_type, _ = mimetypes.guess_type(filepath)
    if content_type is None:
        content_type = 'application/octet-stream'

    bottle.response.content_type = content_type
    with open(filepath, 'rb') as f:
        return f.read()


EXPIRED_TEMPLATE = """<!DOCTYPE html>
<html>
<head><title>File Expired</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 480px; margin: 80px auto; text-align: center; color: #333; }
  h1 { font-size: 1.4em; }
  p { color: #666; }
</style>
</head>
<body>
  <h1>This file is no longer available</h1>
  <p><strong>{{filename}}</strong> has expired and can no longer be accessed.</p>
</body>
</html>
"""


# --- CLI (Click) ---


@click.group()
def cli():
    """vibefs — Vibe File Server

    A simple, secure file preview service for sharing files via time-limited URLs.
    """
    pass


@cli.command()
@click.option('--port', default=DEFAULT_PORT, show_default=True, help='Port to listen on')
@click.option('--host', default=DEFAULT_HOST, show_default=True, help='Host to bind to')
@click.option('--foreground', is_flag=True, default=False, help='Run in foreground (no PID file cleanup timer)')
def serve(port, host, foreground):
    """Start the web server."""
    ensure_state_dir()
    write_pid()
    atexit.register(remove_pid)

    if not foreground:
        start_cleanup_timer()

    click.echo(f'vibefs serving on http://{host}:{port} (pid {os.getpid()})')
    app.run(host=host, port=port, quiet=True)


@cli.command()
@click.argument('path')
@click.option('--ttl', default=DEFAULT_TTL, show_default=True, help='Time-to-live in seconds')
@click.option('--port', default=DEFAULT_PORT, show_default=True, help='Port for URL generation')
@click.option('--host', default='localhost', show_default=True, help='Host for URL generation')
def allow(path, ttl, port, host):
    """Authorize a file for access, auto-start daemon if needed, and print its URL."""
    ensure_state_dir()
    token, filename = add_authorization(path, ttl)
    url = f'http://{host}:{port}/f/{token}/{filename}'
    click.echo(url)

    # Auto-start daemon if not running
    if not is_daemon_running():
        start_daemon(port, DEFAULT_HOST)


@cli.command()
@click.argument('token')
def revoke(token):
    """Revoke access to a file by its token."""
    if remove_authorization(token):
        click.echo(f'Revoked: {token}')
    else:
        click.echo(f'Token not found: {token}', err=True)


@cli.command('list')
def list_cmd():
    """List currently authorized files."""
    rows = list_authorizations()
    if not rows:
        click.echo('No active authorizations.')
        return

    now = time.time()
    for row in rows:
        remaining = row['expires_at'] - now
        if remaining > 0:
            status = f'{int(remaining)}s remaining'
        else:
            status = 'expired'
        click.echo(f'  {row["token"]}  {row["filepath"]}  [{status}]')


@cli.command()
def stop():
    """Stop the running daemon."""
    if stop_daemon():
        click.echo('Daemon stopped.')
    else:
        click.echo('Daemon is not running.', err=True)


@cli.command()
def status():
    """Check if the daemon is running."""
    pid = read_pid()
    if is_daemon_running():
        click.echo(f'Daemon is running (pid {pid}).')
    else:
        click.echo('Daemon is not running.')


if __name__ == '__main__':
    cli()
