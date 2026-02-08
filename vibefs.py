"""vibefs — Vibe File Server

A simple, secure file preview service designed for AI agents to share files
with users via time-limited URLs.
"""

import atexit
import json
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
CONFIG_PATH = os.path.join(STATE_DIR, 'config.json')


def ensure_state_dir():
    os.makedirs(STATE_DIR, exist_ok=True)


# --- Config ---


def load_config():
    if os.path.isfile(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            return json.load(f)
    return {}


def save_config(cfg):
    ensure_state_dir()
    with open(CONFIG_PATH, 'w') as f:
        json.dump(cfg, f, indent=2)
        f.write('\n')


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
    db.execute("""
        CREATE TABLE IF NOT EXISTS git_authorizations (
            token TEXT PRIMARY KEY,
            repo_path TEXT NOT NULL,
            commit_hash TEXT NOT NULL,
            created_at REAL NOT NULL,
            expires_at REAL NOT NULL
        )
    """)
    db.commit()
    return db


def add_authorization(filepath, ttl):
    """Add an authorization record and return (token, filename, is_new)."""
    abs_path = os.path.abspath(filepath)
    if not os.path.isfile(abs_path):
        raise FileNotFoundError(f'File not found: {abs_path}')

    filename = os.path.basename(abs_path)
    now = time.time()

    db = get_db()
    # Check for existing non-expired authorization
    row = db.execute(
        'SELECT token FROM authorizations WHERE filepath = ? AND expires_at > ?',
        (abs_path, now),
    ).fetchone()

    if row:
        # Update expiration time
        token = row['token']
        db.execute(
            'UPDATE authorizations SET expires_at = ? WHERE token = ?',
            (now + ttl, token),
        )
        db.commit()
        db.close()
        return token, filename, False
    else:
        # Create new record
        token = secrets.token_hex(TOKEN_LENGTH)
        db.execute(
            'INSERT INTO authorizations (token, filepath, filename, created_at, expires_at) VALUES (?, ?, ?, ?, ?)',
            (token, abs_path, filename, now, now + ttl),
        )
        db.commit()
        db.close()
        return token, filename, True


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
    """Check if there are any non-expired authorizations (files or git)."""
    db = get_db()
    now = time.time()
    file_cnt = db.execute(
        'SELECT COUNT(*) as cnt FROM authorizations WHERE expires_at > ?',
        (now,),
    ).fetchone()['cnt']
    git_cnt = db.execute(
        'SELECT COUNT(*) as cnt FROM git_authorizations WHERE expires_at > ?',
        (now,),
    ).fetchone()['cnt']
    db.close()
    return (file_cnt + git_cnt) > 0


# --- Git Authorization ---


def add_git_authorization(repo_path, commit_hash, ttl):
    """Add a git commit authorization record and return (token, is_new)."""
    abs_repo = os.path.abspath(repo_path)
    if not os.path.isdir(os.path.join(abs_repo, '.git')):
        raise ValueError(f'Not a git repository: {abs_repo}')

    now = time.time()
    db = get_db()
    # Check for existing non-expired authorization for same repo+commit
    row = db.execute(
        'SELECT token FROM git_authorizations WHERE repo_path = ? AND commit_hash = ? AND expires_at > ?',
        (abs_repo, commit_hash, now),
    ).fetchone()

    if row:
        token = row['token']
        db.execute(
            'UPDATE git_authorizations SET expires_at = ? WHERE token = ?',
            (now + ttl, token),
        )
        db.commit()
        db.close()
        return token, False
    else:
        token = secrets.token_hex(TOKEN_LENGTH)
        db.execute(
            'INSERT INTO git_authorizations (token, repo_path, commit_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)',
            (token, abs_repo, commit_hash, now, now + ttl),
        )
        db.commit()
        db.close()
        return token, True


def lookup_git_authorization(token):
    """Look up a git token. Returns (row, status)."""
    db = get_db()
    row = db.execute(
        'SELECT token, repo_path, commit_hash, created_at, expires_at FROM git_authorizations WHERE token = ?',
        (token,),
    ).fetchone()
    db.close()

    if row is None:
        return None, 'not_found'
    if time.time() > row['expires_at']:
        return row, 'expired'
    return row, 'valid'


def get_git_commit_info(repo_path, commit_hash):
    """Get commit info via git commands. Returns dict with metadata and file diffs."""
    # Get commit metadata
    result = subprocess.run(
        ['git', 'log', '-1', '--format=%H%n%an%n%ae%n%aI%n%s%n%b', commit_hash],
        cwd=repo_path,
        capture_output=True,
        text=True,
        check=True,
    )
    lines = result.stdout.strip().split('\n', 5)
    info = {
        'hash': lines[0] if len(lines) > 0 else commit_hash,
        'author_name': lines[1] if len(lines) > 1 else '',
        'author_email': lines[2] if len(lines) > 2 else '',
        'date': lines[3] if len(lines) > 3 else '',
        'subject': lines[4] if len(lines) > 4 else '',
        'body': lines[5].strip() if len(lines) > 5 else '',
    }

    # Get list of changed files with stats
    result = subprocess.run(
        ['git', 'diff-tree', '--no-commit-id', '-r', '--numstat', commit_hash],
        cwd=repo_path,
        capture_output=True,
        text=True,
        check=True,
    )
    files = []
    for line in result.stdout.strip().split('\n'):
        if not line:
            continue
        parts = line.split('\t', 2)
        if len(parts) == 3:
            added, deleted, filepath = parts
            files.append(
                {
                    'path': filepath,
                    'added': added,
                    'deleted': deleted,
                }
            )

    # Get diff for each file
    for f in files:
        try:
            result = subprocess.run(
                ['git', 'diff', f'{commit_hash}~1', commit_hash, '--', f['path']],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True,
            )
            f['diff'] = result.stdout
        except subprocess.CalledProcessError:
            # Initial commit or other edge case
            try:
                result = subprocess.run(
                    ['git', 'show', f'{commit_hash}', '--', f['path']],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                f['diff'] = result.stdout
            except subprocess.CalledProcessError:
                f['diff'] = ''

    info['files'] = files
    return info


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


# --- Renderers ---


class BaseRenderer:
    """Default renderer: returns raw file content with guessed content-type."""

    def render(self, filepath, head=None, tail=None):
        content_type, _ = mimetypes.guess_type(filepath)
        if content_type is None:
            content_type = 'application/octet-stream'
        bottle.response.content_type = content_type
        if head is not None or tail is not None:
            with open(filepath) as f:
                lines = f.readlines()
            if head is not None:
                lines = lines[:head]
            elif tail is not None:
                lines = lines[-tail:]
            return ''.join(lines)
        with open(filepath, 'rb') as f:
            return f.read()


class CodeRenderer:
    """Renders code files with syntax highlighting via Pygments."""

    def render(self, filepath, head=None, tail=None):
        from pygments import highlight
        from pygments.formatters import HtmlFormatter
        from pygments.lexers import get_lexer_for_filename, TextLexer

        with open(filepath) as f:
            lines = f.readlines()

        if head is not None:
            lines = lines[:head]
        elif tail is not None:
            lines = lines[-tail:]
        code = ''.join(lines)

        try:
            lexer = get_lexer_for_filename(filepath)
        except Exception:
            lexer = TextLexer()

        cfg = load_config()
        pygments_cfg = cfg.get('pygments', {})
        style = pygments_cfg.get('style', 'monokai')
        linenos = 'inline' if pygments_cfg.get('linenos', False) else False

        formatter = HtmlFormatter(
            style=style,
            linenos=linenos,
            cssclass='highlight',
        )
        highlighted = highlight(code, lexer, formatter)
        css = formatter.get_style_defs('.highlight')
        display_path = _display_path(filepath)
        stat = os.stat(filepath)
        file_size = _format_size(stat.st_size)
        file_mtime = time.strftime('%Y-%m-%d %H:%M', time.localtime(stat.st_mtime))
        file_ctime = time.strftime(
            '%Y-%m-%d %H:%M', time.localtime(stat.st_birthtime if hasattr(stat, 'st_birthtime') else stat.st_ctime)
        )

        bottle.response.content_type = 'text/html; charset=utf-8'
        return CODE_HTML_TEMPLATE.format(
            display_path=display_path,
            file_meta=f'{file_size} · {file_mtime} (mtime) · {file_ctime} (ctime)',
            pygments_css=css,
            highlighted=highlighted,
        )


def _display_path(filepath):
    home = os.path.expanduser('~')
    if filepath.startswith(home + '/'):
        return '~/' + filepath[len(home) + 1 :]
    return filepath


def _format_size(nbytes):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if nbytes < 1024:
            return f'{nbytes:.0f} {unit}' if unit == 'B' else f'{nbytes:.1f} {unit}'
        nbytes /= 1024
    return f'{nbytes:.1f} TB'


CODE_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{display_path}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    background: #1e1e1e;
    color: #d4d4d4;
    min-height: 100vh;
  }}
  .file-header {{
    background: #2d2d2d;
    border-bottom: 1px solid #404040;
    padding: 12px 16px;
  }}
  .file-path {{
    font-size: 14px;
    font-weight: 600;
    color: #e0e0e0;
    word-break: break-all;
  }}
  .file-meta {{
    font-size: 12px;
    font-weight: 400;
    color: #888;
    margin-top: 4px;
  }}
  .file-content {{
    overflow-x: auto;
  }}
  /* Pygments overrides */
  {pygments_css}
  .highlight {{
    background: #1e1e1e;
    padding: 0;
  }}
  .highlight pre {{
    padding: 12px 8px;
    margin: 0;
    font-family: 'SF Mono', 'Menlo', 'Monaco', 'Consolas', 'Liberation Mono', monospace;
    font-size: 15px;
    line-height: 1.6;
    white-space: pre-wrap;
    word-wrap: break-word;
    overflow-wrap: break-word;
  }}
  /* Mobile responsive */
  @media (max-width: 768px) {{
    .file-header {{
      padding: 10px 12px;
      font-size: 13px;
    }}
    .highlight pre {{
      font-size: 14px;
      line-height: 1.5;
      padding: 8px 12px;
    }}
  }}
</style>
</head>
<body>
  <div class="file-header">
    <div class="file-path">{display_path}</div>
    <div class="file-meta">{file_meta}</div>
  </div>
  <div class="file-content">
    {highlighted}
  </div>
</body>
</html>"""


# Renderer registry: extension -> renderer instance
_renderers = {}
_fallback_renderer = BaseRenderer()

CODE_EXTENSIONS = [
    '.py',
    '.js',
    '.ts',
    '.jsx',
    '.tsx',
    '.go',
    '.rs',
    '.rb',
    '.java',
    '.c',
    '.cpp',
    '.h',
    '.hpp',
    '.cs',
    '.swift',
    '.kt',
    '.scala',
    '.sh',
    '.bash',
    '.zsh',
    '.fish',
    '.html',
    '.css',
    '.scss',
    '.less',
    '.json',
    '.yaml',
    '.yml',
    '.toml',
    '.ini',
    '.cfg',
    '.xml',
    '.sql',
    '.graphql',
    '.md',
    '.rst',
    '.txt',
    '.lua',
    '.vim',
    '.el',
    '.clj',
    '.hs',
    '.ml',
    '.ex',
    '.exs',
    '.r',
    '.R',
    '.jl',
    '.pl',
    '.pm',
    '.php',
    '.dockerfile',
    '.makefile',
    '.cmake',
    '.conf',
    '.env',
    '.gitignore',
    '.diff',
    '.patch',
]


def init_renderers():
    """Register renderers for known extensions."""
    code_renderer = CodeRenderer()
    for ext in CODE_EXTENSIONS:
        _renderers[ext] = code_renderer


def get_renderer(filepath):
    """Get the appropriate renderer for a file, falling back to BaseRenderer."""
    _, ext = os.path.splitext(filepath)
    return _renderers.get(ext.lower(), _fallback_renderer)


init_renderers()


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

    head = bottle.request.query.get('head')
    tail = bottle.request.query.get('tail')
    head = int(head) if head else None
    tail = int(tail) if tail else None

    renderer = get_renderer(filepath)
    return renderer.render(filepath, head=head, tail=tail)


@app.route('/git/<token>')
def serve_git(token):
    row, status = lookup_git_authorization(token)

    if status == 'not_found':
        bottle.abort(404, 'Not found')

    if status == 'expired':
        return bottle.template(EXPIRED_TEMPLATE, filename=f'git commit')

    repo_path = row['repo_path']
    commit_hash = row['commit_hash']

    try:
        info = get_git_commit_info(repo_path, commit_hash)
    except Exception as e:
        bottle.abort(500, f'Failed to read git commit: {e}')

    # Render diffs with Pygments
    from pygments import highlight
    from pygments.formatters import HtmlFormatter
    from pygments.lexers import DiffLexer

    cfg = load_config()
    pygments_cfg = cfg.get('pygments', {})
    style = pygments_cfg.get('style', 'monokai')
    formatter = HtmlFormatter(style=style, cssclass='highlight', nowrap=False)
    lexer = DiffLexer()
    pygments_css = formatter.get_style_defs('.highlight')

    files_html = []
    for f in info['files']:
        stats = f'+{f["added"]} -{f["deleted"]}'
        diff_highlighted = highlight(f['diff'], lexer, formatter) if f['diff'] else '<pre>No diff available</pre>'
        files_html.append(
            f'<details><summary><span class="file-path">{_html_escape(f["path"])}</span>'
            f' <span class="file-stats">({stats})</span></summary>'
            f'<div class="diff-content">{diff_highlighted}</div></details>'
        )

    repo_display = _display_path(repo_path)
    short_hash = info['hash'][:12]
    body_html = f'<p class="commit-body">{_html_escape(info["body"])}</p>' if info['body'] else ''

    bottle.response.content_type = 'text/html; charset=utf-8'
    return GIT_HTML_TEMPLATE.format(
        repo_path=_html_escape(repo_display),
        short_hash=short_hash,
        full_hash=info['hash'],
        author_name=_html_escape(info['author_name']),
        author_email=_html_escape(info['author_email']),
        date=_html_escape(info['date']),
        subject=_html_escape(info['subject']),
        body_html=body_html,
        files_html='\n'.join(files_html),
        file_count=len(info['files']),
        pygments_css=pygments_css,
    )


def _html_escape(text):
    """Simple HTML escape."""
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')


GIT_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{repo_path} · {short_hash}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    background: #1e1e1e;
    color: #d4d4d4;
    min-height: 100vh;
  }}
  .commit-header {{
    background: #2d2d2d;
    border-bottom: 1px solid #404040;
    padding: 16px;
  }}
  .commit-repo {{
    font-size: 12px;
    color: #888;
    margin-bottom: 8px;
  }}
  .commit-subject {{
    font-size: 16px;
    font-weight: 600;
    color: #e0e0e0;
    margin-bottom: 8px;
  }}
  .commit-body {{
    font-size: 14px;
    color: #b0b0b0;
    white-space: pre-wrap;
    margin-bottom: 8px;
  }}
  .commit-meta {{
    font-size: 13px;
    color: #888;
  }}
  .commit-meta .hash {{
    font-family: 'SF Mono', 'Menlo', monospace;
    color: #6ab0f3;
  }}
  .file-list {{
    padding: 8px 0;
  }}
  .file-list details {{
    border-bottom: 1px solid #333;
  }}
  .file-list summary {{
    padding: 10px 16px;
    cursor: pointer;
    font-size: 14px;
    font-family: 'SF Mono', 'Menlo', monospace;
    background: #252525;
  }}
  .file-list summary:hover {{
    background: #2a2a2a;
  }}
  .file-path {{
    color: #e0e0e0;
  }}
  .file-stats {{
    color: #888;
    font-size: 12px;
  }}
  .diff-content {{
    overflow-x: auto;
  }}
  {pygments_css}
  .highlight {{
    background: #1e1e1e;
    padding: 0;
  }}
  .highlight pre {{
    padding: 8px 16px;
    margin: 0;
    font-family: 'SF Mono', 'Menlo', 'Monaco', 'Consolas', monospace;
    font-size: 13px;
    line-height: 1.5;
    white-space: pre-wrap;
    word-wrap: break-word;
  }}
  .file-summary {{
    padding: 12px 16px;
    font-size: 13px;
    color: #888;
    background: #2d2d2d;
    border-bottom: 1px solid #404040;
  }}
  @media (max-width: 768px) {{
    .commit-header {{ padding: 12px; }}
    .file-list summary {{ padding: 8px 12px; font-size: 13px; }}
    .highlight pre {{ font-size: 12px; padding: 6px 12px; }}
  }}
</style>
</head>
<body>
  <div class="commit-header">
    <div class="commit-repo">{repo_path}</div>
    <div class="commit-subject">{subject}</div>
    {body_html}
    <div class="commit-meta">
      <span class="hash">{short_hash}</span> · {author_name} &lt;{author_email}&gt; · {date}
    </div>
  </div>
  <div class="file-summary">{file_count} files changed</div>
  <div class="file-list">
    {files_html}
  </div>
</body>
</html>"""


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
@click.option(
    '--ttl', default=None, type=int, help=f'Time-to-live in seconds (default: config file_ttl or {DEFAULT_TTL})'
)
@click.option('--port', default=DEFAULT_PORT, show_default=True, help='Port for URL generation')
@click.option('--host', default='localhost', show_default=True, help='Host for URL generation')
@click.option('--head', default=None, type=int, help='Only show first N lines')
@click.option('--tail', default=None, type=int, help='Only show last N lines')
def allow(path, ttl, port, host, head, tail):
    """Authorize a file for access, auto-start daemon if needed, and print its URL."""
    ensure_state_dir()
    if ttl is None:
        cfg = load_config()
        ttl = cfg.get('file_ttl', DEFAULT_TTL)
    token, filename, is_new = add_authorization(path, ttl)
    base_url = load_config().get('base_url')
    if base_url:
        url = f'{base_url.rstrip("/")}/f/{token}/{filename}'
    else:
        url = f'http://{host}:{port}/f/{token}/{filename}'
    params = []
    if head is not None:
        params.append(f'head={head}')
    if tail is not None:
        params.append(f'tail={tail}')
    if params:
        url += '?' + '&'.join(params)
    click.echo(url)
    if not is_new:
        click.echo('(existing authorization extended)', err=True)

    # Auto-start daemon if not running
    if not is_daemon_running():
        start_daemon(port, DEFAULT_HOST)


@cli.command('allow-git')
@click.argument('repo_path')
@click.argument('commit_hash')
@click.option(
    '--ttl', default=None, type=int, help=f'Time-to-live in seconds (default: config file_ttl or {DEFAULT_TTL})'
)
@click.option('--port', default=DEFAULT_PORT, show_default=True, help='Port for URL generation')
def allow_git(repo_path, commit_hash, ttl, port):
    """Authorize a git commit for viewing and print its URL."""
    ensure_state_dir()
    if ttl is None:
        cfg = load_config()
        ttl = cfg.get('file_ttl', DEFAULT_TTL)
    try:
        token, is_new = add_git_authorization(repo_path, commit_hash, ttl)
    except ValueError as e:
        click.echo(str(e), err=True)
        sys.exit(1)
    base_url = load_config().get('base_url')
    if base_url:
        url = f'{base_url.rstrip("/")}/git/{token}'
    else:
        url = f'http://localhost:{port}/git/{token}'
    click.echo(url)
    if not is_new:
        click.echo('(existing authorization extended)', err=True)

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
    """List currently authorized files and git commits."""
    rows = list_authorizations()
    now = time.time()
    has_any = False

    if rows:
        has_any = True
        click.echo('Files:')
        for row in rows:
            remaining = row['expires_at'] - now
            status = f'{int(remaining)}s remaining' if remaining > 0 else 'expired'
            click.echo(f'  {row["token"]}  {row["filepath"]}  [{status}]')

    # Git authorizations
    db = get_db()
    git_rows = db.execute(
        'SELECT token, repo_path, commit_hash, created_at, expires_at FROM git_authorizations ORDER BY created_at DESC'
    ).fetchall()
    db.close()

    if git_rows:
        has_any = True
        click.echo('Git commits:')
        for row in git_rows:
            remaining = row['expires_at'] - now
            status = f'{int(remaining)}s remaining' if remaining > 0 else 'expired'
            short_hash = row['commit_hash'][:12]
            click.echo(f'  {row["token"]}  {_display_path(row["repo_path"])} {short_hash}  [{status}]')

    if not has_any:
        click.echo('No active authorizations.')


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


@cli.group()
def config():
    """Get or set configuration values."""
    pass


VALID_CONFIG_KEYS = ['base_url', 'file_ttl', 'pygments.style', 'pygments.linenos']


def _get_nested(cfg, key):
    """Get a value from config, supporting dot notation (e.g. pygments.style)."""
    parts = key.split('.')
    value = cfg
    for part in parts:
        if not isinstance(value, dict):
            return None
        value = value.get(part)
        if value is None:
            return None
    return value


def _set_nested(cfg, key, value):
    """Set a value in config, supporting dot notation (e.g. pygments.style)."""
    parts = key.split('.')
    target = cfg
    for part in parts[:-1]:
        if part not in target or not isinstance(target[part], dict):
            target[part] = {}
        target = target[part]
    # Handle type conversions
    if key == 'pygments.linenos':
        value = value.lower() in ('true', '1', 'yes', 'table', 'inline')
    elif key == 'file_ttl':
        value = int(value)
    target[parts[-1]] = value


@config.command('set')
@click.argument('key')
@click.argument('value')
def config_set(key, value):
    """Set a config value (e.g. vibefs config set pygments.style dracula)."""
    if key not in VALID_CONFIG_KEYS:
        click.echo(f'Unknown config key: {key}. Valid keys: {", ".join(VALID_CONFIG_KEYS)}', err=True)
        sys.exit(1)
    cfg = load_config()
    _set_nested(cfg, key, value)
    save_config(cfg)
    click.echo(f'{key} = {_get_nested(cfg, key)}')


@config.command('get')
@click.argument('key')
def config_get(key):
    """Get a config value (e.g. vibefs config get pygments.style)."""
    if key not in VALID_CONFIG_KEYS:
        click.echo(f'Unknown config key: {key}. Valid keys: {", ".join(VALID_CONFIG_KEYS)}', err=True)
        sys.exit(1)
    cfg = load_config()
    value = _get_nested(cfg, key)
    if value is None:
        click.echo(f'{key}: (not set)')
    else:
        click.echo(f'{key} = {value}')


if __name__ == '__main__':
    cli()
