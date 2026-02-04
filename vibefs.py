"""vibefs — Vibe File Server

A simple, secure file preview service designed for AI agents to share files
with users via time-limited URLs.
"""

import hashlib
import mimetypes
import os
import secrets
import sqlite3
import time

import bottle
import click

# --- Constants ---

DEFAULT_PORT = 8080
DEFAULT_HOST = '0.0.0.0'
DEFAULT_TTL = 3600  # 1 hour
TOKEN_LENGTH = 4  # bytes, produces 8 hex chars
DB_FILENAME = 'vibefs.db'

# --- Database ---


def get_db_path():
    return os.environ.get('VIBEFS_DB', DB_FILENAME)


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
def serve(port, host):
    """Start the web server."""
    click.echo(f'vibefs serving on http://{host}:{port}')
    app.run(host=host, port=port, quiet=True)


@cli.command()
@click.argument('path')
@click.option('--ttl', default=DEFAULT_TTL, show_default=True, help='Time-to-live in seconds')
@click.option('--port', default=DEFAULT_PORT, show_default=True, help='Port for URL generation')
@click.option('--host', default='localhost', show_default=True, help='Host for URL generation')
def allow(path, ttl, port, host):
    """Authorize a file for access and print its URL."""
    token, filename = add_authorization(path, ttl)
    url = f'http://{host}:{port}/f/{token}/{filename}'
    click.echo(url)


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


if __name__ == '__main__':
    cli()
