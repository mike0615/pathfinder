"""Loopback-only HTTP application; use an HTTPS reverse proxy for remote access."""
import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from . import __version__
from .core import Store, compare, csv_export, scope_addresses
from .collector import Jobs
from .demo import topology

STATIC = Path(__file__).parent / 'static'


def create_server(store, password, host='127.0.0.1', port=8765, allowed=(), operator_password=None):
    if not ipaddress.ip_address(host).is_loopback:
        raise ValueError('Bind to loopback; use a trusted HTTPS reverse proxy for remote access')
    if len(password) < 16 or (operator_password and len(operator_password) < 16):
        raise ValueError('Passwords must contain at least 16 characters')
    if operator_password and hmac.compare_digest(password, operator_password):
        raise ValueError('Administrator and operator passwords must differ')
    import threading
    import time
    sessions, attempts = {}, {}
    auth_lock = threading.Lock()
    jobs = Jobs(store, allowed)
    auth_salt = secrets.token_bytes(16)
    def digest(value):
        return hashlib.scrypt(value.encode(), salt=auth_salt, n=16384, r=8, p=1)
    admin_hash = digest(password)
    operator_hash = digest(operator_password) if operator_password else None
    password = operator_password = None

    class Handler(BaseHTTPRequestHandler):
        server_version = 'Pathfinder'

        def log_message(self, fmt, *args):
            # Avoid logging URL query strings, cookies, credentials or request bodies.
            pass

        def send(self, status, data, mime='application/json', extra=None):
            if not isinstance(data, bytes):
                data = json.dumps(data).encode() if mime == 'application/json' else str(data).encode()
            self.send_response(status)
            self.send_header('Content-Type', mime + ('; charset=utf-8' if mime.startswith('text/') else ''))
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def session(self):
            jar = cookies.SimpleCookie()
            try:
                jar.load(self.headers.get('Cookie', ''))
                token = jar['pf_session'].value
            except (KeyError, cookies.CookieError):
                return None
            with auth_lock:
                session = sessions.get(token)
                if session and session['expires'] > time.time():
                    return session
                sessions.pop(token, None)
                return None

        def require(self, admin=False, mutation=False):
            session = self.session()
            if not session:
                self.send(401, dict(error='Sign in required'))
                return False
            if admin and session['role'] != 'admin':
                self.send(403, dict(error='Administrator required'))
                return False
            if mutation and not hmac.compare_digest(self.headers.get('X-CSRF-Token', ''), session['csrf']):
                self.send(403, dict(error='Invalid request token'))
                return False
            return True

        def body(self):
            size = int(self.headers.get('Content-Length', '0'))
            if size < 0 or size > 4 * 1024 * 1024:
                raise ValueError('Request exceeds 4 MiB')
            if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                raise ValueError('Expected application/json')
            result = json.loads(self.rfile.read(size))
            if not isinstance(result, dict):
                raise ValueError('Expected JSON object')
            return result

        def do_GET(self):
            try:
                path = urlparse(self.path).path
                if path in ('/', '/app.js', '/style.css'):
                    filename = {'/': 'index.html', '/app.js': 'app.js', '/style.css': 'style.css'}[path]
                    mime = {'/': 'text/html', '/app.js': 'application/javascript', '/style.css': 'text/css'}[path]
                    return self.send(200, (STATIC / filename).read_bytes(), mime)
                if not self.require():
                    return
                q = parse_qs(urlparse(self.path).query)
                if path == '/api/session':
                    s = self.session()
                    return self.send(200, dict(role=s['role'], csrf=s['csrf'], version=__version__, allowed_networks=list(allowed)))
                if path == '/api/help':
                    return self.send(200, json.loads((Path(__file__).parent / 'help.json').read_text()))
                if path == '/api/profiles':
                    return self.send(200, store.profiles())
                if path == '/api/snapshots':
                    return self.send(200, store.snapshots())
                if path.startswith('/api/jobs/'):
                    return self.send(200, jobs.view(path.rsplit('/', 1)[1]))
                if path == '/api/demo':
                    return self.send(200, topology())
                if path == '/api/snapshot':
                    return self.send(200, store.load(q.get('id', [''])[0]))
                if path == '/api/compare':
                    return self.send(200, compare(store.load(q.get('before', [''])[0]), store.load(q.get('after', [''])[0])))
                if path == '/api/export':
                    t = store.load(q.get('id', [''])[0])
                    fmt = q.get('format', ['json'])[0]
                    if fmt == 'json':
                        return self.send(200, t, extra={'Content-Disposition': 'attachment; filename="pathfinder-full-topology.json"'})
                    if fmt == 'csv':
                        return self.send(200, csv_export(t), 'text/csv', {'Content-Disposition': 'attachment; filename="pathfinder-full-tables.csv"'})
                    raise ValueError('Supported server export formats: json, csv')
                self.send(404, dict(error='Not found'))
            except (ValueError, KeyError, TypeError):
                self.send(400, dict(error='Invalid request or unknown resource'))
            except Exception:
                self.send(500, dict(error='Internal error'))

        def do_POST(self):
            try:
                path = urlparse(self.path).path
                # Same-origin check, including login. Origin-less CLI requests are allowed.
                origin = self.headers.get('Origin')
                if origin and urlparse(origin).netloc != self.headers.get('Host'):
                    return self.send(403, dict(error='Cross-origin request rejected'))
                if path == '/api/login':
                    peer = self.client_address[0]
                    with auth_lock:
                        recent = [x for x in attempts.get(peer, []) if x > time.time() - 60]
                        if len(recent) >= 10:
                            return self.send(429, dict(error='Too many attempts; wait one minute'))
                        attempts[peer] = recent + [time.time()]
                    body = self.body()
                    supplied = body.get('password', '')
                    if not isinstance(supplied, str) or len(supplied) > 1024:
                        raise ValueError('Invalid password')
                    candidate = digest(supplied)
                    role = 'admin' if hmac.compare_digest(candidate, admin_hash) else 'operator' if operator_hash and hmac.compare_digest(candidate, operator_hash) else None
                    if not role:
                        return self.send(401, dict(error='Invalid password'))
                    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                    with auth_lock:
                        for key in list(sessions):
                            if sessions[key]['expires'] <= time.time():
                                sessions.pop(key)
                        if len(sessions) >= 100:
                            sessions.pop(next(iter(sessions)))
                        sessions[token] = dict(role=role, csrf=csrf, expires=time.time()+8*3600)
                    secure = '; Secure' if self.headers.get('X-Forwarded-Proto') == 'https' else ''
                    return self.send(200, dict(role=role, csrf=csrf), extra={'Set-Cookie': 'pf_session='+token+'; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800'+secure})
                if not self.require(admin=path.startswith('/api/profiles'), mutation=True):
                    return
                body = self.body()
                if path == '/api/logout':
                    session = self.session()
                    with auth_lock:
                        for key in list(sessions):
                            if sessions[key] is session:
                                sessions.pop(key)
                    return self.send(200, dict(ok=True), extra={'Set-Cookie': 'pf_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'})
                if path == '/api/profiles':
                    ident = store.save_profile(body.get('name'), body.get('username'), body.get('auth_password'), body.get('priv_password'))
                    return self.send(201, dict(id=ident))
                if path == '/api/profiles/delete':
                    store.delete_profile(body.get('id', ''))
                    return self.send(200, dict(ok=True))
                if path == '/api/snapshots':
                    # Import arbitrary JSON is deferred; only server-produced demo or job results.
                    if body.get('source') != 'demo':
                        raise ValueError('Only demo snapshots can be created here')
                    return self.send(201, dict(id=store.save(topology(), body.get('name', 'Demo snapshot'))))
                if path == '/api/scan':
                    addresses = scope_addresses(body.get('cidrs', []), body.get('seeds', []), allowed)
                    return self.send(202, jobs.start(addresses, body.get('profile_id', '')))
                if path == '/api/cancel':
                    return self.send(200, jobs.cancel(body.get('id', '')))
                self.send(404, dict(error='Not found'))
            except (ValueError, KeyError, TypeError) as e:
                self.send(400, dict(error=str(e) if isinstance(e, ValueError) else 'Invalid request'))
            except Exception:
                self.send(500, dict(error='Internal error'))

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


def main():
    parser = argparse.ArgumentParser(description='Cyber Chief Pathfinder')
    parser.add_argument('--state-dir', default=os.environ.get('PATHFINDER_STATE', './state'))
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--init', action='store_true', help='Create private state and administrator password file, then exit')
    args = parser.parse_args()
    os.umask(0o077)
    store = Store(args.state_dir)
    password_file = store.directory / 'admin.password'
    if args.init:
        from .core import private_file
        if password_file.exists():
            parser.error('Administrator password file already exists')
        private_file(password_file, secrets.token_urlsafe(24).encode())
        print('Initialized. Read admin.password privately to sign in; keep the profile key separate from database backups.')
        return
    if not password_file.exists() or password_file.stat().st_mode & 0o077:
        parser.error('Run --init first; admin.password must have mode 0600')
    operator_file = store.directory / 'operator.password'
    if operator_file.exists() and operator_file.stat().st_mode & 0o077:
        parser.error('operator.password must have mode 0600')
    allowed = [x.strip() for x in os.environ.get('PATHFINDER_ALLOWED_CIDRS', '').split(',') if x.strip()]
    for network in allowed:
        ipaddress.ip_network(network, strict=True)
    server = create_server(store, password_file.read_text().strip(), port=args.port, allowed=allowed, operator_password=operator_file.read_text().strip() if operator_file.exists() else None)
    print('Pathfinder %s listening at http://127.0.0.1:%d — live scan scope: %s' % (__version__, args.port, ','.join(allowed) or 'disabled'))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
