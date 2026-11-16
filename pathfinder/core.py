"""Evidence-preserving model, encrypted profiles and snapshot persistence."""
import csv
import io
import ipaddress
import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken


def now():
    return datetime.now(timezone.utc).isoformat()


def private_file(path, content):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(content)


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.directory.stat().st_mode & 0o077:
            raise ValueError('State directory must have permissions 0700')
        self.db = self.directory / 'pathfinder.sqlite'
        if not self.db.exists():
            private_file(self.db, b'')
        if self.db.stat().st_mode & 0o077:
            raise ValueError('Database must have permissions 0600')
        self.key_path = self.directory / 'profiles.key'
        if not self.key_path.exists():
            private_file(self.key_path, Fernet.generate_key())
        if self.key_path.stat().st_mode & 0o077:
            raise ValueError('Profile key must have permissions 0600')
        self.cipher = Fernet(self.key_path.read_bytes())
        self.lock = threading.RLock()
        with self.connect() as c:
            c.executescript('CREATE TABLE IF NOT EXISTS profiles (id TEXT PRIMARY KEY, name TEXT NOT NULL, secret BLOB NOT NULL); CREATE TABLE IF NOT EXISTS snapshots (id TEXT PRIMARY KEY, created TEXT NOT NULL, name TEXT NOT NULL, payload TEXT NOT NULL);')

    def connect(self):
        return sqlite3.connect(self.db, timeout=10)

    def profiles(self):
        with self.connect() as c:
            return [dict(id=r[0], name=r[1]) for r in c.execute('SELECT id,name FROM profiles ORDER BY name')]

    def save_profile(self, name, username, auth_password, priv_password):
        # Net-SNMP config uses line-based syntax; forbid config injection.
        values = [name, username, auth_password, priv_password]
        if any(not isinstance(v, str) or not v or len(v) > 256 or any(ord(ch) < 32 for ch in v) for v in values):
            raise ValueError('Profile fields must be nonempty single-line strings, at most 256 characters')
        if any(ch.isspace() or ch in '#"\\' for ch in username + auth_password + priv_password):
            raise ValueError('This adapter requires SNMP fields without spaces, quotes, # or backslashes')
        if len(auth_password) < 8 or len(priv_password) < 8:
            raise ValueError('SNMPv3 passphrases require at least 8 characters')
        ident = uuid.uuid4().hex
        token = self.cipher.encrypt(json.dumps(dict(username=username, auth_password=auth_password, priv_password=priv_password)).encode())
        with self.lock, self.connect() as c:
            c.execute('INSERT INTO profiles VALUES (?,?,?)', (ident, name, token))
        return ident

    def secret(self, ident):
        with self.connect() as c:
            row = c.execute('SELECT secret FROM profiles WHERE id=?', (ident,)).fetchone()
        if row is None:
            raise ValueError('Unknown profile')
        try:
            return json.loads(self.cipher.decrypt(row[0]))
        except InvalidToken:
            raise ValueError('Credential key mismatch or ciphertext tampering') from None

    def delete_profile(self, ident):
        with self.lock, self.connect() as c:
            c.execute('DELETE FROM profiles WHERE id=?', (ident,))

    def save(self, topology, name):
        validate_topology(topology)
        ident = uuid.uuid4().hex
        with self.lock, self.connect() as c:
            c.execute('INSERT INTO snapshots VALUES (?,?,?,?)', (ident, now(), str(name)[:128], json.dumps(topology)))
        return ident

    def snapshots(self):
        with self.connect() as c:
            return [dict(id=r[0], created=r[1], name=r[2]) for r in c.execute('SELECT id,created,name FROM snapshots ORDER BY created DESC')]

    def load(self, ident):
        with self.connect() as c:
            row = c.execute('SELECT payload FROM snapshots WHERE id=?', (ident,)).fetchone()
        if row is None:
            raise ValueError('Unknown snapshot')
        return json.loads(row[0])


def validate_topology(t):
    if not isinstance(t, dict) or t.get('schema_version') != 1:
        raise ValueError('Expected topology schema_version 1')
    for field in ('devices', 'links', 'observations', 'errors'):
        if not isinstance(t.get(field), list) or len(t[field]) > 50000:
            raise ValueError('Invalid or oversized ' + field)
    ids = []
    for d in t['devices']:
        if not isinstance(d, dict) or not isinstance(d.get('id'), str) or not isinstance(d.get('name'), str):
            raise ValueError('Device requires id and name strings')
        if len(d['id']) > 256 or len(d['name']) > 256:
            raise ValueError('Device field too long')
        if not isinstance(d.get('interfaces', []), list):
            raise ValueError('interfaces must be a list')
        for port in d.get('interfaces', []):
            if not isinstance(port, dict) or not isinstance(port.get('name'), str):
                raise ValueError('Interface name required')
        ids.append(d['id'])
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate device ids')
    for link in t['links']:
        if not isinstance(link, dict) or link.get('source') not in ids or link.get('target') not in ids or link.get('confidence') not in ('confirmed', 'inferred') or not isinstance(link.get('evidence'), list):
            raise ValueError('Invalid link or missing evidence')
    return t


def scope_addresses(cidrs, seeds, allowed, limit=256):
    if not isinstance(cidrs, list) or not isinstance(seeds, list) or len(cidrs) > 16 or len(seeds) > limit:
        raise ValueError('Supply bounded lists of CIDRs and seed IP addresses')
    networks = [ipaddress.ip_network(x, strict=True) for x in allowed]
    if not networks:
        raise ValueError('Configure allowed management CIDRs before live discovery')
    result = set()
    for value in cidrs:
        network = ipaddress.ip_network(value, strict=True)
        if not any(network.version == a.version and network.subnet_of(a) for a in networks):
            raise ValueError('Requested subnet outside allowed management networks')
        if network.num_addresses > limit + 2:
            raise ValueError('Subnet exceeds scan limit')
        result.update(str(a) for a in network.hosts())
    for value in seeds:
        address = ipaddress.ip_address(value)
        if not any(address.version == a.version and address in a for a in networks):
            raise ValueError('Seed outside allowed management networks')
        result.add(str(address))
    if not result or len(result) > limit:
        raise ValueError('Scan must contain 1 to %d addresses' % limit)
    return sorted(result, key=lambda x: (ipaddress.ip_address(x).version, int(ipaddress.ip_address(x))))


def compare(before, after):
    def indexed(t):
        return {d['id']: d for d in t['devices']}
    a, b = indexed(before), indexed(after)
    def content(d):
        return {k: v for k, v in d.items() if k not in ('observed_at',)}
    def links(t):
        return {(l['source'], l['target'], str(l.get('source_port', '')), str(l.get('target_port', '')), l['confidence']) for l in t['links']}
    return dict(added=sorted(b.keys()-a.keys()), removed=sorted(a.keys()-b.keys()), changed=sorted(k for k in a.keys() & b.keys() if content(a[k]) != content(b[k])), links_added=[list(x) for x in sorted(links(after)-links(before))], links_removed=[list(x) for x in sorted(links(before)-links(after))])


def csv_export(t):
    out = io.StringIO(newline='')
    w = csv.writer(out)
    w.writerow(['record_type', 'device_id', 'device_name', 'ip', 'interface', 'mac', 'vlan', 'source', 'observed_at'])
    def safe(v):
        s = '' if v is None else str(v)
        return "'" + s if s.startswith(('=', '+', '-', '@', '\t', '\r')) else s
    for d in t['devices']:
        ports = d.get('interfaces') or [{}]
        for port in ports:
            w.writerow([safe(v) for v in ['device', d['id'], d['name'], d.get('ip'), port.get('name'), d.get('mac'), port.get('vlan'), d.get('source'), d.get('observed_at')]])
    for o in t['observations']:
        if o.get('kind') in ('fdb', 'arp', 'vlan_fdb'):
            w.writerow([safe(v) for v in [o['kind'], o.get('device_id'), '', o.get('ip'), o.get('interface'), o.get('mac'), o.get('vlan'), o.get('protocol'), o.get('observed_at')]])
    return out.getvalue()
