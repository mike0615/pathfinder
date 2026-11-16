"""Read-only numeric-OID Net-SNMP adapter. No configuration writes."""
import concurrent.futures
import os
import re
import shutil
import subprocess
import tempfile
import threading
import uuid
from pathlib import Path
from .core import now

OIDS = {
 'name': '.1.3.6.1.2.1.1.5', 'description': '.1.3.6.1.2.1.1.1',
 'interfaces': '.1.3.6.1.2.1.31.1.1.1.1', 'ifdescr': '.1.3.6.1.2.1.2.2.1.2',
 'status': '.1.3.6.1.2.1.2.2.1.8', 'speed': '.1.3.6.1.2.1.31.1.1.1.15',
 'bridge_ports': '.1.3.6.1.2.1.17.1.4.1.2', 'fdb': '.1.3.6.1.2.1.17.4.3.1.2',
 'vlan_fdb': '.1.3.6.1.2.1.17.7.1.2.2.1.2',
 'arp': '.1.3.6.1.2.1.4.22.1.2',
 'lldp_names': '.1.0.8802.1.1.2.1.4.1.1.9',
 'lldp_ports': '.1.0.8802.1.1.2.1.4.1.1.7',
 'lldp_local': '.1.0.8802.1.1.2.1.3.7.1.3',
}


def parse_walk(text, root):
    result = {}
    for line in text.splitlines():
        match = re.match(r'^\.?([\d.]+)\s+=\s+([^:]+):\s*(.*)$', line)
        if not match:
            continue
        oid, kind, value = match.groups()
        prefix = root.lstrip('.') + '.'
        if not oid.startswith(prefix):
            continue
        if kind == 'STRING':
            value = value.strip('"')
        result[oid[len(prefix):]] = value
    return result


class Cancelled(Exception):
    pass


def walk(address, root, config_dir, cancel):
    if cancel.is_set():
        raise Cancelled()
    executable = shutil.which('snmpwalk')
    if not executable:
        raise ValueError('Install net-snmp-utils to enable live discovery')
    env = dict(os.environ, SNMPCONFPATH=config_dir, MIBS='')
    # Secrets live only in a mode-0600 temporary snmp.conf, never process argv.
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen([executable, '-v3', '-On', '-t', '1', '-r', '0', address, root], env=env, stdout=output, stderr=subprocess.DEVNULL)
        try:
            for _ in range(50):
                if cancel.is_set():
                    raise Cancelled()
                if os.fstat(output.fileno()).st_size > 8 * 1024 * 1024:
                    raise ValueError('SNMP table exceeds output limit')
                if process.poll() is not None:
                    break
                cancel.wait(0.1)
            else:
                raise ValueError('SNMP table collection exceeded five seconds')
            if process.returncode:
                raise ValueError('SNMP collection failed: timeout, authorization or unsupported capability')
            output.seek(0)
            stdout = output.read(8 * 1024 * 1024 + 1)
            if len(stdout) > 8 * 1024 * 1024:
                raise ValueError('SNMP table exceeds output limit')
            text = stdout.decode(errors='replace')
            if 'No Such' in text or 'No more variables' in text:
                raise ValueError('SNMP capability absent or inaccessible')
            return parse_walk(text, root)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


def collect_device(address, profile, cancel):
    stamp = now()
    tables, errors, observations = {}, [], []
    with tempfile.TemporaryDirectory(prefix='pathfinder-snmp-') as directory:
        path = Path(directory) / 'snmp.conf'
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write('defSecurityLevel authPriv\ndefAuthType SHA\ndefPrivType AES\ndefSecurityName %s\ndefAuthPassphrase %s\ndefPrivPassphrase %s\n' % (profile['username'], profile['auth_password'], profile['priv_password']))
        for key, oid in OIDS.items():
            if cancel.is_set():
                raise Cancelled()
            try:
                tables[key] = walk(address, oid, directory, cancel)
                observations.append(dict(kind='snmp_table', device_id=address, protocol='SNMPv3', oid=oid, table=key, values=tables[key], observed_at=stamp))
            except ValueError as e:
                errors.append(dict(device=address, capability=key, message=str(e), observed_at=stamp))
                # No reason to attempt every table when the basic query fails.
                if key == 'name':
                    return None, observations, errors
    names = tables.get('interfaces') or tables.get('ifdescr', {})
    interfaces = [dict(index=i, name=n, status='up' if tables.get('status', {}).get(i) in ('1', 'up(1)') else 'unknown/down', speed_mbps=tables.get('speed', {}).get(i)) for i, n in names.items()]
    device = dict(id=address, name=tables.get('name', {}).get('0', address), ip=address, kind='managed', description=tables.get('description', {}).get('0', ''), interfaces=interfaces, observed_at=stamp, source='SNMPv3')
    bridge = tables.get('bridge_ports', {})
    for table in ('fdb', 'vlan_fdb'):
        for suffix, port in tables.get(table, {}).items():
            parts = suffix.split('.')
            if len(parts) < 6:
                continue
            mac = ':'.join('%02x' % int(x) for x in parts[-6:])
            observations.append(dict(kind=table, device_id=address, mac=mac, interface=names.get(bridge.get(port, ''), 'bridge-port:' + port), vlan=None, fdb_id=parts[0] if table == 'vlan_fdb' else None, protocol='SNMPv3', observed_at=stamp, limitation='FDB identifier is not assumed to equal VLAN; learned MAC may be downstream of an uplink'))
    for suffix, mac in tables.get('arp', {}).items():
        parts = suffix.split('.')
        if len(parts) == 5:
            observations.append(dict(kind='arp', device_id=address, ip='.'.join(parts[1:]), mac=mac, interface=names.get(parts[0], parts[0]), protocol='SNMPv3', observed_at=stamp))
    return device, observations, errors


def correlate(devices, observations):
    # LLDP names alone are not globally unique identities: draw only inferences.
    links = []
    by_name = {}
    for d in devices:
        by_name.setdefault(d['name'], []).append(d['id'])
    tables = {(o['device_id'], o['table']): o['values'] for o in observations if o['kind'] == 'snmp_table'}
    for device in devices:
        names = tables.get((device['id'], 'lldp_names'), {})
        ports = tables.get((device['id'], 'lldp_ports'), {})
        local = tables.get((device['id'], 'lldp_local'), {})
        for index, remote_name in names.items():
            matches = by_name.get(remote_name, [])
            if len(matches) != 1 or matches[0] == device['id']:
                continue
            bits = index.split('.')
            local_port = local.get(bits[-2], 'LLDP-port:' + bits[-2]) if len(bits) >= 3 else 'unknown'
            evidence = dict(protocol='LLDP over SNMPv3', source_device=device['id'], local_index=index, remote_name=remote_name, observed_at=device['observed_at'], limitation='Name match only; chassis identity not yet corroborated')
            links.append(dict(source=device['id'], target=matches[0], source_port=local_port, target_port=ports.get(index, 'unknown'), confidence='inferred', evidence=[evidence]))
    return links


class Jobs:
    def __init__(self, store, allowed):
        self.store, self.allowed = store, allowed
        self.jobs = {}
        self.lock = threading.Lock()

    def start(self, addresses, profile_id):
        profile = self.store.secret(profile_id)
        with self.lock:
            if any(j['status'] in ('queued', 'running', 'cancelling') for j in self.jobs.values()):
                raise ValueError('A scan is already active')
            if len(self.jobs) >= 100:
                self.jobs.pop(next(iter(self.jobs)))
            ident = uuid.uuid4().hex
            job = dict(id=ident, status='queued', completed=0, total=len(addresses), created=now(), snapshot_id=None, cancel=threading.Event())
            self.jobs[ident] = job
        threading.Thread(target=self.run, args=(job, addresses, profile), daemon=True).start()
        return self.view(ident)

    def view(self, ident):
        with self.lock:
            if ident not in self.jobs:
                raise ValueError('Unknown job')
            return {k: v for k, v in self.jobs[ident].items() if k != 'cancel'}

    def cancel(self, ident):
        with self.lock:
            if ident not in self.jobs:
                raise ValueError('Unknown job')
            job = self.jobs[ident]
            if job['status'] in ('queued', 'running'):
                job['cancel'].set()
                job['status'] = 'cancelling'
        return self.view(ident)

    def run(self, job, addresses, profile):
        devices, observations, errors = [], [], []
        try:
            with self.lock:
                job['status'] = 'cancelling' if job['cancel'].is_set() else 'running'
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                futures = {pool.submit(collect_device, address, profile, job['cancel']): address for address in addresses}
                for future in concurrent.futures.as_completed(futures):
                    try:
                        device, obs, err = future.result()
                        if device:
                            devices.append(device)
                        observations.extend(obs)
                        errors.extend(err)
                    except Cancelled:
                        pass
                    except Exception:
                        errors.append(dict(device=futures[future], message='Collector failed; partial results retained'))
                    with self.lock:
                        job['completed'] += 1
            t = dict(schema_version=1, name='Live SNMPv3 scan', created=now(), synthetic=False, devices=devices, observations=observations, links=correlate(devices, observations), errors=errors)
            ident = self.store.save(t, t['name'])
            with self.lock:
                job.update(snapshot_id=ident, status='cancelled' if job['cancel'].is_set() else 'completed', finished=now())
        except Exception:
            with self.lock:
                job.update(status='failed', message='Scan failed; check state storage and configuration')
        finally:
            profile.clear()
