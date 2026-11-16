import http.cookiejar
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch
from cryptography.fernet import Fernet
from pathfinder.core import Store, compare, csv_export, scope_addresses
from pathfinder.demo import topology
from pathfinder.collector import correlate, parse_walk, Jobs
from pathfinder.server import create_server

class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(self.temp.name)
    def tearDown(self):
        self.temp.cleanup()
    def test_profiles_encrypted_and_tampering_fails(self):
        p = self.store.save_profile('test', 'reader', 'auth-secret-123', 'priv-secret-123')
        self.assertNotIn(b'auth-secret', self.store.db.read_bytes())
        self.assertEqual(self.store.secret(p)['username'], 'reader')
        with self.store.connect() as c:
            c.execute('UPDATE profiles SET secret=?', (b'tampered',))
        with self.assertRaises(ValueError): self.store.secret(p)
    def test_wrong_key(self):
        p = self.store.save_profile('test','reader','auth-secret','priv-secret')
        self.store.key_path.write_bytes(Fernet.generate_key())
        with self.assertRaises(ValueError): Store(self.temp.name).secret(p)
    def test_permissions(self):
        self.assertEqual(self.store.db.stat().st_mode & 0o777, 0o600)
        self.store.key_path.chmod(0o644)
        with self.assertRaises(ValueError): Store(self.temp.name)
    def test_scope(self):
        self.assertEqual(len(scope_addresses(['192.0.2.0/30'],[],['192.0.2.0/24'])),2)
        for cidrs,seeds in [(['192.0.0.0/16'],[]),([],['198.51.100.1']),([],['example.com']),(['192.0.2.1/24'],[])]:
            with self.assertRaises(ValueError): scope_addresses(cidrs,seeds,['192.0.2.0/24'])
        with self.assertRaises(ValueError): scope_addresses([],['192.0.2.1'],[])
    def test_profile_config_injection(self):
        for bad in ['user\ninclude bad', 'user name', '#bad']:
            with self.assertRaises(ValueError): self.store.save_profile('x',bad,'abcdefgh','abcdefgh')
    def test_snapshot_and_diff(self):
        a=topology(); ident=self.store.save(a,'test')
        self.assertEqual(self.store.load(ident),a)
        b=topology(); self.assertEqual(compare(a,b)['changed'],[])
        b['devices'].pop(); b['links'].pop()
        self.assertEqual(compare(a,b)['removed'],['unknown'])
        self.assertEqual(len(compare(a,b)['links_removed']),1)
    def test_csv_formula_protection(self):
        t=topology();t['devices'][0]['name']='=HYPERLINK("evil")'
        result=csv_export(t)
        self.assertIn("'=HYPERLINK",result)
        self.assertIn('02:00:00:00:00:20',result)
    def test_numeric_walk_parser(self):
        self.assertEqual(parse_walk('.1.3.6.1.2.1.1.5.0 = STRING: "CORE"','.1.3.6.1.2.1.1.5'),{'0':'CORE'})
    def test_ambiguous_lldp_not_correlated(self):
        ds=[dict(id='a',name='x',observed_at='now'),dict(id='b',name='same'),dict(id='c',name='same')]
        obs=[dict(kind='snmp_table',device_id='a',table='lldp_names',values={'0.1.1':'same'})]
        self.assertEqual(correlate(ds,obs),[])
        ds.pop();links=correlate(ds,obs)
        self.assertEqual(links[0]['confidence'],'inferred')
    def test_partial_collection_job(self):
        profile=self.store.save_profile('test','user','abcdefgh','abcdefgh')
        jobs=Jobs(self.store,[])
        with patch('pathfinder.collector.collect_device',return_value=(None,[],[dict(message='missing permission')])):
            j=jobs.start(['192.0.2.1'],profile)
            import time
            for _ in range(100):
                v=jobs.view(j['id'])
                if v['status']=='completed': break
                time.sleep(.01)
        self.assertEqual(v['status'],'completed')
        self.assertEqual(len(self.store.load(v['snapshot_id'])['errors']),1)
    def test_help_matches(self):
        root=Path(__file__).resolve().parents[1]
        topics=json.loads((root/'pathfinder/help.json').read_text())
        expected='# Pathfinder help\n\nGenerated from pathfinder/help.json.\n\n'+'\n\n'.join('## '+t['title']+'\n\n'+t['body'] for t in topics)+'\n'
        self.assertEqual((root/'HELP.md').read_text(),expected)

class APITests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.store=Store(self.temp.name)
        self.server=create_server(self.store,'administrator-12345',port=0,operator_password='operator-password-12345')
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
        self.base='http://127.0.0.1:'+str(self.server.server_port)
        self.client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.csrf=''
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.temp.cleanup()
    def req(self,path,body=None,headers=None):
        h={'Content-Type':'application/json','X-CSRF-Token':self.csrf};h.update(headers or {})
        r=self.client.open(urllib.request.Request(self.base+path,data=json.dumps(body).encode() if body is not None else None,headers=h))
        return json.loads(r.read())
    def login(self,password='administrator-12345'):
        self.csrf=self.req('/api/login',dict(password=password))['csrf']
    def test_auth_csrf_and_roles(self):
        with self.assertRaises(urllib.error.HTTPError) as e:self.req('/api/snapshots')
        self.assertEqual(e.exception.code,401)
        self.login('operator-password-12345')
        with self.assertRaises(urllib.error.HTTPError) as e:self.req('/api/profiles',dict(name='x'))
        self.assertEqual(e.exception.code,403)
        with self.assertRaises(urllib.error.HTTPError) as e:self.req('/api/snapshots',dict(source='demo'),{'X-CSRF-Token':'wrong'})
        self.assertEqual(e.exception.code,403)
    def test_demo_save_export_and_help(self):
        self.login();self.assertTrue(self.req('/api/demo')['synthetic'])
        ident=self.req('/api/snapshots',dict(source='demo'))['id']
        self.assertEqual(self.req('/api/export?id='+ident)['schema_version'],1)
        self.assertGreater(len(self.req('/api/help')),8)
        page=self.client.open(self.base+'/').read()
        self.assertNotIn(b'https://cdn',page)
    def test_secrets_not_exposed_and_scope_denied(self):
        self.login()
        p=self.req('/api/profiles',dict(name='Lab',username='reader',auth_password='auth-secret',priv_password='priv-secret'))
        self.assertNotIn('secret',json.dumps(self.req('/api/profiles')))
        with self.assertRaises(urllib.error.HTTPError) as e:self.req('/api/scan',dict(seeds=['192.0.2.1'],profile_id=p['id']))
        self.assertEqual(e.exception.code,400)
        with self.assertRaises(urllib.error.HTTPError):self.req('/api/profiles/'+p['id'])
    def test_cross_origin_login_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as e:self.req('/api/login',dict(password='administrator-12345'),{'Origin':'https://evil.invalid'})
        self.assertEqual(e.exception.code,403)
    def test_nonloopback_rejected(self):
        with self.assertRaises(ValueError):create_server(self.store,'administrator-12345',host='0.0.0.0')

if __name__=='__main__':unittest.main()
