from .core import now


def topology():
    stamp = now()
    def device(ident, name, ip, kind, count):
        return dict(id=ident, name=name, ip=ip, kind=kind, interfaces=[dict(index=str(i), name=('Gi1/0/' if count > 8 else 'eth')+str(i), status='up' if i in (1,2,3,4,24,48) else 'down') for i in range(1,count+1)], source='synthetic fixture', observed_at=stamp)
    devices = [device('core','CORE-9300','192.0.2.1','switch',48), device('access','ACCESS-NETGEAR','192.0.2.2','switch',48), device('gateway','EDGE-SRX','192.0.2.254','router',4), device('host','ENGINEERING-01','192.0.2.20','endpoint',1), device('unknown','Unknown downstream segment',None,'unknown',0)]
    def link(a,b,port,remote,confidence,why):
        return dict(source=a,target=b,source_port=port,target_port=remote,confidence=confidence,evidence=[dict(protocol='synthetic fixture',observed_at=stamp,detail=why)])
    links = [link('core','access','Gi1/0/48','Gi1/0/48','confirmed','Fixture models reciprocal LLDP chassis and port identities'),link('gateway','core','eth1','Gi1/0/1','confirmed','Fixture models reciprocal LLDP chassis and port identities'),link('access','host','Gi1/0/3','eth1','inferred','MAC learned here; direct attachment is unverified'),link('access','unknown','Gi1/0/24','unknown','inferred','Multiple MACs; unknown downstream segment')]
    observations=[dict(kind='fdb',device_id='access',interface='Gi1/0/3',mac='02:00:00:00:00:20',vlan=20,protocol='synthetic fixture',observed_at=stamp)]
    return dict(schema_version=1,name='Demo • synthetic network',created=stamp,synthetic=True,devices=devices,links=links,observations=observations,errors=[dict(device='unknown',message='Synthetic example: unmanaged segment has no port-level evidence')])
