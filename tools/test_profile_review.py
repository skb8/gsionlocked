"""Synthetic report based on sanitized profile facts; no owner PIDs or raw report."""
import copy,json
from pathlib import Path
from review_pd2425 import review,select_keys
ROOT=Path(__file__).resolve().parents[1]
p=json.loads((ROOT/'profiles/pd2425-originos6.json').read_text())
r={'schema':2,'component':'apk-probe','uid':0,'runtime_ready':False,'no_device_changes':True,'device':'PD2425','sdk':'36','abi':'arm64-v8a','fingerprint':p['accepted_host_fingerprints'][1],'ota_identity_match':False,'selinux_enforce':{'errno':0,'value':'1'},'battery_temp':{'errno':0,'value':'278'},'cgroup_controllers':{'errno':0,'value':''},'watchdog':{},'services':[]}
for i,s in enumerate(p['services']+p['host_services']):
    e=s.get('observed_identity');entry={'name':s['name'],'state':'stopped'}
    if e:
        entry.update(state='running',pid_source='init_property',pid=i+100,snapshot_stable=True,executable=s['executable'],executable_matches=True,executable_errno=0,uid=' '.join([str(e['uid'])]*4),gid=' '.join([str(e['gid'])]*4),groups=' '.join(map(str,e['supplementary_groups'])),cap_eff=e['cap_eff'],selinux_context=e['selinux_context'])
        for f in ['uid','gid','groups','cap_eff','selinux']:entry[f+'_errno']=0
    if s['name']=='vendor.gatekeeper_spu':entry['state']=''
    r['services'].append(entry)
r['inputs']={'devices':[{'path':'/dev/input/event7','name':'gpio-keys','name_errno':0,'keys_errno':0,'touch':False,'volume_up':True,'volume_down':False},{'path':'/dev/input/event8','name':'pmic_resin','name_errno':0,'keys_errno':0,'touch':False,'volume_up':False,'volume_down':True},{'path':'/dev/input/event9','name':'headset Button Jack','name_errno':0,'keys_errno':0,'touch':False,'volume_up':True,'volume_down':True}]}
def codes(j):return {x['code'] for x in review(j,p)['issues']}
result=review(r,p)
assert result['host_profile_match'] and not result['ota_fingerprint_exact_match'] and not result['runtime_ready']
assert codes(r)=={'cgroup_version_unconfirmed','watchdog_strategy_unresolved'}
assert result['return_keys']['up_path']=='/dev/input/event7' and result['return_keys']['down_path']=='/dev/input/event8'
headset=copy.deepcopy(r);headset['inputs']['devices']=headset['inputs']['devices'][-1:]
assert 'physical_return_keys_unknown' in codes(headset)
changed=copy.deepcopy(r);changed['fingerprint']=changed['fingerprint'].replace('V000L1','V000L2');assert 'host_profile_mismatch' in codes(changed)
composer=next(s for s in r['services'] if s['name']=='vendor.qti.hardware.display.composer');assert composer['gid'].startswith('1003')
changed=copy.deepcopy(r);next(s for s in changed['services'] if s['name']==composer['name'])['gid']='1000 1000 1000 1000'
assert 'primary_gid_drift' in codes(changed)
changed=copy.deepcopy(r);next(s for s in changed['services'] if s['name']=='thermal-engine')['selinux_context']='u:r:wrong:s0';assert 'selinux_context_drift' in codes(changed)
r['schema']=3;r['host_profile_match']=True;r['cgroup_filesystem']={'errno':0,'is_cgroup2':True}
assert codes(r)=={'watchdog_strategy_unresolved'} # Empty controllers != no cgroup2.
r['boot_id']={'errno':0,'value':'synthetic-one-boot\n'}
t={'schema':1,'component':'cgroup-self-test','runtime_ready':False,'uid':0,'fingerprint':r['fingerprint'],'boot_id':r['boot_id'],'passed':True,'group_created':True,'test_only_children':True,'host_services_changed':False,'is_cgroup2':True,'membership_verified':True,'kill_succeeded':True,'drained':True,'cleanup_complete':True,'spawned':2,'pidfds':2,'reaped':2,'errno':0,'cleanup_errno':0}
r['no_device_changes']=False;r['observations_read_only']=True;r['self_tests']={'cgroup':t}
assert review(r,p)['cgroup_kill_child_test_passed'] and not review(r,p)['runtime_ready']
for field,value in [('cleanup_complete',False),('reaped',1),('boot_id',{'errno':0,'value':'another-boot'}),('host_services_changed',True)]:
    changed=copy.deepcopy(r);changed['self_tests']['cgroup'][field]=value
    assert not review(changed,p)['cgroup_kill_child_test_passed'] and 'cgroup_test_not_passed' in codes(changed)
print('PASS: exact fingerprint alias, 14 observed identities, primary GID drift, headset exclusion, controllerless cgroup2 and test proof linkage')

# Full namespace proof is independent of a mere passed flag.
ns=copy.deepcopy(t);ns.update(component='namespace-self-test',parent_checked=True,parent_unchanged=True,temporary_directory_removed=True,parent_mount_namespace={'device':5,'inode':10},parent_network_namespace={'device':5,'inode':20},parent_binder=[{'name':'binder','present':True,'major':10,'minor':1}])
ns['children']=[]
for index in range(2):
    ns['children'].append({'index':index,'reported':True,'errno':0,'stage':'complete','private_mounts':True,'private_network':True,'devices_created':3,'mount_namespace':{'device':5,'inode':100+index},'network_namespace':{'device':5,'inode':200+index},'binder':[{'name':name,'major':600,'minor':index*3+n,'protocol':8} for n,name in enumerate(['binder','hwbinder','vndbinder'])]})
r['self_tests']={'namespaces':ns}
assert review(r,p)['namespace_test_passed'] and not review(r,p)['runtime_ready']
for target,field,value in [('parent','parent_unchanged',False),('parent','cleanup_complete',False),('child','network_namespace',{'device':5,'inode':20}),('node','protocol',7),('node','minor',0)]:
    bad=copy.deepcopy(r);test=bad['self_tests']['namespaces']
    obj=test if target=='parent' else test['children'][1] if target=='child' else test['children'][1]['binder'][0]
    obj[field]=value
    assert not review(bad,p)['namespace_test_passed'] and 'namespace_test_not_passed' in codes(bad)
print('PASS: namespace proof linkage, stock Binder exclusion, unique child devices, parent preservation and protocol checks')
