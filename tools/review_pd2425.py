"""Review schema-2/3 owner observations; NEVER generates launch authorization."""
import argparse,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
REMAINING=['physical display/touch handoff and reboot-based exit/recovery','watchdog behavior during guest hardware use and reboot recovery','effective enforcing SELinux policy and guest compatibility','guest HAL/service-manager integration; PID/rootfs/BPF isolation','complete GSI/APEX/shim bootstrap','bounded on-device session and cleanup fault injection']
def select_keys(devices,profile):
    names=profile['return_keys'];up=[];down=[]
    for d in devices:
        if not isinstance(d,dict) or d.get('keys_errno')!=0 or d.get('name_errno')!=0 or d.get('touch') is not False:continue
        if d.get('name')==names['up_name'] and d.get('volume_up') is True and d.get('volume_down') is False:up.append(d.get('path'))
        if d.get('name')==names['down_name'] and d.get('volume_down') is True and d.get('volume_up') is False:down.append(d.get('path'))
    valid=len(up)==len(down)==1 and up[0]!=down[0] and all(isinstance(p,str) and re.fullmatch(r'/dev/input/event\d+',p) for p in up+down)
    return {'selection_valid':bool(valid),'up_path':up[0] if valid else None,'down_path':down[0] if valid else None,'physical_chord_tested':False}
def contained_test_ok(test,component,report):
    if not isinstance(test,dict):return False
    a,b=report.get('boot_id',{}),test.get('boot_id',{})
    same_boot=isinstance(a,dict) and isinstance(b,dict) and a.get('errno')==b.get('errno')==0 and isinstance(a.get('value'),str) and bool(a['value'].strip()) and a.get('value')==b.get('value')
    return (test.get('component')==component and test.get('schema')==1 and test.get('fingerprint')==report.get('fingerprint') and same_boot and type(test.get('uid')) is int and test['uid']==0 and test.get('runtime_ready') is False and all(test.get(k) is True for k in ['passed','test_only_children','group_created','is_cgroup2','membership_verified','kill_succeeded','drained','cleanup_complete']) and test.get('host_services_changed') is False and test.get('spawned')==test.get('pidfds')==test.get('reaped')==2 and test.get('errno')==test.get('cleanup_errno')==0)
def namespace_test_ok(test,report):
    if not contained_test_ok(test,'namespace-self-test',report):return False
    if not all(test.get(k) is True for k in ['parent_checked','parent_unchanged','temporary_directory_removed']):return False
    def namespace(value):
        if not isinstance(value,dict) or type(value.get('device')) is not int or value['device']<0 or type(value.get('inode')) is not int or value['inode']<=0:return None
        return value['device'],value['inode']
    parent_mnt,parent_net=namespace(test.get('parent_mount_namespace')),namespace(test.get('parent_network_namespace'))
    if parent_mnt is None or parent_net is None:return False
    parent_binder=test.get('parent_binder');children=test.get('children')
    if not isinstance(parent_binder,list) or not isinstance(children,list) or len(children)!=2:return False
    def device(value):
        if not isinstance(value,dict) or type(value.get('major')) is not int or not 0<value['major']<=0xffffffff or type(value.get('minor')) is not int or not 0<=value['minor']<=0xffffffff:return None
        return value['major'],value['minor']
    stock={device(d) for d in parent_binder if isinstance(d,dict) and d.get('present') is True}
    if None in stock or not any(d.get('name')=='binder' and d.get('present') is True for d in parent_binder if isinstance(d,dict)):return False
    seen_indices=set();mounts=set();networks=set();devices=set()
    for child in children:
        if not isinstance(child,dict) or type(child.get('index')) is not int or child['index'] not in [0,1] or child['index'] in seen_indices:return False
        seen_indices.add(child['index'])
        if child.get('reported') is not True or child.get('errno')!=0 or child.get('stage')!='complete' or child.get('private_mounts') is not True or child.get('private_network') is not True or child.get('devices_created')!=3 or child.get('binderfs_verified') is not True:return False
        mnt,net=namespace(child.get('mount_namespace')),namespace(child.get('network_namespace'))
        if mnt is None or net is None or mnt==parent_mnt or net==parent_net or mnt in mounts or net in networks:return False
        mounts.add(mnt);networks.add(net)
        nodes=child.get('binder')
        if not isinstance(nodes,list) or len(nodes)!=3:return False
        names=set()
        for node in nodes:
            if not isinstance(node,dict) or node.get('name') not in ['binder','hwbinder','vndbinder'] or node['name'] in names or node.get('protocol')!=8:return False
            names.add(node['name']);identity=device(node)
            if identity is None or identity in stock or identity in devices:return False
            devices.add(identity)
    return True
def bootstrap_test_ok(test,report,rootfs_only=False):
    if not contained_test_ok(test,'rootfs-self-test' if rootfs_only else 'bootstrap-self-test',report):return False
    if rootfs_only and (test.get('pid_namespace_required') is not False or test.get('proc_required') is not False):return False
    if not all(test.get(k) is True for k in ['parent_checked','parent_unchanged','temporary_directory_removed']):return False
    def identity(value):
        if not isinstance(value,dict) or type(value.get('device')) is not int or value['device']<0 or type(value.get('inode')) is not int or value['inode']<=0:return None
        return value['device'],value['inode']
    parent_pid=identity(test.get('parent_pid_namespace'));parent_mnt=identity(test.get('parent_mount_namespace'));parent_root=identity(test.get('parent_root'))
    if parent_mnt is None or parent_root is None or (not rootfs_only and parent_pid is None):return False
    children=test.get('children')
    if not isinstance(children,list) or len(children)!=2:return False
    indices=set();pids=set();mounts=set();roots=set()
    for child in children:
        if not isinstance(child,dict) or type(child.get('index')) is not int or child['index'] not in [0,1] or child['index'] in indices:return False
        indices.add(child['index'])
        if child.get('reported') is not True or child.get('stage')!='complete' or child.get('errno')!=0:return False
        if not all(child.get(k) is True for k in (['root_read_only','inherited_fds_closed'] if rootfs_only else ['root_read_only','proc_read_only','inherited_fds_closed'])):return False
        if rootfs_only:
            if type(child.get('pid')) is not int or child['pid']<=1 or type(child.get('ppid')) is not int or child['ppid']<=0 or child.get('proc_self_pid')!=0 or child.get('proc_pid_count')!=0 or child.get('proc_read_only') is not False:return False
        elif any(type(child.get(k)) is not int or child[k]!=v for k,v in [('pid',1),('ppid',0),('proc_self_pid',1),('proc_pid_count',1)]):return False
        pid=identity(child.get('pid_namespace'));mnt=identity(child.get('mount_namespace'));root=identity(child.get('root'))
        if mnt is None or root is None or mnt==parent_mnt or root[0]==parent_root[0] or mnt in mounts or root[0] in roots:return False
        if rootfs_only:
            if child.get('pid_namespace')!={'device':0,'inode':0}:return False
        elif pid is None or pid==parent_pid or pid in pids:return False
        pids.add(pid);mounts.add(mnt);roots.add(root[0])
    return True
GUARD_NAMES={'kill','tkill','tgkill','pidfd_send_signal','rt_sigqueueinfo','rt_tgsigqueueinfo','ptrace','process_vm_writev','process_madvise','bpf','perf_event_open','process_vm_readv'}
def guard_test_ok(test,report):
    if not isinstance(test,dict) or test.get('component')!='guard-self-test' or test.get('guard_required') is not True or test.get('parent_guard_checked') is not True:return False
    if type(test.get('parent_seccomp_mode')) is not int or test['parent_seccomp_mode'] not in [0,2] or type(test.get('parent_no_new_privs')) is not int or test['parent_no_new_privs'] not in [0,1]:return False
    base=dict(test);base['component']='rootfs-self-test'
    if not bootstrap_test_ok(base,report,True):return False
    for child in test['children']:
        g=child.get('guard')
        if not isinstance(g,dict) or g.get('baseline_self_signal_allowed') is not True or g.get('installed') is not True or g.get('no_new_privs')!=1 or g.get('seccomp_mode')!=2 or g.get('verified')!=len(GUARD_NAMES) or g.get('phase')!=5:return False
        denials=g.get('denials')
        if not isinstance(denials,list) or len(denials)!=len(GUARD_NAMES):return False
        names=set()
        for item in denials:
            if not isinstance(item,dict) or not isinstance(item.get('name'),str) or item['name'] not in GUARD_NAMES or item['name'] in names or type(item.get('errno')) is not int or item['errno']!=1:return False
            names.add(item['name'])
    return True
def gsi_preview_ok(test,report):
    if not isinstance(test,dict) or test.get('component')!='gsi-preview' or test.get('schema')!=1 or test.get('runtime_ready') is not False or test.get('guest_boot_complete') is not False or test.get('host_services_changed') is not False:return False
    a,b=report.get('boot_id',{}),test.get('boot_id',{})
    if not isinstance(a,dict) or not isinstance(b,dict) or a.get('errno')!=0 or b.get('errno')!=0 or not a.get('value') or a.get('value')!=b.get('value') or test.get('fingerprint')!=report.get('fingerprint') or test.get('uid')!=0:return False
    pin=json.loads((ROOT/'profiles/pd2425-evox-preview.json').read_text())
    if test.get('image_sha256')!=pin['image_sha256']:return False
    if not all(test.get(k) is True for k in ['preview_passed','prepared','capabilities_zero','namespaces_private','metadata_received','parent_unchanged','loops_released','temporary_directory_removed']):return False
    if any(type(test.get(k)) is not int or test[k]!=v for k,v in [('errno',0),('child_errno',0),('cleanup_errno',0),('spawned',1),('reaped',1),('exit_code',0),('signal',0),('guest_uid',65534),('guest_gid',65534),('no_new_privs',1),('filter_verified',5)]):return False
    return test.get('stage')=='complete' and test.get('child_stage')=='exec' and isinstance(test.get('output'),str) and 'PD2425_GSI_SHELL_OK\n' in test['output']
def service_loader_ok(test,report):
    if not isinstance(test,dict) or test.get('component')!='service-loader-preview' or test.get('schema')!=1 or test.get('runtime_ready') is not False or test.get('guest_boot_complete') is not False or test.get('host_services_changed') is not False:return False
    a,b=report.get('boot_id',{}),test.get('boot_id',{})
    if not isinstance(a,dict) or not isinstance(b,dict) or a.get('errno')!=0 or b.get('errno')!=0 or not a.get('value') or a.get('value')!=b.get('value') or test.get('fingerprint')!=report.get('fingerprint') or test.get('uid')!=0:return False
    pin=json.loads((ROOT/'profiles/pd2425-evox-preview.json').read_text())
    if test.get('image_sha256')!=pin['image_sha256']:return False
    if not all(test.get(k) is True for k in ['preview_passed','prepared','capabilities_zero','namespaces_private','metadata_received','parent_unchanged','loops_released','temporary_directory_removed']):return False
    if any(type(test.get(k)) is not int or test[k]!=v for k,v in [('errno',0),('child_errno',0),('cleanup_errno',0),('spawned',1),('reaped',1),('exit_code',0),('signal',0),('guest_uid',65534),('guest_gid',65534),('no_new_privs',1),('filter_verified',5)]):return False
    expected=pin['service_loader_preview']
    return (test.get('stage')=='complete' and test.get('child_stage')=='exec' and test.get('target')==expected['target'] and test.get('service_main_executed') is False and test.get('linkerconfig_readonly') is True and test.get('bootstrap_linkerconfig_sha256')==expected['bootstrap_linkerconfig_sha256'] and isinstance(test.get('output'),str) and 'libbinder.so' in test['output'] and 'libc.so' in test['output'])
def review(report,profile):
    issues=[];observed=[]
    def issue(code,detail):issues.append({'code':code,'detail':detail})
    if not isinstance(report,dict) or report.get('schema') not in [2,3]:
        return {'schema':2,'runtime_ready':False,'issues':[{'code':'report_schema','detail':'Native schema 2 or 3 required'}],'remaining_device_tests':REMAINING}
    tests=report.get('self_tests',{});cgtest=tests.get('cgroup') if isinstance(tests,dict) else None
    nstest=tests.get('namespaces') if isinstance(tests,dict) else None
    bstest=tests.get('bootstrap') if isinstance(tests,dict) else None
    rftest=tests.get('rootfs') if isinstance(tests,dict) else None
    guardtest=tests.get('guard') if isinstance(tests,dict) else None
    preview=tests.get('gsi_preview') if isinstance(tests,dict) else None
    if report.get('runtime_ready') is not False:issue('report_contract','Unexpected readiness claim')
    if report.get('no_device_changes') is not True:
        if not (isinstance(cgtest,dict) or isinstance(nstest,dict) or isinstance(bstest,dict) or isinstance(rftest,dict) or isinstance(guardtest,dict) or isinstance(preview,dict)) or report.get('observations_read_only') is not True:issue('report_contract','Unrecognized non-read-only report')
    hardware=report.get('device')==profile['device'] and report.get('sdk')==str(profile['host_sdk']) and report.get('abi')=='arm64-v8a'
    host_match=hardware and report.get('fingerprint') in profile.get('accepted_host_fingerprints',[profile['fingerprint']])
    ota_exact=hardware and report.get('fingerprint')==profile['fingerprint']
    if not host_match:issue('host_profile_mismatch','Device/API/ABI/fingerprint is not in the exact observed allowlist')
    if report.get('ota_identity_match') is not ota_exact:issue('identity_claim_inconsistent','OTA-exact flag contradicts original OTA fingerprint')
    if report['schema']==3 and report.get('host_profile_match') is not host_match:issue('identity_claim_inconsistent','Host profile flag contradicts source fields')
    if type(report.get('uid')) is not int or report['uid']!=0:issue('root_unconfirmed','Probe did not run as UID 0')
    def value(field):
        v=report.get(field)
        if not isinstance(v,dict) or type(v.get('errno')) is not int or v['errno']!=0 or not isinstance(v.get('value'),str):
            issue('unreadable_'+field,'Missing or failed read');return None
        return v['value'].strip()
    enforcing=value('selinux_enforce')=='1'
    if not enforcing:issue('selinux_not_enforcing','Need original enforcing mode; do not disable SELinux')
    temperature=value('battery_temp')
    if temperature is None or not re.fullmatch(r'-?[0-9]+',temperature) or not -200<=int(temperature)<=1000:issue('temperature_unknown','Battery temperature unavailable or invalid')
    elif int(temperature)>380:issue('temperature_high','Above existing 38 C start guard; no handoff authorized at any temperature')
    value('cgroup_controllers') # Empty is valid: controllers do not establish cgroup.kill support.
    fs=report.get('cgroup_filesystem',{})
    if not isinstance(fs,dict) or fs.get('errno')!=0 or fs.get('is_cgroup2') is not True:issue('cgroup_version_unconfirmed','Need statfs or child-only cgroup test, not a nonempty controllers list')
    raw=report.get('services');services={}
    if not isinstance(raw,list):issue('services_missing','No service observations');raw=[]
    for service in raw:
        if not isinstance(service,dict) or not isinstance(service.get('name'),str):issue('service_malformed','Invalid service entry');continue
        if service['name'] in services:issue('service_duplicate',service['name'])
        services[service['name']]=service
    inactive=set()
    for group in profile.get('service_alternatives',[]):
        selected=group['expected_active'];active=services.get(selected,{})
        if active.get('state')=='running' and active.get('snapshot_stable') is True:
            for name in group['members']:
                if name!=selected:
                    if services.get(name,{}).get('state')=='running':issue('unexpected_alternative_active',name)
                    else:inactive.add(name)
        else:issue('selected_alternative_missing',selected)
    for expected in profile['services']+profile.get('host_services',[]):
        name=expected['name'];service=services.get(name)
        if name in inactive:continue
        if service is None:issue('service_missing',name);continue
        state=service.get('state')
        if expected.get('required_running') and state!='running':issue('host_service_not_running',name)
        if state=='stopped':continue
        if state!='running':issue('service_state_unknown',name);continue
        if service.get('pid_source')!='init_property':issue('init_pid_unconfirmed',name+'; executable candidates do not prove init ownership')
        if service.get('snapshot_stable') is not True:issue('process_unstable',name)
        if service.get('executable')!=expected['executable'] or service.get('executable_matches') is not True or service.get('executable_errno')!=0:issue('executable_mismatch',name)
        fields_ok=True;numbers={}
        for field in ['uid','gid']:
            v=service.get(field)
            if service.get(field+'_errno')!=0 or not isinstance(v,str) or not re.fullmatch(r'\d+\s+\d+\s+\d+\s+\d+',v):issue('credentials_missing',name+': '+field);fields_ok=False
            else:numbers[field]=list(map(int,v.split()))
        groups=service.get('groups');caps=service.get('cap_eff');context=service.get('selinux_context')
        if service.get('groups_errno')!=0 or not isinstance(groups,str) or not re.fullmatch(r'(?:\d+\s*)*',groups):issue('groups_missing',name);fields_ok=False
        if service.get('cap_eff_errno')!=0 or not isinstance(caps,str) or not re.fullmatch(r'[0-9a-fA-F]{1,16}',caps):issue('capabilities_missing',name);fields_ok=False
        if service.get('selinux_errno')!=0 or not isinstance(context,str) or not re.fullmatch(r'u:r:[A-Za-z0-9_-]+:s\d+(?::[A-Za-z0-9_,.-]+)?',context.strip()):issue('selinux_context_missing',name);fields_ok=False
        baseline=expected.get('observed_identity')
        if fields_ok and baseline:
            if numbers['uid']!=[baseline['uid']]*4:issue('uid_drift',name)
            if numbers['gid']!=[baseline['gid']]*4:issue('primary_gid_drift',name)
            if sorted(map(int,groups.split()))!=baseline['supplementary_groups']:issue('supplementary_groups_drift',name)
            if int(caps,16)!=int(baseline['cap_eff'],16):issue('capabilities_drift',name)
            if context.strip()!=baseline['selinux_context']:issue('selinux_context_drift',name)
        if fields_ok and service.get('snapshot_stable') is True:
            observed.append({'name':name,'pid_source':service.get('pid_source'),'executable':service['executable'],'uid':service['uid'],'gid':service['gid'],'groups':groups,'cap_eff':caps,'selinux_context':context.strip()})
    inputs=report.get('inputs',{});devices=inputs.get('devices',[]) if isinstance(inputs,dict) else []
    selected_keys=select_keys(devices if isinstance(devices,list) else [],profile)
    if not selected_keys['selection_valid']:issue('physical_return_keys_unknown','Need one profile-named GPIO up and PMIC down; headset is not accepted')
    watchdog=report.get('watchdog',{});watchdog=watchdog if isinstance(watchdog,dict) else {}
    missing=[]
    for field in ['identity','timeout','nowayout','state']:
        item=watchdog.get(field,{})
        if not isinstance(item,dict) or item.get('errno')!=0 or not item.get('value'):missing.append(field)
    if missing:issue('watchdog_strategy_unresolved','watchdog0 metadata unavailable: '+', '.join(missing)+'; this does not prove no watchdog exists')
    test_environment_ok=host_match and type(report.get('uid')) is int and report['uid']==0 and enforcing
    cgroup_pass=test_environment_ok and contained_test_ok(cgtest,'cgroup-self-test',report)
    if cgtest is not None and not cgroup_pass:issue('cgroup_test_not_passed',str(cgtest.get('stage',cgtest.get('collection_error',cgtest.get('not_run','incomplete result')))) if isinstance(cgtest,dict) else 'invalid result')
    namespace_pass=test_environment_ok and namespace_test_ok(nstest,report)
    if nstest is not None and not namespace_pass:issue('namespace_test_not_passed',str(nstest.get('stage',nstest.get('collection_error',nstest.get('not_run','incomplete result')))) if isinstance(nstest,dict) else 'invalid result')
    bootstrap_pass=test_environment_ok and bootstrap_test_ok(bstest,report)
    if bstest is not None and not bootstrap_pass:issue('bootstrap_test_not_passed',str(bstest.get('stage',bstest.get('collection_error',bstest.get('not_run','incomplete result')))) if isinstance(bstest,dict) else 'invalid result')
    rootfs_pass=test_environment_ok and bootstrap_test_ok(rftest,report,True)
    if rftest is not None and not rootfs_pass:issue('rootfs_test_not_passed',str(rftest.get('stage',rftest.get('collection_error',rftest.get('not_run','incomplete result')))) if isinstance(rftest,dict) else 'invalid result')
    guard_pass=test_environment_ok and guard_test_ok(guardtest,report)
    if guardtest is not None and not guard_pass:issue('guard_test_not_passed',str(guardtest.get('stage',guardtest.get('collection_error',guardtest.get('not_run','incomplete result')))) if isinstance(guardtest,dict) else 'invalid result')
    service=tests.get('service_loader') if isinstance(tests,dict) else None
    service_pass=test_environment_ok and service_loader_ok(service,report)
    if service is not None and not service_pass:issue('service_loader_not_passed',str(service.get('child_stage',service.get('stage','incomplete result'))) if isinstance(service,dict) else 'invalid result')
    preview_pass=test_environment_ok and gsi_preview_ok(preview,report)
    if preview is not None and not preview_pass:issue('gsi_preview_not_passed',str(preview.get('child_stage',preview.get('stage','incomplete result'))) if isinstance(preview,dict) else 'invalid result')
    return {'schema':2,'runtime_ready':False,'host_profile_match':host_match,'ota_fingerprint_exact_match':ota_exact,'observation_checks_passed':not issues,'issues':issues,'observed_process_credentials':observed,'return_keys':selected_keys,'cgroup_kill_child_test_passed':bool(cgroup_pass or namespace_pass or bootstrap_pass or rootfs_pass or guard_pass),'namespace_test_passed':namespace_pass,'bootstrap_test_passed':bootstrap_pass,'rootfs_test_passed':bool(rootfs_pass or guard_pass),'syscall_guard_test_passed':guard_pass,'gsi_shell_preview_passed':preview_pass,'service_loader_passed':service_pass,'remaining_device_tests':REMAINING,'warning':'Observed identities and test results are not launch authorization. No service control is generated.'}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path);p.add_argument('--output',type=Path);a=p.parse_args()
    result=review(json.loads(a.report.read_text()),json.loads((ROOT/'profiles/pd2425-originos6.json').read_text()))
    text=json.dumps(result,ensure_ascii=False,indent=2)+'\n'
    if a.output:a.output.write_text(text)
    else:print(text,end='')
    return 0 if result.get('observation_checks_passed') else 4
if __name__=='__main__':raise SystemExit(main())
