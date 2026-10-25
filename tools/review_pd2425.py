"""Review schema-2/3 owner observations; NEVER generates launch authorization."""
import argparse,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
REMAINING=['physical display/touch handoff and exact restore','watchdog ownership/keepalive and recovery strategy','effective enforcing SELinux policy and guest compatibility','HAL/Binder/namespace/cgroup/network integration','complete GSI/APEX/shim bootstrap','bounded on-device session and cleanup fault injection']
def select_keys(devices,profile):
    names=profile['return_keys'];up=[];down=[]
    for d in devices:
        if not isinstance(d,dict) or d.get('keys_errno')!=0 or d.get('name_errno')!=0 or d.get('touch') is not False:continue
        if d.get('name')==names['up_name'] and d.get('volume_up') is True and d.get('volume_down') is False:up.append(d.get('path'))
        if d.get('name')==names['down_name'] and d.get('volume_down') is True and d.get('volume_up') is False:down.append(d.get('path'))
    valid=len(up)==len(down)==1 and up[0]!=down[0] and all(isinstance(p,str) and re.fullmatch(r'/dev/input/event\d+',p) for p in up+down)
    return {'selection_valid':bool(valid),'up_path':up[0] if valid else None,'down_path':down[0] if valid else None,'physical_chord_tested':False}
def review(report,profile):
    issues=[];observed=[]
    def issue(code,detail):issues.append({'code':code,'detail':detail})
    if not isinstance(report,dict) or report.get('schema') not in [2,3]:
        return {'schema':2,'runtime_ready':False,'issues':[{'code':'report_schema','detail':'Native schema 2 or 3 required'}],'remaining_device_tests':REMAINING}
    tests=report.get('self_tests',{});cgtest=tests.get('cgroup') if isinstance(tests,dict) else None
    if report.get('runtime_ready') is not False:issue('report_contract','Unexpected readiness claim')
    if report.get('no_device_changes') is not True:
        if not isinstance(cgtest,dict) or report.get('observations_read_only') is not True:issue('report_contract','Unrecognized non-read-only report')
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
    if value('selinux_enforce')!='1':issue('selinux_not_enforcing','Need original enforcing mode; do not disable SELinux')
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
    cgroup_pass=False
    if cgtest is not None:
        if not isinstance(cgtest,dict):issue('cgroup_test_invalid','Invalid child-only test result')
        else:
            base_boot=report.get('boot_id',{});test_boot=cgtest.get('boot_id',{})
            same_boot=isinstance(base_boot,dict) and isinstance(test_boot,dict) and base_boot.get('errno')==test_boot.get('errno')==0 and isinstance(base_boot.get('value'),str) and bool(base_boot['value'].strip()) and base_boot.get('value')==test_boot.get('value')
            cgroup_pass=(cgtest.get('component')=='cgroup-self-test' and cgtest.get('schema')==1 and cgtest.get('fingerprint')==report.get('fingerprint') and same_boot and cgtest.get('uid')==0 and cgtest.get('runtime_ready') is False and all(cgtest.get(k) is True for k in ['passed','test_only_children','is_cgroup2','membership_verified','kill_succeeded','drained','cleanup_complete']) and cgtest.get('host_services_changed') is False and cgtest.get('spawned')==cgtest.get('pidfds')==cgtest.get('reaped')==2 and cgtest.get('errno')==cgtest.get('cleanup_errno')==0)
            if not cgroup_pass:issue('cgroup_test_not_passed',str(cgtest.get('stage',cgtest.get('collection_error',cgtest.get('not_run','incomplete result')))))
    return {'schema':2,'runtime_ready':False,'host_profile_match':host_match,'ota_fingerprint_exact_match':ota_exact,'observation_checks_passed':not issues,'issues':issues,'observed_process_credentials':observed,'return_keys':selected_keys,'cgroup_kill_child_test_passed':bool(cgroup_pass),'remaining_device_tests':REMAINING,'warning':'Observed identities and test results are not launch authorization. No service control is generated.'}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path);p.add_argument('--output',type=Path);a=p.parse_args()
    result=review(json.loads(a.report.read_text()),json.loads((ROOT/'profiles/pd2425-originos6.json').read_text()))
    text=json.dumps(result,ensure_ascii=False,indent=2)+'\n'
    if a.output:a.output.write_text(text)
    else:print(text,end='')
    return 0 if result.get('observation_checks_passed') else 4
if __name__=='__main__':raise SystemExit(main())
