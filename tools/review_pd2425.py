"""Review native schema-2 observations. NEVER generates launch authorization."""
import argparse,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
REMAINING=['physical display/touch handoff and exact restore','watchdog fd ownership/adoption/keepalive and recovery','effective enforcing SELinux policy and guest compatibility','HAL/Binder/namespace/cgroup/network integration','complete GSI/APEX/shim bootstrap','bounded on-device session and cleanup fault injection']
def review(report,profile):
    issues=[];observed=[]
    def issue(code,detail):issues.append({'code':code,'detail':detail})
    if not isinstance(report,dict) or report.get('schema')!=2:
        return {'schema':1,'runtime_ready':False,'issues':[{'code':'report_schema','detail':'Native schema 2 required'}],'remaining_device_tests':REMAINING}
    if report.get('runtime_ready') is not False or report.get('no_device_changes') is not True:issue('report_contract','Unexpected probe contract')
    checks=[('device',profile['device']),('sdk',str(profile['host_sdk'])),('abi','arm64-v8a'),('fingerprint',profile['fingerprint'])]
    if not all(report.get(k)==v for k,v in checks) or report.get('ota_identity_match') is not True:issue('ota_mismatch','Exact OTA identity was not established')
    if type(report.get('uid')) is not int or report['uid']!=0:issue('root_unconfirmed','Probe did not run as UID 0')
    def value(field):
        v=report.get(field)
        if not isinstance(v,dict) or type(v.get('errno')) is not int or v['errno']!=0 or not isinstance(v.get('value'),str):
            issue('unreadable_'+field,'Missing or failed read');return None
        return v['value'].strip()
    if value('selinux_enforce')!='1':issue('selinux_not_enforcing','Need observations with original enforcing mode; do not disable SELinux')
    temperature=value('battery_temp')
    if temperature is None or not re.fullmatch(r'-?[0-9]+',temperature) or not -200<=int(temperature)<=1000:issue('temperature_unknown','Battery temperature unavailable or invalid')
    elif int(temperature)>380:issue('temperature_high','Above the existing 38 C start guard; no handoff authorized at any temperature')
    controllers=value('cgroup_controllers')
    if not controllers:issue('cgroup_unknown','cgroup v2 controllers not observed')
    raw=report.get('services');services={}
    if not isinstance(raw,list):issue('services_missing','No service observations');raw=[]
    for service in raw:
        if not isinstance(service,dict) or not isinstance(service.get('name'),str):issue('service_malformed','Invalid service entry');continue
        if service['name'] in services:issue('service_duplicate',service['name'])
        services[service['name']]=service
    for expected in profile['services']+profile.get('host_services',[]):
        name=expected['name'];service=services.get(name)
        if service is None:issue('service_missing',name);continue
        state=service.get('state')
        if expected.get('required_running') and state!='running':issue('host_service_not_running',name)
        if state=='stopped':continue
        if state!='running':issue('service_state_unknown',name);continue
        if service.get('pid_source')!='init_property':issue('init_pid_unconfirmed',name+'; executable candidates do not prove init ownership')
        if service.get('snapshot_stable') is not True:issue('process_unstable',name)
        if service.get('executable')!=expected['executable'] or service.get('executable_matches') is not True or service.get('executable_errno')!=0:issue('executable_mismatch',name)
        fields_ok=True
        for field in ['uid','gid']:
            raw_value=service.get(field)
            if service.get(field+'_errno')!=0 or not isinstance(raw_value,str) or not re.fullmatch(r'\d+\s+\d+\s+\d+\s+\d+',raw_value):
                issue('credentials_missing',name+': '+field);fields_ok=False
        groups=service.get('groups');caps=service.get('cap_eff');context=service.get('selinux_context')
        if service.get('groups_errno')!=0 or not isinstance(groups,str) or not re.fullmatch(r'(?:\d+\s*)*',groups):issue('groups_missing',name);fields_ok=False
        if service.get('cap_eff_errno')!=0 or not isinstance(caps,str) or not re.fullmatch(r'[0-9a-fA-F]{1,16}',caps):issue('capabilities_missing',name);fields_ok=False
        if service.get('selinux_errno')!=0 or not isinstance(context,str) or not re.fullmatch(r'u:r:[A-Za-z0-9_]+:s\d+(?::[A-Za-z0-9_,.-]+)?',context.strip()):issue('selinux_context_missing',name);fields_ok=False
        if fields_ok and service.get('snapshot_stable') is True:
            observed.append({'name':name,'pid_source':service.get('pid_source'),'executable':service['executable'],'uid':service['uid'],'gid':service['gid'],'groups':groups,'cap_eff':caps,'selinux_context':context.strip()})
    inputs=report.get('inputs',{});devices=inputs.get('devices',[]) if isinstance(inputs,dict) else []
    devices=[x for x in devices if isinstance(x,dict) and x.get('keys_errno')==0] if isinstance(devices,list) else []
    keys=any(x.get('volume_up') is True for x in devices) and any(x.get('volume_down') is True for x in devices)
    if not keys:issue('return_key_capabilities_unknown','Both volume key capabilities have not been observed')
    watchdog=report.get('watchdog',{})
    if not isinstance(watchdog,dict):watchdog={}
    for field in ['identity','timeout','nowayout','state']:
        item=watchdog.get(field,{})
        if not isinstance(item,dict) or item.get('errno')!=0 or not item.get('value'):issue('watchdog_metadata_missing',field)
    return {'schema':1,'runtime_ready':False,'observation_checks_passed':not issues,'issues':issues,'observed_process_credentials':observed,
        'volume_key_capabilities_observed':keys,'remaining_device_tests':REMAINING,
        'warning':'A clean observation report does not validate handoff. No runtime profile or service-control commands are generated.'}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path);p.add_argument('--output',type=Path);a=p.parse_args()
    result=review(json.loads(a.report.read_text()),json.loads((ROOT/'profiles/pd2425-originos6.json').read_text()))
    text=json.dumps(result,ensure_ascii=False,indent=2)+'\n'
    if a.output:a.output.write_text(text)
    else:print(text,end='')
    return 0 if result.get('observation_checks_passed') else 4
if __name__=='__main__':raise SystemExit(main())
