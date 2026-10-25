"""Generate source-only observation identities and service names from PD2425 profile."""
import json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def generate_services(directory):
    profile=json.loads((ROOT/'profiles/pd2425-originos6.json').read_text())
    services=profile['services']+profile.get('host_services',[])
    if profile['launch_enabled'] or not 1<=len(services)<=20:raise ValueError('Invalid diagnostic profile')
    seen=set();rows=[]
    for service in services:
        name,exe=service['name'],service['executable']
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,70}',name) or name in seen:raise ValueError('Invalid or duplicate service')
        if not re.fullmatch(r'/(?:system|vendor)/bin/[A-Za-z0-9_./@+-]+',exe) or '..' in Path(exe).parts:raise ValueError('Invalid executable')
        seen.add(name);identity='{0,0,0,0,{0},UINT64_C(0),""}'
        observed=service.get('observed_identity')
        if observed:
            uid,gid=observed['uid'],observed['gid'];groups=observed['supplementary_groups'];caps=observed['cap_eff'];context=observed['selinux_context']
            if any(type(x) is not int or not 0<=x<=0xffffffff for x in [uid,gid]+groups) or len(groups)>32 or len(set(groups))!=len(groups):raise ValueError('Invalid identity numbers')
            if not re.fullmatch(r'[0-9a-f]{16}',caps) or not re.fullmatch(r'u:r:[A-Za-z0-9_-]+:s\d+(?::[A-Za-z0-9_,.-]+)?',context):raise ValueError('Invalid identity context/capabilities')
            identity='{1,'+str(uid)+','+str(gid)+','+str(len(groups))+',{'+(','.join(map(str,groups)) or '0')+'},UINT64_C(0x'+caps+'),'+json.dumps(context)+'}'
        rows.append('    {'+json.dumps(name)+','+json.dumps(exe)+','+identity+'},')
    keys=profile['return_keys']
    for key in ['up_name','down_name']:
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',keys[key]):raise ValueError('Invalid input name')
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    (directory/'services.generated.h').write_text('/* Generated declarations and observed identities; NOT launch permission. */\n#define PD_KEY_UP_NAME '+json.dumps(keys['up_name'])+'\n#define PD_KEY_DOWN_NAME '+json.dumps(keys['down_name'])+'\nstatic const struct observed_service pd_services[]={\n'+'\n'.join(rows)+'\n};\n')
    return directory
