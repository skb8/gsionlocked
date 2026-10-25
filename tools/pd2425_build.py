"""Generate the native observation list from the source-only PD2425 profile."""
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
        seen.add(name);rows.append('    {'+json.dumps(name)+','+json.dumps(exe)+'},')
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    (directory/'services.generated.h').write_text('/* Generated from profiles/pd2425-originos6.json; declarations, not launch permission. */\nstatic const struct observed_service pd_services[]={\n'+'\n'.join(rows)+'\n};\n')
    return directory
