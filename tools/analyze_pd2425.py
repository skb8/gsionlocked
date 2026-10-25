"""Derive an init/HAL/VINTF/SELinux inventory from locally extracted OTA trees."""
import argparse,hashlib,json,re,shlex,xml.etree.ElementTree as ET
from pathlib import Path

def digest(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        while b:=f.read(1024*1024):h.update(b)
    return h.hexdigest()
def inventory(tree,system):
    roots={p.name:p for p in tree.iterdir() if p.is_dir()};roots['system-selected']=system
    contexts=[];services=[];manifests=[];policies=[]
    for partition,root in sorted(roots.items()):
        for p in sorted(root.rglob('*')):
            if not p.is_file() or p.is_symlink():continue
            rel=partition+'/'+p.relative_to(root).as_posix()
            if p.name.endswith('file_contexts'):
                for line in p.read_text(errors='replace').splitlines():
                    w=line.split()
                    if len(w)>=2 and not line.lstrip().startswith('#'):contexts.append((w[0],w[-1]))
            if p.suffix=='.cil' or p.name.endswith(('_file_contexts','_service_contexts','_hwservice_contexts','_property_contexts')):
                policies.append({'source':rel,'sha256':digest(p),'bytes':p.stat().st_size})
            if p.suffix=='.rc':
                current=None
                for line in p.read_text(errors='replace').replace('\\\n',' ').splitlines():
                    if not line.strip() or line.lstrip().startswith('#'):continue
                    if not line[0].isspace():
                        words=shlex.split(line,comments=True) if line.startswith(('service ','service\t')) else []
                        current=None
                        if len(words)>=3:
                            current={'name':words[1],'argv':words[2:],'source':rel,'options':[]};services.append(current)
                    elif current is not None:current['options'].append(line.strip())
            if p.suffix=='.xml' and ('vintf' in p.parts or p.name=='manifest.xml'):
                doc=ET.parse(p).getroot()
                if doc.tag!='manifest':continue
                hals=[{'name':h.findtext('name'),'format':h.get('format'),'versions':[x.text for x in h.findall('version')],'fqnames':[x.text for x in h.findall('fqname')],
                    'interfaces':[{'name':x.findtext('name'),'instances':[y.text for y in x.findall('instance')]} for x in h.findall('interface')]} for h in doc.findall('hal')]
                manifests.append({'source':rel,'target_level':doc.get('target-level'),'hals':hals})
    for service in services:
        service['file_context_candidates']=[]
        for pattern,context in contexts:
            try:
                if re.fullmatch(pattern,service['argv'][0]):service['file_context_candidates'].append(context)
            except re.error:pass
    return {'warning':'Offline declarations; conditional imports, manifest variants and file contexts do not prove active services or effective SELinux permissions.',
        'services':services,'manifests':manifests,'policy_files':policies}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--tree',type=Path,required=True);p.add_argument('--system-selected',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(inventory(a.tree,a.system_selected),ensure_ascii=False,indent=2)+'\n')
if __name__=='__main__':main()
