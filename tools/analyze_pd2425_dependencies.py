"""Read-only candidate ELF dependency graph for the pinned GSI/APEX set.

This is not Android namespace, symbol-version, dlopen or HAL compatibility proof.
No extracted program is executed, and this tool never emits launch authorization.
"""
import argparse, hashlib, json, os, posixpath, re, stat, subprocess, tempfile
from pathlib import Path
from fetch_preview_gsi import digest
ROOT=Path(__file__).resolve().parents[1]
PATH=re.compile(r'/[A-Za-z0-9_.+@/\-]*\Z')
LIB=re.compile(r'[A-Za-z0-9_.+@\-]+\Z')
BASE=['/apex/com.android.runtime/lib64/bionic','/system/lib64','/system/system_ext/lib64','/apex/com.android.runtime/lib64']

class Missing(ValueError): pass

def safe(path):
    if not isinstance(path,str) or not PATH.fullmatch(path): raise Missing('Unsupported guest path')
    return posixpath.normpath(path)

def symbol_table(text):
    required=set();provided=set();unversioned=set()
    for line in text.splitlines():
        m=re.match(r'\s*\d+:\s+\S+\s+\S+\s+.+?\s+(GLOBAL|WEAK|UNIQUE)\s+(DEFAULT|PROTECTED|HIDDEN|INTERNAL)\s+(\S+)\s+(\S+)',line)
        if not m:continue
        bind,visibility,index,name=m.groups()
        if index=='UND':
            if bind=='GLOBAL':required.add(name.replace('@@','@'))
        elif visibility in ('DEFAULT','PROTECTED'):
            provided.add(name.replace('@@','@'))
            if '@' not in name:unversioned.add(name)
            if '@@' in name:provided.add(name.split('@@')[0])
    return required,provided,unversioned

class Images:
    def __init__(self,image,prepared,work,pin,catalog):
        self.image=Path(image);self.prepared=Path(prepared);self.work=Path(work)
        self.pin=pin;self.catalog=catalog;self.opened={};self.stats={};self.elfs={};self.symbols={}
        self.modules={m['manifest_identity']['name']:m for m in catalog['modules']}
        if len(self.modules)!=len(catalog['modules']):raise ValueError('Ambiguous module identity')
        for m in catalog['modules']:
            if not m['manifest_identity_verified'] or not m['payload_manifest_verified']:raise ValueError('Unverified manifest identity')
    def source(self,name):
        if name in self.opened:return self.opened[name][0]
        if name=='gsi':path=self.image;size=self.pin['image_bytes'];sha=self.pin['image_sha256']
        else:
            if name not in self.modules:raise Missing('APEX not available: '+name)
            m=self.modules[name];path=self.prepared/(m['package_filename']+'.img');size=m['payload']['bytes'];sha=m['payload']['sha256']
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            before=os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size!=size:raise ValueError('Image type/size mismatch: '+name)
            with os.fdopen(os.dup(fd),'rb') as f:
                if hashlib.file_digest(f,'sha256').hexdigest()!=sha:raise ValueError('Image hash mismatch: '+name)
            reference=Path('/proc/self/fd/'+str(fd))
            if not reference.exists():
                reference=self.work/('image-'+str(len(self.opened))+'.raw');os.lseek(fd,0,os.SEEK_SET)
                with os.fdopen(os.dup(fd),'rb') as src,reference.open('xb') as dst:
                    total=0
                    while block:=src.read(1024*1024):
                        total+=len(block)
                        if total>size:raise ValueError('Image grew')
                        dst.write(block)
                if reference.stat().st_size!=size or digest(reference)!=sha:raise ValueError('Snapshot mismatch')
                reference.chmod(0o400)
            self.opened[name]=(reference,fd,before);return reference
        except BaseException:os.close(fd);raise
    def close(self):
        changed=[]
        for name,(_,fd,before) in self.opened.items():
            after=os.fstat(fd);os.close(fd)
            if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):changed.append(name)
        self.opened={}
        if changed:raise ValueError('Source changed: '+str(changed))
    def mapped(self,path):
        if path.startswith('/apex/'):
            parts=path.split('/');name=parts[2]
            return self.source(name),'/'+('/'.join(parts[3:]))
        return self.source('gsi'),path
    def command(self,path,verb):
        reference,inside=self.mapped(path)
        p=subprocess.run(['debugfs','-R',verb+' '+inside,str(reference)],cwd=self.work,
                         pass_fds=tuple(v[1] for v in self.opened.values()),capture_output=True,text=True,timeout=30)
        if p.returncode:raise Missing('debugfs failure: '+path)
        return p.stdout
    def info(self,path):
        if path in self.stats:return self.stats[path]
        if path=='/apex':return ('directory',None,0)
        text=self.command(path,'stat');kind=re.search(r'Inode:.*?Type:\s+(\w+)',text)
        if not kind:raise Missing('Absent path: '+path)
        link=re.search(r'Fast link dest: "([^"\n]+)"',text);size=re.search(r'\bSize:\s+(\d+)',text)
        row=(kind[1],link[1] if link else None,int(size[1]) if size else 0);self.stats[path]=row;return row
    def resolve(self,path):
        path=safe(path)
        for _ in range(32):
            parts=path.strip('/').split('/');current='';changed=False
            for i,part in enumerate(parts):
                current+='/'+part;kind,link,_=self.info(current)
                if kind=='symlink':
                    if not link:raise Missing('Unsupported long symlink: '+current)
                    target=link if link.startswith('/') else posixpath.join(posixpath.dirname(current),link)
                    path=safe(posixpath.join(target,*parts[i+1:]));changed=True;break
                if i<len(parts)-1 and kind!='directory':raise Missing('Non-directory path component')
            if not changed:return path
        raise Missing('Symlink cycle/depth exceeded')
    def elf(self,path):
        if path in self.elfs:return self.elfs[path]
        kind,_,size=self.info(path)
        if kind!='regular' or not 0<size<=128*1024*1024:raise Missing('Invalid ELF file type/size')
        filename='elf-'+str(len(self.elfs));reference,inside=self.mapped(path)
        p=subprocess.run(['debugfs','-R','dump '+inside+' '+filename,str(reference)],cwd=self.work,pass_fds=tuple(v[1] for v in self.opened.values()),capture_output=True,text=True,timeout=30)
        target=self.work/filename
        if p.returncode or not target.exists() or target.stat().st_size!=size:raise Missing('ELF dump failed: '+path)
        with target.open('rb') as f:header=f.read(20)
        if header[:6]!=b'\x7fELF\x02\x01' or header[18:20]!=b'\xb7\x00':raise Missing('Not ARM64 ELF64: '+path)
        dynamic=subprocess.run(['readelf','-d','--dyn-syms','--wide',str(target)],capture_output=True,text=True,check=True,timeout=30).stdout
        result={'path':path,'bytes':size,'sha256':digest(target),'needed':re.findall(r'\(NEEDED\).*?\[(.*?)\]',dynamic),'runpaths':re.findall(r'\((?:RUNPATH|RPATH)\).*?\[(.*?)\]',dynamic)}
        required,provided,plain=symbol_table(dynamic);self.symbols[path]=(required,provided,plain)
        result['strong_undefined_symbols']=len(required);result['provided_dynamic_symbols']=len(provided)
        self.elfs[path]=result;target.unlink();return result

def directories(path):
    result=list(BASE)
    if path.startswith('/apex/'):
        own='/apex/'+path.split('/')[2]+'/lib64'
        result.insert(1,own)
    return list(dict.fromkeys(result))

def graph(images,target,exports):
    nodes={};edges=[];missing=[];pending=[target]
    while pending:
        original=pending.pop(0)
        try:
            path=images.resolve(original)
            if path in nodes:continue
            if len(nodes)>=512:raise Missing('ELF graph node limit')
            node=images.elf(path);nodes[path]=node
            if node['runpaths']:missing.append({'from':path,'reason':'RUNPATH/RPATH not modeled'})
            for name in node['needed']:
                if not LIB.fullmatch(name):missing.append({'from':path,'library':name,'reason':'Unsupported SONAME'});continue
                search=directories(path)+[p+'/lib64' for p in exports.get(name,[])]
                candidates=[]
                for directory in dict.fromkeys(search):
                    try:resolved=images.resolve(directory+'/'+name)
                    except Missing:continue
                    if resolved not in candidates:candidates.append(resolved)
                if not candidates:missing.append({'from':path,'library':name,'reason':'No candidate in modeled search paths'});continue
                edges.append({'from':path,'library':name,'selected':candidates[0],'alternatives':candidates[1:]});pending.append(candidates[0])
        except Missing as error:missing.append({'from':original,'reason':str(error)})
    providers={}
    for e in edges:providers.setdefault(e['library'],set()).add(e['selected'])
    duplicates={name:sorted(values) for name,values in sorted(providers.items()) if len(values)>1}
    symbol_missing=[];symbol_checked=0;available=set();plain_providers={};fallbacks=[]
    if hasattr(images,'symbols'):
        for path in nodes:
            table=images.symbols[path];available.update(table[1])
            for name in table[2] if len(table)>2 else ():
                plain_providers.setdefault(name,[]).append(path)
        for path in nodes:
            required=images.symbols[path][0];symbol_checked+=len(required)
            for name in sorted(required-available):
                providers=plain_providers.get(name.split('@')[0],[]) if '@' in name else []
                if providers:fallbacks.append({'from':path,'symbol':name,'unversioned_candidates':providers})
                else:symbol_missing.append({'from':path,'symbol':name})
    return {'target':target,'candidate_closure_complete':not missing,'elf_count':len(nodes),'nodes':[nodes[p] for p in sorted(nodes)],'edges':edges,'missing':missing,
            'multiple_selected_providers':duplicates,'requires_namespace_partitioning':bool(duplicates),
            'strong_symbol_union_checked':symbol_checked,'strong_symbol_union_missing':symbol_missing,
            'unversioned_fallback_candidates':fallbacks,
            'strong_symbol_union_available':(False if symbol_missing else None if fallbacks else True) if symbol_checked else None,
            'namespace_compatibility_verified':False,'symbol_versions_verified':False,'program_executed':False}

def summarize(report):
    result={k:v for k,v in report.items() if k!='targets'};result['targets']=[]
    for target in report['targets']:
        row={k:v for k,v in target.items() if k not in ('nodes','edges')}
        for key in ('nodes','edges'):
            data=json.dumps(target[key],sort_keys=True,separators=(',',':')).encode()
            row[key+'_sha256']=hashlib.sha256(data).hexdigest()
        row['dependency_edges']=len(target['edges']);result['targets'].append(row)
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('image',type=Path);p.add_argument('prepared',type=Path);p.add_argument('--output',type=Path,required=True);p.add_argument('--summary',type=Path);a=p.parse_args()
    pin=json.loads((ROOT/'profiles/pd2425-evox-preview.json').read_text());catalog=json.loads((ROOT/'profiles/pd2425-evox-apex.json').read_text())
    if catalog['image_sha256']!=pin['image_sha256']:raise ValueError('Catalog source mismatch')
    exports={}
    for m in catalog['modules']:
        for name in m['manifest_identity']['provide_native_libs']:exports.setdefault(name,[]).append('/apex/'+m['manifest_identity']['name'])
    (ROOT/'build').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='deps-',dir=ROOT/'build') as work:
        images=Images(a.image,a.prepared,work,pin,catalog)
        try:results=[graph(images,r['path'],exports) for r in catalog['programs']]
        finally:images.close()
    report={'schema':1,'image_sha256':pin['image_sha256'],'runtime_ready':False,'scope':'Static candidate graph plus strong symbol name/version availability in the union only; ordered bootstrap/owner paths plus manifest exports; no dlopen, actual binding, symbol-version provider, namespace or HAL proof','targets':results}
    with a.output.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
    if a.summary:
        with a.summary.open('x') as f:json.dump(summarize(report),f,indent=2);f.write('\n')
    print([(r['target'],r['elf_count'],len(r['missing']),len(r['strong_symbol_union_missing']),len(r['unversioned_fallback_candidates'])) for r in results])
if __name__=='__main__':main()
