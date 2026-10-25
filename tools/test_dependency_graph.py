"""Candidate graph tests: cycles, missing libraries, provider ordering and limitations."""
from analyze_pd2425_dependencies import graph, safe, Missing, symbol_table, summarize

class Fixture:
    def __init__(self):
        self.nodes={
            '/system/bin/demo':{'needed':['liba.so','libmissing.so'],'runpaths':[]},
            '/system/lib64/liba.so':{'needed':['libb.so'],'runpaths':[]},
            '/system/lib64/libb.so':{'needed':['liba.so'],'runpaths':[]},
            '/apex/com.example/lib64/liba.so':{'needed':[],'runpaths':[]}}
    def resolve(self,path):
        path=safe(path)
        if path not in self.nodes:raise Missing('absent')
        return path
    def elf(self,path):return dict(self.nodes[path],path=path)

f=Fixture();r=graph(f,'/system/bin/demo',{'liba.so':['/apex/com.example']})
assert r['elf_count']==3 and not r['candidate_closure_complete'] and len(r['missing'])==1
assert r['missing'][0]['library']=='libmissing.so'
assert r['edges'][0]['selected']=='/system/lib64/liba.so' and r['edges'][0]['alternatives']==['/apex/com.example/lib64/liba.so']
assert not r['namespace_compatibility_verified'] and not r['symbol_versions_verified'] and not r['program_executed']
f.nodes['/system/bin/demo']['needed']=['liba.so'];r=graph(f,'/system/bin/demo',{})
assert r['candidate_closure_complete'] and r['elf_count']==3
f.nodes['/system/lib64/liba.so']['runpaths']=['$ORIGIN/private'];r=graph(f,'/system/bin/demo',{})
assert not r['candidate_closure_complete'] and r['missing'][0]['reason']=='RUNPATH/RPATH not modeled'
f.nodes['/system/bin/demo']['needed']=['../invalid'];r=graph(f,'/system/bin/demo',{})
assert not r['candidate_closure_complete']
for path in ['/system/lib64/x"y','/system/lib64/x\ny','relative']:
    try:safe(path)
    except Missing:pass
    else:raise AssertionError('unsafe debugfs command path accepted')
assert safe('/system/../apex/com.example/lib64/a.so')=='/apex/com.example/lib64/a.so'
print('PASS: dependency cycles, missing libraries, ordered providers, unsafe paths and explicit unsupported/compatibility states')

required,provided,plain=symbol_table("""
 1: 0000 0 FUNC GLOBAL DEFAULT UND malloc@LIBC (2)
 2: 0010 4 FUNC GLOBAL DEFAULT 1 malloc@@LIBC
 3: 0014 4 FUNC WEAK DEFAULT UND optional
 4: 0018 4 FUNC GLOBAL HIDDEN 1 private
 5: 001c 4 FUNC GLOBAL DEFAULT 1 old@V1
 6: 0020 4 <OS specific>: 10 GLOBAL DEFAULT 1 memcpy@@LIBC
""")
assert plain==set()
assert required=={'malloc@LIBC'} and provided=={'malloc@LIBC','malloc','old@V1','memcpy@LIBC','memcpy'}
f=Fixture();f.nodes['/system/bin/demo']['needed']=['liba.so'];f.symbols={}
old_elf=f.elf
def with_symbols(path):
 node=old_elf(path);f.symbols[path]=({'absent@V1'},set()) if path.endswith('demo') else (set(),{'unrelated@V2'});return node
f.elf=with_symbols
r=graph(f,'/system/bin/demo',{})
assert r['candidate_closure_complete'] and not r['strong_symbol_union_available'] and r['strong_symbol_union_missing'][0]['symbol']=='absent@V1'
print('PASS: strong/weak/default-version symbols and missing symbol availability remain distinct from path closure')

f=Fixture();f.nodes['/system/bin/demo']['needed']=['liba.so'];f.symbols={};old_elf2=f.elf
def fallback_symbols(path):
 node=old_elf2(path);f.symbols[path]=({'plain@V1'},set(),set()) if path.endswith('demo') else (set(),{'plain'},{'plain'});return node
f.elf=fallback_symbols;r=graph(f,'/system/bin/demo',{})
assert r['strong_symbol_union_available'] is None and not r['strong_symbol_union_missing'] and r['unversioned_fallback_candidates']
print('PASS: unversioned provider fallback remains pending instead of false ABI failure/success')

summary=summarize({'schema':1,'runtime_ready':False,'targets':[r]})
assert 'nodes' not in summary['targets'][0] and 'edges' not in summary['targets'][0] and len(summary['targets'][0]['nodes_sha256'])==64
assert not summary['runtime_ready'] and not summary['targets'][0]['namespace_compatibility_verified']
print('PASS: compact reproducible graph digests preserve pending compatibility states')
