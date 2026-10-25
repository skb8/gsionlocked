"""Synthetic ELF metadata fixture + real C SHA/copy gates; no GSI bytes in CI."""
import hashlib,json,os,struct,subprocess,tempfile
from pathlib import Path
import prepare_service_entry as entry
from pd2425_build import generate_services
ROOT=Path(__file__).resolve().parents[1]
def fixture():
    b=bytearray(137200);b[:7]=b'\x7fELF\x02\x01\x01';struct.pack_into('<HH',b,16,3,183);struct.pack_into('<Q',b,40,135408)
    struct.pack_into('<IIQQQQQQ',b,64+2*56,1,4,0,0,0,0x8398,0x8398,0x4000)
    struct.pack_into('<IIQQQQIIQQ',b,135408+8*64,68,3,2,6008,6008,8031,0,0,1,0)
    for n,(tag,value) in enumerate([(21,0),(5,6008),(10,8031)]):struct.pack_into('<QQ',b,0x1d200+16*n,tag,value)
    b[0x1778:0x1778+8031]=bytes(n%251 for n in range(8031));b[0xc000:0x19f20]=b'X'*(0x19f20-0xc000)
    b[0x2e0:0x2ff]=b'/system/bin/bootstrap/linker64\0'.ljust(31,b'\0')
    return bytes(b)
original_sha=entry.SOURCE_SHA
source=fixture();entry.SOURCE_SHA=hashlib.sha256(source).hexdigest();patched,meta=entry.adapt(source)
assert source[0xc000:0x19f20]==patched[0xc000:0x19f20] and source[0x2e0:0x2ff]==patched[0x2e0:0x2ff]
assert len(patched)==len(source) and patched[meta['string_destination']:meta['string_destination']+8031]==source[6008:6008+8031]
assert patched[meta['string_destination']+8031:meta['string_destination']+8031+len(entry.HELPER)]==entry.HELPER
for mutate in ['hash','machine','padding','load','dynstr','duplicate']:
    bad=bytearray(source)
    if mutate=='hash':bad[100]^=1
    elif mutate=='machine':struct.pack_into('<H',bad,18,62)
    elif mutate=='padding':bad[0x8398]=1
    elif mutate=='load':struct.pack_into('<Q',bad,64+2*56+32,0x8399)
    elif mutate=='dynstr':struct.pack_into('<Q',bad,0x1d200+16+8,6009)
    else:struct.pack_into('<QQ',bad,0x1d200+3*16,5,6008)
    entry.SOURCE_SHA=hashlib.sha256(bad).hexdigest() if mutate!='hash' else meta['source_sha256']
    try:entry.adapt(bad)
    except ValueError:pass
    else:raise AssertionError(mutate)
entry.SOURCE_SHA=meta['source_sha256']
code=r'''
#define main preview_main
#include "gsi_preview.c"
#undef main
#include <assert.h>
int __system_property_get(const char *key,char *value){(void)key;*value=0;return 0;}
int main(int argc,char **argv){assert(argc==4);int from=open(argv[1],O_RDONLY|O_CLOEXEC),to=open(argv[2],O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,0600);assert(from>=0&&to>=0);int error=sm_patch_entry(from,to);close(from);close(to);assert(error==atoi(argv[3]));return 0;}
'''
with tempfile.TemporaryDirectory() as temp:
    d=Path(temp);generate_services(d);(d/'sys').mkdir();(d/'sys/system_properties.h').write_text('#define PROP_VALUE_MAX 92\nint __system_property_get(const char*,char*);\n')
    (d/'service_entry_meta.h').write_text(entry.header(meta));(d/'test.c').write_text(code);(d/'source').write_bytes(source)
    subprocess.run([os.getenv('CC','cc'),'-O2','-Wall','-Wextra','-Werror','-DSM_ENTRY_META_HEADER='+json.dumps(str(d/'service_entry_meta.h')),'-I',str(d),'-I',str(ROOT/'runtime/pd2425/src'),'-I',str(ROOT/'runtime/pd2425/include'),str(d/'test.c'),'-o',str(d/'test')],check=True)
    subprocess.run([str(d/'test'),str(d/'source'),str(d/'patched'),'0'],check=True,timeout=5)
    assert (d/'patched').read_bytes()==patched
    bad=bytearray(source);bad[100]^=1;(d/'bad').write_bytes(bad)
    subprocess.run([str(d/'test'),str(d/'bad'),str(d/'rejected'),'74'],check=True,timeout=5) # EBADMSG on Linux.
    assert (d/'rejected').stat().st_size==0
entry.SOURCE_SHA=original_sha
print('PASS: pinned ELF/hash/layout/padding rejection; unchanged instructions/interpreter, deterministic DT_NEEDED metadata and C/Python byte identity; rejected input writes nothing')

# Optional local integration with the exact image-extracted public ELF.
import sys
if len(sys.argv)==2:
    actual=Path(sys.argv[1]).read_bytes();expected,metadata=entry.adapt(actual)
    assert entry.header(metadata)==(ROOT/'runtime/pd2425/include/service_entry_meta.h').read_text()
    with tempfile.TemporaryDirectory() as temp:
        d=Path(temp);generate_services(d);(d/'sys').mkdir();(d/'sys/system_properties.h').write_text('#define PROP_VALUE_MAX 92\nint __system_property_get(const char*,char*);\n');(d/'test.c').write_text(code)
        subprocess.run([os.getenv('CC','cc'),'-O2','-Wall','-Wextra','-Werror','-I',str(d),'-I',str(ROOT/'runtime/pd2425/src'),'-I',str(ROOT/'runtime/pd2425/include'),str(d/'test.c'),'-o',str(d/'test')],check=True)
        subprocess.run([str(d/'test'),str(Path(sys.argv[1]).resolve()),str(d/'patched'),'0'],check=True,timeout=5)
        assert (d/'patched').read_bytes()==expected
        output=subprocess.check_output(['readelf','-l','-d',str(d/'patched')],text=True)
        assert '[Requesting program interpreter: /system/bin/bootstrap/linker64]' in output
        assert 'Shared library: [/data/local/tmp/pd2425-sm-check.so]' in output
    print('PASS: actual pinned GSI ELF, C/Python/header identical; readelf validates native interpreter and mandatory helper dependency')
