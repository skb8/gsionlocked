"""Fetch the pinned unmodified upstream EvoX archive and verify/decompress it. No root/mounts."""
import argparse,hashlib,json,lzma,os,tempfile,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def digest(path):
    with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def decompress(archive,target,size,sha):
    target=Path(target)
    if target.exists():
        if target.stat().st_size==size and digest(target)==sha:return
        raise ValueError('Existing target differs; refusing to overwrite it')
    fd,name=tempfile.mkstemp(prefix='decompress-',suffix='.part',dir=target.parent);part=Path(name)
    try:
        h=hashlib.sha256();total=0
        with os.fdopen(fd,'wb') as out,lzma.open(archive,'rb') as src:
            while block:=src.read(1024*1024):
                total+=len(block)
                if total>size:raise ValueError('Decompressed image exceeds pinned size')
                out.write(block);h.update(block)
            out.flush();os.fsync(out.fileno())
        if total!=size or h.hexdigest()!=sha:raise ValueError('Decompressed image size/SHA-256 mismatch')
        # Exclusive link keeps an existing target intact even if it appears mid-run.
        os.link(part,target)
    finally:part.unlink(missing_ok=True)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,default=ROOT/'local-runtime/pd2425-evox-preview');a=p.parse_args()
    pin=json.loads((ROOT/'profiles/pd2425-evox-preview.json').read_text());out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    archive=out/(pin['image_name']+'.xz')
    if archive.exists():
        if digest(archive)!=pin['archive_sha256']:raise ValueError('Existing archive differs; refusing to overwrite it')
    else:
        fd,name=tempfile.mkstemp(prefix='download-',suffix='.part',dir=out);part=Path(name)
        try:
            h=hashlib.sha256();total=0
            with os.fdopen(fd,'wb') as dst,urllib.request.urlopen(pin['archive_url'],timeout=45) as src:
                while block:=src.read(1024*1024):
                    total+=len(block)
                    if total>pin['archive_bytes']:raise ValueError('Archive exceeds pinned size')
                    dst.write(block);h.update(block)
                dst.flush();os.fsync(dst.fileno())
            if total!=pin['archive_bytes'] or h.hexdigest()!=pin['archive_sha256']:raise ValueError('Archive size/SHA-256 mismatch')
            os.link(part,archive)
        finally:part.unlink(missing_ok=True)
    image=out/pin['image_name'];decompress(archive,image,pin['image_bytes'],pin['image_sha256']);print(image);print('SHA-256: '+pin['image_sha256'])
if __name__=='__main__':main()
