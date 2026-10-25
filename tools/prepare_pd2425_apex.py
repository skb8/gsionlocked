"""Prepare offline APEX inputs from the exact pinned GSI; no root, mounts or execution."""
import argparse, hashlib, json, os, re, stat, subprocess, tempfile, zipfile
from pathlib import Path
from fetch_preview_gsi import digest
from apex_manifest import check_identity

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 512 * 1024 * 1024
TOTAL_LIMIT = 2 * 1024 * 1024 * 1024
MODULE = re.compile(r'com(?:\.[A-Za-z0-9_]+)+\.(?:apex|capex)\Z')
PROGRAMS = (('linkerconfig', '/apex/com.android.runtime/bin/linkerconfig', '/bin/linkerconfig', 'com.android.runtime'),
            ('servicemanager', '/system/bin/servicemanager', '/system/bin/servicemanager', None),
            ('hwservicemanager', '/system/bin/hwservicemanager', '/system/system_ext/bin/hwservicemanager', None),
            ('app_process64', '/system/bin/app_process64', '/system/bin/app_process64', None))

def member(z, name, target, limit=LIMIT):
    """Extract one exact member, never ZIP paths; verify CRC and bounded sizes."""
    entries = [i for i in z.infolist() if i.filename == name]
    if len(entries) != 1:
        raise ValueError('Missing or duplicate ZIP member: ' + name)
    info = entries[0]
    if not 0 < info.file_size <= limit or info.flag_bits & 1 or stat.S_ISLNK(info.external_attr >> 16):
        raise ValueError('Invalid ZIP member: ' + name)
    if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        raise ValueError('Unsupported ZIP compression')
    h = hashlib.sha256(); total = 0
    with z.open(info) as src, Path(target).open('xb') as dst:
        while block := src.read(1024 * 1024):
            total += len(block)
            if total > info.file_size or total > limit:
                raise ValueError('ZIP size limit exceeded')
            dst.write(block); h.update(block)
    if total != info.file_size:
        raise ValueError('Truncated ZIP member')
    return {'bytes': total, 'sha256': h.hexdigest()}

def filesystem(path):
    with Path(path).open('rb') as f:
        f.seek(1024); magic = f.read(58)
    if magic[56:58] == b'\x53\xef': return 'ext4'
    if magic[:4] == b'\xe2\xe1\xf5\xe0': return 'erofs'
    raise ValueError('Unsupported APEX payload filesystem')

def unpack(source, name, output, budget=TOTAL_LIMIT):
    if not MODULE.fullmatch(name): raise ValueError('Invalid APEX filename')
    output = Path(output); package = name.rsplit('.', 1)[0]
    apex = output / (package + '.apex')
    outer_manifest = None
    with zipfile.ZipFile(source) as z:
        if name.endswith('.capex'):
            outer_path = output / (package + '.capex.manifest.pb')
            member(z, 'apex_manifest.pb', outer_path, 65536)
            outer_manifest = check_identity(outer_path.read_bytes(), package)
            apex_info = member(z, 'original_apex', apex, min(LIMIT, budget))
        else:
            # Source came from an exclusive temporary dump; retain the exact package.
            if not 0 < Path(source).stat().st_size <= min(LIMIT, budget): raise ValueError('APEX size limit')
            os.link(source, apex)
            apex_info = {'bytes': apex.stat().st_size, 'sha256': digest(apex)}
    payload = output / (package + '.img')
    manifest = output / (package + '.manifest.pb')
    with zipfile.ZipFile(apex) as z:
        payload_info = member(z, 'apex_payload.img', payload, min(LIMIT, budget - apex_info['bytes']))
        manifest_info = member(z, 'apex_manifest.pb', manifest, 65536)
    identity = check_identity(manifest.read_bytes(), package)
    if outer_manifest is not None and identity != outer_manifest:
        raise ValueError('CAPEX/original APEX manifest mismatch')
    return {'package_filename': package, 'source_name': name,
            'source_bytes': Path(source).stat().st_size, 'source_sha256': digest(source),
            'apex': apex_info, 'payload': dict(payload_info, filesystem=filesystem(payload)),
            'manifest': manifest_info,
            'manifest_identity_verified': True, 'manifest_identity': identity,
            'capex_identity_verified': outer_manifest is not None,
            'payload_manifest_verified': False, 'avb_signature_verified': False}

def listing(text):
    result = []
    for line in text.splitlines():
        fields = line.split('/')
        if len(fields) < 8 or not fields[1].isdigit(): continue
        name = fields[5]
        if name in ('.', '..'): continue
        if not MODULE.fullmatch(name) or int(fields[2], 8) != 0o100644:
            raise ValueError('Unexpected system/apex entry: ' + name)
        size = int(fields[6])
        if not 0 < size <= LIMIT: raise ValueError('APEX container size limit')
        if any(n == name for n, _ in result): raise ValueError('Duplicate module filename')
        result.append((name, size))
    if not result or len(result) > 128: raise ValueError('Invalid APEX module count')
    packages = [n.rsplit('.', 1)[0] for n, _ in result]
    if len(set(packages)) != len(packages): raise ValueError('Ambiguous compressed/plain module')
    return sorted(result)

def validate_runtime(modules, pin):
    runtime = [m for m in modules if m['package_filename'] == 'com.android.runtime']
    if len(runtime) != 1: raise ValueError('Missing/ambiguous runtime APEX')
    r = runtime[0]; expected = pin['runtime_apex']
    if (r['apex']['bytes'], r['apex']['sha256'], r['payload']['bytes'], r['payload']['sha256'], r['payload']['filesystem']) != (
            expected['bytes'], expected['sha256'], expected['payload_bytes'], expected['payload_sha256'], expected['filesystem']):
        raise ValueError('Runtime catalog differs from proven preview pins')

def debugfs(fd, command, cwd, reference):
    p = subprocess.run(['debugfs', '-R', command, str(reference)],
                       pass_fds=(fd,), cwd=cwd, capture_output=True, text=True, timeout=90)
    if p.returncode: raise RuntimeError('debugfs failed: ' + p.stderr[:1000])
    return p.stdout

def prepare(image, output, pin):
    fd = os.open(image, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size != pin['image_bytes']:
            raise ValueError('Expected regular raw image with pinned size')
        with os.fdopen(os.dup(fd), 'rb') as f:
            if hashlib.file_digest(f, 'sha256').hexdigest() != pin['image_sha256']:
                raise ValueError('Pinned image SHA-256 mismatch')
        output = Path(output).resolve(); output.mkdir(mode=0o700, parents=True, exist_ok=False)
        modules = []; total = 0
        with tempfile.TemporaryDirectory(prefix='apex-work-', dir=output) as temp:
            work = Path(temp)
            reference = Path('/proc/self/fd/' + str(fd))
            if not reference.exists():
                # Restricted analysis containers may omit /proc. Use an exact
                # private snapshot rather than reopening an unpinned source path.
                reference = work / 'source.raw'; os.lseek(fd, 0, os.SEEK_SET)
                with os.fdopen(os.dup(fd), 'rb') as src, reference.open('xb') as dst:
                    copied = 0
                    while block := src.read(1024 * 1024):
                        copied += len(block)
                        if copied > pin['image_bytes']: raise ValueError('Source grew during snapshot')
                        dst.write(block)
                if reference.stat().st_size != pin['image_bytes'] or digest(reference) != pin['image_sha256']:
                    raise ValueError('Private source snapshot differs')
                reference.chmod(0o400)
            rows = listing(debugfs(fd, 'ls -p /system/apex', work, reference))
            for name, size in rows:
                source = work / 'container'
                debugfs(fd, 'dump /system/apex/' + name + ' container', work, reference)
                if source.stat().st_size != size: raise ValueError('Dump size mismatch')
                row = unpack(source, name, output, TOTAL_LIMIT - total)
                if row['payload']['filesystem'] != 'ext4': raise ValueError('Payload manifest verification requires ext4')
                payload_manifest = work / 'payload-manifest'
                debugfs(fd, 'dump /apex_manifest.pb payload-manifest', work, output / (row['package_filename'] + '.img'))
                if digest(payload_manifest) != row['manifest']['sha256']: raise ValueError('Payload/ZIP manifest mismatch')
                row['payload_manifest_verified'] = True; payload_manifest.unlink(); modules.append(row)
                total += row['apex']['bytes'] + row['payload']['bytes']
                if total > TOTAL_LIMIT: raise ValueError('Total APEX output limit exceeded')
                source.unlink()
            programs = []
            symlink = debugfs(fd, 'stat /system/bin/hwservicemanager', work, reference)
            if 'Fast link dest: "/system/system_ext/bin/hwservicemanager"' not in symlink:
                raise ValueError('Unexpected hwservicemanager symlink')
            for name, guest_path, source_path, module in PROGRAMS:
                binary = work / 'program'
                source_ref = output / (module + '.img') if module else reference
                debugfs(fd, 'dump ' + source_path + ' program', work, source_ref)
                with binary.open('rb') as f: header = f.read(20)
                if header[:6] != b'\x7fELF\x02\x01' or header[18:20] != b'\xb7\x00':
                    raise ValueError('Expected AArch64 ELF64: ' + name)
                dynamic = subprocess.run(['readelf', '-d', '--wide', str(binary)],
                                         capture_output=True, text=True, check=True, timeout=30).stdout
                programs.append({'path': guest_path, 'source_path': source_path, 'source_module': module, 'bytes': binary.stat().st_size,
                                 'sha256': digest(binary),
                                 'direct_needed': re.findall(r'\(NEEDED\).*?\[(.*?)\]', dynamic),
                                 'executed': False, 'dependency_closure_verified': False})
                binary.unlink()
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('Source changed during analysis')
        validate_runtime(modules, pin)
        catalog = {'schema': 1, 'state': 'offline-inputs-only', 'runtime_ready': False,
                   'image_sha256': pin['image_sha256'], 'module_count': len(modules),
                   'compressed_count': sum(n.endswith('.capex') for n, _ in rows),
                   'modules': modules, 'programs': programs,
                   'limitations': ['No AVB signature verification',
                                   'No mounts, GSI code execution, Binder/HAL or Android bootstrap',
                                   'Direct DT_NEEDED only; no transitive closure or classpath verification']}
        with (output / 'catalog.json').open('x') as f: json.dump(catalog, f, indent=2); f.write('\n')
        return catalog
    finally: os.close(fd)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('image', type=Path); p.add_argument('--output', type=Path, required=True)
    a = p.parse_args(); pin = json.loads((ROOT / 'profiles/pd2425-evox-preview.json').read_text())
    c = prepare(a.image, a.output, pin)
    print('Prepared', c['module_count'], 'APEX payloads;', c['compressed_count'], 'compressed containers')
    print(a.output / 'catalog.json')

if __name__ == '__main__': main()
