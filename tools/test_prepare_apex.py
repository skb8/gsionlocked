"""Offline CAPEX fixtures: bounds, duplicate/path rejection and no source writes."""
import hashlib, io, json, os, tempfile, zipfile
from pathlib import Path
from prepare_pd2425_apex import unpack, listing, member, prepare, validate_runtime

MANIFEST = b'\x0a\x0fcom.android.art\x10\x01'

def apex(payload):
    b = io.BytesIO()
    with zipfile.ZipFile(b, 'w') as z:
        z.writestr('apex_payload.img', payload)
        z.writestr('apex_manifest.pb', MANIFEST)
        z.writestr('../../must-not-extract', b'bad')
    return b.getvalue()

with tempfile.TemporaryDirectory() as temp:
    root = Path(temp); payload = bytearray(4096); payload[1080:1082] = b'\x53\xef'
    original = apex(payload); capex = root / 'input.capex'
    with zipfile.ZipFile(capex, 'w') as z:
        z.writestr('original_apex', original, compress_type=zipfile.ZIP_DEFLATED)
        z.writestr('apex_manifest.pb', MANIFEST)
    out = root / 'out'; out.mkdir(); before = capex.read_bytes()
    c = unpack(capex, 'com.android.art.capex', out)
    assert c['payload']['filesystem'] == 'ext4' and c['payload']['sha256'] == hashlib.sha256(payload).hexdigest()
    runtime = dict(c, package_filename='com.android.runtime')
    pin = {'runtime_apex':dict(c['apex'],payload_bytes=c['payload']['bytes'],payload_sha256=c['payload']['sha256'],filesystem='ext4')}
    validate_runtime([runtime],pin)
    pin['runtime_apex']['payload_sha256']='0'*64
    try: validate_runtime([runtime],pin)
    except ValueError: pass
    else: raise AssertionError('runtime pins mismatch accepted')
    assert not c['avb_signature_verified'] and c['manifest_identity_verified']
    assert capex.read_bytes() == before and not (root / 'must-not-extract').exists()
    assert (out / 'com.android.art.apex').read_bytes() == original
    try: unpack(capex, '../escape.capex', out)
    except ValueError: pass
    else: raise AssertionError('unsafe filename accepted')
    try: unpack(capex, 'com.android.art.capex', out)
    except FileExistsError: pass
    else: raise AssertionError('existing output overwritten')
    assert (out / 'com.android.art.apex').read_bytes() == original
    with zipfile.ZipFile(capex) as z:
        try: member(z, 'original_apex', root / 'over-limit', len(original)-1)
        except ValueError: pass
        else: raise AssertionError('ZIP output limit ignored')
    assert not (root / 'over-limit').exists()
    budget_out = root / 'budget'; budget_out.mkdir()
    try: unpack(capex, 'com.android.art.capex', budget_out, len(original))
    except ValueError: pass
    else: raise AssertionError('aggregate output budget ignored')
    assert not (budget_out / 'com.android.art.img').exists()
    damaged = bytearray(original); offset = damaged.index(b'com.android.art'); damaged[offset] ^= 1
    corrupt = root / 'corrupt.apex'; corrupt.write_bytes(damaged)
    crc_out = root / 'crc'; crc_out.mkdir()
    try: unpack(corrupt, 'com.android.art.apex', crc_out)
    except zipfile.BadZipFile: pass
    else: raise AssertionError('corrupt member CRC accepted')
    duplicate = io.BytesIO()
    with zipfile.ZipFile(duplicate, 'w') as z:
        z.writestr('x', b'1')
        # Build a second logical name via public metadata to avoid an expected warning.
        z.writestr('y', b'2')
    with zipfile.ZipFile(duplicate) as z:
        z.infolist()[1].filename = 'x'
        try: member(z, 'x', root / 'duplicate')
        except ValueError: pass
        else: raise AssertionError('ambiguous ZIP member accepted')
    assert listing('/1/040755/0/0/.//\n/2/100644/0/0/com.android.art.capex/4096/\n') == [('com.android.art.capex',4096)]
    for text in ['/2/120777/0/0/com.android.art.capex/1/',
                 '/2/100644/0/0/evil/1/',
                 '/2/100644/0/0/com.android.art.capex/1/\n/3/100644/0/0/com.android.art.apex/1/']:
        try: listing(text)
        except ValueError: pass
        else: raise AssertionError('unsafe/ambiguous listing accepted')
    image = root / 'image'; image.write_bytes(b'wrong')
    try: prepare(image, root / 'failed', {'image_bytes':5,'image_sha256':'0'*64})
    except ValueError: pass
    else: raise AssertionError('wrong GSI accepted')
    assert image.read_bytes() == b'wrong' and not (root / 'failed').exists()
    link = root / 'symlink'; link.symlink_to(image)
    try: prepare(link, root / 'failed', {'image_bytes':5,'image_sha256':'0'*64})
    except OSError: pass
    else: raise AssertionError('image symlink accepted')
print('PASS: CAPEX/ZIP extraction, exact bounds/CRC, safe names, duplicates, source/hash/symlink gates; no mounts or guest execution')
