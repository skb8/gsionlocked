"""Schema/identity tests for bounded APEX protobuf parsing."""
from apex_manifest import parse_manifest, check_identity

base = b'\x0a\x0fcom.android.art\x10\x01'
assert check_identity(base, 'com.android.art')['version'] == 1
assert parse_manifest(base+b'\x30\x01')['no_code'] is True
assert parse_manifest(base+b'\x3a\x07libc.so')['provide_native_libs'] == ['libc.so']
assert parse_manifest(base+b'\xa2\x06\x03xyz')['name'] == 'com.android.art'  # unknown field
bad = [b'', base[:-1], base+b'\x10\x01', base+b'\x00', base+b'\x33',
       base+b'\x30\x02', base+b'\x32\x00', base+b'\x3a\xff\x7f',
       base+b'\xa0\x06'+b'\xff'*10, b'\x0a\x0fcom.android.art\x10\x80\x00',
       b'\x0a\x02\xff\xfe\x10\x01', b'\x0a\x03../\x10\x01',
       b'\x0a\x0fcom.android.art', b'x'*65537]
for data in bad:
    try: parse_manifest(data)
    except (ValueError, UnicodeDecodeError): pass
    else: raise AssertionError('malformed manifest accepted: '+repr(data[:40]))
try: check_identity(base, 'com.android.runtime')
except ValueError: pass
else: raise AssertionError('wrong module identity accepted')
print('PASS: APEX names/version, lists, unknown fields, truncation, overflow, duplicate singleton and malformed schema rejection')
