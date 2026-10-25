"""Bounded reader for AOSP ApexManifest protobuf; no signature/AVB claims.

Schema: platform/system/apex/proto/apex_manifest.proto (AOSP).
Unknown non-group fields are skipped; known singleton duplicates are rejected.
"""
import re

TEXT = {1:'name',3:'pre_install_hook',4:'post_install_hook',5:'version_name',14:'vndk_version'}
LIST = {7:'provide_native_libs',8:'require_native_libs',9:'jni_libs',10:'require_shared_apex_libs'}
BOOL = {6:'no_code',11:'provide_shared_apex_libs',13:'rebootless_update',15:'vendor_bootstrap',16:'bootstrap'}
NAME = re.compile(r'com(?:\.[A-Za-z0-9_]+)+\Z')

def varint(data, offset):
    value = 0
    for n in range(10):
        if offset >= len(data): raise ValueError('Truncated protobuf varint')
        byte = data[offset]; offset += 1
        if n == 9 and byte > 1: raise ValueError('Protobuf varint overflow')
        value |= (byte & 127) << (7*n)
        if not byte & 128:
            if n and not byte: raise ValueError('Noncanonical protobuf varint')
            return value, offset
    raise ValueError('Protobuf varint overflow')

def parse_manifest(data):
    if not 0 < len(data) <= 65536: raise ValueError('Manifest size limit')
    result = {v:'' for v in TEXT.values()}
    result.update({v:[] for v in LIST.values()}); result.update({v:False for v in BOOL.values()})
    result['version'] = 0; seen = set(); offset = 0; fields = 0
    while offset < len(data):
        fields += 1
        if fields > 4096: raise ValueError('Manifest field count limit')
        key, offset = varint(data, offset); number, wire = key >> 3, key & 7
        if not 0 < number < 1 << 29: raise ValueError('Invalid protobuf field number')
        if wire == 0: value, offset = varint(data, offset)
        elif wire in (1,5):
            size = 8 if wire == 1 else 4
            if offset+size > len(data): raise ValueError('Truncated fixed field')
            value = data[offset:offset+size]; offset += size
        elif wire == 2:
            size, offset = varint(data, offset)
            if size > len(data)-offset: raise ValueError('Truncated length field')
            value = data[offset:offset+size]; offset += size
        else: raise ValueError('Unsupported protobuf wire type')
        known = number in TEXT or number in BOOL or number in LIST or number == 2
        if known and number not in LIST:
            if number in seen: raise ValueError('Duplicate singleton field')
            seen.add(number)
        if number in TEXT or number in LIST:
            if wire != 2: raise ValueError('Wrong string wire type')
            text = value.decode('utf-8', errors='strict')
            if '\0' in text or len(text) > 4096: raise ValueError('Invalid manifest string')
            if number in TEXT: result[TEXT[number]] = text
            else:
                items = result[LIST[number]]
                if len(items) >= 512: raise ValueError('Manifest list limit')
                items.append(text)
        elif number in BOOL:
            if wire != 0 or value not in (0,1): raise ValueError('Invalid protobuf bool')
            result[BOOL[number]] = bool(value)
        elif number == 2:
            if wire != 0 or not 0 < value < 1 << 63: raise ValueError('Invalid APEX version')
            result['version'] = value
    if not NAME.fullmatch(result['name']) or not result['version']:
        raise ValueError('Missing/invalid APEX identity')
    return result

def check_identity(data, expected_name):
    manifest = parse_manifest(data)
    if manifest['name'] != expected_name: raise ValueError('APEX filename/manifest identity mismatch')
    return manifest
