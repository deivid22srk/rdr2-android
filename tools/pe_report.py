#!/usr/bin/env python3
"""PE inventory report for local (never-committed) game executables.

Emits headers, section entropy/flags, imports, exports, TLS, delay imports,
relocation summary, exception directory size. Facts only.
"""
import sys, json, math, hashlib, collections, datetime, os
import pefile

def entropy(b):
    if not b: return 0.0
    c = collections.Counter(b); n = len(b)
    return -sum((v/n) * math.log2(v/n) for v in c.values())

def sha256_file(p, chunk=1<<20):
    h = hashlib.sha256()
    with open(p,'rb') as f:
        while True:
            b = f.read(chunk)
            if not b: break
            h.update(b)
    return h.hexdigest()

def report(path, do_hash=True):
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories()
    out = {
        'path': path,
        'sha256': sha256_file(path) if do_hash else None,
        'size': os.path.getsize(path),
        'machine': hex(pe.FILE_HEADER.Machine),
        'machine_name': pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine),
        'magic': hex(pe.OPTIONAL_HEADER.Magic),
        'is_pe32_plus': pe.OPTIONAL_HEADER.Magic == 0x20b,
        'timestamp': pe.FILE_HEADER.TimeDateStamp,
        'timestamp_utc': datetime.datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat()+'Z',
        'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
        'entry_point_rva': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        'entry_point_va': hex(pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        'subsystem': pe.OPTIONAL_HEADER.Subsystem,
        'dll_characteristics': hex(pe.OPTIONAL_HEADER.DllCharacteristics),
        'size_of_image': hex(pe.OPTIONAL_HEADER.SizeOfImage),
        'size_of_code': hex(pe.OPTIONAL_HEADER.SizeOfCode),
        'checksum': hex(pe.OPTIONAL_HEADER.CheckSum),
        'sections': [], 'imports': {}, 'delay_imports': {}, 'exports': [],
        'tls': None, 'reloc_blocks': 0, 'reloc_entries': 0, 'exception_entries': 0,
    }
    for s in pe.sections:
        data = s.get_data()
        out['sections'].append({
            'name': s.Name.rstrip(b'\0').decode('latin1'),
            'va': hex(pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress),
            'vsize': hex(s.Misc_VirtualSize), 'rawsize': hex(s.SizeOfRawData),
            'flags': hex(s.Characteristics),
            'exec': bool(s.Characteristics & 0x20000000),
            'writable': bool(s.Characteristics & 0x80000000),
            'entropy': round(entropy(data), 3),
            'first16': data[:16].hex(),
        })
    for attr,key in (('DIRECTORY_ENTRY_IMPORT','imports'),('DIRECTORY_ENTRY_DELAY_IMPORT','delay_imports')):
        if hasattr(pe,attr):
            for e in getattr(pe,attr):
                out[key][e.dll.decode('latin1')] = [
                    (i.name.decode('latin1') if i.name else f'ord{i.ordinal}') for i in e.imports]
    if hasattr(pe,'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT:
        for s in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            out['exports'].append({'name': s.name.decode('latin1') if s.name else None,
                                   'ordinal': s.ordinal, 'rva': hex(s.address)})
    if hasattr(pe,'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS:
        t = pe.DIRECTORY_ENTRY_TLS.struct
        out['tls'] = {'start': hex(t.StartAddressOfRawData), 'end': hex(t.EndAddressOfRawData),
                      'index': hex(t.AddressOfIndex), 'callbacks': hex(t.AddressOfCallBacks)}
    if hasattr(pe,'DIRECTORY_ENTRY_BASERELOC'):
        for b in pe.DIRECTORY_ENTRY_BASERELOC:
            out['reloc_blocks'] += 1; out['reloc_entries'] += len(b.entries)
    if hasattr(pe,'DIRECTORY_ENTRY_EXCEPTION'):
        out['exception_entries'] = len(pe.DIRECTORY_ENTRY_EXCEPTION)
    return out

if __name__ == '__main__':
    print(json.dumps([report(p) for p in sys.argv[1:]], indent=1))
