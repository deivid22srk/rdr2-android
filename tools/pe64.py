"""Minimal PE32+ (x86-64) reader: headers, sections, imports, exports, base relocations,
exception table (.pdata) and TLS. No third-party dependencies.

Modelled on the PE32 reader of RunnerRecompiled (MIT) and extended for 64-bit images.
All public addresses are VAs (image base + RVA), as everywhere else in this project.
"""
import struct

IMAGE_SCN_MEM_EXECUTE = 0x20000000


class Section:
    __slots__ = ("name", "va", "vsize", "raw_off", "raw_size", "chars")

    def __init__(self, name, va, vsize, raw_off, raw_size, chars):
        self.name, self.va, self.vsize = name, va, vsize
        self.raw_off, self.raw_size, self.chars = raw_off, raw_size, chars

    @property
    def is_code(self):
        return bool(self.chars & IMAGE_SCN_MEM_EXECUTE)


class PE64:
    def __init__(self, data: bytes):
        self.data = data
        if data[:2] != b"MZ":
            raise ValueError("not an MZ file")
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise ValueError("not a PE file")
        machine, nsec, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, pe + 4)
        if machine != 0x8664:
            raise ValueError(f"machine {machine:#x} is not AMD64")
        opt = pe + 24
        if struct.unpack_from("<H", data, opt)[0] != 0x20B:
            raise ValueError("not PE32+")
        self.entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        self.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        self.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
        self.size_of_headers = struct.unpack_from("<I", data, opt + 60)[0]
        self.dll_chars = struct.unpack_from("<H", data, opt + 70)[0]
        self.subsystem = struct.unpack_from("<H", data, opt + 68)[0]
        ndirs = struct.unpack_from("<I", data, opt + 108)[0]
        self.dirs = [struct.unpack_from("<II", data, opt + 112 + 8 * i) for i in range(ndirs)]
        self.sections = []
        for i in range(nsec):
            off = opt + opt_size + 40 * i
            name = data[off:off + 8].rstrip(b"\0").decode("latin-1")
            vsize, va, raw_size, raw_off = struct.unpack_from("<IIII", data, off + 8)
            chars = struct.unpack_from("<I", data, off + 36)[0]
            self.sections.append(Section(name, va, vsize, raw_off, raw_size, chars))

    # --- addressing ---
    @property
    def entry(self):
        return self.image_base + self.entry_rva

    def section_of(self, va):
        rva = va - self.image_base
        for s in self.sections:
            if s.va <= rva < s.va + max(s.vsize, s.raw_size):
                return s
        return None

    def read(self, va, n):
        s = self.section_of(va)
        if s is None:
            return b""
        off = va - self.image_base - s.va
        if off >= max(s.vsize, s.raw_size):
            return b""
        chunk = self.data[s.raw_off + off: s.raw_off + min(off + n, s.raw_size)]
        return chunk + b"\0" * (n - len(chunk))

    def u16(self, va):
        return struct.unpack("<H", self.read(va, 2))[0]

    def u32(self, va):
        return struct.unpack("<I", self.read(va, 4))[0]

    def u64(self, va):
        return struct.unpack("<Q", self.read(va, 8))[0]

    def cstr(self, va, limit=512):
        return self.read(va, limit).split(b"\0", 1)[0].decode("latin-1")

    def code_blob(self):
        """(first VA, bytes) over every executable section, gaps zero-filled."""
        secs = [s for s in self.sections if s.is_code]
        start = min(s.va for s in secs)
        end = max(s.va + s.vsize for s in secs)
        blob = bytearray(end - start)
        for s in secs:
            raw = self.data[s.raw_off: s.raw_off + min(s.raw_size, s.vsize)]
            blob[s.va - start: s.va - start + len(raw)] = raw
        return self.image_base + start, bytes(blob)

    # --- directories ---
    def imports(self):
        """{iat_slot_va: (dll, name_or_#ordinal)}"""
        rva, size = self.dirs[1]
        out = {}
        if not rva:
            return out
        d = self.image_base + rva
        while True:
            oft, _, _, name_rva, ft = struct.unpack("<IIIII", self.read(d, 20))
            if not name_rva:
                break
            dll = self.cstr(self.image_base + name_rva)
            lookup = oft or ft
            i = 0
            while True:
                ent = self.u64(self.image_base + lookup + 8 * i)
                if not ent:
                    break
                sym = f"#{ent & 0xFFFF}" if ent & 0x8000000000000000 else self.cstr(self.image_base + (ent & 0x7FFFFFFF) + 2)
                out[self.image_base + ft + 8 * i] = (dll, sym)
                i += 1
            d += 20
        return out

    def delay_imports(self):
        rva, size = self.dirs[13]
        out = {}
        if not rva:
            return out
        d = self.image_base + rva
        while True:
            attrs, name_rva, _, iat, int_, _, _ = struct.unpack("<IIIIIII", self.read(d, 32))
            if not name_rva:
                break
            dll = self.cstr(self.image_base + name_rva)
            lookup = int_ or iat
            i = 0
            while True:
                ent = self.u64(self.image_base + lookup + 8 * i)
                if not ent:
                    break
                sym = f"#{ent & 0xFFFF}" if ent & 0x8000000000000000 else self.cstr(self.image_base + (ent & 0x7FFFFFFF) + 2)
                out[self.image_base + iat + 8 * i] = (dll, sym)
                i += 1
            d += 32
        return out

    def exports(self):
        rva, size = self.dirs[0]
        out = {}
        if not rva:
            return out
        d = self.image_base + rva
        _, _, _, _, _, base, nfuncs, nnames, funcs, names, ords = struct.unpack("<IIHHIIIIIII", self.read(d, 40))
        addr = [self.u32(self.image_base + funcs + 4 * i) for i in range(nfuncs)]
        for i in range(nnames):
            name = self.cstr(self.image_base + self.u32(self.image_base + names + 4 * i))
            idx = self.u16(self.image_base + ords + 2 * i)
            if idx < nfuncs and addr[idx] and not (rva <= addr[idx] < rva + size):
                out[name] = self.image_base + addr[idx]
        return out

    def relocations(self):
        """[(slot_va, type)]  type 10 = DIR64, 3 = HIGHLOW."""
        rva, size = self.dirs[5]
        out = []
        if not rva:
            return out
        d = self.image_base + rva
        end = d + size
        while d < end:
            page, blk = struct.unpack("<II", self.read(d, 8))
            if blk < 8:
                break
            n = (blk - 8) // 2
            for i in range(n):
                e = self.u16(d + 8 + 2 * i)
                out.append((self.image_base + page + (e & 0xFFF), e >> 12))
            d += blk
        return out

    def exceptions(self):
        """[(begin_va, end_va, unwind_va)] from .pdata: the authoritative function list."""
        rva, size = self.dirs[3]
        out = []
        if not rva:
            return out
        d = self.image_base + rva
        for i in range(size // 12):
            begin, end, unwind = struct.unpack("<III", self.read(d + 12 * i, 12))
            if begin:
                out.append((self.image_base + begin, self.image_base + end, self.image_base + unwind))
        return out

    def tls(self):
        rva, _ = self.dirs[9]
        if not rva:
            return None
        d = self.image_base + rva
        start, end, index, cbs = struct.unpack("<QQQQ", self.read(d, 32))
        return {"start": start, "end": end, "index": index, "callbacks": cbs}

    def resource_dir(self):
        rva, size = self.dirs[2]
        return (self.image_base + rva, size) if rva else (0, 0)
