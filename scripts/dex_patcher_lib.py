"""
Pure-Python DEX reader, method inspector, and Dalvik bytecode assembler.
Used by `patch_and_build_apk.py` for zero-dependency DEX bytecode patching on Haylou Fun v4.0.8.
"""

from __future__ import annotations

import hashlib
import struct
import zlib


def encode_uleb128_4bytes(val: int) -> bytes:
    """Encode an integer in [0x200000, 0x0fffffff] into its canonical 4-byte ULEB128."""
    assert 0x200000 <= val <= 0x0FFFFFFF, f"Value 0x{val:x} does not fit in 4-byte ULEB128"
    return bytes([
        (val & 0x7F) | 0x80,
        ((val >> 7) & 0x7F) | 0x80,
        ((val >> 14) & 0x7F) | 0x80,
        (val >> 21) & 0x7F,
    ])


def recompute_dex_checksums(data: bytearray) -> bytes:
    """Recompute DEX SHA-1 signature (bytes 12..31) and Adler-32 checksum (bytes 8..11)."""
    sha1 = hashlib.sha1(data[32:]).digest()
    data[12:32] = sha1
    adler = zlib.adler32(data[12:]) & 0xFFFFFFFF
    struct.pack_into("<I", data, 8, adler)
    return bytes(data)


class DexFile:
    def __init__(self, data: bytes):
        self.data = data
        (
            self.file_size,
            self.header_size,
            _endian_tag,
            _link_size,
            _link_off,
            _map_off,
            self.string_ids_size,
            self.string_ids_off,
            self.type_ids_size,
            self.type_ids_off,
            self.proto_ids_size,
            self.proto_ids_off,
            self.field_ids_size,
            self.field_ids_off,
            self.method_ids_size,
            self.method_ids_off,
            self.class_defs_size,
            self.class_defs_off,
            _data_size,
            _data_off,
        ) = struct.unpack_from("<20I", data, 32)
        self._strings = [None] * self.string_ids_size

    def read_uleb128(self, off: int):
        result = 0
        shift = 0
        while True:
            b = self.data[off]
            off += 1
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        return result, off

    def get_string(self, idx: int) -> str:
        s = self._strings[idx]
        if s is not None:
            return s
        str_data_off = struct.unpack_from("<I", self.data, self.string_ids_off + idx * 4)[0]
        _, off = self.read_uleb128(str_data_off)
        end = self.data.index(0, off)
        s = self.data[off:end].decode("utf-8", errors="replace")
        self._strings[idx] = s
        return s

    def get_type(self, idx: int) -> str:
        if idx == 0xFFFFFFFF or idx >= self.type_ids_size:
            return "<none>"
        desc_idx = struct.unpack_from("<I", self.data, self.type_ids_off + idx * 4)[0]
        return self.get_string(desc_idx)

    def get_proto(self, idx: int) -> str:
        _shorty, ret_idx, params_off = struct.unpack_from("<3I", self.data, self.proto_ids_off + idx * 12)
        ret = self.get_type(ret_idx)
        params = []
        if params_off != 0:
            size = struct.unpack_from("<I", self.data, params_off)[0]
            for i in range(size):
                t_idx = struct.unpack_from("<H", self.data, params_off + 4 + i * 2)[0]
                params.append(self.get_type(t_idx))
        return f"({''.join(params)}){ret}"

    def get_field(self, idx: int) -> str:
        cls_idx, type_idx, name_idx = struct.unpack_from("<HHI", self.data, self.field_ids_off + idx * 8)
        return f"{self.get_type(cls_idx)}->{self.get_string(name_idx)}:{self.get_type(type_idx)}"

    def get_method(self, idx: int) -> str:
        cls_idx, proto_idx, name_idx = struct.unpack_from("<HHI", self.data, self.method_ids_off + idx * 8)
        return f"{self.get_type(cls_idx)}->{self.get_string(name_idx)}{self.get_proto(proto_idx)}"

    def find_idx(self, kind: str, target: str) -> int:
        if kind == "string":
            for i in range(self.string_ids_size):
                if self.get_string(i) == target:
                    return i
        elif kind == "type":
            for i in range(self.type_ids_size):
                if self.get_type(i) == target:
                    return i
        elif kind == "field":
            for i in range(self.field_ids_size):
                if self.get_field(i) == target:
                    return i
        elif kind == "method":
            for i in range(self.method_ids_size):
                if self.get_method(i) == target:
                    return i
        raise KeyError(f"{kind} not found in DEX: {target}")

    def iter_classes(self):
        for i in range(self.class_defs_size):
            off = self.class_defs_off + i * 32
            cls_idx, _acc, super_idx, _if, src_idx, _ann, class_data_off, _st = struct.unpack_from("<8I", self.data, off)
            yield {
                "index": i,
                "type": self.get_type(cls_idx),
                "super": self.get_type(super_idx),
                "source": self.get_string(src_idx) if src_idx != 0xFFFFFFFF else None,
                "class_data_off": class_data_off,
            }

    def find_method_info(self, class_type: str, target_desc: str, allow_tries: bool = False) -> dict:
        for c in self.iter_classes():
            if c["type"] != class_type:
                continue
            off = c["class_data_off"]
            if off == 0:
                continue
            sf_size, off = self.read_uleb128(off)
            if_size, off = self.read_uleb128(off)
            dm_size, off = self.read_uleb128(off)
            vm_size, off = self.read_uleb128(off)
            for _ in range(sf_size + if_size):
                _, off = self.read_uleb128(off)
                _, off = self.read_uleb128(off)
            for count in (dm_size, vm_size):
                m_idx = 0
                for _ in range(count):
                    diff, off = self.read_uleb128(off)
                    acc_pos = off
                    acc_val, off = self.read_uleb128(off)
                    code_pos = off
                    code_off, off = self.read_uleb128(off)
                    m_idx += diff
                    if self.get_method(m_idx) == target_desc:
                        regs, ins_s, outs_s, tries_s, dbg_off, insns_s = struct.unpack_from("<4H2I", self.data, code_off)
                        if not allow_tries:
                            assert tries_s == 0 and dbg_off == 0, f"Unexpected tries={tries_s} dbg={dbg_off} on {target_desc}"
                        return {
                            "method_idx": m_idx,
                            "acc_pos": acc_pos,
                            "access_flags": acc_val,
                            "code_pos": code_pos,
                            "code_pos_len": off - code_pos,
                            "code_off": code_off,
                            "insns_size": insns_s,
                            "ins_size": ins_s,
                            "regs_size": regs,
                            "outs_size": outs_s,
                        }
        raise RuntimeError(f"Method {target_desc} not found in {class_type}")


class DalvikAssembler:
    def __init__(self):
        self.items = []

    def label(self, name: str):
        self.items.append(("label", name))

    def nop(self):
        self.items.append(("words", [0x0000]))

    def move(self, dst: int, src: int):
        if dst < 16 and src < 16:
            self.items.append(("words", [0x01 | ((dst | (src << 4)) << 8)]))
        else:
            assert 0 <= dst < 256 and 0 <= src < 65536
            self.items.append(("words", [0x02 | (dst << 8), src]))

    def move_wide(self, dst: int, src: int):
        if dst < 16 and src < 16:
            self.items.append(("words", [0x04 | ((dst | (src << 4)) << 8)]))
        else:
            assert 0 <= dst < 256 and 0 <= src < 65536
            self.items.append(("words", [0x05 | (dst << 8), src]))

    def move_object(self, dst: int, src: int):
        if dst < 16 and src < 16:
            self.items.append(("words", [0x07 | ((dst | (src << 4)) << 8)]))
        else:
            assert 0 <= dst < 256 and 0 <= src < 65536
            self.items.append(("words", [0x08 | (dst << 8), src]))

    def move_result(self, dst: int):
        assert 0 <= dst < 256
        self.items.append(("words", [0x0A | (dst << 8)]))

    def move_result_wide(self, dst: int):
        assert 0 <= dst < 256
        self.items.append(("words", [0x0B | (dst << 8)]))

    def move_result_object(self, dst: int):
        assert 0 <= dst < 256
        self.items.append(("words", [0x0C | (dst << 8)]))

    def move_exception(self, dst: int):
        assert 0 <= dst < 256
        self.items.append(("words", [0x0D | (dst << 8)]))

    def return_void(self):
        self.items.append(("words", [0x0E]))

    def return_int(self, reg: int):
        assert 0 <= reg < 256
        self.items.append(("words", [0x0F | (reg << 8)]))

    def return_object(self, reg: int):
        assert 0 <= reg < 256
        self.items.append(("words", [0x11 | (reg << 8)]))

    def const4(self, dst: int, val: int):
        assert 0 <= dst < 16 and -8 <= val <= 7
        self.items.append(("words", [0x12 | ((dst | ((val & 0xF) << 4)) << 8)]))

    def const16(self, dst: int, val: int):
        assert 0 <= dst < 256 and -32768 <= val <= 32767
        self.items.append(("words", [0x13 | (dst << 8), val & 0xFFFF]))

    def const32(self, dst: int, val: int):
        assert 0 <= dst < 256
        u = val & 0xFFFFFFFF
        self.items.append(("words", [0x14 | (dst << 8), u & 0xFFFF, u >> 16]))

    def const_high16(self, dst: int, hi16: int):
        assert 0 <= dst < 256
        self.items.append(("words", [0x15 | (dst << 8), hi16 & 0xFFFF]))

    def const_wide16(self, dst: int, val: int):
        assert 0 <= dst < 256 and -32768 <= val <= 32767
        self.items.append(("words", [0x16 | (dst << 8), val & 0xFFFF]))

    def const_wide32(self, dst: int, val: int):
        assert 0 <= dst < 256 and -0x80000000 <= val <= 0x7FFFFFFF
        u = val & 0xFFFFFFFF
        self.items.append(("words", [0x17 | (dst << 8), u & 0xFFFF, (u >> 16) & 0xFFFF]))

    def const_string(self, dst: int, str_idx: int):
        assert 0 <= dst < 256 and 0 <= str_idx < 65536
        self.items.append(("words", [0x1A | (dst << 8), str_idx]))

    def const_class(self, dst: int, type_idx: int):
        assert 0 <= dst < 256 and 0 <= type_idx < 65536
        self.items.append(("words", [0x1C | (dst << 8), type_idx]))

    def check_cast(self, reg: int, type_idx: int):
        assert 0 <= reg < 256 and 0 <= type_idx < 65536
        self.items.append(("words", [0x1F | (reg << 8), type_idx]))

    def instance_of(self, dst: int, src: int, type_idx: int):
        assert 0 <= dst < 16 and 0 <= src < 16 and 0 <= type_idx < 65536
        self.items.append(("words", [0x20 | ((dst | (src << 4)) << 8), type_idx]))

    def array_length(self, dst: int, arr: int):
        assert 0 <= dst < 16 and 0 <= arr < 16
        self.items.append(("words", [0x21 | ((dst | (arr << 4)) << 8)]))

    def new_instance(self, dst: int, type_idx: int):
        assert 0 <= dst < 256 and 0 <= type_idx < 65536
        self.items.append(("words", [0x22 | (dst << 8), type_idx]))

    def new_array(self, dst: int, size_reg: int, type_idx: int):
        assert 0 <= dst < 16 and 0 <= size_reg < 16 and 0 <= type_idx < 65536
        self.items.append(("words", [0x23 | ((dst | (size_reg << 4)) << 8), type_idx]))

    def filled_new_array(self, regs: list, type_idx: int):
        assert 0 <= len(regs) <= 5 and all(0 <= r < 16 for r in regs)
        r = regs + [0] * (5 - len(regs))
        w0 = 0x24 | (((len(regs) << 4) | r[4]) << 8)
        w2 = r[0] | (r[1] << 4) | (r[2] << 8) | (r[3] << 12)
        self.items.append(("words", [w0, type_idx, w2]))

    def fill_array_data(self, reg: int, target: str):
        assert 0 <= reg < 256
        self.items.append(("branch31t", 0x26, reg, target))

    def array_data_bytes(self, label_name: str, raw: bytes):
        self.items.append(("array_data", label_name, bytes(raw)))

    def aget(self, dst: int, arr: int, idx: int):
        assert all(0 <= x < 256 for x in (dst, arr, idx))
        self.items.append(("words", [0x44 | (dst << 8), arr | (idx << 8)]))

    def aget_object(self, dst: int, arr: int, idx: int):
        assert all(0 <= x < 256 for x in (dst, arr, idx))
        self.items.append(("words", [0x46 | (dst << 8), arr | (idx << 8)]))

    def aput(self, src: int, arr: int, idx: int):
        assert all(0 <= x < 256 for x in (src, arr, idx))
        self.items.append(("words", [0x4B | (src << 8), arr | (idx << 8)]))

    def aput_object(self, src: int, arr: int, idx: int):
        assert all(0 <= x < 256 for x in (src, arr, idx))
        self.items.append(("words", [0x4D | (src << 8), arr | (idx << 8)]))

    def iget(self, dst: int, obj: int, field_idx: int):
        assert 0 <= dst < 16 and 0 <= obj < 16 and 0 <= field_idx < 65536
        self.items.append(("words", [0x52 | ((dst | (obj << 4)) << 8), field_idx]))

    def iget_object(self, dst: int, obj: int, field_idx: int):
        assert 0 <= dst < 16 and 0 <= obj < 16 and 0 <= field_idx < 65536
        self.items.append(("words", [0x54 | ((dst | (obj << 4)) << 8), field_idx]))

    def iget_boolean(self, dst: int, obj: int, field_idx: int):
        assert 0 <= dst < 16 and 0 <= obj < 16 and 0 <= field_idx < 65536
        self.items.append(("words", [0x55 | ((dst | (obj << 4)) << 8), field_idx]))

    def sget_object(self, dst: int, field_idx: int):
        assert 0 <= dst < 256 and 0 <= field_idx < 65536
        self.items.append(("words", [0x62 | (dst << 8), field_idx]))

    def sget_boolean(self, dst: int, field_idx: int):
        assert 0 <= dst < 256 and 0 <= field_idx < 65536
        self.items.append(("words", [0x63 | (dst << 8), field_idx]))

    def sput_wide(self, src: int, field_idx: int):
        assert 0 <= src < 256 and 0 <= field_idx < 65536
        self.items.append(("words", [0x68 | (src << 8), field_idx]))

    def const_float(self, dst: int, val: float):
        bits = struct.unpack("<I", struct.pack("<f", val))[0]
        if (bits & 0xFFFF) == 0:
            self.const_high16(dst, bits >> 16)
        else:
            self.const32(dst, bits)

    def cmpl_float(self, dst: int, a: int, b: int):
        assert all(0 <= x < 256 for x in (dst, a, b))
        self.items.append(("words", [0x2D | (dst << 8), a | (b << 8)]))

    def cmpg_float(self, dst: int, a: int, b: int):
        assert all(0 <= x < 256 for x in (dst, a, b))
        self.items.append(("words", [0x2E | (dst << 8), a | (b << 8)]))

    def cmp_long(self, dst: int, a: int, b: int):
        assert all(0 <= x < 256 for x in (dst, a, b))
        self.items.append(("words", [0x31 | (dst << 8), a | (b << 8)]))

    def int_to_long(self, dst: int, src: int):
        assert 0 <= dst < 16 and 0 <= src < 16
        self.items.append(("words", [0x81 | ((dst | (src << 4)) << 8)]))

    def int_to_float(self, dst: int, src: int):
        assert 0 <= dst < 16 and 0 <= src < 16
        self.items.append(("words", [0x82 | ((dst | (src << 4)) << 8)]))

    def long_to_int(self, dst: int, src: int):
        assert 0 <= dst < 16 and 0 <= src < 16
        self.items.append(("words", [0x84 | ((dst | (src << 4)) << 8)]))

    def long_to_float(self, dst: int, src: int):
        assert 0 <= dst < 16 and 0 <= src < 16
        self.items.append(("words", [0x85 | ((dst | (src << 4)) << 8)]))

    def float_to_int(self, dst: int, src: int):
        assert 0 <= dst < 16 and 0 <= src < 16
        self.items.append(("words", [0x87 | ((dst | (src << 4)) << 8)]))

    def float_to_double(self, dst: int, src: int):
        assert 0 <= dst < 16 and 0 <= src < 16
        self.items.append(("words", [0x89 | ((dst | (src << 4)) << 8)]))

    def double_to_float(self, dst: int, src: int):
        assert 0 <= dst < 16 and 0 <= src < 16
        self.items.append(("words", [0x8C | ((dst | (src << 4)) << 8)]))

    def add_long(self, dst: int, a: int, b: int):
        assert all(0 <= x < 256 for x in (dst, a, b))
        self.items.append(("words", [0x9B | (dst << 8), a | (b << 8)]))

    def sub_long(self, dst: int, a: int, b: int):
        assert all(0 <= x < 256 for x in (dst, a, b))
        self.items.append(("words", [0x9C | (dst << 8), a | (b << 8)]))

    def add_float(self, dst: int, a: int, b: int):
        assert all(0 <= x < 256 for x in (dst, a, b))
        self.items.append(("words", [0xA6 | (dst << 8), a | (b << 8)]))

    def sub_float(self, dst: int, a: int, b: int):
        assert all(0 <= x < 256 for x in (dst, a, b))
        self.items.append(("words", [0xA7 | (dst << 8), a | (b << 8)]))

    def mul_float(self, dst: int, a: int, b: int):
        assert all(0 <= x < 256 for x in (dst, a, b))
        self.items.append(("words", [0xA8 | (dst << 8), a | (b << 8)]))

    def div_float(self, dst: int, a: int, b: int):
        assert all(0 <= x < 256 for x in (dst, a, b))
        self.items.append(("words", [0xA9 | (dst << 8), a | (b << 8)]))

    def sub_long_2addr(self, dst: int, src: int):
        assert 0 <= dst < 16 and 0 <= src < 16
        self.items.append(("words", [0xBC | ((dst | (src << 4)) << 8)]))

    def mul_long_2addr(self, dst: int, src: int):
        assert 0 <= dst < 16 and 0 <= src < 16
        self.items.append(("words", [0xBD | ((dst | (src << 4)) << 8)]))

    def div_long_2addr(self, dst: int, src: int):
        assert 0 <= dst < 16 and 0 <= src < 16
        self.items.append(("words", [0xBE | ((dst | (src << 4)) << 8)]))

    def add_float_2addr(self, dst: int, src: int):
        assert 0 <= dst < 16 and 0 <= src < 16
        self.items.append(("words", [0xC6 | ((dst | (src << 4)) << 8)]))

    def sub_float_2addr(self, dst: int, src: int):
        assert 0 <= dst < 16 and 0 <= src < 16
        self.items.append(("words", [0xC7 | ((dst | (src << 4)) << 8)]))

    def mul_float_2addr(self, dst: int, src: int):
        assert 0 <= dst < 16 and 0 <= src < 16
        self.items.append(("words", [0xC8 | ((dst | (src << 4)) << 8)]))

    def div_float_2addr(self, dst: int, src: int):
        assert 0 <= dst < 16 and 0 <= src < 16
        self.items.append(("words", [0xC9 | ((dst | (src << 4)) << 8)]))

    def add_int_2addr(self, dst: int, src: int):
        assert 0 <= dst < 16 and 0 <= src < 16
        self.items.append(("words", [0xB0 | ((dst | (src << 4)) << 8)]))

    def sub_int_2addr(self, dst: int, src: int):
        assert 0 <= dst < 16 and 0 <= src < 16
        self.items.append(("words", [0xB1 | ((dst | (src << 4)) << 8)]))

    def mul_int_2addr(self, dst: int, src: int):
        assert 0 <= dst < 16 and 0 <= src < 16
        self.items.append(("words", [0xB2 | ((dst | (src << 4)) << 8)]))

    def div_int_2addr(self, dst: int, src: int):
        assert 0 <= dst < 16 and 0 <= src < 16
        self.items.append(("words", [0xB3 | ((dst | (src << 4)) << 8)]))

    def and_int_2addr(self, dst: int, src: int):
        assert 0 <= dst < 16 and 0 <= src < 16
        self.items.append(("words", [0xB5 | ((dst | (src << 4)) << 8)]))

    def or_int_2addr(self, dst: int, src: int):
        assert 0 <= dst < 16 and 0 <= src < 16
        self.items.append(("words", [0xB6 | ((dst | (src << 4)) << 8)]))

    def add_long_2addr(self, dst: int, src: int):
        assert 0 <= dst < 16 and 0 <= src < 16
        self.items.append(("words", [0xBB | ((dst | (src << 4)) << 8)]))

    def rsub_int_lit16(self, dst: int, src: int, lit: int):
        assert 0 <= dst < 16 and 0 <= src < 16 and -32768 <= lit <= 32767
        self.items.append(("words", [0xD1 | ((dst | (src << 4)) << 8), lit & 0xFFFF]))

    def mul_int_lit16(self, dst: int, src: int, lit: int):
        assert 0 <= dst < 16 and 0 <= src < 16 and -32768 <= lit <= 32767
        self.items.append(("words", [0xD2 | ((dst | (src << 4)) << 8), lit & 0xFFFF]))

    def div_int_lit16(self, dst: int, src: int, lit: int):
        assert 0 <= dst < 16 and 0 <= src < 16 and -32768 <= lit <= 32767
        self.items.append(("words", [0xD3 | ((dst | (src << 4)) << 8), lit & 0xFFFF]))

    def add_int_lit8(self, dst: int, src: int, lit: int):
        assert 0 <= dst < 256 and 0 <= src < 256 and -128 <= lit <= 127
        self.items.append(("words", [0xD8 | (dst << 8), src | ((lit & 0xFF) << 8)]))

    def mul_int_lit8(self, dst: int, src: int, lit: int):
        assert 0 <= dst < 256 and 0 <= src < 256 and -128 <= lit <= 127
        self.items.append(("words", [0xDA | (dst << 8), src | ((lit & 0xFF) << 8)]))

    def div_int_lit8(self, dst: int, src: int, lit: int):
        assert 0 <= dst < 256 and 0 <= src < 256 and -128 <= lit <= 127
        self.items.append(("words", [0xDB | (dst << 8), src | ((lit & 0xFF) << 8)]))

    def and_int_lit8(self, dst: int, src: int, lit: int):
        assert 0 <= dst < 256 and 0 <= src < 256 and -128 <= lit <= 127
        self.items.append(("words", [0xDD | (dst << 8), src | ((lit & 0xFF) << 8)]))

    def shl_int_lit8(self, dst: int, src: int, lit: int):
        assert 0 <= dst < 256 and 0 <= src < 256 and 0 <= lit <= 31
        self.items.append(("words", [0xE0 | (dst << 8), src | ((lit & 0xFF) << 8)]))

    def ushr_int_lit8(self, dst: int, src: int, lit: int):
        assert 0 <= dst < 256 and 0 <= src < 256 and 0 <= lit <= 31
        self.items.append(("words", [0xE2 | (dst << 8), src | ((lit & 0xFF) << 8)]))

    def goto16(self, target: str):
        self.items.append(("branch20t", 0x29, target))

    def if_eq(self, ra: int, rb: int, target: str):
        assert 0 <= ra < 16 and 0 <= rb < 16
        self.items.append(("branch22t", 0x32, ra, rb, target))

    def if_ne(self, ra: int, rb: int, target: str):
        assert 0 <= ra < 16 and 0 <= rb < 16
        self.items.append(("branch22t", 0x33, ra, rb, target))

    def if_lt(self, ra: int, rb: int, target: str):
        assert 0 <= ra < 16 and 0 <= rb < 16
        self.items.append(("branch22t", 0x34, ra, rb, target))

    def if_ge(self, ra: int, rb: int, target: str):
        assert 0 <= ra < 16 and 0 <= rb < 16
        self.items.append(("branch22t", 0x35, ra, rb, target))

    def if_gt(self, ra: int, rb: int, target: str):
        assert 0 <= ra < 16 and 0 <= rb < 16
        self.items.append(("branch22t", 0x36, ra, rb, target))

    def if_le(self, ra: int, rb: int, target: str):
        assert 0 <= ra < 16 and 0 <= rb < 16
        self.items.append(("branch22t", 0x37, ra, rb, target))

    def if_eqz(self, reg: int, target: str):
        assert 0 <= reg < 256
        self.items.append(("branch21t", 0x38, reg, target))

    def if_nez(self, reg: int, target: str):
        assert 0 <= reg < 256
        self.items.append(("branch21t", 0x39, reg, target))

    def if_ltz(self, reg: int, target: str):
        assert 0 <= reg < 256
        self.items.append(("branch21t", 0x3A, reg, target))

    def if_gez(self, reg: int, target: str):
        assert 0 <= reg < 256
        self.items.append(("branch21t", 0x3B, reg, target))

    def if_gtz(self, reg: int, target: str):
        assert 0 <= reg < 256
        self.items.append(("branch21t", 0x3C, reg, target))

    def if_lez(self, reg: int, target: str):
        assert 0 <= reg < 256
        self.items.append(("branch21t", 0x3D, reg, target))

    def _invoke35c(self, op: int, regs: list, meth_idx: int):
        assert 0 <= len(regs) <= 5 and all(0 <= r < 16 for r in regs)
        r = regs + [0] * (5 - len(regs))
        w0 = op | (((len(regs) << 4) | r[4]) << 8)
        w2 = r[0] | (r[1] << 4) | (r[2] << 8) | (r[3] << 12)
        self.items.append(("words", [w0, meth_idx, w2]))

    def invoke_virtual(self, regs: list, meth_idx: int):
        self._invoke35c(0x6E, regs, meth_idx)

    def invoke_direct(self, regs: list, meth_idx: int):
        self._invoke35c(0x70, regs, meth_idx)

    def invoke_static(self, regs: list, meth_idx: int):
        self._invoke35c(0x71, regs, meth_idx)

    def invoke_interface(self, regs: list, meth_idx: int):
        self._invoke35c(0x72, regs, meth_idx)

    def invoke_virtual_range(self, start_reg: int, count: int, meth_idx: int):
        assert 0 <= count < 256 and 0 <= start_reg < 65536
        self.items.append(("words", [0x74 | (count << 8), meth_idx, start_reg]))

    def invoke_direct_range(self, start_reg: int, count: int, meth_idx: int):
        assert 0 <= count < 256 and 0 <= start_reg < 65536
        self.items.append(("words", [0x76 | (count << 8), meth_idx, start_reg]))

    def invoke_static_range(self, start_reg: int, count: int, meth_idx: int):
        assert 0 <= count < 256 and 0 <= start_reg < 65536
        self.items.append(("words", [0x77 | (count << 8), meth_idx, start_reg]))

    def invoke_interface_range(self, start_reg: int, count: int, meth_idx: int):
        assert 0 <= count < 256 and 0 <= start_reg < 65536
        self.items.append(("words", [0x78 | (count << 8), meth_idx, start_reg]))

    def assemble(self, pad_to_words=None) -> bytes:
        labels = {}
        pc = 0
        for item in self.items:
            kind = item[0]
            if kind == "label":
                assert item[1] not in labels, f"Duplicate label {item[1]}"
                labels[item[1]] = pc
            elif kind == "words":
                pc += len(item[1])
            elif kind in ("branch20t", "branch21t", "branch22t"):
                pc += 2
            elif kind == "branch31t":
                pc += 3
            elif kind == "array_data":
                _, name, raw = item
                if pc % 2 != 0:
                    pc += 1
                assert name not in labels, f"Duplicate label {name}"
                labels[name] = pc
                pc += 4 + (len(raw) + 1) // 2
            else:
                raise ValueError(kind)

        self.last_labels = labels
        out_words = []
        pc = 0
        for item in self.items:
            kind = item[0]
            if kind == "label":
                continue
            elif kind == "words":
                out_words.extend(item[1])
                pc += len(item[1])
            elif kind == "branch20t":
                _, op, target = item
                rel = labels[target] - pc
                assert -32768 <= rel <= 32767 and rel != 0
                out_words.extend([op, rel & 0xFFFF])
                pc += 2
            elif kind == "branch21t":
                _, op, reg, target = item
                rel = labels[target] - pc
                assert -32768 <= rel <= 32767
                out_words.extend([op | (reg << 8), rel & 0xFFFF])
                pc += 2
            elif kind == "branch22t":
                _, op, ra, rb, target = item
                rel = labels[target] - pc
                assert -32768 <= rel <= 32767
                out_words.extend([op | ((ra | (rb << 4)) << 8), rel & 0xFFFF])
                pc += 2
            elif kind == "branch31t":
                _, op, reg, target = item
                tpc = labels[target]
                assert tpc % 2 == 0, f"Unaligned payload label {target} at +{tpc:x}"
                rel = (tpc - pc) & 0xFFFFFFFF
                out_words.extend([op | (reg << 8), rel & 0xFFFF, (rel >> 16) & 0xFFFF])
                pc += 3
            elif kind == "array_data":
                _, name, raw = item
                if pc % 2 != 0:
                    out_words.append(0x0000)
                    pc += 1
                assert pc == labels[name]
                n = len(raw)
                padded = raw + (b"\x00" if (n % 2) else b"")
                out_words.extend([0x0300, 1, n & 0xFFFF, (n >> 16) & 0xFFFF])
                for i in range(0, len(padded), 2):
                    out_words.append(padded[i] | (padded[i + 1] << 8))
                pc += 4 + len(padded) // 2

        if pad_to_words is not None:
            assert len(out_words) <= pad_to_words, f"Code {len(out_words)} words > budget {pad_to_words} words"
            out_words.extend([0x0000] * (pad_to_words - len(out_words)))

        return b"".join(struct.pack("<H", w) for w in out_words)
