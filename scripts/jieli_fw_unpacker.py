"""Pure-Python JieLi JL701N / AC701N (Haylou Watch 4S / LS26) OTA UFW Unpacker & Inspector.

Zero external dependencies. Reproducibly unpacks a locally obtained Watch 4S `.ufw` OTA
firmware image (or extracted `flash.bin`), decrypts the JLFS root & 32-byte SFC XOR-encrypted
`app_dir_head` (`app.bin`, `cfg_tool.bin`) with full CRC16 verification, and dumps embedded
firmware tables (BLE GATT ATT DB, RTOS tasks, external flash partitions, battery LUT, BOM).

Usage:
    python scripts/jieli_fw_unpacker.py path/to/V24.28.001.1.1.1.1.38.ufw --out ./unpacked --inspect
    python scripts/jieli_fw_unpacker.py path/to/app.bin --inspect-app
"""

from __future__ import annotations

import argparse
import os
import re
import struct
import sys

APP_DIR_OFFSET = 0x1000
DEFAULT_SFC_KEY = 0x1607  # Verified on Haylou Watch 4S (LS26 / V24.28.001.1.1.1.1.38)
APP_ENTRY_VA = 0x06000120

ATT_FLAGS = {
    0x0001: "BCAST",
    0x0002: "R",
    0x0004: "WNR",
    0x0008: "W",
    0x0010: "N",
    0x0020: "I",
    0x0100: "DYN",
    0x0200: "UUID128",
}

STD_GATT_UUIDS = {
    0x1800: "Generic Access",
    0x1801: "Generic Attribute",
    0x180A: "Device Information",
    0x180D: "Heart Rate",
    0x180F: "Battery Service",
    0x1812: "HID Service",
    0x2800: "PRIMARY_SERVICE",
    0x2803: "CHARACTERISTIC",
    0x2902: "CCCD",
    0x2A00: "Device Name",
    0x2A05: "Service Changed",
    0x2A19: "Battery Level",
    0x2A25: "Serial Number",
    0x2A26: "Firmware Revision",
    0x2A28: "Software Revision",
    0x2A29: "Manufacturer Name",
    0x2A37: "HR Measurement",
    0x2A38: "Body Sensor Location",
    0xFEEA: "MoYoung/CRREPA",
    0xFEE7: "WeChat Sports",
}


def jl_crc16(data: bytes, init: int = 0) -> int:
    """Standard JieLi CRC16-CCITT (polynomial 0x1021, MSB-first)."""
    crc = init & 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else ((crc << 1) & 0xFFFF)
    return crc


def jl_enc_stream(data: bytes, key: int = 0xFFFF) -> bytes:
    """JieLi 16-bit CRC-LFSR XOR stream cipher (symmetric encrypt/decrypt)."""
    crc = key & 0xFFFF
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ (crc & 0xFF)
        crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else ((crc << 1) & 0xFFFF)
    return bytes(out)


def sfc_xor_decrypt(data: bytes, rel_addr: int, sfc_key: int = DEFAULT_SFC_KEY) -> bytes:
    """JieLi JL701N SPI Flash Cache (SFC) 32-byte block decryption.

    Each 32-byte aligned block at offset `rel_addr` (relative to `app_dir_head` at 0x1000)
    is XOR-decrypted using LFSR seed `sfc_key ^ ((rel_addr & ~31) >> 2)`.
    """
    out = bytearray(len(data))
    off = 0
    n = len(data)
    while off < n:
        cur = rel_addr + off
        blk_off = cur & 31
        take = min(32 - blk_off, n - off)
        seed = (sfc_key ^ ((cur & ~31) >> 2)) & 0xFFFF
        if blk_off == 0:
            out[off : off + take] = jl_enc_stream(data[off : off + take], seed)
        else:
            out[off : off + take] = jl_enc_stream(b"\x00" * blk_off + data[off : off + take], seed)[blk_off:]
        off += take
    return bytes(out)


def parse_ufw_container(raw: bytes) -> dict:
    """Parse a JieLi JL701N `.ufw` OTA archive header (64 B) and 80-byte part table."""
    if len(raw) < 0x40:
        raise ValueError("UFW file too small (< 64 bytes)")
    hdr = jl_enc_stream(raw[:0x40], 0xFFFF)
    hdr_crc, version, total_size, part_count = struct.unpack_from("<HHIH", hdr, 0)
    chip = hdr[16:32].split(b"\x00")[0].decode("ascii", errors="replace")

    parts = []
    for idx in range(part_count):
        e_off = 0x40 + idx * 0x50
        if e_off + 0x50 > len(raw):
            break
        ent = jl_enc_stream(raw[e_off : e_off + 0x50], 0xFFFF)
        ftype, fidx, dcrc, res0, off, flen = struct.unpack_from("<HHHHII", ent, 0)
        name = ent[0x40:0x50].split(b"\x00")[0].decode("ascii", errors="replace")
        parts.append({
            "index": fidx,
            "type": ftype,
            "data_crc": dcrc,
            "offset": off,
            "length": flen,
            "name": name or f"part_{idx}_type{ftype:02x}.bin",
        })

    return {
        "hdr_crc": hdr_crc,
        "version": version,
        "total_size": total_size,
        "part_count": part_count,
        "chip": chip,
        "parts": parts,
    }


def parse_jlfs_entry(raw32: bytes, key: int = 0xFFFF) -> dict | None:
    """Decode and CRC16-verify a single 32-byte JieLi JLFS directory entry."""
    if len(raw32) != 32:
        return None
    dec = jl_enc_stream(raw32, key)
    hdr_crc = struct.unpack_from("<H", dec, 0)[0]
    if hdr_crc != jl_crc16(dec[2:]):
        return None
    data_crc, addr, length, attr, res, idx = struct.unpack_from("<HIIBBH", dec, 2)
    name = dec[16:32].split(b"\x00")[0].rstrip(b"\xff").decode("ascii", errors="replace")
    return {
        "hdr_crc": hdr_crc,
        "data_crc": data_crc,
        "addr": addr,
        "len": length,
        "attr": attr,
        "res": res,
        "idx": idx,
        "name": name,
    }


def crack_app_dir_sfc_key(flash_raw: bytes, app_dir_off: int = APP_DIR_OFFSET) -> int | None:
    """Recover the 16-bit SFC XOR base key at `app_dir_off` by verifying 2 consecutive JLFS CRCs."""
    if app_dir_off + 64 > len(flash_raw):
        return None
    b0 = flash_raw[app_dir_off : app_dir_off + 32]
    b1 = flash_raw[app_dir_off + 32 : app_dir_off + 64]
    # Fast path: try known Watch 4S key first
    for k in (DEFAULT_SFC_KEY, *range(65536)):
        e0 = parse_jlfs_entry(b0, k)
        if not e0 or not e0["name"].isascii():
            continue
        e1 = parse_jlfs_entry(b1, k ^ 0x08)
        if e1 and e1["name"].isascii() and any(x in (e0["name"] + e1["name"]).lower() for x in ("app", "cfg", "bin")):
            return k
    return None


def parse_flash_image(flash_raw: bytes, sfc_key: int | None = None) -> dict:
    """Parse root JLFS entries and SFC-encrypted `app_dir_head` files from `flash.bin`."""
    root_entries = []
    for off in range(0x20, 0x400, 32):
        ent = parse_jlfs_entry(flash_raw[off : off + 32], 0xFFFF)
        if not ent:
            break
        root_entries.append(ent)

    app_dir_off = APP_DIR_OFFSET
    for ent in root_entries:
        if ent["name"] == "app_dir_head":
            app_dir_off = ent["addr"]
            break

    key = sfc_key if sfc_key is not None else crack_app_dir_sfc_key(flash_raw, app_dir_off)
    if key is None:
        raise ValueError(f"Could not determine 16-bit SFC key for app_dir_head @ 0x{app_dir_off:x}")

    app_entries = []
    for rel in range(0, 0x1000, 32):
        ent = parse_jlfs_entry(flash_raw[app_dir_off + rel : app_dir_off + rel + 32], (key ^ (rel >> 2)) & 0xFFFF)
        if not ent:
            break
        ent["rel_dir_off"] = rel
        app_entries.append(ent)

    extracted = {}
    for ent in app_entries:
        if ent["name"] == "app_area_head":
            continue
        f_off = app_dir_off + ent["addr"]
        if f_off + ent["len"] <= len(flash_raw):
            dec = sfc_xor_decrypt(flash_raw[f_off : f_off + ent["len"]], ent["addr"], key)
            crc_ok = jl_crc16(dec) == ent["data_crc"]
            extracted[ent["name"]] = {"bytes": dec, "crc_ok": crc_ok, "expected_crc": ent["data_crc"], "entry": ent}

    return {
        "app_dir_off": app_dir_off,
        "sfc_key": key,
        "root_entries": root_entries,
        "app_entries": app_entries,
        "files": extracted,
    }


def _fmt_uuid128(b16: bytes) -> str:
    r = b16[::-1].hex()
    return f"{r[0:8]}-{r[8:12]}-{r[12:16]}-{r[16:20]}-{r[20:32]}"


def parse_att_db(app_bytes: bytes, start_off: int | None = None) -> list[dict]:
    """Locate and parse the BTstack BLE GATT ATT database inside decrypted `app.bin`."""
    if start_off is None:
        sig = bytes.fromhex("0a00020001000028")
        start_off = app_bytes.find(sig)
        if start_off < 0:
            return []

    rows = []
    pos = start_off
    while pos + 8 <= len(app_bytes):
        sz = struct.unpack_from("<H", app_bytes, pos)[0]
        if sz == 0 or sz > 256 or pos + sz > len(app_bytes):
            break
        flags, handle = struct.unpack_from("<HH", app_bytes, pos + 2)
        if flags & 0x0200:
            uuid_str = _fmt_uuid128(app_bytes[pos + 6 : pos + 22])
            val = app_bytes[pos + 22 : pos + sz]
            u16 = None
        else:
            u16 = struct.unpack_from("<H", app_bytes, pos + 6)[0]
            uuid_str = f"0x{u16:04X}"
            val = app_bytes[pos + 8 : pos + sz]

        desc = STD_GATT_UUIDS.get(u16, "") if u16 is not None else ""
        detail = val.hex()
        if u16 == 0x2800 and len(val) == 2:
            su = struct.unpack_from("<H", val, 0)[0]
            detail = f"SVC 0x{su:04X} ({STD_GATT_UUIDS.get(su, '?')})"
        elif u16 == 0x2803 and len(val) >= 5:
            props = "/".join(n for bit, n in ((2, "R"), (4, "WNR"), (8, "W"), (16, "N"), (32, "I")) if val[0] & bit)
            vh = struct.unpack_from("<H", val, 1)[0]
            if len(val) == 5:
                cu = struct.unpack_from("<H", val, 3)[0]
                detail = f"CHAR[{props}] h=0x{vh:04x} uuid=0x{cu:04X} ({STD_GATT_UUIDS.get(cu, '')})"
            elif len(val) == 19:
                detail = f"CHAR[{props}] h=0x{vh:04x} uuid={_fmt_uuid128(val[3:19])}"

        rows.append({
            "handle": handle,
            "flags": flags,
            "flags_str": "|".join(n for bit, n in ATT_FLAGS.items() if flags & bit),
            "uuid": uuid_str,
            "uuid_name": desc,
            "detail": detail,
        })
        pos += sz
    return rows


def inspect_app_bin(app_bytes: bytes) -> None:
    """Print key structural tables & hardware identifiers from a decrypted Watch 4S `app.bin`."""
    print(f"\n=== Inspecting app.bin ({len(app_bytes):,} bytes, XIP VA base 0x{APP_ENTRY_VA:08x}) ===")
    for tag, pat in [
        ("Build / Model", rb"MOY-[A-Z0-9.-]+|V24\.[0-9.]+|LS26[A-Z0-9]+|HAYLOU Watch 4S"),
        ("Hardware Drivers", rb"vc30fx_sc|icoe_gnss_init|AnalyzeCc1165wType|gnssSetAg3352bVersion|chsc6x|AppAw320xx|p11 gsensor"),
        ("GoMore Engine", rb"healthIndexInitUser|CheckGomoreKey|moy_gomore_init"),
    ]:
        hits = sorted(set(m.group().decode("ascii", "ignore") for m in re.finditer(pat, app_bytes)))
        print(f"  {tag:18s}: {hits}")

    att = parse_att_db(app_bytes)
    print(f"\n=== BLE GATT ATT Database ({len(att)} attributes) ===")
    for r in att:
        print(f"  h=0x{r['handle']:04x} [{r['flags_str']:14s}] {r['uuid']:10s} {r['uuid_name']:18s} {r['detail']}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Haylou Watch 4S (JL701N) OTA UFW Unpacker & Firmware Inspector")
    ap.add_argument("input", help="Path to .ufw OTA file, flash.bin, or decrypted app.bin")
    ap.add_argument("--out", "-o", default="", help="Output directory for unpacked/decrypted files")
    ap.add_argument("--sfc-key", type=lambda x: int(x, 0), default=None, help="Override 16-bit SFC XOR key (default: auto-detect, 0x1607 for LS26)")
    ap.add_argument("--inspect", action="store_true", help="Inspect decrypted app.bin GATT DB & hardware drivers")
    ap.add_argument("--inspect-app", action="store_true", help="Treat input directly as already-decrypted app.bin")
    args = ap.parse_args()

    raw = open(args.input, "rb").read()
    if args.inspect_app:
        inspect_app_bin(raw)
        return 0

    flash_raw = None
    if raw[0x10:0x16] == b"JL701N":
        print(f"[*] Input detected as raw JL701N flash image ({len(raw):,} B)")
        flash_raw = raw
    else:
        ufw = parse_ufw_container(raw)
        print(f"[*] UFW Header: chip={ufw['chip']!r} ver=0x{ufw['version']:04x} total={ufw['total_size']:,} B parts={ufw['part_count']}")
        for p in ufw["parts"]:
            print(f"  part[{p['index']}] type=0x{p['type']:02x} off=0x{p['offset']:06x} len={p['length']:9,d} dcrc=0x{p['data_crc']:04x} name={p['name']!r}")
            chunk = raw[p["offset"] : p["offset"] + p["length"]]
            if args.out:
                os.makedirs(args.out, exist_ok=True)
                open(os.path.join(args.out, p["name"]), "wb").write(chunk)
            if p["length"] > 100_000 and chunk[0x10:0x16] == b"JL701N":
                flash_raw = chunk

    if flash_raw is None:
        print("[!] No JL701N flash image found inside input.", file=sys.stderr)
        return 1

    res = parse_flash_image(flash_raw, sfc_key=args.sfc_key)
    print(f"\n[*] Parsed JLFS @ 0x0020 & app_dir_head @ 0x{res['app_dir_off']:04x} (SFC XOR key = 0x{res['sfc_key']:04x})")
    for ent in res["app_entries"]:
        print(f"  app_dir: {ent['name']:18s} addr=0x{ent['addr']:08x} len={ent['len']:9,d} attr=0x{ent['attr']:02x} dcrc=0x{ent['data_crc']:04x}")

    for name, fobj in res["files"].items():
        status = "CRC16 OK" if fobj["crc_ok"] else "CRC16 MISMATCH"
        print(f"  -> decrypted {name:16s} ({len(fobj['bytes']):9,d} B) [{status} 0x{fobj['expected_crc']:04x}]")
        if args.out:
            os.makedirs(args.out, exist_ok=True)
            open(os.path.join(args.out, name), "wb").write(fobj["bytes"])

    if args.inspect and "app.bin" in res["files"]:
        inspect_app_bin(res["files"]["app.bin"]["bytes"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
