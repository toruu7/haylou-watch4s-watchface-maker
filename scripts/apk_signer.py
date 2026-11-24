"""
Pure-Python APK zipalign (-p 4) + APK Signature Scheme v2 & v3 signer + verifier.

Zero Java / keytool / zipalign / apksigner dependencies — uses only Python stdlib + `cryptography`.
Supports both PEM/DER keystore directories (`debug_key.pem` + `debug_cert.der`) and
standard PKCS#12 `.keystore` / `.p12` files (auto-generating an RSA-2048 debug key if missing).
"""

from __future__ import annotations

import datetime
import hashlib
import os
import struct
import zipfile
import zlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
V2_ID = 0x7109871A
V3_ID = 0xF05368C0
PADDING_ID = 0x42726577
ALG_RSA_PKCS1_V1_5_SHA256 = 0x0103


def _len_prefixed(b: bytes) -> bytes:
    return struct.pack("<I", len(b)) + b


def compute_content_digest_sha256(before_sig: bytes, central_dir: bytes, eocd_for_digest: bytes) -> bytes:
    """APK Signature Scheme v2/v3 1 MB-chunked SHA-256 content digest."""
    chunk_digests = []
    chunk_size = 1024 * 1024
    for section in (before_sig, central_dir, eocd_for_digest):
        off = 0
        n = len(section)
        while off < n:
            chunk = section[off : off + chunk_size]
            h = hashlib.sha256()
            h.update(b"\xa5")
            h.update(struct.pack("<I", len(chunk)))
            h.update(chunk)
            chunk_digests.append(h.digest())
            off += chunk_size
    top = hashlib.sha256()
    top.update(b"\x5a")
    top.update(struct.pack("<I", len(chunk_digests)))
    for d in chunk_digests:
        top.update(d)
    return top.digest()


def _generate_rsa2048_self_signed():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Android"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Android Debug"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365 * 30))
        .sign(priv, hashes.SHA256())
    )
    return priv, cert


def load_or_create_signing_key(keystore_path: str, ks_pass: str = "android"):
    """
    Load (private_key, cert_der) from either:
      1. A directory containing `debug_key.pem` + `debug_cert.der` (auto-created if missing), OR
      2. A PKCS#12 `.keystore` / `.p12` / `.pfx` file (auto-created in pure Python if missing).
    Also supports checking sibling `debug_key.pem` + `debug_cert.der` if an older JKS file is passed.
    """
    is_file_like = keystore_path.lower().endswith((".keystore", ".p12", ".pfx", ".jks", ".pem"))

    if not is_file_like:
        os.makedirs(keystore_path, exist_ok=True)
        key_path = os.path.join(keystore_path, "debug_key.pem")
        cert_path = os.path.join(keystore_path, "debug_cert.der")
        if os.path.isfile(key_path) and os.path.isfile(cert_path):
            priv = serialization.load_pem_private_key(open(key_path, "rb").read(), password=None)
            cert_der = open(cert_path, "rb").read()
            return priv, cert_der
        print(f"[*] Generating fresh RSA-2048 debug key in {keystore_path}...")
        priv, cert = _generate_rsa2048_self_signed()
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        with open(key_path, "wb") as f:
            f.write(
                priv.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
        with open(cert_path, "wb") as f:
            f.write(cert_der)
        return priv, cert_der

    # File path specified
    parent_dir = os.path.dirname(os.path.abspath(keystore_path))
    os.makedirs(parent_dir, exist_ok=True)

    if keystore_path.lower().endswith(".pem"):
        cert_path = os.path.join(parent_dir, "debug_cert.der")
        if os.path.isfile(keystore_path) and os.path.isfile(cert_path):
            priv = serialization.load_pem_private_key(open(keystore_path, "rb").read(), password=None)
            return priv, open(cert_path, "rb").read()
        raise FileNotFoundError(f"Expected PEM key ({keystore_path}) and sibling debug_cert.der ({cert_path})")

    if os.path.isfile(keystore_path):
        raw = open(keystore_path, "rb").read()
        # Try PKCS#12 directly (standard format produced by modern keytool & this script)
        try:
            pwd = ks_pass.encode("utf-8") if ks_pass is not None else None
            priv, cert, _ = pkcs12.load_key_and_certificates(raw, pwd)
            if priv is not None and cert is not None:
                return priv, cert.public_bytes(serialization.Encoding.DER)
        except Exception:
            pass
        # Fallback: check sibling debug_key.pem + debug_cert.der (e.g. if keystore is legacy JKS)
        sib_key = os.path.join(parent_dir, "debug_key.pem")
        sib_cert = os.path.join(parent_dir, "debug_cert.der")
        if os.path.isfile(sib_key) and os.path.isfile(sib_cert):
            priv = serialization.load_pem_private_key(open(sib_key, "rb").read(), password=None)
            return priv, open(sib_cert, "rb").read()
        raise ValueError(
            f"Could not parse {keystore_path} as PKCS#12 (wrong password or legacy JKS format). "
            f"Convert with `keytool -importkeystore -deststoretype pkcs12` or point --keystore at a directory."
        )

    # Create a fresh PKCS#12 debug.keystore + PEM/DER pair in pure Python (no Java needed!)
    print(f"[*] Generating pure-Python PKCS#12 RSA-2048 keystore at {keystore_path}...")
    priv, cert = _generate_rsa2048_self_signed()
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    enc = serialization.BestAvailableEncryption(ks_pass.encode("utf-8")) if ks_pass else serialization.NoEncryption()
    p12_bytes = pkcs12.serialize_key_and_certificates(
        name=b"androiddebugkey",
        key=priv,
        cert=cert,
        cas=None,
        encryption_algorithm=enc,
    )
    with open(keystore_path, "wb") as f:
        f.write(p12_bytes)
    # Also save PEM/DER copies alongside for easy inspection/reuse
    with open(os.path.join(parent_dir, "debug_key.pem"), "wb") as f:
        f.write(
            priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    with open(os.path.join(parent_dir, "debug_cert.der"), "wb") as f:
        f.write(cert_der)
    return priv, cert_der


def repack_align_and_sign_apk(
    src_apk: str,
    out_apk: str,
    replacements: dict,
    keystore_path: str,
    ks_pass: str = "android",
    min_sdk: int = 24,
):
    """
    Repackages `src_apk` with `replacements` (zip_path -> bytes), strips old META-INF signatures,
    stores `resources.arsc` uncompressed (4-byte aligned) and `.so` libraries 4096-byte page-aligned
    (`zipalign -p 4` equivalent), and signs with APK Signature Scheme v2 + v3 in pure Python.
    """
    entries = []
    with zipfile.ZipFile(src_apk, "r") as zf:
        for info in zf.infolist():
            fn = info.filename
            if fn.startswith("META-INF/") and (
                fn.endswith((".SF", ".RSA", ".DSA", ".EC")) or fn == "META-INF/MANIFEST.MF"
            ):
                continue
            if fn in replacements:
                raw_uncompressed = replacements[fn]
                compress_type = (
                    zipfile.ZIP_STORED
                    if (fn == "resources.arsc" or info.compress_type == zipfile.ZIP_STORED)
                    else zipfile.ZIP_DEFLATED
                )
                crc = zlib.crc32(raw_uncompressed) & 0xFFFFFFFF
                uncomp_size = len(raw_uncompressed)
                if compress_type == zipfile.ZIP_DEFLATED:
                    comp_obj = zlib.compressobj(6, zlib.DEFLATED, -15)
                    comp_data = comp_obj.compress(raw_uncompressed) + comp_obj.flush()
                else:
                    comp_data = raw_uncompressed
            elif fn == "resources.arsc" and info.compress_type != zipfile.ZIP_STORED:
                # Android 11+ requires resources.arsc to be stored uncompressed & 4-byte aligned
                raw_uncompressed = zf.read(fn)
                compress_type = zipfile.ZIP_STORED
                crc = zlib.crc32(raw_uncompressed) & 0xFFFFFFFF
                uncomp_size = len(raw_uncompressed)
                comp_data = raw_uncompressed
            else:
                comp_data = None
                crc = info.CRC
                uncomp_size = info.file_size
                compress_type = info.compress_type
            entries.append((info, compress_type, crc, uncomp_size, comp_data))

    src_bytes = open(src_apk, "rb").read()
    body = bytearray()
    cd_records = bytearray()

    for info, compress_type, crc, uncomp_size, comp_data in entries:
        fn_bytes = info.filename.encode("utf-8")
        if comp_data is None:
            lh_off = info.header_offset
            assert src_bytes[lh_off : lh_off + 4] == b"PK\x03\x04", f"Bad local header at 0x{lh_off:x}"
            fn_len, ex_len = struct.unpack_from("<HH", src_bytes, lh_off + 26)
            data_start = lh_off + 30 + fn_len + ex_len
            comp_data = src_bytes[data_start : data_start + info.compress_size]

        local_header_offset = len(body)
        extra = b""
        if compress_type == zipfile.ZIP_STORED:
            align = 4096 if info.filename.endswith(".so") else 4
            data_off_no_pad = local_header_offset + 30 + len(fn_bytes)
            pad = (align - (data_off_no_pad % align)) % align
            extra = b"\x00" * pad

        dt = info.date_time
        dosdate = ((max(1980, dt[0]) - 1980) << 9) | (dt[1] << 5) | dt[2]
        dostime = (dt[3] << 11) | (dt[4] << 5) | (dt[5] // 2)
        gp_flags = info.flag_bits & ~0x08
        version_needed = 20 if compress_type == zipfile.ZIP_DEFLATED else 10

        lh = struct.pack(
            "<4sHHHHHIIIHH",
            b"PK\x03\x04",
            version_needed,
            gp_flags,
            compress_type,
            dostime,
            dosdate,
            crc,
            len(comp_data),
            uncomp_size,
            len(fn_bytes),
            len(extra),
        )
        body.extend(lh)
        body.extend(fn_bytes)
        body.extend(extra)
        if compress_type == zipfile.ZIP_STORED:
            align = 4096 if info.filename.endswith(".so") else 4
            assert len(body) % align == 0, f"Alignment failed for {info.filename}"
        body.extend(comp_data)

        cd = struct.pack(
            "<4sHHHHHHIIIHHHHHII",
            b"PK\x01\x02",
            info.create_version or 20,
            version_needed,
            gp_flags,
            compress_type,
            dostime,
            dosdate,
            crc,
            len(comp_data),
            uncomp_size,
            len(fn_bytes),
            0,
            0,
            0,
            info.internal_attr,
            info.external_attr,
            local_header_offset,
        )
        cd_records.extend(cd)
        cd_records.extend(fn_bytes)

    before_sig = bytes(body)
    central_dir = bytes(cd_records)
    eocd_for_digest = struct.pack(
        "<4sHHHHIIH",
        b"PK\x05\x06",
        0,
        0,
        len(entries),
        len(entries),
        len(central_dir),
        len(before_sig),
        0,
    )

    digest = compute_content_digest_sha256(before_sig, central_dir, eocd_for_digest)
    priv, cert_der = load_or_create_signing_key(keystore_path, ks_pass=ks_pass)
    pub_der = priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # APK Signature Scheme v2 (0x7109871a)
    digest_entry = struct.pack("<I", ALG_RSA_PKCS1_V1_5_SHA256) + _len_prefixed(digest)
    digests_seq = _len_prefixed(_len_prefixed(digest_entry))
    certs_seq = _len_prefixed(_len_prefixed(cert_der))
    v2_attr = _len_prefixed(struct.pack("<II", 0xBEEFF00D, 3))
    v2_attrs_seq = _len_prefixed(v2_attr)
    v2_signed_data = digests_seq + certs_seq + v2_attrs_seq + struct.pack("<I", 0)
    v2_sig = priv.sign(v2_signed_data, padding.PKCS1v15(), hashes.SHA256())
    v2_sig_entry = struct.pack("<I", ALG_RSA_PKCS1_V1_5_SHA256) + _len_prefixed(v2_sig)
    v2_sigs_seq = _len_prefixed(_len_prefixed(v2_sig_entry))
    v2_signer = _len_prefixed(v2_signed_data) + v2_sigs_seq + _len_prefixed(pub_der)
    v2_value = _len_prefixed(_len_prefixed(v2_signer))

    # APK Signature Scheme v3 (0xf05368c0)
    max_sdk = 0x7FFFFFFF
    v3_attrs_seq = struct.pack("<I", 0)
    v3_signed_data = digests_seq + certs_seq + struct.pack("<II", min_sdk, max_sdk) + v3_attrs_seq
    v3_sig = priv.sign(v3_signed_data, padding.PKCS1v15(), hashes.SHA256())
    v3_sig_entry = struct.pack("<I", ALG_RSA_PKCS1_V1_5_SHA256) + _len_prefixed(v3_sig)
    v3_sigs_seq = _len_prefixed(_len_prefixed(v3_sig_entry))
    v3_signer = (
        _len_prefixed(v3_signed_data)
        + struct.pack("<II", min_sdk, max_sdk)
        + v3_sigs_seq
        + _len_prefixed(pub_der)
    )
    v3_value = _len_prefixed(_len_prefixed(v3_signer))

    def make_pair(pid: int, val: bytes) -> bytes:
        return struct.pack("<QI", 4 + len(val), pid) + val

    pairs = bytearray()
    pairs.extend(make_pair(V2_ID, v2_value))
    pairs.extend(make_pair(V3_ID, v3_value))

    # 4096-byte alignment padding pair (0x42726577)
    base_total = len(before_sig) + 8 + len(pairs) + 8 + 16
    rem = base_total % 4096
    if rem != 0:
        needed = 4096 - rem
        if needed < 12:
            needed += 4096
        pairs.extend(make_pair(PADDING_ID, b"\x00" * (needed - 12)))

    size_of_block = len(pairs) + 8 + 16
    sig_block = (
        struct.pack("<Q", size_of_block)
        + bytes(pairs)
        + struct.pack("<Q", size_of_block)
        + APK_SIG_BLOCK_MAGIC
    )

    new_cd_off = len(before_sig) + len(sig_block)
    assert new_cd_off % 4096 == 0, "Central Directory offset not 4KB-aligned"
    final_eocd = struct.pack(
        "<4sHHHHIIH",
        b"PK\x05\x06",
        0,
        0,
        len(entries),
        len(entries),
        len(central_dir),
        new_cd_off,
        0,
    )

    os.makedirs(os.path.dirname(os.path.abspath(out_apk)), exist_ok=True)
    with open(out_apk, "wb") as f:
        f.write(before_sig)
        f.write(sig_block)
        f.write(central_dir)
        f.write(final_eocd)
    return out_apk


def verify_apk_signatures(apk_path: str) -> dict:
    """Verify APK Signature Scheme v2 & v3 SHA-256 content digests and RSA signatures."""
    data = open(apk_path, "rb").read()
    eocd_off = data.rfind(b"PK\x05\x06")
    if eocd_off < 0:
        raise ValueError("Not a valid ZIP/APK (missing EOCD)")
    cd_size, cd_off = struct.unpack_from("<II", data, eocd_off + 12)
    magic = data[cd_off - 16 : cd_off]
    if magic != APK_SIG_BLOCK_MAGIC:
        raise ValueError("Missing APK Signing Block 42")
    sig_size_end = struct.unpack_from("<Q", data, cd_off - 24)[0]
    sig_start = cd_off - 8 - sig_size_end

    before_sig = data[:sig_start]
    central_dir = data[cd_off:eocd_off]
    eocd_mut = bytearray(data[eocd_off:])
    struct.pack_into("<I", eocd_mut, 16, sig_start)

    expected_digest = compute_content_digest_sha256(before_sig, central_dir, bytes(eocd_mut))
    verified = {"v2": False, "v3": False, "cd_aligned_4k": (cd_off % 4096 == 0), "digest_sha256": expected_digest.hex()}

    pos = sig_start + 8
    end = cd_off - 24
    while pos < end:
        pair_len = struct.unpack_from("<Q", data, pos)[0]
        pair_id = struct.unpack_from("<I", data, pos + 8)[0]
        val = data[pos + 12 : pos + 8 + pair_len]
        if pair_id in (V2_ID, V3_ID):
            scheme = "v2" if pair_id == V2_ID else "v3"
            signer = val[8 : 8 + struct.unpack_from("<I", val, 4)[0]]
            sd_len = struct.unpack_from("<I", signer, 0)[0]
            sd = signer[4 : 4 + sd_len]
            digests_len = struct.unpack_from("<I", sd, 0)[0]
            d_entry = sd[8 : 4 + digests_len]
            d_bytes = d_entry[8 : 8 + struct.unpack_from("<I", d_entry, 4)[0]]
            if d_bytes != expected_digest:
                raise ValueError(f"APK {scheme} content digest mismatch!")
            off = 4 + sd_len
            if pair_id == V3_ID:
                off += 8
            sigs_len = struct.unpack_from("<I", signer, off)[0]
            sig_entry = signer[off + 8 : off + 4 + sigs_len]
            sig_bytes = sig_entry[8 : 8 + struct.unpack_from("<I", sig_entry, 4)[0]]
            pk_off = off + 4 + sigs_len
            pk_bytes = signer[pk_off + 4 : pk_off + 4 + struct.unpack_from("<I", signer, pk_off)[0]]
            pub = serialization.load_der_public_key(pk_bytes)
            pub.verify(sig_bytes, sd, padding.PKCS1v15(), hashes.SHA256())
            verified[scheme] = True
        pos += 8 + pair_len

    return verified
