"""
Haylou Watch 4S (LS26) Customizer & Watchface Maker
Automated APK Patcher for Haylou Fun (v4.0.8)

Patches applied:
1. classes.dex:
   Overrides `com.crrepa.f.a2.a(CRPWatchFaceLayoutInfo)` to issue JieLi BLE command 0xB4
   with `showPointer=false` and 0 overlay elements, cleanly disabling hands, digital clock digits,
   and widgets for pure custom AMOLED background display.
2. classes3.dex:
   Overrides `com.facebook.FacebookSdk.getApplicationSignature(Context)` to return Haylou's official
   release signature hash ("UHVvEzDXInBYrb0oGpukqdW1VV4="). This bypasses Facebook SDK's client hash
   validation on debug-signed builds without triggering ART bytecode verification errors.
3. Repackages with uncompressed `resources.arsc` (ZIP_STORED), 4-byte zipaligns, and signs with v2/v3 scheme.
"""

import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import zipfile
import zlib

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))

DEFAULT_SRC_APK = os.path.join(os.path.expanduser("~"), "Downloads", "haylou-fun-v4-0-8.apk")
DEFAULT_OUT_APK = os.path.join(PROJECT_DIR, "haylou-fun-v4-0-8-noclock.apk")
DEFAULT_KEYSTORE = os.path.join(PROJECT_DIR, "keystore", "debug.keystore")

def find_build_tools():
    candidates = []
    for env_var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        val = os.environ.get(env_var)
        if val:
            candidates.append(os.path.join(val, "build-tools"))
    # Standard default SDK locations across Windows, macOS, and Linux
    home = os.path.expanduser("~")
    candidates.extend([
        os.path.join(home, "AppData", "Local", "Android", "Sdk", "build-tools"),
        os.path.join(home, "Library", "Android", "sdk", "build-tools"),
        os.path.join(home, "Android", "Sdk", "build-tools"),
    ])
    for bt_root in candidates:
        if os.path.exists(bt_root):
            versions = sorted(os.listdir(bt_root), reverse=True)
            if versions:
                return os.path.join(bt_root, versions[0])
    return None

def ensure_debug_keystore(keystore_path):
    if os.path.exists(keystore_path):
        return True
    os.makedirs(os.path.dirname(os.path.abspath(keystore_path)), exist_ok=True)
    print(f"[*] Generating fresh debug keystore at {keystore_path}...")
    cmd = [
        "keytool", "-genkeypair", "-v",
        "-keystore", keystore_path,
        "-storepass", "android",
        "-alias", "androiddebugkey",
        "-keypass", "android",
        "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
        "-dname", "CN=Android Debug,O=Android,C=US"
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print("[-] Failed to generate debug keystore via keytool:", res.stderr)
        return False
    print("[+] Debug keystore created!")
    return True

def patch_classes_dex(dex_bytes):
    print("[*] Patching classes.dex (Watchface No-Clock Layout via 0xB0)...")
    data = bytearray(dex_bytes)
    code_off = 5875116 # offset of Lcom/crrepa/f/a2;->a(CRPWatchFaceLayoutInfo;)[B
    
    # Keep 0000..0008 untouched (allocates 52-byte zeroed array v0, sets v0[0] = 0x11, v2 = 0).
    # At 0009 (byte offset +18 in insns):
    #   0009: const/4 v1, -1          (0xFF -> invalid/hidden watchFaceStyle)
    #   000a: const/4 v3, 1
    #   000b: aput-byte v1, v0, v3    (v0[1] = 0xFF; v0[2..19] stay 0x00 = NONE widgets & 0 color)
    #   000d: goto/16 0090            (+0x83 words -> jumps to MD5 copy & c2.a(0xB0, v0))
    #   000f..008f: nop (129 words = 258 bytes)
    # Keep 0090..00b7 untouched (copies 32-byte MD5 into v0[20..51] and calls invoke-static c2.a(-80, v0)).
    patch_bytes = bytearray([
        0x12, 0xf1,              # 0009: const/4 v1, -1 (0xFF)
        0x12, 0x13,              # 000a: const/4 v3, 1
        0x4f, 0x01, 0x00, 0x03,  # 000b: aput-byte v1, v0, v3
        0x29, 0x00, 0x83, 0x00,  # 000d: goto/16 0090 (+0x83)
    ])
    nop_pad = b'\x00' * (129 * 2) # 000f..008f
    replacement = patch_bytes + nop_pad
    assert len(replacement) == (0x90 - 0x09) * 2
    
    insns_start = code_off + 16
    data[insns_start + 0x09 * 2 : insns_start + 0x90 * 2] = replacement
    
    sha1 = hashlib.sha1(data[32:]).digest()
    data[12:32] = sha1
    
    adler = zlib.adler32(data[12:]) & 0xFFFFFFFF
    struct.pack_into('<I', data, 8, adler)
    
    print(f"[+] classes.dex successfully patched! (SHA-1: {sha1.hex()[:10]}..., Adler: {adler:08x})")
    return bytes(data)

def patch_classes3_dex(dex_bytes):
    print("[*] Patching classes3.dex (Facebook SDK Key Hash Bypass)...")
    data = bytearray(dex_bytes)
    code_off = 5043980 # offset of Lcom/facebook/FacebookSdk;->getApplicationSignature(Context)Ljava/lang/String;
    target_bytes = b'UHVvEzDXInBYrb0oGpukqdW1VV4='

    # Total size to next item (at 5044204) is 224 bytes.
    # Header: 16 bytes. Instruction units: (224 - 16) / 2 = 104 words.
    # Setting tries_size = 0 removes catches completely so ART Verifier never rejects try alignment.
    code_units = bytearray()
    code_units += bytes([0x13, 0x02, 0x1c, 0x00]) # 0: const/16 v2, 28 (2 words)
    code_units += bytes([0x23, 0x20, 0xda, 0x29]) # 2: new-array v0, v2, [B (2 words)
    code_units += bytes([0x26, 0x00, 0x0a, 0x00, 0x00, 0x00]) # 4: fill-array-data v0, +10 words (3 words)
    code_units += bytes([0x22, 0x01, 0x2d, 0x28]) # 7: new-instance v1, String (2 words)
    code_units += bytes([0x70, 0x20, 0x11, 0xfa, 0x01, 0x00]) # 9: invoke-direct {v1, v0}, String.<init> (3 words)
    code_units += bytes([0x11, 0x01]) # 12: return-object v1 (1 word)
    code_units += bytes([0x00, 0x00]) # 13: nop (1 word, for 4-byte alignment of payload)
    # 14: payload (18 words = 36 bytes)
    code_units += struct.pack('<HHI', 0x0300, 1, 28)
    code_units += target_bytes
    # Pad to exactly 104 words (208 bytes)
    code_units += b'\x00' * (104 * 2 - len(code_units))
    assert len(code_units) == 104 * 2

    # New header: reg=5, ins=1, outs=2, tries=0, debug=0, insns_size=104
    new_header = struct.pack('<HHHHII', 5, 1, 2, 0, 0, 104)
    data[code_off : code_off + 16] = new_header
    data[code_off + 16 : code_off + 16 + len(code_units)] = code_units

    sha1 = hashlib.sha1(data[32:]).digest()
    data[12:32] = sha1

    adler = zlib.adler32(data[12:]) & 0xFFFFFFFF
    struct.pack_into('<I', data, 8, adler)

    print(f"[+] classes3.dex successfully patched! (SHA-1: {sha1.hex()[:10]}..., Adler: {adler:08x})")
    return bytes(data)

def patch_classes6_dex(dex_bytes, mode="sideload"):
    data = bytearray(dex_bytes)
    off = 0x26099c
    orig_expected = bytes([
        0x6e, 0x10, 0xb0, 0x01, 0x0d, 0x00,  # invoke-virtual {v13}, Context.getFilesDir()
        0x0c, 0x0d,                          # move-result-object v13
        0x6e, 0x10, 0xbc, 0xea, 0x0d, 0x00,  # invoke-virtual {v13}, File.getAbsolutePath()
        0x0c, 0x0d,                          # move-result-object v13
        0x1a, 0x01, 0x5a, 0x9d,              # const-string v1, "ls25plate.bin"
        0x71, 0x30, 0x85, 0xef, 0x1d, 0x0f,  # invoke-static {v13, v1, v15}, Ll6/c;.m(...)
        0x0c, 0x0d,                          # move-result-object v13
    ])
    assert data[off:off+28] == orig_expected, f"Unexpected bytes at 0x{off:x}: {data[off:off+28].hex()}"

    if mode == "capture":
        print("[*] Patching classes6.dex (CAPTURE mode: save downloaded cloud .bin to external cache dir)...")
        data[off + 2] = 0xad  # getFilesDir() -> getExternalCacheDir()
    else:
        print("[*] Patching classes6.dex (SIDELOAD mode: send custom ls25plate.bin from external cache dir)...")
        replacement = bytes([
            0x6e, 0x10, 0xad, 0x01, 0x0d, 0x00,  # invoke-virtual {v13}, Context.getExternalCacheDir()
            0x0c, 0x0d,                          # move-result-object v13
            0x1a, 0x01, 0x5a, 0x9d,              # const-string v1, "ls25plate.bin"
            0x22, 0x02, 0xdd, 0x2f,              # new-instance v2, Ljava/io/File; (type 0x2fdd)
            0x70, 0x30, 0xb3, 0xea, 0xd2, 0x01,  # invoke-direct {v2, v13, v1}, File.<init>(File, String)V
            0x07, 0x2d,                          # move-object v13, v2
            0x00, 0x00,                          # nop
            0x00, 0x00,                          # nop
        ])
        assert len(replacement) == 28
        data[off:off+28] = replacement

    sha1 = hashlib.sha1(data[32:]).digest()
    data[12:32] = sha1

    adler = zlib.adler32(data[12:]) & 0xFFFFFFFF
    struct.pack_into('<I', data, 8, adler)

    print(f"[+] classes6.dex successfully patched ({mode})! (SHA-1: {sha1.hex()[:10]}..., Adler: {adler:08x})")
    return bytes(data)

def build_modded_apk(src_apk, out_apk, keystore_path, build_tools_dir, mode="sideload"):
    if not os.path.exists(src_apk):
        print(f"[-] Source APK not found: {src_apk}")
        print("    Download the official Haylou Fun v4.0.8 APK and pass --src <path/to/haylou-fun-v4-0-8.apk>")
        sys.exit(1)
        
    if not ensure_debug_keystore(keystore_path):
        print(f"[-] Keystore not found and could not be generated: {keystore_path}")
        sys.exit(1)

    zipalign_bin = os.path.join(build_tools_dir, "zipalign.exe" if os.name == "nt" else "zipalign")
    apksigner_bin = os.path.join(build_tools_dir, "apksigner.bat" if os.name == "nt" else "apksigner")

    if not os.path.exists(zipalign_bin) or not os.path.exists(apksigner_bin):
        print(f"[-] Missing zipalign or apksigner in {build_tools_dir}")
        sys.exit(1)

    unaligned_apk = out_apk + ".unaligned"
    if os.path.exists(unaligned_apk):
        os.remove(unaligned_apk)

    print(f"[*] Reading source APK: {src_apk}")
    with zipfile.ZipFile(src_apk, 'r') as src_zip:
        dex1_patched = patch_classes_dex(src_zip.read('classes.dex'))
        dex3_patched = patch_classes3_dex(src_zip.read('classes3.dex'))
        dex6_patched = patch_classes6_dex(src_zip.read('classes6.dex'), mode=mode)
        
        print(f"[*] Repackaging into unaligned APK: {unaligned_apk}...")
        with zipfile.ZipFile(unaligned_apk, 'w') as dst_zip:
            total = len(src_zip.infolist())
            for idx, item in enumerate(src_zip.infolist()):
                if item.filename.startswith('META-INF/') and any(item.filename.endswith(ext) for ext in ['.SF', '.RSA', '.DSA', '.MF']):
                    continue
                
                zinfo = zipfile.ZipInfo(filename=item.filename, date_time=item.date_time)
                if item.filename == 'resources.arsc' or item.compress_type == zipfile.ZIP_STORED:
                    zinfo.compress_type = zipfile.ZIP_STORED
                else:
                    zinfo.compress_type = zipfile.ZIP_DEFLATED
                
                if item.filename == 'classes.dex':
                    dst_zip.writestr(zinfo, dex1_patched)
                elif item.filename == 'classes3.dex':
                    dst_zip.writestr(zinfo, dex3_patched)
                elif item.filename == 'classes6.dex':
                    dst_zip.writestr(zinfo, dex6_patched)
                else:
                    dst_zip.writestr(zinfo, src_zip.read(item.filename))
                    
                if (idx + 1) % 1000 == 0 or idx == total - 1:
                    print(f"    [{idx+1}/{total}] files packed...")

    # Run zipalign -p -f 4
    print("[*] Running zipalign (4-byte alignment with page-alignment for .so)...")
    if os.path.exists(out_apk):
        os.remove(out_apk)
        
    zres = subprocess.run([zipalign_bin, "-p", "-f", "4", unaligned_apk, out_apk], capture_output=True, text=True)
    if zres.returncode != 0:
        print("[-] zipalign error:", zres.stderr)
        sys.exit(1)
    print("[+] zipalign completed successfully!")
    
    # Run apksigner with v2/v3 signing
    print("[*] Running apksigner (v1, v2, v3 schemes)...")
    prefix = ["cmd.exe", "/c"] if os.name == "nt" else []
    apksigner_cmd = prefix + [
        apksigner_bin, "sign",
        "--ks", keystore_path,
        "--ks-pass", "pass:android",
        "--ks-key-alias", "androiddebugkey",
        "--key-pass", "pass:android",
        out_apk
    ]
    sres = subprocess.run(apksigner_cmd, capture_output=True, text=True)
    if sres.returncode != 0:
        print("[-] apksigner error:", sres.stderr, sres.stdout)
        sys.exit(1)
    print("[+] apksigner signed successfully!")
    
    # Cleanup unaligned APK
    if os.path.exists(unaligned_apk):
        os.remove(unaligned_apk)
        
    size_mb = os.path.getsize(out_apk) / (1024 * 1024)
    print(f"\n[SUCCESS] Modded APK generated: {out_apk} ({size_mb:.2f} MB)")
    return out_apk

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Build modded Haylou Fun APK for Haylou Watch 4S")
    parser.add_argument("--src", default=DEFAULT_SRC_APK, help="Path to original Haylou Fun APK")
    parser.add_argument("--out", default=DEFAULT_OUT_APK, help="Path for generated modded APK")
    parser.add_argument("--keystore", default=DEFAULT_KEYSTORE, help="Path to signing keystore")
    parser.add_argument("--build-tools", default=find_build_tools(), help="Path to Android SDK build-tools directory")
    parser.add_argument("--mode", choices=["sideload", "capture"], default="sideload", help="sideload (default) or capture")
    args = parser.parse_args()

    if not args.build_tools:
        print("[-] Android SDK build-tools directory not found. Please specify with --build-tools")
        sys.exit(1)

    build_modded_apk(args.src, args.out, args.keystore, args.build_tools, mode=args.mode)
