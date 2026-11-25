"""
Haylou Watch 4S (LS26) — Zero-Dependency Pure-Python Haylou Fun v4.0.8 APK Patcher & Signer

No Java, no keytool, no Android SDK build-tools (`zipalign` / `apksigner`) required!
Uses pure-Python DEX patching + 4-byte / 4096-byte APK alignment + APK Signature Scheme v2 & v3 signing.

Modular patch flags (default: --all):
  --noclock       1) classes.dex: Suppress photo-dial clock overlay (0xB0)
                  2) classes3.dex: Bypass Facebook SDK release signature hash
                  3) classes6.dex: Sideload (or capture) custom ls25plate.bin from external cache dir
  --unlock-cards  classes7.dex: Unlock Watch 4S hidden WatchConfig features
                  (PAI/Vitality, VO2 Max, HRV, Quick SMS Reply, WhatsApp Quick Reply)
  --rhr           classes7.dex: Add 3rd "Resting heart rate" StatCard to Heart Rate Details
                  (Day tab + Week/Month/Year tabs, computed from lowest quiet HR window)
  --vitality-vo2  classes6.dex: Computed Vitality Score (PAI) + VO2 Max engines
                  (backfills up to 30 days on Home launch + live update on every BLE HR sync)
  --night-raise-to-wake
                  classes3/6/7.dex: Unhide Device Settings -> Do Not Disturb schedule UI
                  and wire it exclusively to Watch 4S Raise-to-Wake schedule (BLE 0x72),
                  defaulting to 23:00-07:00 off (07:00-23:00 active) while keeping calls &
                  notifications active at night.
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
import zipfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from apk_signer import repack_align_and_sign_apk, verify_apk_signatures
from dex_patcher_lib import (
    DalvikAssembler,
    DexFile,
    encode_uleb128_4bytes,
    recompute_dex_checksums,
)

DEFAULT_SRC_APK = os.path.join(os.path.expanduser("~"), "Downloads", "haylou-fun-v4-0-8.apk")
DEFAULT_OUT_FULL = os.path.join(PROJECT_DIR, "haylou-fun-v4-0-8-full-health.apk")
DEFAULT_OUT_NOCLOCK = os.path.join(PROJECT_DIR, "haylou-fun-v4-0-8-noclock.apk")
DEFAULT_KEYSTORE = os.path.join(PROJECT_DIR, "keystore", "debug.keystore")

WATCHCONFIG_UNLOCK_METHODS = (
    ("Vitality/PAI", "Lcom/yingsheng/protocol/config/WatchConfig;->isSupportPai()Z"),
    ("VO2 Max", "Lcom/yingsheng/protocol/config/WatchConfig;->isSupportVo2Max()Z"),
    ("HRV", "Lcom/yingsheng/protocol/config/WatchConfig;->isSupportHrv()Z"),
    ("Quick SMS Reply", "Lcom/yingsheng/protocol/config/WatchConfig;->isSupportQuickReplyMsg()Z"),
    ("WhatsApp Quick Reply", "Lcom/yingsheng/protocol/config/WatchConfig;->isSupportWhatsAppQuickReplyMsg()Z"),
)


# --------------------------------------------------------------------------- #
# 1. classes.dex — Watchface No-Clock Layout (0xB0)
# --------------------------------------------------------------------------- #

def patch_classes_dex_noclock(dex_bytes: bytes) -> bytes:
    print("[*] Patching classes.dex (Watchface No-Clock Layout via 0xB0)...")
    data = bytearray(dex_bytes)
    code_off = 5875116  # Lcom/crrepa/f/a2;->a(CRPWatchFaceLayoutInfo;)[B
    patch_bytes = bytearray([
        0x12, 0xF1,              # 0009: const/4 v1, -1 (0xFF = hidden watchFaceStyle)
        0x12, 0x13,              # 000a: const/4 v3, 1
        0x4F, 0x01, 0x00, 0x03,  # 000b: aput-byte v1, v0, v3
        0x29, 0x00, 0x83, 0x00,  # 000d: goto/16 0090 (+0x83)
    ])
    replacement = bytes(patch_bytes) + (b"\x00" * (129 * 2))
    assert len(replacement) == (0x90 - 0x09) * 2

    insns_start = code_off + 16
    if bytes(data[insns_start + 0x09 * 2 : insns_start + 0x90 * 2]) == replacement:
        print("    [skip] Already patched.")
        return bytes(data)

    data[insns_start + 0x09 * 2 : insns_start + 0x90 * 2] = replacement
    out = recompute_dex_checksums(data)
    print(f"[+] classes.dex patched (Adler: {struct.unpack_from('<I', out, 8)[0]:08x})")
    return out


# --------------------------------------------------------------------------- #
# 2. classes3.dex — Facebook SDK Release Signature Hash Bypass
# --------------------------------------------------------------------------- #

def patch_classes3_dex_fb_bypass(dex_bytes: bytes) -> bytes:
    print("[*] Patching classes3.dex (Facebook SDK Key Hash Bypass)...")
    data = bytearray(dex_bytes)
    code_off = 5043980  # Lcom/facebook/FacebookSdk;->getApplicationSignature(Context)Ljava/lang/String;
    target_bytes = b"UHVvEzDXInBYrb0oGpukqdW1VV4="

    code_units = bytearray()
    code_units += bytes([0x13, 0x02, 0x1C, 0x00])              # const/16 v2, 28
    code_units += bytes([0x23, 0x20, 0xDA, 0x29])              # new-array v0, v2, [B
    code_units += bytes([0x26, 0x00, 0x0A, 0x00, 0x00, 0x00])  # fill-array-data v0, +10
    code_units += bytes([0x22, 0x01, 0x2D, 0x28])              # new-instance v1, String
    code_units += bytes([0x70, 0x20, 0x11, 0xFA, 0x01, 0x00])  # invoke-direct {v1, v0}, String.<init>([B)V
    code_units += bytes([0x11, 0x01])                          # return-object v1
    code_units += bytes([0x00, 0x00])                          # nop (4-byte align payload)
    code_units += struct.pack("<HHI", 0x0300, 1, 28)
    code_units += target_bytes
    code_units += b"\x00" * (104 * 2 - len(code_units))
    assert len(code_units) == 104 * 2

    new_header = struct.pack("<HHHHII", 5, 1, 2, 0, 0, 104)
    if (
        bytes(data[code_off : code_off + 16]) == new_header
        and bytes(data[code_off + 16 : code_off + 16 + len(code_units)]) == bytes(code_units)
    ):
        print("    [skip] Already patched.")
        return bytes(data)

    data[code_off : code_off + 16] = new_header
    data[code_off + 16 : code_off + 16 + len(code_units)] = code_units
    out = recompute_dex_checksums(data)
    print(f"[+] classes3.dex patched (Adler: {struct.unpack_from('<I', out, 8)[0]:08x})")
    return out


def patch_classes3_night_quickview(dex_bytes: bytes) -> bytes:
    """
    Hook Lcom/crrepa/h/a;->sendCurrentVolume(I)V in classes3.dex so magic ints
    with bit 30 set (0x40000000 | (sH<<18) | (sM<<12) | (eH<<6) | eM) dispatch
    directly to sendQuickViewTime(new CRPPeriodTimeInfo(sH, sM, eH, eM)) (BLE 0x72).
    Normal volume calls (0..100) execute untouched.
    """
    print("[*] Patching classes3.dex (BLE 0x72 sendQuickViewTime dispatcher)...")
    d3 = DexFile(dex_bytes)
    buf = bytearray(dex_bytes)

    m_scv = d3.find_method_info(
        "Lcom/crrepa/h/a;",
        "Lcom/crrepa/h/a;->sendCurrentVolume(I)V",
    )
    m_host = d3.find_method_info(
        "Landroidx/core/graphics/BitmapCompat;",
        "Landroidx/core/graphics/BitmapCompat;->createScaledBitmap(Landroid/graphics/Bitmap;IILandroid/graphics/Rect;Z)Landroid/graphics/Bitmap;",
    )

    T_PERIOD = d3.find_idx("type", "Lcom/crrepa/ble/conn/bean/CRPPeriodTimeInfo;")
    M_PERIOD_INIT = d3.find_idx("method", "Lcom/crrepa/ble/conn/bean/CRPPeriodTimeInfo;-><init>(IIII)V")
    M_SEND_QV_TIME = d3.find_idx("method", "Lcom/crrepa/h/a;->sendQuickViewTime(Lcom/crrepa/ble/conn/bean/CRPPeriodTimeInfo;)V")
    M_Z1_A = d3.find_idx("method", "Lcom/crrepa/f/z1;->a(I)[B")
    M_MF_H = d3.find_idx("method", "Lcom/crrepa/m/f;->h([B)V")
    F_HA_B = d3.find_idx("field", "Lcom/crrepa/h/a;->b:Lcom/crrepa/m/f;")

    def _build_insns(pad_words: int) -> bytes:
        # regs=8, ins=2, outs=5 -> p0=v6 (this), p1=v7 (int arg)
        a = DalvikAssembler()
        a.const_high16(0, 0x4000)  # 0x40000000 magic bit
        a.and_int_2addr(0, 7)
        a.if_eqz(0, "normal_vol")

        a.ushr_int_lit8(1, 7, 18)
        a.and_int_lit8(1, 1, 0x3F)  # startHour
        a.ushr_int_lit8(2, 7, 12)
        a.and_int_lit8(2, 2, 0x3F)  # startMinute
        a.ushr_int_lit8(3, 7, 6)
        a.and_int_lit8(3, 3, 0x3F)  # endHour
        a.and_int_lit8(4, 7, 0x3F)  # endMinute

        a.new_instance(0, T_PERIOD)
        a.invoke_direct([0, 1, 2, 3, 4], M_PERIOD_INIT)
        a.invoke_virtual([6, 0], M_SEND_QV_TIME)
        a.return_void()

        a.label("normal_vol")
        a.invoke_static([7], M_Z1_A)
        a.move_result_object(0)
        a.iget_object(1, 6, F_HA_B)
        a.invoke_virtual([1, 0], M_MF_H)
        a.return_void()
        return a.assemble(pad_to_words=pad_words)

    if m_scv["insns_size"] >= 100:
        insns = _build_insns(m_scv["insns_size"])
        struct.pack_into("<4H2I", buf, m_scv["code_off"], 8, 2, 5, 0, 0, m_scv["insns_size"])
        buf[m_scv["code_off"] + 16 : m_scv["code_off"] + 16 + len(insns)] = insns
        out = recompute_dex_checksums(buf)
        print("    [refresh] Updated classes3.dex 0x72 dispatcher in-place.")
        return out

    assert m_scv["code_pos_len"] == 4 and m_host["code_pos_len"] == 4
    insns = _build_insns(m_host["insns_size"])
    struct.pack_into("<4H2I", buf, m_host["code_off"], 8, 2, 5, 0, 0, m_host["insns_size"])
    buf[m_host["code_off"] + 16 : m_host["code_off"] + 16 + len(insns)] = insns

    stub = DalvikAssembler()
    stub.const4(0, 0)
    stub.return_object(0)
    stub_bytes = stub.assemble(pad_to_words=m_scv["insns_size"])
    struct.pack_into("<4H2I", buf, m_scv["code_off"], m_host["ins_size"] + 1, m_host["ins_size"], 0, 0, 0, m_scv["insns_size"])
    buf[m_scv["code_off"] + 16 : m_scv["code_off"] + 16 + len(stub_bytes)] = stub_bytes

    buf[m_scv["code_pos"] : m_scv["code_pos"] + 4] = encode_uleb128_4bytes(m_host["code_off"])
    buf[m_host["code_pos"] : m_host["code_pos"] + 4] = encode_uleb128_4bytes(m_scv["code_off"])

    out = recompute_dex_checksums(buf)
    print(f"[+] classes3.dex 0x72 dispatcher patched (Adler: {struct.unpack_from('<I', out, 8)[0]:08x})")
    return out


# --------------------------------------------------------------------------- #
# 3. classes6.dex — Watchface Sideload / Capture + PAI & VO2 Max Engines
# --------------------------------------------------------------------------- #

def patch_classes6_sideload(dex_bytes: bytes, mode: str = "sideload") -> bytes:
    data = bytearray(dex_bytes)
    off = 0x26099C
    orig_expected = bytes([
        0x6E, 0x10, 0xB0, 0x01, 0x0D, 0x00,  # invoke-virtual {v13}, Context.getFilesDir()
        0x0C, 0x0D,                          # move-result-object v13
        0x6E, 0x10, 0xBC, 0xEA, 0x0D, 0x00,  # invoke-virtual {v13}, File.getAbsolutePath()
        0x0C, 0x0D,                          # move-result-object v13
        0x1A, 0x01, 0x5A, 0x9D,              # const-string v1, "ls25plate.bin"
        0x71, 0x30, 0x85, 0xEF, 0x1D, 0x0F,  # invoke-static {v13, v1, v15}, Ll6/c;.m(...)
        0x0C, 0x0D,                          # move-result-object v13
    ])
    sideload_bytes = bytes([
        0x6E, 0x10, 0xAD, 0x01, 0x0D, 0x00,  # Context.getExternalCacheDir()
        0x0C, 0x0D,
        0x1A, 0x01, 0x5A, 0x9D,              # const-string v1, "ls25plate.bin"
        0x22, 0x02, 0xDD, 0x2F,              # new-instance v2, Ljava/io/File;
        0x70, 0x30, 0xB3, 0xEA, 0xD2, 0x01,  # File.<init>(File, String)V
        0x07, 0x2D,                          # move-object v13, v2
        0x00, 0x00, 0x00, 0x00,
    ])
    capture_bytes = bytearray(orig_expected)
    capture_bytes[2] = 0xAD  # getFilesDir() -> getExternalCacheDir()
    capture_bytes = bytes(capture_bytes)

    cur = bytes(data[off : off + 28])
    target = capture_bytes if mode == "capture" else sideload_bytes
    if cur == target:
        print(f"[*] classes6.dex watchface path ({mode}): already patched [skip].")
        return bytes(data)

    if cur not in (orig_expected, sideload_bytes, capture_bytes):
        raise RuntimeError(f"Unexpected bytes at classes6.dex 0x{off:x}: {cur.hex()}")

    print(f"[*] Patching classes6.dex (watchface {mode.upper()} mode for ls25plate.bin)...")
    data[off : off + 28] = target
    out = recompute_dex_checksums(data)
    print(f"[+] classes6.dex watchface patch applied (Adler: {struct.unpack_from('<I', out, 8)[0]:08x})")
    return out


def _build_pai_vo2_engine_insns(d6: DexFile, pad_words: int) -> bytes:
    STR_EMPTY = d6.find_idx("string", "")

    T_ARRAYLIST = d6.find_idx("type", "Ljava/util/ArrayList;")
    T_DATE = d6.find_idx("type", "Ljava/util/Date;")
    T_HR_TABLE = d6.find_idx("type", "Lcom/liesheng/lib_room/table/HeartRateDataTable;")
    T_USER_TABLE = d6.find_idx("type", "Lcom/liesheng/lib_room/table/UserInfoTable;")
    T_SPORT_TABLE = d6.find_idx("type", "Lcom/liesheng/lib_room/table/SportTable;")
    T_PAI_TABLE = d6.find_idx("type", "Lcom/liesheng/lib_room/table/VitalityIndexTable;")
    T_PAI_ITEM = d6.find_idx("type", "Lcom/liesheng/lib_room/table/PaiItem;")
    T_VO2_TABLE = d6.find_idx("type", "Lcom/liesheng/lib_room/table/Vo2MaxTable;")

    F_APPDB_COMP = d6.find_idx("field", "Lcom/liesheng/AppDatabase;->a:Lcom/liesheng/AppDatabase$a;")

    M_APPDB_GET = d6.find_idx("method", "Lcom/liesheng/AppDatabase$a;->b()Lcom/liesheng/AppDatabase;")
    M_DB_HR = d6.find_idx("method", "Lcom/liesheng/AppDatabase;->l()Lcom/liesheng/lib_room/dao/HeartRateDataDao;")
    M_DB_SPORT = d6.find_idx("method", "Lcom/liesheng/AppDatabase;->u()Lcom/liesheng/lib_room/dao/SportDao;")
    M_DB_USER = d6.find_idx("method", "Lcom/liesheng/AppDatabase;->y()Lcom/liesheng/lib_room/dao/UserInfoDao;")
    M_DB_PAI = d6.find_idx("method", "Lcom/liesheng/AppDatabase;->z()Lcom/liesheng/lib_room/dao/VitalityIndexDao;")
    M_DB_VO2 = d6.find_idx("method", "Lcom/liesheng/AppDatabase;->A()Lcom/liesheng/lib_room/dao/Vo2MaxDao;")

    M_USER_ALL = d6.find_idx("method", "Lcom/liesheng/lib_room/dao/UserInfoDao;->getAllUserInfo()Ljava/util/List;")
    M_USER_AGE = d6.find_idx("method", "Lcom/liesheng/lib_room/table/UserInfoTable;->getAge()I")

    M_HR_ALL = d6.find_idx("method", "Lcom/liesheng/lib_room/dao/HeartRateDataDao;->getAllOrderDesc()Ljava/util/List;")
    M_HR_DATE = d6.find_idx("method", "Lcom/liesheng/lib_room/table/HeartRateDataTable;->getRecordDate()Ljava/util/Date;")
    M_HR_ITEMS = d6.find_idx("method", "Lcom/liesheng/lib_room/table/HeartRateDataTable;->getItems()[I")
    M_HR_MIN = d6.find_idx("method", "Lcom/liesheng/lib_room/table/HeartRateDataTable;->getMinHeartRate()I")
    M_HR_AVG = d6.find_idx("method", "Lcom/liesheng/lib_room/table/HeartRateDataTable;->getAverageHeartRate()I")
    M_HR_ADDR = d6.find_idx("method", "Lcom/liesheng/lib_room/table/HeartRateDataTable;->getBleAddress()Ljava/lang/String;")

    M_SPORT_DATE = d6.find_idx("method", "Lcom/liesheng/lib_room/dao/SportDao;->getSportDataByDate(JJ)Ljava/util/List;")
    M_SPORT_DUR = d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getDuration()I")
    M_SPORT_HR = d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getAvrHeartRate()I")
    M_SPORT_DIST = d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getDistance()F")

    M_PAI_DEL_ALL = d6.find_idx("method", "Lcom/liesheng/lib_room/dao/VitalityIndexDao;->deleteAllData()V")
    M_PAI_BY_DATE = d6.find_idx("method", "Lcom/liesheng/lib_room/dao/VitalityIndexDao;->getDataByDate(J)Lcom/liesheng/lib_room/table/VitalityIndexTable;")
    M_PAI_INSERT = d6.find_idx("method", "Lcom/liesheng/lib_room/dao/VitalityIndexDao;->insert(Lcom/liesheng/lib_room/table/VitalityIndexTable;)V")
    M_PAI_INIT = d6.find_idx("method", "Lcom/liesheng/lib_room/table/VitalityIndexTable;-><init>(Ljava/util/Date;Ljava/lang/String;JIIILjava/util/List;)V")
    M_PAI_ITEM_INIT = d6.find_idx("method", "Lcom/liesheng/lib_room/table/PaiItem;-><init>(JIII)V")

    M_VO2_DEL_ALL = d6.find_idx("method", "Lcom/liesheng/lib_room/dao/Vo2MaxDao;->deleteAllData()V")
    M_VO2_BY_DATE = d6.find_idx("method", "Lcom/liesheng/lib_room/dao/Vo2MaxDao;->getDataByDate(J)Lcom/liesheng/lib_room/table/Vo2MaxTable;")
    M_VO2_INSERT = d6.find_idx("method", "Lcom/liesheng/lib_room/dao/Vo2MaxDao;->insert(Lcom/liesheng/lib_room/table/Vo2MaxTable;)V")
    M_VO2_DESC = d6.find_idx("method", "Lcom/liesheng/lib_room/dao/Vo2MaxDao;->getDataOrderDesc(I)Ljava/util/List;")
    M_VO2_INIT = d6.find_idx("method", "Lcom/liesheng/lib_room/table/Vo2MaxTable;-><init>(Ljava/util/Date;II)V")

    M_KTX_TO_LOCAL = d6.find_idx("method", "Lcom/liesheng/lib_common/ktx/c;->b(J)J")
    M_REPO_D_B = d6.find_idx("method", "Lcom/liesheng/module_home/repository/d;->b(Ljava/util/List;)Ljava/util/List;")

    M_LIST_SIZE = d6.find_idx("method", "Ljava/util/List;->size()I")
    M_LIST_GET = d6.find_idx("method", "Ljava/util/List;->get(I)Ljava/lang/Object;")
    M_LIST_EMPTY = d6.find_idx("method", "Ljava/util/List;->isEmpty()Z")
    M_AL_INIT = d6.find_idx("method", "Ljava/util/ArrayList;-><init>()V")
    M_AL_ADD = d6.find_idx("method", "Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z")
    M_DATE_INIT_J = d6.find_idx("method", "Ljava/util/Date;-><init>(J)V")
    M_DATE_TIME = d6.find_idx("method", "Ljava/util/Date;->getTime()J")
    M_SYS_TIME = d6.find_idx("method", "Ljava/lang/System;->currentTimeMillis()J")

    a = DalvikAssembler()

    # 1. Obtain AppDatabase & DAOs
    a.sget_object(0, F_APPDB_COMP)
    a.invoke_virtual([0], M_APPDB_GET)
    a.move_result_object(0)
    a.move_object(16, 0)

    a.invoke_virtual([0], M_DB_PAI)
    a.move_result_object(1)
    a.move_object(17, 1)

    a.invoke_virtual([0], M_DB_VO2)
    a.move_result_object(1)
    a.move_object(18, 1)

    a.invoke_virtual([0], M_DB_SPORT)
    a.move_result_object(1)
    a.move_object(19, 1)

    # 2. User maxHr = 220 - age (fallback age=30)
    a.const16(1, 30)
    a.invoke_virtual([0], M_DB_USER)
    a.move_result_object(2)
    a.invoke_interface([2], M_USER_ALL)
    a.move_result_object(2)
    a.if_eqz(2, "age_ready")
    a.invoke_interface([2], M_LIST_SIZE)
    a.move_result(3)
    a.if_lez(3, "age_ready")
    a.const4(3, 0)
    a.invoke_interface([2, 3], M_LIST_GET)
    a.move_result_object(2)
    a.check_cast(2, T_USER_TABLE)
    a.invoke_virtual([2], M_USER_AGE)
    a.move_result(3)
    a.const16(4, 10)
    a.if_lt(3, 4, "age_ready")
    a.const16(4, 90)
    a.if_gt(3, 4, "age_ready")
    a.move(1, 3)

    a.label("age_ready")
    a.rsub_int_lit16(1, 1, 220)
    a.move(20, 1)

    # 3. Fetch up to 30 most recent HR days
    a.invoke_virtual([0], M_DB_HR)
    a.move_result_object(1)
    a.invoke_interface([1], M_HR_ALL)
    a.move_result_object(1)
    a.if_eqz(1, "orig_epilogue")
    a.move_object(21, 1)
    a.invoke_interface([1], M_LIST_SIZE)
    a.move_result(2)
    a.if_lez(2, "orig_epilogue")
    a.const16(3, 30)
    a.if_le(2, 3, "days_ok")
    a.move(2, 3)
    a.label("days_ok")
    a.move(22, 2)
    a.const4(0, 0)
    a.move(23, 0)

    # 4. Per-day computation loop
    a.label("day_loop")
    a.move(0, 23)
    a.move(1, 22)
    a.if_ge(0, 1, "orig_epilogue")

    a.move_object(2, 21)
    a.invoke_interface([2, 0], M_LIST_GET)
    a.move_result_object(2)
    a.check_cast(2, T_HR_TABLE)
    a.move_object(24, 2)

    a.invoke_virtual([2], M_HR_DATE)
    a.move_result_object(3)
    a.if_eqz(3, "day_next")
    a.invoke_virtual([3], M_DATE_TIME)
    a.move_result_wide(4)
    a.move_wide(25, 4)      # Asia/Shanghai midnight (PAI key)
    a.invoke_static([4, 5], M_KTX_TO_LOCAL)
    a.move_result_wide(14)  # Local midnight (VO2 Max & SportDao key)

    a.if_nez(0, "chk_hist_skip")
    a.move_object(3, 18)
    a.move_wide(4, 14)
    a.invoke_interface([3, 4, 5], M_VO2_BY_DATE)
    a.move_result_object(3)
    a.if_nez(3, "compute_day")
    a.move_object(3, 18)
    a.invoke_interface([3], M_VO2_DEL_ALL)
    a.move_object(3, 17)
    a.invoke_interface([3], M_PAI_DEL_ALL)
    a.goto16("compute_day")

    a.label("chk_hist_skip")
    a.const4(1, 1)
    a.if_le(0, 1, "compute_day")
    a.move_object(3, 17)
    a.invoke_interface([3, 4, 5], M_PAI_BY_DATE)
    a.move_result_object(3)
    a.if_eqz(3, "compute_day")
    a.move_object(3, 18)
    a.move_wide(4, 14)
    a.invoke_interface([3, 4, 5], M_VO2_BY_DATE)
    a.move_result_object(3)
    a.if_nez(3, "day_next")

    a.label("compute_day")
    a.move_object(13, 24)
    a.invoke_virtual([13], M_HR_MIN)
    a.move_result(1)
    a.invoke_virtual([13], M_HR_AVG)
    a.move_result(2)
    a.invoke_virtual([13], M_HR_ITEMS)
    a.move_result_object(13)

    a.if_gtz(1, "has_hr_data")
    a.if_eqz(13, "day_next")
    a.array_length(0, 13)
    a.if_lez(0, "day_next")

    a.label("has_hr_data")
    # RHR = min 5-sample sliding average in [38..130] BPM
    a.const16(3, 9999)
    a.if_eqz(13, "rhr_fallback")
    a.array_length(4, 13)
    a.const4(5, 5)
    a.if_lt(4, 5, "rhr_fallback")

    a.const4(5, 0)
    a.const4(6, 0)
    a.const4(7, 0)
    a.label("rhr_scan")
    a.if_ge(5, 4, "rhr_scan_done")
    a.aget(0, 13, 5)
    a.const16(8, 38)
    a.if_lt(0, 8, "rhr_reset")
    a.const16(8, 130)
    a.if_gt(0, 8, "rhr_reset")
    a.add_int_2addr(6, 0)
    a.add_int_lit8(7, 7, 1)
    a.const4(8, 5)
    a.if_lt(7, 8, "rhr_next")
    a.if_eq(7, 8, "rhr_check_best")
    a.add_int_lit8(8, 5, -5)
    a.aget(8, 13, 8)
    a.sub_int_2addr(6, 8)
    a.const4(7, 5)
    a.label("rhr_check_best")
    a.if_ge(6, 3, "rhr_next")
    a.move(3, 6)
    a.goto16("rhr_next")
    a.label("rhr_reset")
    a.const4(6, 0)
    a.const4(7, 0)
    a.label("rhr_next")
    a.add_int_lit8(5, 5, 1)
    a.goto16("rhr_scan")

    a.label("rhr_scan_done")
    a.const16(8, 9999)
    a.if_ge(3, 8, "rhr_fallback")
    a.add_int_lit8(3, 3, 2)
    a.div_int_lit8(3, 3, 5)
    a.goto16("rhr_clamp")

    a.label("rhr_fallback")
    a.if_lez(1, "rhr_default")
    a.move(3, 1)
    a.if_le(2, 1, "rhr_clamp")
    a.mul_int_lit8(3, 1, 2)
    a.add_int_2addr(3, 2)
    a.add_int_lit8(3, 3, 1)
    a.div_int_lit8(3, 3, 3)
    a.goto16("rhr_clamp")

    a.label("rhr_default")
    a.const16(3, 68)

    a.label("rhr_clamp")
    a.const16(0, 42)
    a.if_ge(3, 0, "rhr_hi_chk")
    a.move(3, 0)
    a.label("rhr_hi_chk")
    a.const16(0, 105)
    a.if_le(3, 0, "rhr_done")
    a.move(3, 0)

    a.label("rhr_done")
    a.move(27, 3)

    a.move(12, 20)
    a.sub_int_2addr(12, 3)
    a.const16(0, 50)
    a.if_ge(12, 0, "hrr_ok")
    a.move(12, 0)
    a.label("hrr_ok")

    # PAI Karvonen HRR zones (Low >= 18%, Mod >= 38%, High >= 60%)
    a.const4(8, 0)
    a.const4(9, 0)
    a.const4(10, 0)
    a.const4(11, 0)
    a.if_eqz(13, "sport_phase")
    a.array_length(4, 13)
    a.if_lez(4, "sport_phase")

    a.const4(6, 5)
    a.const16(0, 720)
    a.if_lt(4, 0, "pai_scan_init")
    a.const4(6, 1)
    a.label("pai_scan_init")
    a.const4(5, 0)
    a.label("pai_scan")
    a.if_ge(5, 4, "sport_phase")
    a.aget(0, 13, 5)
    a.const16(7, 40)
    a.if_lt(0, 7, "pai_scan_next")
    a.const16(7, 220)
    a.if_gt(0, 7, "pai_scan_next")
    a.sub_int_2addr(0, 3)
    a.if_lez(0, "pai_scan_next")
    a.mul_int_lit8(0, 0, 100)
    a.div_int_2addr(0, 12)
    a.const16(7, 60)
    a.if_lt(0, 7, "pai_chk_med")
    a.add_int_2addr(11, 6)
    a.goto16("pai_scan_next")
    a.label("pai_chk_med")
    a.const16(7, 38)
    a.if_lt(0, 7, "pai_chk_low")
    a.add_int_2addr(10, 6)
    a.goto16("pai_scan_next")
    a.label("pai_chk_low")
    a.const16(7, 18)
    a.if_lt(0, 7, "pai_scan_next")
    a.add_int_2addr(9, 6)
    a.label("pai_scan_next")
    a.add_int_lit8(5, 5, 1)
    a.goto16("pai_scan")

    # SportTable workouts refinement
    a.label("sport_phase")
    a.move_object(0, 19)
    a.move_wide(1, 14)
    a.const_wide32(3, 86400000)
    a.add_long_2addr(3, 1)
    a.invoke_interface([0, 1, 2, 3, 4], M_SPORT_DATE)
    a.move_result_object(13)
    a.if_eqz(13, "vo2_compute")
    a.invoke_interface([13], M_LIST_SIZE)
    a.move_result(4)
    a.if_lez(4, "vo2_compute")

    a.const4(5, 0)
    a.label("sport_loop")
    a.if_ge(5, 4, "vo2_compute")
    a.invoke_interface([13, 5], M_LIST_GET)
    a.move_result_object(0)
    a.check_cast(0, T_SPORT_TABLE)
    a.invoke_virtual([0], M_SPORT_DUR)
    a.move_result(1)
    a.invoke_virtual([0], M_SPORT_HR)
    a.move_result(2)
    a.invoke_virtual([0], M_SPORT_DIST)
    a.move_result(6)
    a.float_to_int(6, 6)

    a.move(3, 27)
    a.const16(7, 120)
    a.if_lt(1, 7, "sport_next")

    a.div_int_lit8(0, 1, 60)
    a.if_gt(2, 3, "sp_has_hr")
    a.const16(7, 1500)
    a.if_lt(6, 7, "sp_nohr_low")
    a.add_int_2addr(10, 0)
    a.goto16("sport_next")
    a.label("sp_nohr_low")
    a.add_int_2addr(9, 0)
    a.goto16("sport_next")

    a.label("sp_has_hr")
    a.move(7, 2)
    a.sub_int_2addr(7, 3)
    a.mul_int_lit8(7, 7, 100)
    a.div_int_2addr(7, 12)

    a.const16(2, 60)
    a.if_lt(7, 2, "sp_pai_med")
    a.add_int_2addr(11, 0)
    a.goto16("sp_vo2_chk")
    a.label("sp_pai_med")
    a.const16(2, 38)
    a.if_lt(7, 2, "sp_pai_low")
    a.add_int_2addr(10, 0)
    a.goto16("sp_vo2_chk")
    a.label("sp_pai_low")
    a.const16(2, 18)
    a.if_lt(7, 2, "sp_vo2_chk")
    a.add_int_2addr(9, 0)

    a.label("sp_vo2_chk")
    a.const16(0, 360)
    a.if_lt(1, 0, "sport_next")
    a.const16(0, 500)
    a.if_lt(6, 0, "sport_next")
    a.const16(0, 30)
    a.if_lt(7, 0, "sport_next")

    a.const16(0, 45)
    a.if_ge(7, 0, "wpct_hi")
    a.move(7, 0)
    a.label("wpct_hi")
    a.const16(0, 100)
    a.if_le(7, 0, "wpct_ok")
    a.move(7, 0)
    a.label("wpct_ok")

    a.mul_int_lit8(6, 6, 60)
    a.div_int_2addr(6, 1)
    a.const16(0, 60)
    a.if_lt(6, 0, "sport_next")
    a.const16(0, 700)
    a.if_gt(6, 0, "sport_next")

    a.const16(0, 260)
    a.if_gt(6, 0, "sp_cycle_vo2")
    a.mul_int_lit8(6, 6, 18)
    a.div_int_lit8(6, 6, 10)
    a.add_int_lit8(6, 6, 35)
    a.goto16("sp_vo2_div")
    a.label("sp_cycle_vo2")
    a.add_int_lit8(6, 6, 35)

    a.label("sp_vo2_div")
    a.mul_int_lit8(6, 6, 10)
    a.div_int_2addr(6, 7)
    a.const16(0, 25)
    a.if_ge(6, 0, "sp_vo2_hi")
    a.move(6, 0)
    a.label("sp_vo2_hi")
    a.const16(0, 75)
    a.if_le(6, 0, "sp_vo2_save")
    a.move(6, 0)
    a.label("sp_vo2_save")
    a.if_le(6, 8, "sport_next")
    a.move(8, 6)

    a.label("sport_next")
    a.add_int_lit8(5, 5, 1)
    a.goto16("sport_loop")

    # Upsert Vo2MaxTable (Uth-Sorensen 15.3 * maxHr / rhr, refined by GPS workout)
    a.label("vo2_compute")
    a.move(0, 20)
    a.mul_int_lit16(0, 0, 153)
    a.move(1, 27)
    a.mul_int_lit8(1, 1, 10)
    a.div_int_2addr(0, 1)

    a.if_lez(8, "vo2_clamp")
    a.add_int_2addr(0, 8)
    a.add_int_lit8(0, 0, 1)
    a.div_int_lit8(0, 0, 2)

    a.label("vo2_clamp")
    a.const16(1, 25)
    a.if_ge(0, 1, "vo2_hi_chk")
    a.move(0, 1)
    a.label("vo2_hi_chk")
    a.const16(1, 72)
    a.if_le(0, 1, "vo2_insert")
    a.move(0, 1)

    a.label("vo2_insert")
    a.new_instance(1, T_DATE)
    a.move_wide(2, 14)
    a.invoke_direct([1, 2, 3], M_DATE_INIT_J)
    a.new_instance(2, T_VO2_TABLE)
    a.const4(3, 0)
    a.invoke_direct([2, 1, 0, 3], M_VO2_INIT)
    a.move_object(1, 18)
    a.invoke_interface([1, 2], M_VO2_INSERT)

    # Convert PAI zone minutes -> daily PAI points & upsert VitalityIndexTable
    a.if_lez(9, "pai_med_calc")
    a.add_int_lit8(9, 9, 7)
    a.div_int_lit8(9, 9, 15)
    a.if_gtz(9, "pai_low_cap")
    a.const4(9, 1)
    a.label("pai_low_cap")
    a.const16(0, 20)
    a.if_le(9, 0, "pai_med_calc")
    a.move(9, 0)

    a.label("pai_med_calc")
    a.if_lez(10, "pai_hi_calc")
    a.mul_int_lit8(10, 10, 2)
    a.add_int_lit8(10, 10, 2)
    a.div_int_lit8(10, 10, 5)
    a.if_gtz(10, "pai_med_cap")
    a.const4(10, 1)
    a.label("pai_med_cap")
    a.const16(0, 35)
    a.if_le(10, 0, "pai_hi_calc")
    a.move(10, 0)

    a.label("pai_hi_calc")
    a.if_lez(11, "pai_build")
    a.mul_int_lit8(11, 11, 4)
    a.add_int_lit8(11, 11, 2)
    a.div_int_lit8(11, 11, 5)
    a.const16(0, 50)
    a.if_le(11, 0, "pai_build")
    a.move(11, 0)

    a.label("pai_build")
    a.new_instance(0, T_PAI_ITEM)
    a.move_wide(1, 25)
    a.move(3, 9)
    a.move(4, 10)
    a.move(5, 11)
    a.invoke_direct_range(0, 6, M_PAI_ITEM_INIT)

    a.new_instance(8, T_ARRAYLIST)
    a.invoke_direct([8], M_AL_INIT)
    a.invoke_virtual([8, 0], M_AL_ADD)

    a.new_instance(0, T_PAI_TABLE)
    a.new_instance(1, T_DATE)
    a.move_wide(2, 25)
    a.invoke_direct([1, 2, 3], M_DATE_INIT_J)

    a.move_object(2, 24)
    a.invoke_virtual([2], M_HR_ADDR)
    a.move_result_object(2)
    a.if_nez(2, "ble_ok")
    a.const_string(2, STR_EMPTY)
    a.label("ble_ok")

    a.move(5, 23)
    a.if_nez(5, "upd_hist")
    a.invoke_static([], M_SYS_TIME)
    a.move_result_wide(3)
    a.goto16("upd_ready")
    a.label("upd_hist")
    a.move_wide(3, 14)

    a.label("upd_ready")
    a.move(5, 9)
    a.move(6, 10)
    a.move(7, 11)
    a.invoke_direct_range(0, 9, M_PAI_INIT)

    a.move_object(1, 17)
    a.invoke_interface([1, 0], M_PAI_INSERT)

    a.label("day_next")
    a.move(0, 23)
    a.add_int_lit8(0, 0, 1)
    a.move(23, 0)
    a.goto16("day_loop")

    # 5. Original repository/d;->a() epilogue
    a.label("orig_epilogue")
    a.move_object(0, 18)
    a.const4(1, 3)
    a.invoke_interface([0, 1], M_VO2_DESC)
    a.move_result_object(0)
    a.invoke_interface([0], M_LIST_EMPTY)
    a.move_result(1)
    a.if_eqz(1, "ret_populated")
    a.new_instance(0, T_ARRAYLIST)
    a.invoke_direct([0], M_AL_INIT)
    a.return_object(0)
    a.label("ret_populated")
    a.invoke_static([0], M_REPO_D_B)
    a.move_result_object(0)
    a.return_object(0)

    return a.assemble(pad_to_words=pad_words)


def patch_classes6_vitality_vo2(dex_bytes: bytes) -> bytes:
    print("[*] Patching classes6.dex (Computed Vitality Score PAI + VO2 Max Engines)...")
    d6 = DexFile(dex_bytes)
    buf = bytearray(dex_bytes)

    m_repo_a = d6.find_method_info(
        "Lcom/liesheng/module_home/repository/d;",
        "Lcom/liesheng/module_home/repository/d;->a()Ljava/util/List;",
    )
    m_host_big = d6.find_method_info(
        "Lcom/liesheng/hayloufun/sport/bean/SportRunningData;",
        "Lcom/liesheng/hayloufun/sport/bean/SportRunningData;->copy$default(Lcom/liesheng/hayloufun/sport/bean/SportRunningData;JJFJLjava/lang/String;IILjava/util/List;IIFJIIIIIIIIIIIIILjava/util/List;Ljava/util/List;FILjava/util/List;Ljava/lang/String;ZIILjava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/util/List;IIILjava/lang/Integer;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;ILjava/lang/Integer;Ljava/util/List;IIIILjava/lang/Object;)Lcom/liesheng/hayloufun/sport/bean/SportRunningData;",
    )
    m_db_o = d6.find_method_info(
        "Lcom/liesheng/haylou/db/f;",
        "Lcom/liesheng/haylou/db/f;->o(Lcom/liesheng/lib_room/table/HeartRateDataTable;)V",
    )
    m_host_med = d6.find_method_info(
        "Lcom/liesheng/module_home/bean/SleepDetailsBean$SleepDetailsList;",
        "Lcom/liesheng/module_home/bean/SleepDetailsBean$SleepDetailsList;->copy$default(Lcom/liesheng/module_home/bean/SleepDetailsBean$SleepDetailsList;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;JJIIIIIIILjava/util/List;Ljava/util/List;FIIILjava/lang/Object;)Lcom/liesheng/module_home/bean/SleepDetailsBean$SleepDetailsList;",
    )

    if m_repo_a["insns_size"] >= 600:
        # Already swapped on an earlier patch run — refresh engine code in place!
        engine_insns = _build_pai_vo2_engine_insns(d6, pad_words=m_repo_a["insns_size"])
        struct.pack_into("<4H2I", buf, m_repo_a["code_off"], 28, 0, 9, 0, 0, m_repo_a["insns_size"])
        buf[m_repo_a["code_off"] + 16 : m_repo_a["code_off"] + 16 + len(engine_insns)] = engine_insns
        out = recompute_dex_checksums(buf)
        print("    [refresh] Updated existing PAI + VO2 Max engine in-place.")
        return out

    assert m_repo_a["code_pos_len"] == 4 and m_host_big["code_pos_len"] == 4
    assert m_db_o["code_pos_len"] == 4 and m_host_med["code_pos_len"] == 4

    # 1. Write PAI + VO2 Max engine into unreferenced SportRunningData.copy$default slot
    engine_insns = _build_pai_vo2_engine_insns(d6, pad_words=m_host_big["insns_size"])
    struct.pack_into("<4H2I", buf, m_host_big["code_off"], 28, 0, 9, 0, 0, m_host_big["insns_size"])
    buf[m_host_big["code_off"] + 16 : m_host_big["code_off"] + 16 + len(engine_insns)] = engine_insns

    stub1 = DalvikAssembler()
    stub1.const4(0, 0)
    stub1.return_object(0)
    stub1_bytes = stub1.assemble(pad_to_words=m_repo_a["insns_size"])
    struct.pack_into("<4H2I", buf, m_repo_a["code_off"], m_host_big["ins_size"] + 1, m_host_big["ins_size"], 0, 0, 0, m_repo_a["insns_size"])
    buf[m_repo_a["code_off"] + 16 : m_repo_a["code_off"] + 16 + len(stub1_bytes)] = stub1_bytes

    buf[m_repo_a["code_pos"] : m_repo_a["code_pos"] + 4] = encode_uleb128_4bytes(m_host_big["code_off"])
    buf[m_host_big["code_pos"] : m_host_big["code_pos"] + 4] = encode_uleb128_4bytes(m_repo_a["code_off"])

    # 2. Clone db/f.o into SleepDetailsList.copy$default slot + trigger repo/d.a() on every BLE HR sync
    orig_fo_words = m_db_o["insns_size"]
    orig_fo_bytes = dex_bytes[m_db_o["code_off"] + 16 : m_db_o["code_off"] + 16 + orig_fo_words * 2]
    assert struct.unpack_from("<H", orig_fo_bytes, (orig_fo_words - 1) * 2)[0] == 0x000E
    tail = DalvikAssembler()
    tail.invoke_static([], m_repo_a["method_idx"])
    tail.return_void()
    new_fo_bytes = orig_fo_bytes[:-2] + tail.assemble()
    pad_bytes = b"\x00\x00" * (m_host_med["insns_size"] - len(new_fo_bytes) // 2)
    struct.pack_into(
        "<4H2I",
        buf,
        m_host_med["code_off"],
        m_db_o["regs_size"],
        m_db_o["ins_size"],
        m_db_o["outs_size"],
        0,
        0,
        m_host_med["insns_size"],
    )
    buf[m_host_med["code_off"] + 16 : m_host_med["code_off"] + 16 + m_host_med["insns_size"] * 2] = new_fo_bytes + pad_bytes

    stub2 = DalvikAssembler()
    stub2.const4(0, 0)
    stub2.return_object(0)
    stub2_bytes = stub2.assemble(pad_to_words=m_db_o["insns_size"])
    struct.pack_into("<4H2I", buf, m_db_o["code_off"], m_host_med["ins_size"] + 1, m_host_med["ins_size"], 0, 0, 0, m_db_o["insns_size"])
    buf[m_db_o["code_off"] + 16 : m_db_o["code_off"] + 16 + len(stub2_bytes)] = stub2_bytes

    buf[m_db_o["code_pos"] : m_db_o["code_pos"] + 4] = encode_uleb128_4bytes(m_host_med["code_off"])
    buf[m_host_med["code_pos"] : m_host_med["code_pos"] + 4] = encode_uleb128_4bytes(m_db_o["code_off"])

    out = recompute_dex_checksums(buf)
    print(f"[+] classes6.dex PAI + VO2 Max patched (Adler: {struct.unpack_from('<I', out, 8)[0]:08x})")
    return out


def _emit_format_hhmm(
    a: DalvikAssembler,
    dst_reg: int,
    hour: int,
    minute: int,
    tmp_sb: int,
    tmp_val: int,
    refs: dict,
) -> None:
    a.new_instance(tmp_sb, refs["T_SB"])
    a.invoke_direct([tmp_sb], refs["M_SB_INIT"])
    if hour < 10:
        a.const_string(tmp_val, refs["S_ZERO"])
        a.invoke_virtual([tmp_sb, tmp_val], refs["M_SB_APP_STR"])
    a.const16(tmp_val, hour)
    a.invoke_virtual([tmp_sb, tmp_val], refs["M_SB_APP_INT"])
    a.const_string(tmp_val, refs["S_COLON"])
    a.invoke_virtual([tmp_sb, tmp_val], refs["M_SB_APP_STR"])
    if minute < 10:
        a.const_string(tmp_val, refs["S_ZERO"])
        a.invoke_virtual([tmp_sb, tmp_val], refs["M_SB_APP_STR"])
    a.const16(tmp_val, minute)
    a.invoke_virtual([tmp_sb, tmp_val], refs["M_SB_APP_INT"])
    a.invoke_virtual([tmp_sb], refs["M_SB_TOSTR"])
    a.move_result_object(dst_reg)


def _emit_parse_hhmm(
    a: DalvikAssembler,
    r_str: int,
    r_h: int,
    r_m: int,
    t0: int,
    t1: int,
    t4: int,
    def_h: int,
    def_m: int,
    pfx: str,
    refs: dict,
) -> None:
    a.const16(r_h, def_h)
    a.const16(r_m, def_m)
    a.if_eqz(r_str, f"{pfx}_done")
    a.const16(t0, 58)  # ':'
    a.invoke_virtual([r_str, t0], refs["M_STR_INDEXOF_C"])
    a.move_result(t0)
    a.if_lez(t0, f"{pfx}_done")
    a.invoke_virtual([r_str], refs["M_STR_LEN"])
    a.move_result(t1)
    a.add_int_lit8(t4, t0, 1)
    a.if_ge(t4, t1, f"{pfx}_done")

    a.const4(t1, 0)
    a.invoke_virtual([r_str, t1, t0], refs["M_STR_SUB2"])
    a.move_result_object(t1)
    a.invoke_static([t1], refs["M_INT_PARSE"])
    a.move_result(r_h)

    a.invoke_virtual([r_str, t4], refs["M_STR_SUB1"])
    a.move_result_object(t1)
    a.invoke_static([t1], refs["M_INT_PARSE"])
    a.move_result(r_m)

    a.if_gez(r_h, f"{pfx}_h_hi")
    a.const4(r_h, 0)
    a.label(f"{pfx}_h_hi")
    a.const16(t0, 24)
    a.if_le(r_h, t0, f"{pfx}_m_lo")
    a.move(r_h, t0)
    a.label(f"{pfx}_m_lo")
    a.if_gez(r_m, f"{pfx}_m_hi")
    a.const4(r_m, 0)
    a.label(f"{pfx}_m_hi")
    a.const16(t0, 59)
    a.if_le(r_m, t0, f"{pfx}_chk24")
    a.move(r_m, t0)
    a.label(f"{pfx}_chk24")
    a.const16(t0, 24)
    a.if_ne(r_h, t0, f"{pfx}_done")
    a.const4(r_m, 0)
    a.label(f"{pfx}_done")


def _emit_pack_schedule_and_send(
    a: DalvikAssembler,
    r_conn: int,
    r_en: int,
    r_start: int,
    r_end: int,
    tmps: tuple[int, int, int, int, int, int],
    pfx: str,
    refs: dict,
    def_night_start: tuple[int, int],
    def_night_end: tuple[int, int],
) -> None:
    """
    Invert night-off window [r_start..r_end] into active Raise-to-Wake window
    [r_end..r_start] (or 00:00..24:00 when r_en == false), pack into magic int
    0x40000000 | (sH<<18) | (sM<<12) | (eH<<6) | eM, and dispatch via
    CRPBleConnection.sendCurrentVolume(packed) -> classes3 BLE 0x72 handler.
    """
    t0, t1, t2, t3, t4, t5 = tmps
    a.if_nez(r_en, f"{pfx}_enabled")
    a.const32(t0, 0x40000000 | (24 << 6))  # 00:00 - 24:00 (Raise-to-Wake always on)
    a.goto16(f"{pfx}_send")

    a.label(f"{pfx}_enabled")
    # Active start = night end (e.g. 07:00)
    _emit_parse_hhmm(a, r_end, t2, t3, t0, t1, t4, def_night_end[0], def_night_end[1], f"{pfx}_s", refs)
    a.const_high16(t5, 0x4000)
    a.shl_int_lit8(t0, t2, 18)
    a.or_int_2addr(t5, t0)
    a.shl_int_lit8(t0, t3, 12)
    a.or_int_2addr(t5, t0)

    # Active end = night start (e.g. 23:00)
    _emit_parse_hhmm(a, r_start, t2, t3, t0, t1, t4, def_night_start[0], def_night_start[1], f"{pfx}_e", refs)
    # If active end is 00:00 while active start != 00:00 (e.g. night-off 00:00-07:00), map end to 24:00
    a.if_nez(t2, f"{pfx}_pack_end")
    a.if_nez(t3, f"{pfx}_pack_end")
    a.const_high16(t0, 0x4000)
    a.if_eq(t5, t0, f"{pfx}_pack_end")
    a.const16(t2, 24)

    a.label(f"{pfx}_pack_end")
    a.shl_int_lit8(t0, t2, 6)
    a.or_int_2addr(t5, t0)
    a.or_int_2addr(t5, t3)
    a.move(t0, t5)

    a.label(f"{pfx}_send")
    a.invoke_interface([r_conn, t0], refs["M_CRP_SEND_VOL"])


def patch_classes6_night_quickview(
    dex_bytes: bytes,
    night_start: tuple[int, int] = (23, 0),
    night_end: tuple[int, int] = (7, 0),
) -> bytes:
    """
    Wire Haylou Fun's hidden Do Not Disturb schedule screen exclusively to Watch 4S
    Raise-to-Wake hours (BLE 0x72):
      1. WatchConfigData.getNoDisturb(): one-time migration of untouched stock default
         (OFF 12:00-14:00) -> (ON <night_start>-<night_end>, default 23:00-07:00).
      2. DeviceConfigViewModel.a0(): emit local NoDisturb via FlowKt.flowOf(...) so
         DoNotDisturbFragment immediately shows the saved schedule on open.
      3. DeviceConfigViewModel$setNotDisturb$1$1.invokeSuspend(): for CRP watches,
         dispatch active Raise-to-Wake window via BLE 0x72 and emit Unit so the UI
         persists the setting locally (does NOT send 0x71 DND — calls/alerts still work).
      4. CrpWatchControlHelper$syncCurrentTime$1.invokeSuspend(): re-apply the saved
         0x72 Raise-to-Wake schedule automatically on every BLE connect / time sync.
    """
    ns_h, ns_m = night_start
    ne_h, ne_m = night_end
    print(
        f"[*] Patching classes6.dex (Night Raise-to-Wake UI & sync, default off "
        f"{ns_h:02d}:{ns_m:02d}-{ne_h:02d}:{ne_m:02d} -> active {ne_h:02d}:{ne_m:02d}-{ns_h:02d}:{ns_m:02d})..."
    )
    d6 = DexFile(dex_bytes)
    buf = bytearray(dex_bytes)

    refs = {
        "S_1200": d6.find_idx("string", "12:00"),
        "S_1400": d6.find_idx("string", "14:00"),
        "S_2200": d6.find_idx("string", "22:00"),
        "S_0700": d6.find_idx("string", "07:00"),
        "S_ZERO": d6.find_idx("string", "0"),
        "S_COLON": d6.find_idx("string", ":"),
        "T_SB": d6.find_idx("type", "Ljava/lang/StringBuilder;"),
        "T_CRP_HELPER": d6.find_idx("type", "Lcom/liesheng/haylou/service/watch/crp/CrpWatchControlHelper;"),
        "T_ND_REQ": d6.find_idx("type", "Lcom/yingsheng/protocol/business/bean/request/NoDisturbRequest;"),
        "T_PROD_SCOPE": d6.find_idx("type", "Lkotlinx/coroutines/channels/ProducerScope;"),
        "F_WCD_ND": d6.find_idx("field", "Lcom/liesheng/lib_common/bean/WatchConfigData;->noDisturb:Lcom/liesheng/lib_common/bean/NoDisturb;"),
        "F_WDH_INST": d6.find_idx("field", "Lcom/liesheng/lib_common/bean/WatchDataHelper;->INSTANCE:Lcom/liesheng/lib_common/bean/WatchDataHelper;"),
        "F_CRP_CONN": d6.find_idx("field", "Lcom/liesheng/haylou/service/watch/crp/CrpWatchControlHelper;->k:Lcom/crrepa/ble/conn/CRPBleConnection;"),
        "F_ND11_H": d6.find_idx("field", "Lcom/liesheng/module_device/setting/viewmodel/DeviceConfigViewModel$setNotDisturb$1$1;->h:Z"),
        "F_ND11_I": d6.find_idx("field", "Lcom/liesheng/module_device/setting/viewmodel/DeviceConfigViewModel$setNotDisturb$1$1;->i:Ljava/lang/String;"),
        "F_ND11_J": d6.find_idx("field", "Lcom/liesheng/module_device/setting/viewmodel/DeviceConfigViewModel$setNotDisturb$1$1;->j:Ljava/lang/String;"),
        "F_SYNC_H": d6.find_idx("field", "Lcom/liesheng/haylou/service/watch/crp/CrpWatchControlHelper$syncCurrentTime$1;->h:Ljava/lang/Object;"),
        "F_SYNC_I": d6.find_idx("field", "Lcom/liesheng/haylou/service/watch/crp/CrpWatchControlHelper$syncCurrentTime$1;->i:Lcom/liesheng/haylou/service/watch/crp/CrpWatchControlHelper;"),
        "F_UNIT": d6.find_idx("field", "Lkotlin/q;->a:Lkotlin/q;"),
        "M_TEXT_EQ": d6.find_idx("method", "Landroid/text/TextUtils;->equals(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Z"),
        "M_WDH_GET": d6.find_idx("method", "Lcom/liesheng/lib_common/bean/WatchDataHelper;->getWatchData()Lcom/liesheng/lib_common/bean/WatchConfigData;"),
        "M_WCD_CFG": d6.find_idx("method", "Lcom/liesheng/lib_common/bean/WatchConfigData;->getWatchConfig()Lcom/yingsheng/protocol/config/WatchConfig;"),
        "M_WCD_ND": d6.find_idx("method", "Lcom/liesheng/lib_common/bean/WatchConfigData;->getNoDisturb()Lcom/liesheng/lib_common/bean/NoDisturb;"),
        "M_WC_SYNC_ND": d6.find_idx("method", "Lcom/yingsheng/protocol/config/WatchConfig;->isSupportSyncDeviceDisturb()Z"),
        "M_ND_IS_EN": d6.find_idx("method", "Lcom/liesheng/lib_common/bean/NoDisturb;->isEnable()Z"),
        "M_ND_GET_START": d6.find_idx("method", "Lcom/liesheng/lib_common/bean/NoDisturb;->getStartTime()Ljava/lang/String;"),
        "M_ND_GET_END": d6.find_idx("method", "Lcom/liesheng/lib_common/bean/NoDisturb;->getEndTime()Ljava/lang/String;"),
        "M_ND_SET_EN": d6.find_idx("method", "Lcom/liesheng/lib_common/bean/NoDisturb;->setEnable(Z)V"),
        "M_ND_SET_START": d6.find_idx("method", "Lcom/liesheng/lib_common/bean/NoDisturb;->setStartTime(Ljava/lang/String;)V"),
        "M_ND_SET_END": d6.find_idx("method", "Lcom/liesheng/lib_common/bean/NoDisturb;->setEndTime(Ljava/lang/String;)V"),
        "M_SB_INIT": d6.find_idx("method", "Ljava/lang/StringBuilder;-><init>()V"),
        "M_SB_APP_INT": d6.find_idx("method", "Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;"),
        "M_SB_APP_STR": d6.find_idx("method", "Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;"),
        "M_SB_TOSTR": d6.find_idx("method", "Ljava/lang/StringBuilder;->toString()Ljava/lang/String;"),
        "M_STR_INDEXOF_C": d6.find_idx("method", "Ljava/lang/String;->indexOf(I)I"),
        "M_STR_LEN": d6.find_idx("method", "Ljava/lang/String;->length()I"),
        "M_STR_SUB1": d6.find_idx("method", "Ljava/lang/String;->substring(I)Ljava/lang/String;"),
        "M_STR_SUB2": d6.find_idx("method", "Ljava/lang/String;->substring(II)Ljava/lang/String;"),
        "M_INT_PARSE": d6.find_idx("method", "Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I"),
        "M_CRP_SEND_VOL": d6.find_idx("method", "Lcom/crrepa/ble/conn/CRPBleConnection;->sendCurrentVolume(I)V"),
        "M_CRP_SYNC_TIME": d6.find_idx("method", "Lcom/crrepa/ble/conn/CRPBleConnection;->syncTime()V"),
        "M_CRP_SEND_TZ": d6.find_idx("method", "Lcom/crrepa/ble/conn/CRPBleConnection;->sendCurrentTimezone()V"),
        "M_FLOW_OF": d6.find_idx("method", "Lkotlinx/coroutines/flow/FlowKt;->flowOf(Ljava/lang/Object;)Lkotlinx/coroutines/flow/Flow;"),
        "M_ANIM_C": d6.find_idx("method", "Landroidx/compose/animation/c;->c(Ljava/lang/Object;)Lcom/yingsheng/protocol/business/watch/WatchControlHelper;"),
        "M_ND_REQ_INIT": d6.find_idx("method", "Lcom/yingsheng/protocol/business/bean/request/NoDisturbRequest;-><init>()V"),
        "M_ND_REQ_SET_EN": d6.find_idx("method", "Lcom/yingsheng/protocol/business/bean/request/NoDisturbRequest;->setEnable(Z)V"),
        "M_ND_REQ_SET_START": d6.find_idx("method", "Lcom/yingsheng/protocol/business/bean/request/NoDisturbRequest;->setNoDisturbStartTime(Ljava/lang/String;)V"),
        "M_ND_REQ_SET_END": d6.find_idx("method", "Lcom/yingsheng/protocol/business/bean/request/NoDisturbRequest;->setNoDisturbEndTime(Ljava/lang/String;)V"),
        "M_WCH_SET_ND": d6.find_idx("method", "Lcom/yingsheng/protocol/business/watch/WatchControlHelper;->setNoDisturbModel(Lcom/yingsheng/protocol/business/bean/request/NoDisturbRequest;)Lkotlinx/coroutines/flow/Flow;"),
        "M_CTRL_GET": d6.find_idx("method", "Lcom/liesheng/haylou/ext/ControlHelperKt;->c()Lcom/yingsheng/protocol/business/watch/WatchControlHelper;"),
        "M_GET_SUSP": d6.find_idx("method", "Lkotlin/coroutines/intrinsics/IntrinsicsKt;->getCOROUTINE_SUSPENDED()Ljava/lang/Object;"),
        "M_KOTLIN_GB": d6.find_idx("method", "Lkotlin/g;->b(Ljava/lang/Object;)V"),
        "M_BOX_BOOL": d6.find_idx("method", "Lkotlin/coroutines/jvm/internal/Boxing;->boxBoolean(Z)Ljava/lang/Boolean;"),
        "M_TRY_SEND": d6.find_idx("method", "Lkotlinx/coroutines/channels/SendChannel;->trySend-JP2dKIU(Ljava/lang/Object;)Ljava/lang/Object;"),
        "M_CLOSE_DEF": d6.find_idx("method", "Lkotlinx/coroutines/channels/SendChannel$DefaultImpls;->close$default(Lkotlinx/coroutines/channels/SendChannel;Ljava/lang/Throwable;ILjava/lang/Object;)Z"),
    }

    def _swap_or_refresh(target_info: dict, host_info: dict, regs: int, ins: int, outs: int, build_fn, swapped_min_words: int):
        if target_info["insns_size"] >= swapped_min_words:
            insns = build_fn(target_info["insns_size"])
            struct.pack_into("<4H2I", buf, target_info["code_off"], regs, ins, outs, 0, 0, target_info["insns_size"])
            buf[target_info["code_off"] + 16 : target_info["code_off"] + 16 + len(insns)] = insns
            return False
        assert target_info["code_pos_len"] == 4 and host_info["code_pos_len"] == 4
        insns = build_fn(host_info["insns_size"])
        struct.pack_into("<4H2I", buf, host_info["code_off"], regs, ins, outs, 0, 0, host_info["insns_size"])
        buf[host_info["code_off"] + 16 : host_info["code_off"] + 16 + len(insns)] = insns

        stub = DalvikAssembler()
        stub.const4(0, 0)
        stub.return_object(0)
        stub_bytes = stub.assemble(pad_to_words=target_info["insns_size"])
        struct.pack_into(
            "<4H2I",
            buf,
            target_info["code_off"],
            host_info["ins_size"] + 1,
            host_info["ins_size"],
            0,
            0,
            0,
            target_info["insns_size"],
        )
        buf[target_info["code_off"] + 16 : target_info["code_off"] + 16 + len(stub_bytes)] = stub_bytes

        buf[target_info["code_pos"] : target_info["code_pos"] + 4] = encode_uleb128_4bytes(host_info["code_off"])
        buf[host_info["code_pos"] : host_info["code_pos"] + 4] = encode_uleb128_4bytes(target_info["code_off"])
        return True

    # 1) WatchConfigData.getNoDisturb(): one-time default upgrade (OFF 12:00-14:00 -> ON night_start-night_end)
    m_get_nd = d6.find_method_info(
        "Lcom/liesheng/lib_common/bean/WatchConfigData;",
        "Lcom/liesheng/lib_common/bean/WatchConfigData;->getNoDisturb()Lcom/liesheng/lib_common/bean/NoDisturb;",
    )
    m_host_nd = d6.find_method_info(
        "Lcom/liesheng/lib_common/bean/UserInfoBean;",
        "Lcom/liesheng/lib_common/bean/UserInfoBean;->copy$default(Lcom/liesheng/lib_common/bean/UserInfoBean;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;JILjava/lang/String;Ljava/lang/Integer;ILjava/lang/Object;)Lcom/liesheng/lib_common/bean/UserInfoBean;",
    )

    def _build_get_nd(pad_words: int) -> bytes:
        # regs=5, ins=1, outs=2 -> p0=v4 (this: WatchConfigData)
        # One-time upgrade of untouched stock defaults:
        #   (false, "12:00", "14:00") [NoDisturb.<init>] OR
        #   (false, "22:00", "07:00") [WatchConfigData.<init>] (unless target itself is 22:00-07:00)
        # -> (true, defaultNightStart, defaultNightEnd)
        a = DalvikAssembler()
        a.iget_object(0, 4, refs["F_WCD_ND"])
        a.if_eqz(0, "ret_nd")
        a.invoke_virtual([0], refs["M_ND_IS_EN"])
        a.move_result(1)
        a.if_nez(1, "ret_nd")

        # Check ("12:00", "14:00")
        a.invoke_virtual([0], refs["M_ND_GET_START"])
        a.move_result_object(1)
        a.const_string(2, refs["S_1200"])
        a.invoke_static([1, 2], refs["M_TEXT_EQ"])
        a.move_result(1)
        a.if_eqz(1, "chk_2200")
        a.invoke_virtual([0], refs["M_ND_GET_END"])
        a.move_result_object(1)
        a.const_string(2, refs["S_1400"])
        a.invoke_static([1, 2], refs["M_TEXT_EQ"])
        a.move_result(1)
        a.if_nez(1, "do_migrate")

        a.label("chk_2200")
        if not (ns_h == 22 and ns_m == 0 and ne_h == 7 and ne_m == 0):
            a.invoke_virtual([0], refs["M_ND_GET_START"])
            a.move_result_object(1)
            a.const_string(2, refs["S_2200"])
            a.invoke_static([1, 2], refs["M_TEXT_EQ"])
            a.move_result(1)
            a.if_eqz(1, "ret_nd")
            a.invoke_virtual([0], refs["M_ND_GET_END"])
            a.move_result_object(1)
            a.const_string(2, refs["S_0700"])
            a.invoke_static([1, 2], refs["M_TEXT_EQ"])
            a.move_result(1)
            a.if_eqz(1, "ret_nd")
        else:
            a.goto16("ret_nd")

        a.label("do_migrate")
        a.const4(1, 1)
        a.invoke_virtual([0, 1], refs["M_ND_SET_EN"])
        _emit_format_hhmm(a, 1, ns_h, ns_m, 2, 3, refs)
        a.invoke_virtual([0, 1], refs["M_ND_SET_START"])
        _emit_format_hhmm(a, 1, ne_h, ne_m, 2, 3, refs)
        a.invoke_virtual([0, 1], refs["M_ND_SET_END"])

        a.label("ret_nd")
        a.return_object(0)
        return a.assemble(pad_to_words=pad_words)

    _swap_or_refresh(m_get_nd, m_host_nd, regs=5, ins=1, outs=2, build_fn=_build_get_nd, swapped_min_words=100)

    # 2) DeviceConfigViewModel.a0(): emit saved local NoDisturb on UI open (in-place at +0035..+004f)
    m_a0 = d6.find_method_info(
        "Lcom/liesheng/module_device/setting/viewmodel/DeviceConfigViewModel;",
        "Lcom/liesheng/module_device/setting/viewmodel/DeviceConfigViewModel;->a0(Lkotlin/coroutines/jvm/internal/ContinuationImpl;)Ljava/lang/Object;",
    )
    a0_patch = DalvikAssembler()
    a0_patch.sget_object(2, refs["F_WDH_INST"])
    a0_patch.invoke_virtual([2], refs["M_WDH_GET"])
    a0_patch.move_result_object(2)
    a0_patch.invoke_virtual([2], refs["M_WCD_CFG"])
    a0_patch.move_result_object(6)
    a0_patch.invoke_virtual([6], refs["M_WC_SYNC_ND"])
    a0_patch.move_result(6)
    a0_patch.if_nez(6, "jump_0050")
    a0_patch.invoke_virtual([2], refs["M_WCD_ND"])
    a0_patch.move_result_object(6)
    a0_patch.invoke_static([6], refs["M_FLOW_OF"])
    a0_patch.move_result_object(6)
    a0_patch.return_object(6)
    a0_patch.nop()
    a0_patch.nop()
    a0_patch.label("jump_0050")
    a0_bytes = a0_patch.assemble()
    assert len(a0_bytes) == 54, f"Expected 54 bytes for a0 patch, got {len(a0_bytes)}"
    a0_off = m_a0["code_off"] + 16 + 0x35 * 2
    cur_a0 = bytes(buf[a0_off : a0_off + 54])
    if cur_a0 != a0_bytes:
        assert cur_a0[0] == 0x62 and cur_a0[52:54] == b"\x11\x06", f"Unexpected bytes in a0(): {cur_a0[:8].hex()}"
        buf[a0_off : a0_off + 54] = a0_bytes

    # 3) DeviceConfigViewModel$setNotDisturb$1$1.invokeSuspend(): send BLE 0x72 & return FlowKt.flowOf(Unit)
    m_set_nd = d6.find_method_info(
        "Lcom/liesheng/module_device/setting/viewmodel/DeviceConfigViewModel$setNotDisturb$1$1;",
        "Lcom/liesheng/module_device/setting/viewmodel/DeviceConfigViewModel$setNotDisturb$1$1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;",
    )
    m_host_set_nd = d6.find_method_info(
        "Lcom/liesheng/haylou/ui/fatweight/data/WeightRecordEntity;",
        "Lcom/liesheng/haylou/ui/fatweight/data/WeightRecordEntity;->copy$default(Lcom/liesheng/haylou/ui/fatweight/data/WeightRecordEntity;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;FFIFFFFFFFFIILjava/lang/String;JIIFLcom/liesheng/haylou/ui/fatweight/data/WeightScaleEntity;ILjava/lang/Object;)Lcom/liesheng/haylou/ui/fatweight/data/WeightRecordEntity;",
    )

    def _build_set_nd(pad_words: int) -> bytes:
        # regs=12, ins=2, outs=3 -> p0=v10 (this), p1=v11 (Object)
        a = DalvikAssembler()
        a.invoke_static([11], refs["M_ANIM_C"])
        a.move_result_object(6)
        a.if_nez(6, "has_helper")
        a.const4(0, 0)
        a.return_object(0)

        a.label("has_helper")
        a.instance_of(0, 6, refs["T_CRP_HELPER"])
        a.if_eqz(0, "non_crp")
        a.check_cast(6, refs["T_CRP_HELPER"])
        a.iget_object(6, 6, refs["F_CRP_CONN"])
        a.if_eqz(6, "ret_flow_unit")
        a.iget_boolean(7, 10, refs["F_ND11_H"])
        a.iget_object(8, 10, refs["F_ND11_I"])
        a.iget_object(9, 10, refs["F_ND11_J"])
        _emit_pack_schedule_and_send(a, 6, 7, 8, 9, (0, 1, 2, 3, 4, 5), "nd", refs, night_start, night_end)

        a.label("ret_flow_unit")
        a.sget_object(0, refs["F_UNIT"])
        a.invoke_static([0], refs["M_FLOW_OF"])
        a.move_result_object(0)
        a.return_object(0)

        a.label("non_crp")
        a.new_instance(0, refs["T_ND_REQ"])
        a.invoke_direct([0], refs["M_ND_REQ_INIT"])
        a.iget_boolean(1, 10, refs["F_ND11_H"])
        a.invoke_virtual([0, 1], refs["M_ND_REQ_SET_EN"])
        a.iget_object(1, 10, refs["F_ND11_I"])
        a.invoke_virtual([0, 1], refs["M_ND_REQ_SET_START"])
        a.iget_object(1, 10, refs["F_ND11_J"])
        a.invoke_virtual([0, 1], refs["M_ND_REQ_SET_END"])
        a.invoke_virtual([6, 0], refs["M_WCH_SET_ND"])
        a.move_result_object(0)
        a.return_object(0)
        return a.assemble(pad_to_words=pad_words)

    _swap_or_refresh(m_set_nd, m_host_set_nd, regs=12, ins=2, outs=3, build_fn=_build_set_nd, swapped_min_words=100)

    # 4) SportHeartrateStateKt.test()V (265w dead dev scratch method): unified static helper
    #    applySavedNightQuickView() — reads WatchDataHelper.noDisturb and dispatches BLE 0x72!
    m_helper = d6.find_method_info(
        "Lcom/liesheng/hayloufun/sport/bean/SportHeartrateStateKt;",
        "Lcom/liesheng/hayloufun/sport/bean/SportHeartrateStateKt;->test()V",
    )
    a_hlp = DalvikAssembler()
    # regs=10, ins=0, outs=3 -> v0..v5 tmps, v6=conn, v7=enable, v8=startTime, v9=endTime
    a_hlp.invoke_static([], refs["M_CTRL_GET"])
    a_hlp.move_result_object(6)
    a_hlp.instance_of(0, 6, refs["T_CRP_HELPER"])
    a_hlp.if_eqz(0, "hlp_done")
    a_hlp.check_cast(6, refs["T_CRP_HELPER"])
    a_hlp.iget_object(6, 6, refs["F_CRP_CONN"])
    a_hlp.if_eqz(6, "hlp_done")
    a_hlp.sget_object(0, refs["F_WDH_INST"])
    a_hlp.invoke_virtual([0], refs["M_WDH_GET"])
    a_hlp.move_result_object(0)
    a_hlp.invoke_virtual([0], refs["M_WCD_ND"])
    a_hlp.move_result_object(0)
    a_hlp.if_eqz(0, "hlp_done")
    a_hlp.invoke_virtual([0], refs["M_ND_IS_EN"])
    a_hlp.move_result(7)
    a_hlp.invoke_virtual([0], refs["M_ND_GET_START"])
    a_hlp.move_result_object(8)
    a_hlp.invoke_virtual([0], refs["M_ND_GET_END"])
    a_hlp.move_result_object(9)
    _emit_pack_schedule_and_send(a_hlp, 6, 7, 8, 9, (0, 1, 2, 3, 4, 5), "hlp", refs, night_start, night_end)
    a_hlp.label("hlp_done")
    a_hlp.return_void()
    hlp_insns = a_hlp.assemble(pad_to_words=m_helper["insns_size"])
    struct.pack_into("<4H2I", buf, m_helper["code_off"], 10, 0, 3, 0, 0, m_helper["insns_size"])
    buf[m_helper["code_off"] + 16 : m_helper["code_off"] + 16 + len(hlp_insns)] = hlp_insns

    def _append_helper_before_return_obj(target_info: dict, host_info: dict, expected_ret_word: int, swapped_min_words: int):
        """Clone target_info into host_info and insert `invoke-static {}, test()V` right before its final return-object."""
        if target_info["insns_size"] >= swapped_min_words:
            return
        assert target_info["code_pos_len"] == 4 and host_info["code_pos_len"] == 4
        orig_words = target_info["insns_size"]
        orig_bytes = dex_bytes[target_info["code_off"] + 16 : target_info["code_off"] + 16 + orig_words * 2]
        last_word = struct.unpack_from("<H", orig_bytes, (orig_words - 1) * 2)[0]
        assert last_word == expected_ret_word, f"Expected trailing word 0x{expected_ret_word:04x}, got 0x{last_word:04x}"
        tail = DalvikAssembler()
        tail.invoke_static([], m_helper["method_idx"])
        tail.items.append(("words", [expected_ret_word]))
        new_bytes = orig_bytes[:-2] + tail.assemble()
        pad_words = host_info["insns_size"] - len(new_bytes) // 2
        assert pad_words >= 0, f"Host slot too small ({host_info['insns_size']}w < {len(new_bytes)//2}w)"
        struct.pack_into(
            "<4H2I",
            buf,
            host_info["code_off"],
            target_info["regs_size"],
            target_info["ins_size"],
            target_info["outs_size"],
            0,
            0,
            host_info["insns_size"],
        )
        buf[host_info["code_off"] + 16 : host_info["code_off"] + 16 + host_info["insns_size"] * 2] = (
            new_bytes + b"\x00\x00" * pad_words
        )
        stub = DalvikAssembler()
        stub.const4(0, 0)
        stub.return_object(0)
        stub_bytes = stub.assemble(pad_to_words=target_info["insns_size"])
        struct.pack_into(
            "<4H2I",
            buf,
            target_info["code_off"],
            host_info["ins_size"] + 1,
            host_info["ins_size"],
            0,
            0,
            0,
            target_info["insns_size"],
        )
        buf[target_info["code_off"] + 16 : target_info["code_off"] + 16 + len(stub_bytes)] = stub_bytes
        buf[target_info["code_pos"] : target_info["code_pos"] + 4] = encode_uleb128_4bytes(host_info["code_off"])
        buf[host_info["code_pos"] : host_info["code_pos"] + 4] = encode_uleb128_4bytes(target_info["code_off"])

    # 5) CrpWatchControlHelper.initBleParams(): auto-push 0x72 on EVERY BLE connect / reconnect!
    m_init_ble = d6.find_method_info(
        "Lcom/liesheng/haylou/service/watch/crp/CrpWatchControlHelper;",
        "Lcom/liesheng/haylou/service/watch/crp/CrpWatchControlHelper;->initBleParams(Lcom/yingsheng/protocol/business/bean/request/InitBleRequest;Lkotlin/jvm/functions/Function1;)Lkotlinx/coroutines/flow/Flow;",
    )
    m_host_init_ble = d6.find_method_info(
        "Lcom/liesheng/hayloufun/sport/bean/SportNetBean;",
        "Lcom/liesheng/hayloufun/sport/bean/SportNetBean;->copy$default(Lcom/liesheng/hayloufun/sport/bean/SportNetBean;JLjava/lang/String;IDDILjava/util/List;Ljava/util/List;JJIIIIDIIIIIILjava/util/List;IIILjava/lang/String;IILjava/util/List;Ljava/util/List;IIIIILjava/lang/String;ILjava/lang/String;Ljava/lang/String;IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;IILjava/lang/Object;)Lcom/liesheng/hayloufun/sport/bean/SportNetBean;",
    )
    _append_helper_before_return_obj(m_init_ble, m_host_init_ble, expected_ret_word=0x0711, swapped_min_words=600)

    # 6) CrpWatchControlHelper$setRaiseUpEnable$1.invokeSuspend(): re-apply 0x72 after Raise-to-Wake toggle
    m_raise = d6.find_method_info(
        "Lcom/liesheng/haylou/service/watch/crp/CrpWatchControlHelper$setRaiseUpEnable$1;",
        "Lcom/liesheng/haylou/service/watch/crp/CrpWatchControlHelper$setRaiseUpEnable$1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;",
    )
    m_host_raise = d6.find_method_info(
        "Lcom/liesheng/lib_room/table/StepDataTable;",
        "Lcom/liesheng/lib_room/table/StepDataTable;->copy$default(Lcom/liesheng/lib_room/table/StepDataTable;Ljava/util/Date;Ljava/lang/String;IIFFI[II[F[FI[I[I[F[FILjava/lang/Object;)Lcom/liesheng/lib_room/table/StepDataTable;",
    )
    _append_helper_before_return_obj(m_raise, m_host_raise, expected_ret_word=0x0311, swapped_min_words=100)

    # 7) CrpWatchControlHelper$syncCurrentTime$1.invokeSuspend(): re-apply 0x72 on manual time sync
    m_sync = d6.find_method_info(
        "Lcom/liesheng/haylou/service/watch/crp/CrpWatchControlHelper$syncCurrentTime$1;",
        "Lcom/liesheng/haylou/service/watch/crp/CrpWatchControlHelper$syncCurrentTime$1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;",
    )
    m_host_sync = d6.find_method_info(
        "Lcom/liesheng/maps/map/HaylouMapOptions;",
        "Lcom/liesheng/maps/map/HaylouMapOptions;->copy$default(Lcom/liesheng/maps/map/HaylouMapOptions;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/Float;Ljava/lang/Float;Lcom/liesheng/maps/map/HaylouCameraOptions;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;ILjava/lang/Object;)Lcom/liesheng/maps/map/HaylouMapOptions;",
    )

    def _build_sync(pad_words: int) -> bytes:
        # regs=4, ins=2, outs=4 -> p0=v2 (this), p1=v3 (Object)
        a = DalvikAssembler()
        a.invoke_static([], refs["M_GET_SUSP"])
        a.invoke_static([3], refs["M_KOTLIN_GB"])
        a.iget_object(3, 2, refs["F_SYNC_H"])
        a.check_cast(3, refs["T_PROD_SCOPE"])
        a.iget_object(0, 2, refs["F_SYNC_I"])
        a.iget_object(1, 0, refs["F_CRP_CONN"])
        a.if_eqz(1, "after_sync_t")
        a.invoke_interface([1], refs["M_CRP_SYNC_TIME"])
        a.label("after_sync_t")
        a.iget_object(0, 0, refs["F_CRP_CONN"])
        a.if_eqz(0, "after_tz")
        a.invoke_interface([0], refs["M_CRP_SEND_TZ"])
        a.invoke_static([], m_helper["method_idx"])
        a.label("after_tz")
        a.const4(0, 1)
        a.invoke_static([0], refs["M_BOX_BOOL"])
        a.move_result_object(1)
        a.invoke_interface([3, 1], refs["M_TRY_SEND"])
        a.const4(1, 0)
        a.invoke_static([3, 1, 0, 1], refs["M_CLOSE_DEF"])
        a.sget_object(3, refs["F_UNIT"])
        a.return_object(3)
        return a.assemble(pad_to_words=pad_words)

    _swap_or_refresh(m_sync, m_host_sync, regs=4, ins=2, outs=4, build_fn=_build_sync, swapped_min_words=100)

    out = recompute_dex_checksums(buf)
    print(f"[+] classes6.dex Night Raise-to-Wake patched (Adler: {struct.unpack_from('<I', out, 8)[0]:08x})")
    return out


# --------------------------------------------------------------------------- #
# 4. classes7.dex — WatchConfig Unlocks + 3-Card Resting Heart Rate UI
# --------------------------------------------------------------------------- #

def patch_classes7_unlock_cards(dex_bytes: bytes) -> bytes:
    print("[*] Patching classes7.dex (WatchConfig feature unlocks: PAI, VO2 Max, HRV, Quick Reply)...")
    d7 = DexFile(dex_bytes)
    buf = bytearray(dex_bytes)
    patched_pattern = bytes([0x12, 0x10, 0x0F, 0x00, 0x00, 0x00])  # const/4 v0, 1; return v0; nop

    unlocked = 0
    for label, desc in WATCHCONFIG_UNLOCK_METHODS:
        info = d7.find_method_info("Lcom/yingsheng/protocol/config/WatchConfig;", desc)
        insns_off = info["code_off"] + 16
        cur = bytes(buf[insns_off : insns_off + 6])
        if cur == patched_pattern:
            print(f"    [skip] {label}: already unlocked")
            continue
        assert cur[0] == 0x55 and cur[4:6] == b"\x0f\x00", f"Unexpected bytes for {label}: {cur.hex()}"
        buf[insns_off : insns_off + 6] = patched_pattern
        unlocked += 1
        print(f"    [+] Unlocked {label}")

    out = recompute_dex_checksums(buf)
    print(f"[+] classes7.dex WatchConfig unlocks complete ({unlocked} newly applied)")
    return out


def patch_classes7_night_quickview(dex_bytes: bytes) -> bytes:
    """Unhide the Device Settings -> Do Not Disturb menu item on Watch 4S."""
    print("[*] Patching classes7.dex (Unhide Do Not Disturb schedule menu)...")
    d7 = DexFile(dex_bytes)
    buf = bytearray(dex_bytes)
    patched_false = bytes([0x12, 0x00, 0x0F, 0x00, 0x00, 0x00])  # const/4 v0, 0; return v0; nop

    info = d7.find_method_info(
        "Lcom/yingsheng/protocol/config/WatchConfig;",
        "Lcom/yingsheng/protocol/config/WatchConfig;->isHiddenNoDisturbMenu()Z",
    )
    insns_off = info["code_off"] + 16
    cur = bytes(buf[insns_off : insns_off + 6])
    if cur == patched_false:
        print("    [skip] Do Not Disturb menu already unhidden")
        return bytes(buf)
    assert cur[0] == 0x55 and cur[4:6] == b"\x0f\x00", f"Unexpected bytes for isHiddenNoDisturbMenu: {cur.hex()}"
    buf[insns_off : insns_off + 6] = patched_false
    out = recompute_dex_checksums(buf)
    print(f"[+] classes7.dex Do Not Disturb menu unhidden (Adler: {struct.unpack_from('<I', out, 8)[0]:08x})")
    return out


def _build_rhr_helper_insns(d7: DexFile, pad_words: int = 468) -> bytes:
    STR_RHR = d7.find_idx("string", "Resting Heart Rate")
    STR_DASH = d7.find_idx("string", "--")

    T_OBJ_ARR = d7.find_idx("type", "[Ljava/lang/Object;")
    T_INT_ARR = d7.find_idx("type", "[I")
    T_CARD = d7.find_idx("type", "Le9/a;")
    T_DAY_DATA = d7.find_idx("type", "Lcom/liesheng/module_home/v2/heart/bean/HeartDayViewData$DayData;")
    T_STATS_DATA = d7.find_idx("type", "Lcom/liesheng/module_home/v2/heart/bean/HeartStatisticsViewData$StatisticsData;")
    T_DAY_DETAILS = d7.find_idx("type", "Lcom/liesheng/module_home/v2/heart/bean/HeartDayDetails;")
    T_HR_ITEM = d7.find_idx("type", "Lcom/liesheng/lib_room/table/HeartRateItem;")
    T_NUMBER = d7.find_idx("type", "Ljava/lang/Number;")

    M_OBJ_CLONE = d7.find_idx("method", "[Ljava/lang/Object;->clone()Ljava/lang/Object;")
    M_AS_LIST = d7.find_idx("method", "Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;")
    M_UNMOD_LIST = d7.find_idx("method", "Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;")
    M_INT_VAL_OF = d7.find_idx("method", "Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;")
    M_NUM_INT_VAL = d7.find_idx("method", "Ljava/lang/Number;->intValue()I")
    M_STR_VAL_OF = d7.find_idx("method", "Ljava/lang/String;->valueOf(I)Ljava/lang/String;")
    M_STR_CONCAT = d7.find_idx("method", "Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;")
    M_STR_SUB1 = d7.find_idx("method", "Ljava/lang/String;->substring(I)Ljava/lang/String;")
    M_STR_SUB2 = d7.find_idx("method", "Ljava/lang/String;->substring(II)Ljava/lang/String;")
    M_STR_LOWER = d7.find_idx("method", "Ljava/lang/String;->toLowerCase()Ljava/lang/String;")
    M_CARD_INIT = d7.find_idx("method", "Le9/a;-><init>(ILjava/lang/String;Ljava/lang/Integer;Ljava/lang/String;ZLjava/lang/Integer;I)V")
    M_DAY_GET_DET = d7.find_idx("method", "Lcom/liesheng/module_home/v2/heart/bean/HeartDayViewData$DayData;->getDetails()Lcom/liesheng/module_home/v2/heart/bean/HeartDayDetails;")
    M_DET_MIN = d7.find_idx("method", "Lcom/liesheng/module_home/v2/heart/bean/HeartDayDetails;->getMinHeartRate()I")
    M_DET_AVG = d7.find_idx("method", "Lcom/liesheng/module_home/v2/heart/bean/HeartDayDetails;->getAverageHeartRate()I")
    M_DET_HRS = d7.find_idx("method", "Lcom/liesheng/module_home/v2/heart/bean/HeartDayDetails;->getHrs()Ljava/util/List;")
    M_DET_NEW_ITEMS = d7.find_idx("method", "Lcom/liesheng/module_home/v2/heart/bean/HeartDayDetails;->getNewItems()Ljava/util/List;")
    M_ITEM_GET_HRM = d7.find_idx("method", "Lcom/liesheng/lib_room/table/HeartRateItem;->getHrm()I")
    M_STATS_GET_DET = d7.find_idx("method", "Lcom/liesheng/module_home/v2/heart/bean/HeartStatisticsViewData$StatisticsData;->getDetails()Lcom/liesheng/module_home/v2/heart/bean/HeartStatisticsDetails;")
    M_SDET_LIST = d7.find_idx("method", "Lcom/liesheng/module_home/v2/heart/bean/HeartStatisticsDetails;->getList()Ljava/util/List;")
    M_LIST_SIZE = d7.find_idx("method", "Ljava/util/List;->size()I")
    M_LIST_GET = d7.find_idx("method", "Ljava/util/List;->get(I)Ljava/lang/Object;")

    RES_BPM = 0x7F1304E2
    RES_AVG_TITLE = 0x7F1304DF

    a = DalvikAssembler()
    a.array_length(1, 15)
    a.const4(2, 3)
    a.if_ne(1, 2, "fallback_clone")
    a.const4(1, 0)
    a.aget_object(10, 15, 1)
    a.instance_of(2, 10, T_CARD)
    a.if_eqz(2, "fallback_clone")
    a.const4(1, 2)
    a.aget_object(10, 15, 1)
    a.instance_of(2, 10, T_CARD)
    a.if_nez(2, "fallback_clone")

    a.const4(0, 0)
    a.instance_of(1, 10, T_DAY_DATA)
    a.if_eqz(1, "check_stats")

    a.check_cast(10, T_DAY_DATA)
    a.invoke_virtual([10], M_DAY_GET_DET)
    a.move_result_object(11)
    a.invoke_virtual([11], M_DET_MIN)
    a.move_result(1)
    a.if_lez(1, "build_card")
    a.invoke_virtual([11], M_DET_AVG)
    a.move_result(2)
    a.invoke_virtual([11], M_DET_HRS)
    a.move_result_object(12)
    a.const4(6, 0)
    a.if_eqz(12, "try_new_items")
    a.invoke_interface([12], M_LIST_SIZE)
    a.move_result(3)
    a.if_lez(3, "try_new_items")

    a.new_array(13, 3, T_INT_ARR)
    a.const4(4, 0)
    a.label("extract_loop")
    a.if_ge(4, 3, "extract_done")
    a.invoke_interface([12, 4], M_LIST_GET)
    a.move_result_object(14)
    a.instance_of(5, 14, T_NUMBER)
    a.if_eqz(5, "extract_next")
    a.check_cast(14, T_NUMBER)
    a.invoke_virtual([14], M_NUM_INT_VAL)
    a.move_result(5)
    a.const16(7, 38)
    a.if_lt(5, 7, "extract_next")
    a.const16(7, 210)
    a.if_gt(5, 7, "extract_next")
    a.aput(5, 13, 6)
    a.add_int_lit8(6, 6, 1)
    a.label("extract_next")
    a.add_int_lit8(4, 4, 1)
    a.goto16("extract_loop")

    a.label("extract_done")
    a.const4(5, 4)
    a.if_ge(6, 5, "sort_start")

    a.label("try_new_items")
    a.invoke_virtual([11], M_DET_NEW_ITEMS)
    a.move_result_object(12)
    a.if_eqz(12, "day_fallback")
    a.invoke_interface([12], M_LIST_SIZE)
    a.move_result(3)
    a.if_lez(3, "day_fallback")
    a.new_array(13, 3, T_INT_ARR)
    a.const4(4, 0)
    a.const4(6, 0)
    a.label("ni_loop")
    a.if_ge(4, 3, "ni_done")
    a.invoke_interface([12, 4], M_LIST_GET)
    a.move_result_object(14)
    a.instance_of(5, 14, T_HR_ITEM)
    a.if_eqz(5, "ni_next")
    a.check_cast(14, T_HR_ITEM)
    a.invoke_virtual([14], M_ITEM_GET_HRM)
    a.move_result(5)
    a.const16(7, 38)
    a.if_lt(5, 7, "ni_next")
    a.const16(7, 210)
    a.if_gt(5, 7, "ni_next")
    a.aput(5, 13, 6)
    a.add_int_lit8(6, 6, 1)
    a.label("ni_next")
    a.add_int_lit8(4, 4, 1)
    a.goto16("ni_loop")

    a.label("ni_done")
    a.const4(5, 4)
    a.if_lt(6, 5, "day_fallback")

    a.label("sort_start")
    a.const4(4, 1)
    a.label("sort_outer")
    a.if_ge(4, 6, "sort_done")
    a.aget(5, 13, 4)
    a.add_int_lit8(7, 4, -1)
    a.label("sort_inner")
    a.if_ltz(7, "sort_insert")
    a.aget(8, 13, 7)
    a.if_le(8, 5, "sort_insert")
    a.add_int_lit8(9, 7, 1)
    a.aput(8, 13, 9)
    a.add_int_lit8(7, 7, -1)
    a.goto16("sort_inner")
    a.label("sort_insert")
    a.add_int_lit8(9, 7, 1)
    a.aput(5, 13, 9)
    a.add_int_lit8(4, 4, 1)
    a.goto16("sort_outer")

    a.label("sort_done")
    a.div_int_lit8(4, 6, 16)
    a.div_int_lit8(3, 6, 4)
    a.add_int_lit8(5, 4, 2)
    a.if_ge(3, 5, "range_ok")
    a.move(3, 5)
    a.label("range_ok")
    a.const4(5, 0)
    a.const4(7, 0)
    a.label("avg_loop")
    a.if_ge(4, 3, "avg_done")
    a.aget(8, 13, 4)
    a.add_int_2addr(5, 8)
    a.add_int_lit8(7, 7, 1)
    a.add_int_lit8(4, 4, 1)
    a.goto16("avg_loop")
    a.label("avg_done")
    a.div_int_2addr(5, 7)
    a.move(0, 5)
    a.goto16("clamp_day")

    a.label("day_fallback")
    a.move(0, 1)
    a.if_le(2, 1, "build_card")
    a.mul_int_lit8(0, 1, 2)
    a.add_int_2addr(0, 2)
    a.add_int_lit8(0, 0, 1)
    a.div_int_lit8(0, 0, 3)

    a.label("clamp_day")
    a.if_lt(0, 1, "clamp_min")
    a.goto16("clamp_max")
    a.label("clamp_min")
    a.move(0, 1)
    a.label("clamp_max")
    a.if_lez(2, "build_card")
    a.if_le(0, 2, "build_card")
    a.move(0, 2)
    a.goto16("build_card")

    a.label("check_stats")
    a.instance_of(1, 10, T_STATS_DATA)
    a.if_eqz(1, "build_card")
    a.check_cast(10, T_STATS_DATA)
    a.invoke_virtual([10], M_STATS_GET_DET)
    a.move_result_object(11)
    a.invoke_virtual([11], M_SDET_LIST)
    a.move_result_object(12)
    a.const4(5, 0)
    a.const4(6, 0)
    a.if_eqz(12, "stats_done")
    a.invoke_interface([12], M_LIST_SIZE)
    a.move_result(3)
    a.const4(4, 0)
    a.label("stats_loop")
    a.if_ge(4, 3, "stats_done")
    a.invoke_interface([12, 4], M_LIST_GET)
    a.move_result_object(14)
    a.check_cast(14, T_DAY_DETAILS)
    a.invoke_virtual([14], M_DET_MIN)
    a.move_result(1)
    a.if_lez(1, "stats_next")
    a.invoke_virtual([14], M_DET_AVG)
    a.move_result(2)
    a.move(7, 1)
    a.if_le(2, 1, "stats_add")
    a.mul_int_lit8(7, 1, 2)
    a.add_int_2addr(7, 2)
    a.add_int_lit8(7, 7, 1)
    a.div_int_lit8(7, 7, 3)
    a.label("stats_add")
    a.add_int_2addr(5, 7)
    a.add_int_lit8(6, 6, 1)
    a.label("stats_next")
    a.add_int_lit8(4, 4, 1)
    a.goto16("stats_loop")
    a.label("stats_done")
    a.if_lez(6, "build_card")
    a.div_int_2addr(5, 6)
    a.move(0, 5)

    a.label("build_card")
    a.if_lez(0, "rhr_dash")
    a.invoke_static([0], M_STR_VAL_OF)
    a.move_result_object(4)
    a.goto16("rhr_str_ready")
    a.label("rhr_dash")
    a.const_string(4, STR_DASH)
    a.label("rhr_str_ready")
    a.const_string(6, STR_RHR)
    a.const4(7, 0)
    a.const16(8, 8)
    a.invoke_virtual([6, 7, 8], M_STR_SUB2)
    a.move_result_object(11)
    a.invoke_virtual([6, 8], M_STR_SUB1)
    a.move_result_object(12)
    a.invoke_virtual([12], M_STR_LOWER)
    a.move_result_object(12)
    a.invoke_virtual([11, 12], M_STR_CONCAT)
    a.move_result_object(6)
    a.new_instance(2, T_CARD)
    a.const32(3, RES_AVG_TITLE)
    a.const32(5, RES_BPM)
    a.invoke_static([5], M_INT_VAL_OF)
    a.move_result_object(5)
    a.const4(7, 0)
    a.const4(8, 0)
    a.const4(9, 0)
    a.invoke_direct_range(2, 8, M_CARD_INIT)
    a.const4(1, 2)
    a.aput_object(2, 15, 1)
    a.invoke_static([15], M_AS_LIST)
    a.move_result_object(10)
    a.return_object(10)

    a.label("fallback_clone")
    a.invoke_virtual([15], M_OBJ_CLONE)
    a.move_result_object(10)
    a.check_cast(10, T_OBJ_ARR)
    a.invoke_static([10], M_AS_LIST)
    a.move_result_object(10)
    a.invoke_static([10], M_UNMOD_LIST)
    a.move_result_object(10)
    a.return_object(10)

    return a.assemble(pad_to_words=pad_words)


def patch_classes7_rhr(dex_bytes: bytes) -> bytes:
    print("[*] Patching classes7.dex (3-Card Resting Heart Rate UI for Day & Statistics tabs)...")
    d7 = DexFile(dex_bytes)
    buf = bytearray(dex_bytes)

    m_util = d7.find_method_info(
        "Lio/grpc/okhttp/internal/Util;",
        "Lio/grpc/okhttp/internal/Util;->immutableList([Ljava/lang/Object;)Ljava/util/List;",
    )
    m_host = d7.find_method_info(
        "Lcom/yc/nadalsdk/ble/open/AdFlashLanguageUtils;",
        "Lcom/yc/nadalsdk/ble/open/AdFlashLanguageUtils;->getPhoneLanguageForAdFlash(Ljava/lang/String;)Ljava/lang/String;",
    )

    T_OBJ_ARR = d7.find_idx("type", "[Ljava/lang/Object;")
    call_asm = DalvikAssembler()
    call_asm.filled_new_array([2, 12, 1], T_OBJ_ARR)
    call_asm.move_result_object(2)
    call_asm.invoke_static([2], m_util["method_idx"])
    call_asm.move_result_object(2)
    call8 = call_asm.assemble()
    assert len(call8) == 16

    ga_off = 0x1D5D38 + 16 + 0x181 * 2
    gd_off = 0x1D643C + 16 + 0x192 * 2

    if m_util["insns_size"] >= 400:
        # Already swapped — refresh helper in place
        helper_insns = _build_rhr_helper_insns(d7, pad_words=m_util["insns_size"])
        struct.pack_into("<4H2I", buf, m_util["code_off"], 16, 1, 8, 0, 0, m_util["insns_size"])
        buf[m_util["code_off"] + 16 : m_util["code_off"] + 16 + len(helper_insns)] = helper_insns
    else:
        assert m_util["code_pos_len"] == 4 and m_host["code_pos_len"] == 4
        helper_insns = _build_rhr_helper_insns(d7, pad_words=m_host["insns_size"])
        struct.pack_into("<4H2I", buf, m_host["code_off"], 16, 1, 8, 0, 0, m_host["insns_size"])
        buf[m_host["code_off"] + 16 : m_host["code_off"] + 16 + len(helper_insns)] = helper_insns

        stub = DalvikAssembler()
        stub.const_string(0, d7.find_idx("string", ""))
        stub.return_object(0)
        stub_insns = stub.assemble(pad_to_words=m_util["insns_size"])
        struct.pack_into("<4H2I", buf, m_util["code_off"], 2, 1, 0, 0, 0, m_util["insns_size"])
        buf[m_util["code_off"] + 16 : m_util["code_off"] + 16 + len(stub_insns)] = stub_insns

        buf[m_util["code_pos"] : m_util["code_pos"] + 4] = encode_uleb128_4bytes(m_host["code_off"])
        buf[m_host["code_pos"] : m_host["code_pos"] + 4] = encode_uleb128_4bytes(m_util["code_off"])

    assert buf[ga_off] == 0x24 and buf[gd_off] == 0x24, "Unexpected bytecode at Heart Rate call sites"
    buf[ga_off : ga_off + 16] = call8
    buf[gd_off : gd_off + 16] = call8

    out = recompute_dex_checksums(buf)
    print(f"[+] classes7.dex RHR 3-card UI patched (Adler: {struct.unpack_from('<I', out, 8)[0]:08x})")
    return out


# --------------------------------------------------------------------------- #
# Main Builder
# --------------------------------------------------------------------------- #

def parse_night_hours(spec: str) -> tuple[tuple[int, int], tuple[int, int]]:
    """Parse 'HH:MM-HH:MM' (default '23:00-07:00') into ((startH, startM), (endH, endM))."""
    parts = spec.strip().split("-")
    if len(parts) != 2:
        raise argparse.ArgumentTypeError(f"Invalid --night-hours {spec!r}; expected HH:MM-HH:MM (e.g. 23:00-07:00)")
    out = []
    for p in parts:
        hm = p.strip().split(":")
        if len(hm) != 2:
            raise argparse.ArgumentTypeError(f"Invalid time {p!r} in --night-hours; expected HH:MM")
        h, m = int(hm[0]), int(hm[1])
        if not (0 <= h <= 23 and 0 <= m <= 59):
            raise argparse.ArgumentTypeError(f"Time out of range {p!r} in --night-hours (00:00..23:59)")
        out.append((h, m))
    return out[0], out[1]


def build_modded_apk(
    src_apk: str,
    out_apk: str,
    keystore_path: str,
    ks_pass: str = "android",
    mode: str = "sideload",
    noclock: bool = True,
    unlock_cards: bool = True,
    rhr: bool = True,
    vitality_vo2: bool = True,
    night_raise_to_wake: bool = True,
    night_hours: tuple[tuple[int, int], tuple[int, int]] = ((23, 0), (7, 0)),
) -> str:
    if not os.path.isfile(src_apk):
        print(f"[-] Source APK not found: {src_apk}")
        print("    Pass --src <path/to/haylou-fun-v4-0-8.apk>")
        sys.exit(1)

    replacements = {}
    print(f"[*] Reading source APK: {src_apk}")
    with zipfile.ZipFile(src_apk, "r") as zf:
        if noclock:
            replacements["classes.dex"] = patch_classes_dex_noclock(zf.read("classes.dex"))

        if noclock or night_raise_to_wake:
            c3 = zf.read("classes3.dex")
            if noclock:
                c3 = patch_classes3_dex_fb_bypass(c3)
            if night_raise_to_wake:
                c3 = patch_classes3_night_quickview(c3)
            replacements["classes3.dex"] = c3

        if noclock or vitality_vo2 or night_raise_to_wake:
            c6 = zf.read("classes6.dex")
            if noclock:
                c6 = patch_classes6_sideload(c6, mode=mode)
            if vitality_vo2:
                c6 = patch_classes6_vitality_vo2(c6)
            if night_raise_to_wake:
                c6 = patch_classes6_night_quickview(c6, night_start=night_hours[0], night_end=night_hours[1])
            replacements["classes6.dex"] = c6

        if unlock_cards or rhr or night_raise_to_wake:
            c7 = zf.read("classes7.dex")
            if unlock_cards:
                c7 = patch_classes7_unlock_cards(c7)
            if rhr:
                c7 = patch_classes7_rhr(c7)
            if night_raise_to_wake:
                c7 = patch_classes7_night_quickview(c7)
            replacements["classes7.dex"] = c7

    print(f"[*] Repackaging, 4B/4KB-aligning, and v2/v3 signing -> {out_apk} (100% pure Python)...")
    repack_align_and_sign_apk(src_apk, out_apk, replacements, keystore_path, ks_pass=ks_pass)

    ver = verify_apk_signatures(out_apk)
    assert ver["v2"] and ver["v3"] and ver["cd_aligned_4k"], f"APK signature self-check failed: {ver}"
    size_mb = os.path.getsize(out_apk) / (1024 * 1024)
    print(f"[+] Verified APK Signature Scheme v2 + v3 (4KB CD aligned, SHA-256: {ver['digest_sha256'][:16]}...)")
    print(f"\n[SUCCESS] Built signed APK: {out_apk} ({size_mb:.2f} MB)")
    return out_apk


def main():
    parser = argparse.ArgumentParser(
        description="Zero-dependency pure-Python Haylou Fun v4.0.8 APK patcher & v2/v3 signer"
    )
    parser.add_argument("--src", default=DEFAULT_SRC_APK, help="Source Haylou Fun v4.0.8 APK")
    parser.add_argument("--out", default=None, help="Output signed APK path")
    parser.add_argument(
        "--keystore",
        default=DEFAULT_KEYSTORE,
        help="PKCS#12 .keystore/.p12 file OR PEM/DER keystore directory (auto-generated if missing)",
    )
    parser.add_argument("--ks-pass", default="android", help="Keystore password (default: android)")
    parser.add_argument("--mode", choices=["sideload", "capture"], default="sideload", help="Watchface ls25plate.bin mode")

    parser.add_argument("--all", action="store_true", help="Apply all patches (default when no specific patch flag is passed)")
    parser.add_argument("--noclock", action="store_true", help="Watchface 0xB0 no-clock + FB hash bypass + ls25plate.bin sideload")
    parser.add_argument("--unlock-cards", action="store_true", help="Unlock hidden WatchConfig features (PAI, VO2 Max, HRV, Quick Reply)")
    parser.add_argument("--rhr", action="store_true", help="Add 3rd Resting Heart Rate card to Heart Rate Details")
    parser.add_argument("--vitality-vo2", action="store_true", help="Add computed Vitality Score (PAI) + VO2 Max engines")
    parser.add_argument(
        "--night-raise-to-wake",
        action="store_true",
        help="Unhide Night Schedule (Do Not Disturb) UI and wire it exclusively to Watch 4S Raise-to-Wake (BLE 0x72)",
    )
    parser.add_argument(
        "--night-hours",
        type=parse_night_hours,
        default=parse_night_hours("23:00-07:00"),
        help="Default night-off hours for --night-raise-to-wake (default: 23:00-07:00)",
    )
    parser.add_argument("--verify-only", metavar="APK", help="Only verify v2/v3 signatures of an existing APK")
    args = parser.parse_args()

    if args.verify_only:
        ver = verify_apk_signatures(args.verify_only)
        print(f"[+] Verified {args.verify_only}: {ver}")
        return

    any_specific = args.noclock or args.unlock_cards or args.rhr or args.vitality_vo2 or args.night_raise_to_wake
    use_all = args.all or not any_specific
    do_noclock = use_all or args.noclock
    do_unlock = use_all or args.unlock_cards
    do_rhr = use_all or args.rhr
    do_pai_vo2 = use_all or args.vitality_vo2
    do_night_qv = use_all or args.night_raise_to_wake

    out_path = args.out or (
        DEFAULT_OUT_FULL if (do_unlock or do_rhr or do_pai_vo2 or do_night_qv) else DEFAULT_OUT_NOCLOCK
    )

    build_modded_apk(
        src_apk=args.src,
        out_apk=out_path,
        keystore_path=args.keystore,
        ks_pass=args.ks_pass,
        mode=args.mode,
        noclock=do_noclock,
        unlock_cards=do_unlock,
        rhr=do_rhr,
        vitality_vo2=do_pai_vo2,
        night_raise_to_wake=do_night_qv,
        night_hours=args.night_hours,
    )


if __name__ == "__main__":
    main()
