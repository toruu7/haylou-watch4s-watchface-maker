"""
Haylou Watch 4S (LS26) — Zero-Dependency Pure-Python Haylou Fun v4.0.8 APK Patcher & Signer

No Java, no keytool, no Android SDK build-tools (`zipalign` / `apksigner`) required!
Uses pure-Python DEX patching + 4-byte / 4096-byte APK alignment + APK Signature Scheme v2 & v3 signing.

Modular patch flags (default: --all):
  --noclock       1) classes.dex: Suppress photo-dial clock overlay (0xB0)
                  2) classes3.dex: Bypass Facebook SDK release signature hash
                  3) classes6.dex: Sideload (or capture) custom ls25plate.bin from external cache dir
  --unlock-cards  classes7.dex: Unlock Watch 4S hidden WatchConfig features
                  (PAI/Vitality, VO2 Max, HRV, Active/Standing Hours, hardware-verified
                  High/Low HR Alert 0x87 & Daytime Sleep Naps 0xBC; keeps unsupported Quick Reply stock)
  --rhr           classes7.dex: Add 3rd "Resting heart rate" StatCard to Heart Rate Details
                  (Day tab + Week/Month/Year tabs, computed from lowest quiet HR window)
  --vitality-vo2  classes6.dex: Computed Vitality Score (PAI) + VO2 Max engines
                  (backfills up to 30 days on Home launch + live update on every BLE HR sync)
  --night-raise-to-wake
                  classes3/6/7.dex: Unhide Device Settings -> Do Not Disturb schedule UI
                  and wire it exclusively to Watch 4S Raise-to-Wake schedule (BLE 0x72),
                  defaulting to 23:00-07:00 off (07:00-23:00 active) while keeping calls &
                  notifications active at night.
  --cycling-fixes classes6.dex: Three cycling fixes for Watch 4S + Haylou Fun:
                  1) Strip phantom handlebar-vibration steps during cycling windows
                     (exact 0x59 30-min overlap when synced with --hourly-charts, 30 steps/min
                     fallback on older days, self-healing signed delta, live BLE guard,
                     and SportTable.steps=0)
                  2) Post-sync GPS moving time & avg speed cleanup for watch-started rides
                     while preserving intact GPS points for Strava's smooth velocity curve
                  3) Live GPS auto-pause & auto-resume for phone-started cycling
                     (auto-pauses phone + watch at < 3.6 km/h for 5s, auto-resumes >= 5.4 km/h)
  --voip-calls    classes6.dex: VoIP incoming call alerts + wrist reject for Watch 4S
                  (WhatsApp, WhatsApp Business, Messenger, Instagram, Telegram, Viber, Discord):
                  rings Watch 4S with real caller name via BLE 0x41, stops ringing when
                  answered/missed, and executes the VoIP app's Decline action on watch Reject.
  --workout-analytics
                  classes6.dex: Compute Aerobic & Anaerobic Training Effect (0.2-5.0),
                  Exercise Load / EPOC, Recovery Time (minutes), and Per-Workout VO2 Max
                  from Watch 4S workout HR arrays (live before Cloud upload + 30-day backfill).
  --hrv-active    classes6/7.dex: Stress-derived 30-min HRV engine (HrvTable from Watch 4S's
                  24/7 PPG Stress + quiet HR) and Hourly Active/Standing Hours engine
                  (StepDataTable.activeItems[24], 30-day backfill + live refresh).
  --hourly-charts classes3/5/6/7.dex: Unlock Watch 4S's native 30-min hardware step histogram
                  (BLE 0x59 queryStepsCategory), populate hourly Steps/Calories/Exercise arrays
                  (with cycling-step reconciliation & workout allocation), and unhide the Day (D)
                  tabs & hourly bar charts in Daily Activities, Steps, Calories, and Home cards.
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
    ("Active/Standing Hours", "Lcom/yingsheng/protocol/config/WatchConfig;->isSupportActiveByHour()Z"),
    ("High/Low Heart Rate Alert", "Lcom/yingsheng/protocol/config/WatchConfig;->isSupportHeartWarning()Z"),
    ("Daytime Sleep Naps", "Lcom/yingsheng/protocol/config/WatchConfig;->isSupportSleepNap()Z"),
)

# Watch 4S (LS26) firmware silently ignores both QuickResponses (0xB9 0x19) and ReplyApp (0xBB 0x21/0x17);
# restore these getters to stock field reads if an earlier patched APK forced them true.
WATCHCONFIG_RESTORE_STOCK = (
    (
        "Quick SMS Reply",
        "Lcom/yingsheng/protocol/config/WatchConfig;->isSupportQuickReplyMsg()Z",
        "Lcom/yingsheng/protocol/config/WatchConfig;->isSupportQuickReplyMsg:Z",
    ),
    (
        "WhatsApp Quick Reply",
        "Lcom/yingsheng/protocol/config/WatchConfig;->isSupportWhatsAppQuickReplyMsg()Z",
        "Lcom/yingsheng/protocol/config/WatchConfig;->isSupportWhatsAppQuickReplyMsg:Z",
    ),
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


def patch_classes3_hourly_charts(dex_bytes: bytes) -> bytes:
    """
    Hook Lcom/crrepa/h/a;->syncStep()V in classes3.dex (swapped into unused
    queryPerformanceInsights()V, 83 words) so every Watch 4S step sync also sends
    queryStepsCategory(CRPCategoryHistoryDay.TODAY) (BLE 0x59 00 / 0x59 01), pulling
    Watch 4S's native 48 half-hour hardware step histogram.
    """
    print("[*] Patching classes3.dex (BLE 0x59 queryStepsCategory on syncStep)...")
    d3 = DexFile(dex_bytes)
    buf = bytearray(dex_bytes)

    m_sync = d3.find_method_info("Lcom/crrepa/h/a;", "Lcom/crrepa/h/a;->syncStep()V")
    m_host = d3.find_method_info("Lcom/crrepa/h/a;", "Lcom/crrepa/h/a;->queryPerformanceInsights()V")
    F_TODAY = d3.find_idx("field", "Lcom/crrepa/ble/conn/type/CRPCategoryHistoryDay;->TODAY:Lcom/crrepa/ble/conn/type/CRPCategoryHistoryDay;")
    M_QSC = d3.find_idx("method", "Lcom/crrepa/h/a;->queryStepsCategory(Lcom/crrepa/ble/conn/type/CRPCategoryHistoryDay;)V")
    F_HA_B = d3.find_idx("field", "Lcom/crrepa/h/a;->b:Lcom/crrepa/m/f;")
    M_MF_C = d3.find_idx("method", "Lcom/crrepa/m/f;->c()V")

    def _build_sync(pad_words: int) -> bytes:
        # regs=2, ins=1, outs=2 -> p0=v1 (this), v0=tmp
        a = DalvikAssembler()
        a.iget_object(0, 1, F_HA_B)
        a.invoke_virtual([0], M_MF_C)
        a.sget_object(0, F_TODAY)
        a.invoke_virtual([1, 0], M_QSC)
        a.return_void()
        return a.assemble(pad_to_words=pad_words)

    if m_sync["insns_size"] >= 50:
        insns = _build_sync(m_sync["insns_size"])
        struct.pack_into("<4H2I", buf, m_sync["code_off"], 2, 1, 2, 0, 0, m_sync["insns_size"])
        buf[m_sync["code_off"] + 16 : m_sync["code_off"] + 16 + len(insns)] = insns
        out = recompute_dex_checksums(buf)
        print("    [refresh] Updated classes3.dex 0x59 queryStepsCategory hook in-place.")
        return out

    assert m_sync["code_pos_len"] == 4 and m_host["code_pos_len"] == 4
    insns = _build_sync(m_host["insns_size"])
    struct.pack_into("<4H2I", buf, m_host["code_off"], 2, 1, 2, 0, 0, m_host["insns_size"])
    buf[m_host["code_off"] + 16 : m_host["code_off"] + 16 + len(insns)] = insns

    stub = DalvikAssembler()
    stub.return_void()
    stub_bytes = stub.assemble(pad_to_words=m_sync["insns_size"])
    struct.pack_into("<4H2I", buf, m_sync["code_off"], 1, 1, 0, 0, 0, m_sync["insns_size"])
    buf[m_sync["code_off"] + 16 : m_sync["code_off"] + 16 + len(stub_bytes)] = stub_bytes

    buf[m_sync["code_pos"] : m_sync["code_pos"] + 4] = encode_uleb128_4bytes(m_host["code_off"])
    buf[m_host["code_pos"] : m_host["code_pos"] + 4] = encode_uleb128_4bytes(m_sync["code_off"])

    out = recompute_dex_checksums(buf)
    print(f"[+] classes3.dex 0x59 queryStepsCategory patched (Adler: {struct.unpack_from('<I', out, 8)[0]:08x})")
    return out


# --------------------------------------------------------------------------- #
# 2b. classes5.dex — Capture Watch 4S 0x59 30-Min Hardware Steps (--hourly-charts)
# --------------------------------------------------------------------------- #

def patch_classes5_hourly_charts(dex_bytes: bytes) -> bytes:
    """
    Hook Lcom/google/common/collect/e1;->onStepsCategoryChange(CRPStepsCategoryInfo)V
    (swapped into unused HuaWo AiDeviceInfo.toString(), 150 words) so when Watch 4S replies
    to BLE 0x59 with its 48 half-hour hardware step counts, the raw CRPStepsCategoryInfo string
    and timestamp are cached in SharedPreferences("CRPSDK") for classes6.dex to ingest cleanly.
    """
    print("[*] Patching classes5.dex (Capture BLE 0x59 StepsCategory into SharedPreferences)...")
    d5 = DexFile(dex_bytes)
    buf = bytearray(dex_bytes)

    m_e1 = d5.find_method_info(
        "Lcom/google/common/collect/e1;",
        "Lcom/google/common/collect/e1;->onStepsCategoryChange(Lcom/crrepa/ble/conn/bean/CRPStepsCategoryInfo;)V",
    )
    m_host = d5.find_method_info(
        "Lcom/huawo/ai/handler/model/AiDeviceInfo;",
        "Lcom/huawo/ai/handler/model/AiDeviceInfo;->toString()Ljava/lang/String;",
    )

    T_SB = d5.find_idx("type", "Ljava/lang/StringBuilder;")
    M_SB_INIT = d5.find_idx("method", "Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V")
    M_SB_APP_OBJ = d5.find_idx("method", "Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;")
    M_SB_APP_STR = d5.find_idx("method", "Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;")
    M_SB_TOSTR = d5.find_idx("method", "Ljava/lang/StringBuilder;->toString()Ljava/lang/String;")
    M_LOG_K = d5.find_idx("method", "Lj2/f;->k(Ljava/lang/String;Ljava/lang/String;)V")
    M_OBJ_TOSTR = d5.find_idx("method", "Ljava/lang/Object;->toString()Ljava/lang/String;")
    M_HYAPP_CTX = d5.find_idx("method", "Lcom/liesheng/haylou/app/HyApplication;->getContext()Lcom/liesheng/haylou/app/HyApplication;")
    M_GET_SP = d5.find_idx("method", "Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;")
    M_SP_EDIT = d5.find_idx("method", "Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;")
    M_ED_PUT_STR = d5.find_idx("method", "Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;")
    M_ED_PUT_LONG = d5.find_idx("method", "Landroid/content/SharedPreferences$Editor;->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;")
    M_ED_APPLY = d5.find_idx("method", "Landroid/content/SharedPreferences$Editor;->apply()V")
    M_SYS_TIME = d5.find_idx("method", "Ljava/lang/System;->currentTimeMillis()J")
    STR_PREFIX = d5.find_idx("string", "onStepsCategoryChange ")
    STR_SPACE = d5.find_idx("string", " ")
    STR_CRPSDK = d5.find_idx("string", "CRPSDK")
    STR_STEPS = d5.find_idx("string", "steps")
    STR_TIME = d5.find_idx("string", "time")

    def _build_e1(pad_words: int) -> bytes:
        # regs=7, ins=2, outs=4 -> p0=v5 (this), p1=v6 (CRPStepsCategoryInfo)
        a = DalvikAssembler()
        # Keep stock CRPSDK log call
        a.new_instance(0, T_SB)
        a.const_string(1, STR_PREFIX)
        a.invoke_direct([0, 1], M_SB_INIT)
        a.invoke_virtual([0, 6], M_SB_APP_OBJ)
        a.const_string(1, STR_SPACE)
        a.invoke_virtual([0, 1], M_SB_APP_STR)
        a.invoke_virtual([0], M_SB_TOSTR)
        a.move_result_object(0)
        a.const_string(1, STR_CRPSDK)
        a.invoke_static([1, 0], M_LOG_K)

        # Save info.toString() + timestamp into SharedPreferences("CRPSDK")
        a.if_eqz(6, "e1_done")
        a.invoke_virtual([6], M_OBJ_TOSTR)
        a.move_result_object(4)
        a.if_eqz(4, "e1_done")
        a.invoke_static([], M_HYAPP_CTX)
        a.move_result_object(0)
        a.if_eqz(0, "e1_done")
        a.const_string(1, STR_CRPSDK)
        a.const4(2, 0)
        a.invoke_virtual([0, 1, 2], M_GET_SP)
        a.move_result_object(0)
        a.if_eqz(0, "e1_done")
        a.invoke_interface([0], M_SP_EDIT)
        a.move_result_object(0)
        a.if_eqz(0, "e1_done")
        a.const_string(1, STR_STEPS)
        a.invoke_interface([0, 1, 4], M_ED_PUT_STR)
        a.move_result_object(0)
        a.const_string(1, STR_TIME)
        a.invoke_static([], M_SYS_TIME)
        a.move_result_wide(2)
        a.invoke_interface([0, 1, 2, 3], M_ED_PUT_LONG)
        a.move_result_object(0)
        a.invoke_interface([0], M_ED_APPLY)
        a.label("e1_done")
        a.return_void()
        return a.assemble(pad_to_words=pad_words)

    if m_e1["insns_size"] >= 100:
        insns = _build_e1(m_e1["insns_size"])
        struct.pack_into("<4H2I", buf, m_e1["code_off"], 7, 2, 4, 0, 0, m_e1["insns_size"])
        buf[m_e1["code_off"] + 16 : m_e1["code_off"] + 16 + len(insns)] = insns
        out = recompute_dex_checksums(buf)
        print("    [refresh] Updated classes5.dex StepsCategory capture in-place.")
        return out

    assert m_e1["code_pos_len"] == 4 and m_host["code_pos_len"] == 4
    insns = _build_e1(m_host["insns_size"])
    struct.pack_into("<4H2I", buf, m_host["code_off"], 7, 2, 4, 0, 0, m_host["insns_size"])
    buf[m_host["code_off"] + 16 : m_host["code_off"] + 16 + len(insns)] = insns

    stub = DalvikAssembler()
    stub.const4(0, 0)
    stub.return_object(0)
    stub_bytes = stub.assemble(pad_to_words=m_e1["insns_size"])
    struct.pack_into("<4H2I", buf, m_e1["code_off"], 2, 1, 0, 0, 0, m_e1["insns_size"])
    buf[m_e1["code_off"] + 16 : m_e1["code_off"] + 16 + len(stub_bytes)] = stub_bytes

    buf[m_e1["code_pos"] : m_e1["code_pos"] + 4] = encode_uleb128_4bytes(m_host["code_off"])
    buf[m_host["code_pos"] : m_host["code_pos"] + 4] = encode_uleb128_4bytes(m_e1["code_off"])

    out = recompute_dex_checksums(buf)
    print(f"[+] classes5.dex StepsCategory capture patched (Adler: {struct.unpack_from('<I', out, 8)[0]:08x})")
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
# 3c. classes6.dex — Cycling Fixes (Phantom Steps + Moving Time + Auto-Pause)
# --------------------------------------------------------------------------- #

def _build_cycling_obj_helper_insns(d6: DexFile, refs: dict, pad_words: int) -> bytes:
    """
    Build Lio/reactivex/internal/functions/ObjectHelper;->hashCode(Ljava/lang/Object;)I
    (swapped into SportTable.copy$default, 649 words, regs=24, ins=1, outs=9, p0=v23).

    Type-dispatched static helper:
      - StepDataTable: strips phantom handlebar-vibration steps recorded during cycling
        workouts — works seamlessly on BOTH daily-total watches (Haylou Watch 4S, where
        CRPStepInfo leaves items[24] empty) AND hourly-bucket watches (updating items[h]
        within cycling hours via a 24-bit hour mask). Uses exact SportTable.steps when
        present, or ~1.5 steps/s (90 steps/min) of moving cycling duration when omitted,
        and tracks stripped totals in unused Room column StepDataTable.baseSteps for
        100% idempotency across backfills and live BLE step syncs.
        Returns 1 if modified, 0 otherwise.
      - android.location.Location: live GPS auto-pause / auto-resume controller for
        phone-started cycling workouts in SportRunningManager.onLocationChange.
        Returns 1 if onLocationChange should proceed normally, 0 if paused/auto-paused.
    """
    a = DalvikAssembler()

    # Dispatch on p0 (v25 -> v15); regs=26 so handle_auto_pause can use v22,v23 for nowMs!
    a.if_eqz(25, "ret_zero")
    a.move_object(15, 25)
    a.instance_of(1, 15, refs["T_STEP_TABLE"])
    a.if_nez(1, "clean_step_table")
    a.instance_of(1, 15, refs["T_LOCATION"])
    a.if_nez(1, "handle_auto_pause")

    a.label("ret_zero")
    a.const4(0, 0)
    a.return_int(0)

    a.label("ret_one")
    a.const4(0, 1)
    a.return_int(0)

    # ------------------------------------------------------------------ #
    # Branch A: cleanStepTable(StepDataTable v15) -> 1 if modified else 0
    # Regs: v15=step, v18,v19=localMidMs, v17=sports, v16=listSize,
    #       v14=spIdx, v13=hasCycle, v12=curTotal, v11=totalSportSteps,
    #       v10=totalCycleSec, v9=hasExactZero
    # ------------------------------------------------------------------ #
    a.label("clean_step_table")
    a.check_cast(15, refs["T_STEP_TABLE"])

    a.invoke_virtual([15], refs["M_STEP_GET_TOTAL"])
    a.move_result(12)  # v12 = curTotal
    a.if_gtz(12, "cs_has_steps")
    a.invoke_virtual([15], refs["M_STEP_GET_BASE"])
    a.move_result(0)
    a.if_lez(0, "ret_zero")
    a.label("cs_has_steps")

    a.invoke_virtual([15], refs["M_STEP_GET_RECDATE"])
    a.move_result_object(0)
    a.if_eqz(0, "ret_zero")
    a.invoke_virtual([0], refs["M_DATE_GET_TIME"])
    a.move_result_wide(0)
    a.invoke_static([0, 1], refs["M_CHINA_TO_LOCAL"])
    a.move_result_wide(0)
    a.invoke_static([0, 1], refs["M_UTC_TO_LOCAL"])
    a.move_result_wide(18)  # v18,v19 = true localMidMs

    a.sget_object(0, refs["F_APPDB_A"])
    a.invoke_virtual([0], refs["M_APPDB_B"])
    a.move_result_object(0)
    a.invoke_virtual([0], refs["M_APPDB_SPORT_DAO"])
    a.move_result_object(0)
    a.move_wide(1, 18)
    a.const_wide32(3, 86400000)
    a.add_long_2addr(3, 1)
    a.invoke_interface([0, 1, 2, 3, 4], refs["M_SPORT_BY_DATE"])
    a.move_result_object(17)
    a.if_eqz(17, "ret_zero")
    a.move_object(0, 17)
    a.invoke_interface([0], refs["M_LIST_SIZE"])
    a.move_result(16)
    a.if_lez(16, "ret_zero")

    a.const4(14, 0)   # spIdx = 0
    a.const4(13, 0)   # hasCycle = 0
    a.const4(11, 0)   # totalSportSteps = 0
    a.const4(10, 0)   # totalCycleSec = 0
    a.const4(9, 0)    # hasExactZero = 0 (1 if 0x59 measured 0 phantom steps, encoded as sportcounter < 0)
    a.const16(20, 0)  # totalCycleDistKm (float 0.0f)
    a.const16(21, 0)  # totalCycleCal (int kcal)

    a.label("cs_sp_loop")
    a.move(1, 16)
    a.if_ge(14, 1, "cs_sp_done")
    a.move_object(0, 17)
    a.invoke_interface([0, 14], refs["M_LIST_GET"])
    a.move_result_object(8)
    a.check_cast(8, refs["T_SPORT_TABLE"])

    a.invoke_virtual([8], refs["M_SPORT_GET_TYPE"])
    a.move_result(1)
    a.sget_object(0, refs["F_STM_INST"])
    a.invoke_virtual([0, 1], refs["M_STM_MAIN_TYPE"])
    a.move_result(0)
    a.const4(1, 2)
    a.if_ne(0, 1, "cs_sp_next")

    a.const4(13, 1)  # hasCycle = 1
    a.invoke_virtual([8], refs["M_SPORT_GET_DIST"])
    a.move_result(0)
    a.const4(1, 0)
    a.cmpl_float(1, 0, 1)
    a.if_lez(1, "cs_add_cal")
    a.add_float(20, 20, 0)
    a.label("cs_add_cal")
    a.invoke_virtual([8], refs["M_SPORT_GET_CAL"])
    a.move_result(0)
    a.if_lez(0, "cs_add_steps")
    a.move(1, 21)
    a.add_int_2addr(1, 0)
    a.move(21, 1)
    a.label("cs_add_steps")
    a.invoke_virtual([8], refs["M_SPORT_GET_STEPS"])
    a.move_result(0)
    a.if_gtz(0, "cs_have_st")
    a.invoke_virtual([8], refs["M_SPORT_GET_COUNTER"])
    a.move_result(0)
    a.if_gtz(0, "cs_have_st")
    a.if_gez(0, "cs_add_dur")
    a.const4(9, 1)   # sportcounter < 0 => exact 0x59 measured 0 phantom steps
    a.goto16("cs_add_dur")
    a.label("cs_have_st")
    a.add_int_2addr(11, 0)
    a.label("cs_add_dur")
    a.invoke_virtual([8], refs["M_SPORT_GET_DUR"])
    a.move_result(0)
    a.if_lez(0, "cs_sp_next")
    a.add_int_2addr(10, 0)

    a.label("cs_sp_next")
    a.add_int_lit8(14, 14, 1)
    a.goto16("cs_sp_loop")

    # Compute lossless, self-healing step deduction using StepDataTable.baseSteps
    a.label("cs_sp_done")
    a.if_eqz(13, "ret_zero")

    a.invoke_virtual([15], refs["M_STEP_GET_BASE"])
    a.move_result(3)       # v3 = alreadyBase
    a.move(4, 12)
    a.add_int_2addr(4, 3)  # v4 = rawTotal = curTotal + alreadyBase

    # want (v5): exact totalSportSteps (0x59 hardware overlap / watch counter) if > 0;
    # else 0 if 0x59 explicitly measured 0 phantom steps (hasExactZero != 0);
    # else fallback totalCycleSec / 2 (~30 steps/min realistic handlebar vibration on historical days)
    a.move(5, 11)
    a.if_gtz(5, "cs_want_ok")
    a.if_nez(9, "cs_want_ok")
    a.div_int_lit8(5, 10, 2)
    a.label("cs_want_ok")
    a.if_le(5, 4, "cs_wcap")
    a.move(5, 4)
    a.label("cs_wcap")

    # Signed delta = want - alreadyBase (negative delta restores previously over-deducted steps/dist/kcal!)
    a.sub_int_2addr(5, 3)
    a.if_eqz(5, "cs_chk_heal")
    a.if_lez(5, "cs_dcap")
    a.if_le(5, 12, "cs_dcap")
    a.move(5, 12)
    a.label("cs_dcap")

    a.move(6, 12)
    a.sub_int_2addr(6, 5)  # v6 = newTotal = curTotal - delta
    a.add_int_2addr(3, 5)  # v3 = newBase = alreadyBase + delta

    a.invoke_virtual([15, 6], refs["M_STEP_SET_TOTAL"])
    a.invoke_virtual([15, 3], refs["M_STEP_SET_BASE"])

    # Adjust ONLY walking-equivalent distance (0.00074 km/step) & kcal (0.04 kcal/step)
    # of delta (positive deducts, negative restores), floored at cycling totals so bike km/kcal stay intact
    a.int_to_float(3, 5)  # v3 = (float) delta

    a.const_float(4, 0.00074)
    a.mul_float_2addr(4, 3)  # v4 = delta * 0.00074 km
    a.invoke_virtual([15], refs["M_STEP_GET_DIST"])
    a.move_result(2)
    a.sub_float_2addr(2, 4)  # newDist = curDist - distDeltaKm
    a.move(0, 20)            # v0 = totalCycleDistKm
    a.cmpl_float(1, 2, 0)
    a.if_gez(1, "cs_dist_ok")
    a.move(2, 0)
    a.label("cs_dist_ok")
    a.invoke_virtual([15, 2], refs["M_STEP_SET_DIST"])

    a.const_float(4, 0.04)
    a.mul_float_2addr(4, 3)  # v4 = delta * 0.04 kcal
    a.invoke_virtual([15], refs["M_STEP_GET_KCAL"])
    a.move_result(2)
    a.sub_float_2addr(2, 4)  # newKcal = curKcal - kcalDelta
    a.move(0, 21)
    a.int_to_float(0, 0)     # v0 = (float) totalCycleCal
    a.cmpl_float(1, 2, 0)
    a.if_gez(1, "cs_kcal_ok")
    a.move(2, 0)
    a.label("cs_kcal_ok")
    a.invoke_virtual([15, 2], refs["M_STEP_SET_KCAL"])
    a.goto16("ret_one")

    # Self-heal if an earlier proportional-scaling pass dropped totalDistance/totalKcal below cycling totals
    a.label("cs_chk_heal")
    a.const4(7, 0)  # modified = 0
    a.invoke_virtual([15], refs["M_STEP_GET_DIST"])
    a.move_result(0)
    a.move(1, 20)
    a.cmpl_float(2, 0, 1)
    a.if_gez(2, "cs_heal_cal")
    a.int_to_float(0, 12)
    a.const_float(2, 0.00074)
    a.mul_float_2addr(0, 2)
    a.add_float_2addr(0, 1)
    a.invoke_virtual([15, 0], refs["M_STEP_SET_DIST"])
    a.const4(7, 1)
    a.label("cs_heal_cal")
    a.invoke_virtual([15], refs["M_STEP_GET_KCAL"])
    a.move_result(0)
    a.move(1, 21)
    a.int_to_float(1, 1)
    a.cmpl_float(2, 0, 1)
    a.if_gez(2, "cs_heal_ret")
    a.int_to_float(0, 12)
    a.const_float(2, 0.04)
    a.mul_float_2addr(0, 2)
    a.add_float_2addr(0, 1)
    a.invoke_virtual([15, 0], refs["M_STEP_SET_KCAL"])
    a.const4(7, 1)
    a.label("cs_heal_ret")
    a.return_int(7)

    # ------------------------------------------------------------------ #
    # Branch B: handleCyclingAutoPause(Location v15) -> 1 proceed, 0 skip
    # Regs: v15=loc, v14=mmkv, v13=isRunning, v12=session,
    #       v20,v21=nowMs, v18,v19=dtMs, v16,v17=curLat, v22=? (use regs=26!)
    # ------------------------------------------------------------------ #
    a.label("handle_auto_pause")
    a.check_cast(15, refs["T_LOCATION"])
    a.sget_boolean(13, refs["F_SRM_K"])
    a.sget_object(12, refs["F_SRM_O"])
    a.if_eqz(12, "ap_passthrough")

    a.invoke_virtual([12], refs["M_WS_GET_TYPE"])
    a.move_result(1)
    a.sget_object(0, refs["F_STM_INST"])
    a.invoke_virtual([0, 1], refs["M_STM_MAIN_TYPE"])
    a.move_result(0)
    a.const4(1, 2)
    a.if_ne(0, 1, "ap_passthrough")

    a.invoke_static([], refs["M_MMKV_DEFAULT"])
    a.move_result_object(14)
    a.if_eqz(14, "ap_passthrough")

    a.if_nez(13, "ap_calc_speed")
    a.const_string(1, refs["STR_KEY_AUTO_PAUSED"])
    a.const4(2, 0)
    a.invoke_virtual([14, 1, 2], refs["M_MMKV_DEC_BOOL"])
    a.move_result(0)
    a.if_eqz(0, "ret_zero")

    a.label("ap_calc_speed")
    a.invoke_static([], refs["M_SYS_TIME"])
    a.move_result_wide(22)

    a.invoke_virtual([15], refs["M_LOC_LAT"])
    a.move_result_wide(18)
    a.invoke_virtual([15], refs["M_LOC_LON"])
    a.move_result_wide(16)

    a.const_string(5, refs["STR_KEY_LAST_TIME"])
    a.const_wide16(6, 0)
    a.invoke_virtual([14, 5, 6, 7], refs["M_MMKV_DEC_LONG"])
    a.move_result_wide(0)

    a.const_string(5, refs["STR_KEY_LAST_LAT"])
    a.const4(6, 0)
    a.invoke_virtual([14, 5, 6], refs["M_MMKV_DEC_FLOAT"])
    a.move_result(2)

    a.const_string(5, refs["STR_KEY_LAST_LON"])
    a.invoke_virtual([14, 5, 6], refs["M_MMKV_DEC_FLOAT"])
    a.move_result(3)

    a.sub_long(20, 22, 0)

    a.const_string(5, refs["STR_KEY_LAST_TIME"])
    a.move_wide(6, 22)
    a.invoke_virtual([14, 5, 6, 7], refs["M_MMKV_ENC_LONG"])

    a.const_string(5, refs["STR_KEY_LAST_LAT"])
    a.move_wide(6, 18)
    a.double_to_float(6, 6)
    a.invoke_virtual([14, 5, 6], refs["M_MMKV_ENC_FLOAT"])

    a.const_string(5, refs["STR_KEY_LAST_LON"])
    a.move_wide(6, 16)
    a.double_to_float(6, 6)
    a.invoke_virtual([14, 5, 6], refs["M_MMKV_ENC_FLOAT"])

    a.const_wide16(4, 0)
    a.cmp_long(4, 0, 4)
    a.if_eqz(4, "ap_passthrough")
    a.const_wide16(4, 500)
    a.cmp_long(4, 20, 4)
    a.if_ltz(4, "ap_passthrough")
    a.const_wide32(4, 30000)
    a.cmp_long(4, 20, 4)
    a.if_gtz(4, "ap_passthrough")

    a.move(9, 3)
    a.float_to_double(0, 2)
    a.float_to_double(2, 9)
    a.move_wide(4, 18)
    a.move_wide(6, 16)
    a.const4(9, 3)
    a.new_array(8, 9, refs["T_FLOAT_ARR"])
    a.invoke_static_range(0, 9, refs["M_LOC_DIST_BETWEEN"])
    a.const4(0, 0)
    a.aget(11, 8, 0)

    a.move_wide(0, 20)
    a.long_to_float(10, 0)
    a.const_float(0, 1000.0)
    a.div_float_2addr(10, 0)

    a.if_eqz(13, "ap_check_resume")

    # ---- Currently running: auto-pause if speed < 1.0 m/s (3.6 km/h) for >= 5s ----
    a.invoke_virtual([12], refs["M_WS_GET_DUR"])
    a.move_result_wide(0)
    a.const_wide16(2, 10)
    a.cmp_long(0, 0, 2)
    a.if_ltz(0, "ret_one")

    a.cmpl_float(0, 11, 10)
    a.if_gez(0, "ap_moving_reset")

    a.const_string(5, refs["STR_KEY_LOW_SINCE"])
    a.const_wide16(6, 0)
    a.invoke_virtual([14, 5, 6, 7], refs["M_MMKV_DEC_LONG"])
    a.move_result_wide(0)
    a.const_wide16(2, 0)
    a.cmp_long(2, 0, 2)
    a.if_nez(2, "ap_chk_5s")

    a.move_wide(6, 22)
    a.invoke_virtual([14, 5, 6, 7], refs["M_MMKV_ENC_LONG"])
    a.goto16("ret_one")

    a.label("ap_chk_5s")
    a.sub_long(0, 22, 0)
    a.const_wide16(2, 5000)
    a.cmp_long(0, 0, 2)
    a.if_ltz(0, "ret_one")

    a.const_wide16(6, 0)
    a.invoke_virtual([14, 5, 6, 7], refs["M_MMKV_ENC_LONG"])
    a.const_string(5, refs["STR_KEY_STREAK"])
    a.const4(6, 0)
    a.invoke_virtual([14, 5, 6], refs["M_MMKV_ENC_INT"])
    a.const_string(5, refs["STR_KEY_AUTO_PAUSED"])
    a.const4(6, 1)
    a.invoke_virtual([14, 5, 6], refs["M_MMKV_ENC_BOOL"])
    a.const_string(5, refs["STR_KEY_AUTO_TRIGGER"])
    a.invoke_virtual([14, 5, 6], refs["M_MMKV_ENC_BOOL"])
    a.invoke_static([], refs["M_HYAPP_CTX"])
    a.move_result_object(0)
    a.const4(1, 0)
    a.invoke_static([0, 1], refs["M_SRM_PAUSE_H"])
    a.goto16("ret_zero")

    a.label("ap_moving_reset")
    a.const_string(5, refs["STR_KEY_LOW_SINCE"])
    a.const_wide16(6, 0)
    a.invoke_virtual([14, 5, 6, 7], refs["M_MMKV_ENC_LONG"])
    a.goto16("ret_one")

    # ---- Currently auto-paused: auto-resume on 2 consecutive fixes >= 1.5 m/s (5.4 km/h) ----
    a.label("ap_check_resume")
    a.invoke_virtual([15], refs["M_LOC_ACC"])
    a.move_result(0)
    a.const_float(1, 35.0)
    a.cmpl_float(0, 0, 1)
    a.if_gtz(0, "ret_zero")

    a.const_float(0, 30.0)
    a.mul_float(0, 10, 0)
    a.cmpl_float(0, 11, 0)
    a.if_gtz(0, "ret_zero")

    a.const_float(0, 1.5)
    a.mul_float(0, 10, 0)
    a.cmpl_float(0, 11, 0)
    a.if_ltz(0, "ap_reset_streak")

    a.const_string(5, refs["STR_KEY_STREAK"])
    a.const4(6, 0)
    a.invoke_virtual([14, 5, 6], refs["M_MMKV_DEC_INT"])
    a.move_result(6)
    a.add_int_lit8(6, 6, 1)
    a.const4(0, 2)
    a.if_ge(6, 0, "ap_do_resume")
    a.invoke_virtual([14, 5, 6], refs["M_MMKV_ENC_INT"])
    a.goto16("ret_zero")

    a.label("ap_do_resume")
    a.const4(6, 0)
    a.invoke_virtual([14, 5, 6], refs["M_MMKV_ENC_INT"])
    a.invoke_static([], refs["M_HYAPP_CTX"])
    a.move_result_object(0)
    a.const4(1, 0)
    a.invoke_static([0, 1], refs["M_SRM_CONT_B"])
    a.goto16("ret_one")

    a.label("ap_reset_streak")
    a.const_string(5, refs["STR_KEY_STREAK"])
    a.const4(6, 0)
    a.invoke_virtual([14, 5, 6], refs["M_MMKV_ENC_INT"])
    a.goto16("ret_zero")

    a.label("ap_passthrough")
    a.return_int(13)

    return a.assemble(pad_to_words=pad_words)


def _build_cycling_backfill_insns(d6: DexFile, refs: dict, pad_words: int) -> bytes:
    """
    Build Lcom/liesheng/haylou/ui/main/WebViewActivity;->getCountryCode()I
    (swapped into SportBasicTable.copy$default, 571 words, regs=33, ins=0, outs=9).

    Walks the last 30 days (including today) idempotently (and runs immediately inside
    CommonUtil.z BEFORE Haylou Cloud / Strava upload):
      1) Zeroes SportTable.steps on cycling workouts (stashing original watch-reported steps
         in local-only SportTable.sportcounter so daily StepDataTable cleanup stays exact).
      2) Post-sync moving time & avg speed cleanup on cycling SportTables with GPS tracks
         (deducts < 0.85 m/s / < 3.06 km/h stopped time when >= 10s stopped; marks movingTime > 0)
         while preserving SportTable.points 100% intact so Strava computes smooth velocity curves
         without flat-block gaps.
      3) Phantom cycling step cleanup on each cycling day's StepDataTable via ObjectHelper.hashCode.
    """
    a = DalvikAssembler()

    # Load SportDao (v27), StepDataDao (v26), nowMs (v24,v25)
    a.sget_object(0, refs["F_APPDB_A"])
    a.invoke_virtual([0], refs["M_APPDB_B"])
    a.move_result_object(1)
    a.invoke_virtual([1], refs["M_APPDB_SPORT_DAO"])
    a.move_result_object(27)
    a.invoke_virtual([1], refs["M_APPDB_STEP_DAO"])
    a.move_result_object(26)
    a.invoke_static([], refs["M_SYS_TIME"])
    a.move_result_wide(24)

    a.const16(23, 0)  # dayOffset = 0..29
    a.label("bf_day_loop")
    a.move(0, 23)
    a.const16(1, 30)
    a.if_ge(0, 1, "bf_done")

    # targetMs = nowMs - dayOffset * 86400000L
    a.int_to_long(0, 0)
    a.const_wide32(2, 86400000)
    a.mul_long_2addr(0, 2)
    a.move_wide(2, 24)
    a.sub_long_2addr(2, 0)

    # chinaMidMs (v21,v22) = IDataHelper.z(targetMs).getTime()
    a.invoke_static([2, 3], refs["M_IDATA_Z"])
    a.move_result_object(0)
    a.if_eqz(0, "bf_day_next")
    a.invoke_virtual([0], refs["M_DATE_GET_TIME"])
    a.move_result_wide(21)

    # localMidMs (v19,v20) = ktx/c.g(ktx/c.b(chinaMidMs))
    a.move_wide(0, 21)
    a.invoke_static([0, 1], refs["M_CHINA_TO_LOCAL"])
    a.move_result_wide(0)
    a.invoke_static([0, 1], refs["M_UTC_TO_LOCAL"])
    a.move_result_wide(19)

    # sports (v18) = SportDao.getSportDataByDate(localMidMs, localMidMs + 86400000L)
    a.move_object(0, 27)
    a.move_wide(1, 19)
    a.const_wide32(3, 86400000)
    a.add_long_2addr(3, 1)
    a.invoke_interface([0, 1, 2, 3, 4], refs["M_SPORT_BY_DATE"])
    a.move_result_object(18)
    a.if_eqz(18, "bf_day_next")
    a.move_object(0, 18)
    a.invoke_interface([0], refs["M_LIST_SIZE"])
    a.move_result(17)
    a.if_lez(17, "bf_day_next")

    a.const16(16, 0)  # spIdx = 0
    a.const4(15, 0)   # hasCycle = 0

    a.label("bf_sp_loop")
    a.move(0, 16)
    a.move(1, 17)
    a.if_ge(0, 1, "bf_sp_done")

    a.move_object(2, 18)
    a.invoke_interface([2, 0], refs["M_LIST_GET"])
    a.move_result_object(14)
    a.check_cast(14, refs["T_SPORT_TABLE"])

    # Cycling check
    a.move_object(0, 14)
    a.invoke_virtual([0], refs["M_SPORT_GET_TYPE"])
    a.move_result(1)
    a.sget_object(0, refs["F_STM_INST"])
    a.invoke_virtual([0, 1], refs["M_STM_MAIN_TYPE"])
    a.move_result(0)
    a.const4(1, 2)
    a.if_ne(0, 1, "bf_sp_next")

    a.const4(15, 1)  # hasCycle = 1

    # Zero SportTable.steps before Cloud/Strava upload, preserving original count in local-only sportcounter
    a.move_object(0, 14)
    a.invoke_virtual([0], refs["M_SPORT_GET_STEPS"])
    a.move_result(1)
    a.if_lez(1, "bf_steps_clean")
    a.invoke_virtual([0, 1], refs["M_SPORT_SET_COUNTER"])
    a.const4(1, 0)
    a.invoke_virtual([0, 1], refs["M_SPORT_SET_STEPS"])
    a.move_object(0, 27)
    a.move_object(1, 14)
    a.invoke_interface([0, 1], refs["M_SPORT_UPDATE"])
    a.label("bf_steps_clean")

    # Compute true moving duration directly from SportTable.points (handles both raw 2s tracks and
    # crp/i.c-deduplicated stationary gaps > 30s, while excluding manual pauses > 120s and GPS spikes).
    a.move_object(0, 14)
    a.invoke_virtual([0], refs["M_SPORT_GET_DUR"])
    a.move_result(4)  # v4 = origDur
    a.const16(1, 60)
    a.if_lt(4, 1, "bf_sp_next")

    a.move_object(0, 14)
    a.invoke_virtual([0], refs["M_SPORT_GET_POINTS"])
    a.move_result_object(13)
    a.if_eqz(13, "bf_sp_next")
    a.move_object(0, 13)
    a.invoke_interface([0], refs["M_LIST_SIZE"])
    a.move_result(12)
    a.const4(1, 5)
    a.if_lt(12, 1, "bf_sp_next")

    # Scan consecutive GPS points (v8 = float[3], v30,v31 = movingMs, v11 = ptIdx)
    # Keep SportTable.points 100% intact so Strava receives the unbroken GPS track for smooth speed curves.
    a.const4(0, 3)
    a.new_array(8, 0, refs["T_FLOAT_ARR"])
    a.const_wide16(30, 0)
    a.const4(11, 1)

    a.label("bf_pt_loop")
    a.if_ge(11, 12, "bf_pt_done")
    a.add_int_lit8(1, 11, -1)
    a.invoke_interface([13, 1], refs["M_LIST_GET"])
    a.move_result_object(0)
    a.check_cast(0, refs["T_LATLNG"])  # v0 = pPrev

    a.invoke_interface([13, 11], refs["M_LIST_GET"])
    a.move_result_object(6)
    a.check_cast(6, refs["T_LATLNG"])  # v6 = pCur

    # dtMs = pCur.getTime() - pPrev.getTime()
    a.invoke_virtual([0], refs["M_PT_TIME"])
    a.move_result_wide(2)
    a.invoke_virtual([6], refs["M_PT_TIME"])
    a.move_result_wide(4)
    a.sub_long_2addr(4, 2)
    a.const_wide16(2, 0)
    a.cmp_long(1, 4, 2)
    a.if_gtz(1, "bf_dt_pos")
    a.const_wide16(4, 2000)
    a.label("bf_dt_pos")
    # Exclude gaps > 120s (manual watch pauses & long stops); keep <= 120s so brief tunnels count if moving
    a.const_wide32(2, 120000)
    a.cmp_long(1, 4, 2)
    a.if_gtz(1, "bf_pt_next")
    a.move_wide(28, 4)  # save dtMs in v28,v29

    # Load lat2(v4,v5), lon2(v6,v7), lon1(v2,v3), lat1(v0,v1) for distanceBetween(v0..v8)
    a.invoke_virtual([6], refs["M_PT_LAT"])
    a.move_result_wide(4)
    a.invoke_virtual([6], refs["M_PT_LON"])
    a.move_result_wide(6)
    a.invoke_virtual([0], refs["M_PT_LON"])
    a.move_result_wide(2)
    a.invoke_virtual([0], refs["M_PT_LAT"])
    a.move_result_wide(0)
    a.invoke_static_range(0, 9, refs["M_LOC_DIST_BETWEEN"])

    a.const4(1, 0)
    a.aget(0, 8, 1)              # v0 = d (meters)
    a.move_wide(2, 28)           # v2,v3 = dtMs
    a.long_to_float(1, 2)        # v1 = (float) dtMs
    a.const_float(4, 0.00085)    # 0.85 m/s = 0.00085 m/ms (~3.06 km/h)
    a.mul_float(5, 1, 4)         # v5 = minDist = 0.85 * dtSec
    a.cmpl_float(4, 0, 5)        # d < minDist ? (stopped — including crp/i.c-deduplicated stops!)
    a.if_ltz(4, "bf_pt_next")
    a.const_float(4, 0.025)      # 25.0 m/s = 90 km/h (reject GPS teleport spikes)
    a.mul_float(5, 1, 4)         # v5 = maxDist = 25.0 * dtSec
    a.cmpl_float(4, 0, 5)        # d > maxDist ?
    a.if_gtz(4, "bf_pt_next")
    a.add_long(30, 30, 2)        # movingMs += dtMs

    a.label("bf_pt_next")
    a.add_int_lit8(11, 11, 1)
    a.goto16("bf_pt_loop")

    a.label("bf_pt_done")
    a.move_wide(4, 30)
    a.const_wide16(2, 1000)
    a.div_long_2addr(4, 2)
    a.long_to_int(6, 4)          # v6 = movingSec

    a.move_object(1, 14)
    a.invoke_virtual([1], refs["M_SPORT_GET_DUR"])
    a.move_result(1)             # v1 = origDur
    a.move(2, 1)                 # v2 = newDur = origDur

    a.const16(3, 60)
    a.if_lt(6, 3, "bf_sp_chk_mark")  # ignore GPS if < 60s total moving signal

    # Self-heal previously 60s-clamped watch-paused ride from GPS movingSec
    a.if_ne(1, 3, "bf_norm_dur")
    a.if_le(6, 3, "bf_sp_chk_mark")
    a.move(2, 6)
    a.goto16("bf_dur_ok")

    # Update duration to true movingSec whenever >= 10s of stationary stops can be stripped
    a.label("bf_norm_dur")
    a.add_int_lit8(3, 6, 10)     # v3 = movingSec + 10
    a.if_gt(3, 1, "bf_sp_chk_mark")  # require movingSec <= origDur - 10
    a.move(2, 6)
    a.label("bf_dur_ok")
    a.move_object(0, 14)
    a.invoke_virtual([0, 2], refs["M_SPORT_SET_DUR"])

    # Persist idempotently: only call SportDao.update if duration or movingTime actually changed
    a.label("bf_sp_chk_mark")
    a.int_to_long(4, 2)          # v4,v5 = (long) newDur
    a.if_ne(2, 1, "bf_sp_save")
    a.move_object(0, 14)
    a.invoke_virtual([0], refs["M_SPORT_GET_MOVING"])
    a.move_result_wide(6)
    a.cmp_long(0, 6, 4)
    a.if_eqz(0, "bf_sp_next")    # already up-to-date -> zero DB write!

    a.label("bf_sp_save")
    a.move_object(0, 14)
    a.invoke_virtual([0, 4, 5], refs["M_SPORT_SET_MOVING"])
    a.move_object(0, 27)
    a.move_object(1, 14)
    a.invoke_interface([0, 1], refs["M_SPORT_UPDATE"])

    a.label("bf_sp_next")
    a.add_int_lit8(16, 16, 1)
    a.goto16("bf_sp_loop")

    # Clean this day's StepDataTable if it has any cycling workouts
    a.label("bf_sp_done")
    a.if_eqz(15, "bf_day_next")
    a.move_object(0, 26)
    a.move_wide(1, 21)
    a.invoke_interface([0, 1, 2], refs["M_STEP_BY_DATE"])
    a.move_result_object(0)
    a.if_eqz(0, "bf_day_next")
    a.invoke_static([0], refs["M_OBJ_HASH"])
    a.move_result(1)
    a.if_eqz(1, "bf_day_next")
    a.move_object(1, 26)
    a.invoke_interface([1, 0], refs["M_STEP_INSERT"])

    a.label("bf_day_next")
    a.add_int_lit8(23, 23, 1)
    a.goto16("bf_day_loop")

    a.label("bf_done")
    a.const4(0, 0)
    a.return_int(0)
    return a.assemble(pad_to_words=pad_words)


def _build_idata_u_insns(d6: DexFile, refs: dict, pad_words: int) -> bytes:
    """
    Build Lcom/liesheng/haylou/db/datahelper/IDataHelper;->u(Lcom/yingsheng/protocol/data/bean/RealStepData;)V
    (swapped into UserInfoTable.copy$default, 420 words, regs=20, ins=2, outs=11, p0=v18, p1=v19).

    Subtracts today's stripped cycling steps (StepDataTable.baseSteps) from incoming live BLE
    RealStepData packets before IDataHelper.J(RealStepData) computes its hourly delta, so real-time
    step updates never re-inflate removed cycling steps.
    """
    a = DalvikAssembler()

    a.if_eqz(19, "u_ret")
    a.move_object(0, 19)
    a.invoke_virtual([0], refs["M_RS_STEP"])
    a.move_result(16)  # v16 = rawSteps
    a.if_lez(16, "u_ret")

    # Preserve original e.e = System.currentTimeMillis() timestamp update
    a.invoke_static([], refs["M_SYS_TIME"])
    a.move_result_wide(0)
    a.sput_wide(0, refs["F_DBE_E"])

    # Fetch today's StepDataTable
    a.invoke_static([0, 1], refs["M_IDATA_Z"])
    a.move_result_object(0)
    a.if_eqz(0, "u_call_j")
    a.invoke_virtual([0], refs["M_DATE_GET_TIME"])
    a.move_result_wide(1)
    a.sget_object(0, refs["F_APPDB_A"])
    a.invoke_virtual([0], refs["M_APPDB_B"])
    a.move_result_object(0)
    a.invoke_virtual([0], refs["M_APPDB_STEP_DAO"])
    a.move_result_object(0)
    a.invoke_interface([0, 1, 2], refs["M_STEP_BY_DATE"])
    a.move_result_object(17)
    a.if_eqz(17, "u_call_j")

    # Check stripped cycling steps (baseSteps)
    a.move_object(0, 17)
    a.invoke_virtual([0], refs["M_STEP_GET_BASE"])
    a.move_result(12)  # v12 = baseSteps
    a.if_lez(12, "u_call_j")

    # adjSteps (v15) = rawSteps - baseSteps; skip J if <= db.totalSteps (avoids J's overwrite branch)
    a.move(0, 16)
    a.sub_int_2addr(0, 12)
    a.if_lez(0, "u_ret")
    a.move(15, 0)

    a.move_object(1, 17)
    a.invoke_virtual([1], refs["M_STEP_GET_TOTAL"])
    a.move_result(1)
    a.if_le(0, 1, "u_ret")

    # Deduct ONLY walking-equivalent cal (40 cal/step = 0.04 kcal * 1000) & distance (0.74 m/step)
    # of stripped cycling steps so real bike calories & distance remain intact
    a.move_object(0, 19)
    a.invoke_virtual([0], refs["M_RS_CAL"])
    a.move_result(14)
    a.mul_int_lit8(0, 12, 40)
    a.sub_int_2addr(14, 0)
    a.if_gez(14, "u_cal_ok")
    a.const4(14, 0)
    a.label("u_cal_ok")

    a.move_object(0, 19)
    a.invoke_virtual([0], refs["M_RS_DIST"])
    a.move_result(13)
    a.mul_int_lit8(0, 12, 74)
    a.div_int_lit8(0, 0, 100)
    a.sub_int_2addr(13, 0)
    a.if_gez(13, "u_dist_ok")
    a.const4(13, 0)
    a.label("u_dist_ok")

    # Construct adjusted RealStepData(stepHour, adjSteps, adjCal, adjDist, activeDur, standCnt, walk, run, 0, null)
    a.new_instance(0, refs["T_REALSTEP"])
    a.move_object(1, 19)
    a.invoke_virtual([1], refs["M_RS_HOUR"])
    a.move_result(1)
    a.move(2, 15)
    a.move(3, 14)
    a.move(4, 13)
    a.move_object(5, 19)
    a.invoke_virtual([5], refs["M_RS_DUR"])
    a.move_result(5)
    a.move_object(6, 19)
    a.invoke_virtual([6], refs["M_RS_STAND"])
    a.move_result(6)
    a.move_object(7, 19)
    a.invoke_virtual([7], refs["M_RS_WALK"])
    a.move_result(7)
    a.move_object(8, 19)
    a.invoke_virtual([8], refs["M_RS_RUN"])
    a.move_result(8)
    a.const4(9, 0)
    a.const4(10, 0)
    a.invoke_direct_range(0, 11, refs["M_REALSTEP_INIT"])
    a.move_object(19, 0)

    a.label("u_call_j")
    a.move_object(0, 18)
    a.move_object(1, 19)
    a.invoke_virtual([0, 1], refs["M_IDATA_J"])

    a.label("u_ret")
    a.return_void()
    return a.assemble(pad_to_words=pad_words)


def patch_classes6_cycling_fixes(dex_bytes: bytes) -> bytes:
    """
    Patch classes6.dex with all three cycling fixes for Watch 4S + Haylou Fun:
      1) Phantom cycling step removal (IDataHelper.N + IDataHelper.u + 30-day backfill)
      2) Post-sync GPS moving time & avg speed cleanup (CommonUtil.z + 30-day backfill)
      3) Live GPS auto-pause & auto-resume for phone-started cycling
         (SportRunningManager.onLocationChange + h + b)
    """
    print("[*] Patching classes6.dex (Cycling Fixes: Phantom Steps + Moving Time + Live GPS Auto-Pause)...")
    d6 = DexFile(dex_bytes)
    buf = bytearray(dex_bytes)

    refs = {
        "T_SPORT_TABLE": d6.find_idx("type", "Lcom/liesheng/lib_room/table/SportTable;"),
        "T_STEP_TABLE": d6.find_idx("type", "Lcom/liesheng/lib_room/table/StepDataTable;"),
        "T_LATLNG": d6.find_idx("type", "Lcom/liesheng/lib_room/table/LatlngPoint;"),
        "T_LOCATION": d6.find_idx("type", "Landroid/location/Location;"),
        "T_REALSTEP": d6.find_idx("type", "Lcom/yingsheng/protocol/data/bean/RealStepData;"),
        "T_INT_ARR": d6.find_idx("type", "[I"),
        "T_FLOAT_ARR": d6.find_idx("type", "[F"),
        "T_ARRAYLIST": d6.find_idx("type", "Ljava/util/ArrayList;"),
        "F_APPDB_A": d6.find_idx("field", "Lcom/liesheng/AppDatabase;->a:Lcom/liesheng/AppDatabase$a;"),
        "F_STM_INST": d6.find_idx("field", "Lcom/liesheng/hayloufun/sport/data/SportTypeManager;->INSTANCE:Lcom/liesheng/hayloufun/sport/data/SportTypeManager;"),
        "F_SRM_K": d6.find_idx("field", "Lcom/liesheng/hayloufun/sport/running/SportRunningManager;->k:Z"),
        "F_SRM_O": d6.find_idx("field", "Lcom/liesheng/hayloufun/sport/running/SportRunningManager;->o:Lcom/liesheng/hayloufun/sport/running/WorkoutSession;"),
        "F_DBE_E": d6.find_idx("field", "Lcom/liesheng/haylou/db/e;->e:J"),
        "M_APPDB_B": d6.find_idx("method", "Lcom/liesheng/AppDatabase$a;->b()Lcom/liesheng/AppDatabase;"),
        "M_APPDB_SPORT_DAO": d6.find_idx("method", "Lcom/liesheng/AppDatabase;->u()Lcom/liesheng/lib_room/dao/SportDao;"),
        "M_APPDB_STEP_DAO": d6.find_idx("method", "Lcom/liesheng/AppDatabase;->w()Lcom/liesheng/lib_room/dao/StepDataDao;"),
        "M_SPORT_BY_DATE": d6.find_idx("method", "Lcom/liesheng/lib_room/dao/SportDao;->getSportDataByDate(JJ)Ljava/util/List;"),
        "M_SPORT_UPDATE": d6.find_idx("method", "Lcom/liesheng/lib_room/dao/SportDao;->update(Lcom/liesheng/lib_room/table/SportTable;)V"),
        "M_STEP_BY_DATE": d6.find_idx("method", "Lcom/liesheng/lib_room/dao/StepDataDao;->getStepDataByDate(J)Lcom/liesheng/lib_room/table/StepDataTable;"),
        "M_STEP_INSERT": d6.find_idx("method", "Lcom/liesheng/lib_room/dao/StepDataDao;->insert(Lcom/liesheng/lib_room/table/StepDataTable;)V"),
        "M_IDATA_Z": d6.find_idx("method", "Lcom/liesheng/haylou/db/datahelper/IDataHelper;->z(J)Ljava/util/Date;"),
        "M_IDATA_J": d6.find_idx("method", "Lcom/liesheng/haylou/db/datahelper/IDataHelper;->J(Lcom/yingsheng/protocol/data/bean/RealStepData;)V"),
        "M_CHINA_TO_LOCAL": d6.find_idx("method", "Lcom/liesheng/lib_common/ktx/c;->b(J)J"),
        "M_UTC_TO_LOCAL": d6.find_idx("method", "Lcom/liesheng/lib_common/ktx/c;->g(J)J"),
        "M_STM_MAIN_TYPE": d6.find_idx("method", "Lcom/liesheng/hayloufun/sport/data/SportTypeManager;->getMainTypeByType(I)I"),
        "M_SPORT_GET_TYPE": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getType()I"),
        "M_SPORT_GET_DUR": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getDuration()I"),
        "M_SPORT_SET_DUR": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->setDuration(I)V"),
        "M_SPORT_GET_MOVING": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getMovingTime()J"),
        "M_SPORT_SET_MOVING": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->setMovingTime(J)V"),
        "M_SPORT_GET_POINTS": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getPoints()Ljava/util/List;"),
        "M_SPORT_SET_POINTS": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->setPoints(Ljava/util/List;)V"),
        "M_SPORT_START": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getStartTime()Ljava/util/Date;"),
        "M_SPORT_END": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getEndTime()Ljava/util/Date;"),
        "M_SPORT_GET_STEPS": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getSteps()I"),
        "M_SPORT_SET_STEPS": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->setSteps(I)V"),
        "M_SPORT_GET_COUNTER": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getSportcounter()I"),
        "M_SPORT_SET_COUNTER": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->setSportcounter(I)V"),
        "M_SPORT_GET_DIST": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getDistance()F"),
        "M_SPORT_GET_CAL": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getCal()I"),
        "M_PT_LAT": d6.find_idx("method", "Lcom/liesheng/lib_room/table/LatlngPoint;->getLatitude()D"),
        "M_PT_LON": d6.find_idx("method", "Lcom/liesheng/lib_room/table/LatlngPoint;->getLongitude()D"),
        "M_PT_TIME": d6.find_idx("method", "Lcom/liesheng/lib_room/table/LatlngPoint;->getTime()J"),
        "M_LOC_DIST_BETWEEN": d6.find_idx("method", "Landroid/location/Location;->distanceBetween(DDDD[F)V"),
        "M_LOC_LAT": d6.find_idx("method", "Landroid/location/Location;->getLatitude()D"),
        "M_LOC_LON": d6.find_idx("method", "Landroid/location/Location;->getLongitude()D"),
        "M_LOC_ACC": d6.find_idx("method", "Landroid/location/Location;->getAccuracy()F"),
        "M_STEP_GET_RECDATE": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->getRecordDate()Ljava/util/Date;"),
        "M_STEP_GET_ITEMS": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->getItems()[I"),
        "M_STEP_GET_TOTAL": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->getTotalSteps()I"),
        "M_STEP_SET_TOTAL": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->setTotalSteps(I)V"),
        "M_STEP_GET_DIST": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->getTotalDistance()F"),
        "M_STEP_SET_DIST": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->setTotalDistance(F)V"),
        "M_STEP_GET_KCAL": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->getTotalKcal()F"),
        "M_STEP_SET_KCAL": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->setTotalKcal(F)V"),
        "M_STEP_GET_BASE": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->getBaseSteps()I"),
        "M_STEP_SET_BASE": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->setBaseSteps(I)V"),
        "M_STEP_GET_SPORT_STEPS": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->getSportSteps()[I"),
        "M_STEP_SET_SPORT_STEPS": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->setSportSteps([I)V"),
        "M_REALSTEP_INIT": d6.find_idx("method", "Lcom/yingsheng/protocol/data/bean/RealStepData;-><init>(IIIIIIIIILkotlin/jvm/internal/i;)V"),
        "M_RS_HOUR": d6.find_idx("method", "Lcom/yingsheng/protocol/data/bean/RealStepData;->getStepHour()I"),
        "M_RS_STEP": d6.find_idx("method", "Lcom/yingsheng/protocol/data/bean/RealStepData;->getRealTimeStep()I"),
        "M_RS_CAL": d6.find_idx("method", "Lcom/yingsheng/protocol/data/bean/RealStepData;->getStepCal()I"),
        "M_RS_DIST": d6.find_idx("method", "Lcom/yingsheng/protocol/data/bean/RealStepData;->getStepDistance()I"),
        "M_RS_DUR": d6.find_idx("method", "Lcom/yingsheng/protocol/data/bean/RealStepData;->getActiveDuration()I"),
        "M_RS_STAND": d6.find_idx("method", "Lcom/yingsheng/protocol/data/bean/RealStepData;->getStandCount()I"),
        "M_RS_WALK": d6.find_idx("method", "Lcom/yingsheng/protocol/data/bean/RealStepData;->getStepsWalk()I"),
        "M_RS_RUN": d6.find_idx("method", "Lcom/yingsheng/protocol/data/bean/RealStepData;->getStepsRun()I"),
        "M_SRM_PAUSE_H": d6.find_idx("method", "Lcom/liesheng/hayloufun/sport/running/SportRunningManager;->h(Landroid/content/Context;Z)V"),
        "M_SRM_CONT_B": d6.find_idx("method", "Lcom/liesheng/hayloufun/sport/running/SportRunningManager;->b(Landroid/content/Context;Z)V"),
        "M_WS_GET_TYPE": d6.find_idx("method", "Lcom/liesheng/hayloufun/sport/running/WorkoutSession;->getSportType()I"),
        "M_WS_GET_DUR": d6.find_idx("method", "Lcom/liesheng/hayloufun/sport/running/WorkoutSession;->getSportDuration()J"),
        "M_HYAPP_CTX": d6.find_idx("method", "Lcom/liesheng/haylou/app/HyApplication;->getContext()Lcom/liesheng/haylou/app/HyApplication;"),
        "M_MMKV_DEFAULT": d6.find_idx("method", "Lcom/tencent/mmkv/MMKV;->defaultMMKV()Lcom/tencent/mmkv/MMKV;"),
        "M_MMKV_DEC_BOOL": d6.find_idx("method", "Lcom/tencent/mmkv/MMKV;->decodeBool(Ljava/lang/String;Z)Z"),
        "M_MMKV_ENC_BOOL": d6.find_idx("method", "Lcom/tencent/mmkv/MMKV;->encode(Ljava/lang/String;Z)Z"),
        "M_MMKV_DEC_LONG": d6.find_idx("method", "Lcom/tencent/mmkv/MMKV;->decodeLong(Ljava/lang/String;J)J"),
        "M_MMKV_ENC_LONG": d6.find_idx("method", "Lcom/tencent/mmkv/MMKV;->encode(Ljava/lang/String;J)Z"),
        "M_MMKV_DEC_FLOAT": d6.find_idx("method", "Lcom/tencent/mmkv/MMKV;->decodeFloat(Ljava/lang/String;F)F"),
        "M_MMKV_ENC_FLOAT": d6.find_idx("method", "Lcom/tencent/mmkv/MMKV;->encode(Ljava/lang/String;F)Z"),
        "M_MMKV_DEC_INT": d6.find_idx("method", "Lcom/tencent/mmkv/MMKV;->decodeInt(Ljava/lang/String;I)I"),
        "M_MMKV_ENC_INT": d6.find_idx("method", "Lcom/tencent/mmkv/MMKV;->encode(Ljava/lang/String;I)Z"),
        "M_LIST_SIZE": d6.find_idx("method", "Ljava/util/List;->size()I"),
        "M_LIST_GET": d6.find_idx("method", "Ljava/util/List;->get(I)Ljava/lang/Object;"),
        "M_AL_INIT_CAP": d6.find_idx("method", "Ljava/util/ArrayList;-><init>(I)V"),
        "M_AL_ADD": d6.find_idx("method", "Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z"),
        "M_AL_SIZE": d6.find_idx("method", "Ljava/util/ArrayList;->size()I"),
        "M_DATE_GET_TIME": d6.find_idx("method", "Ljava/util/Date;->getTime()J"),
        "M_SYS_TIME": d6.find_idx("method", "Ljava/lang/System;->currentTimeMillis()J"),
        "M_OBJ_HASH": d6.find_idx("method", "Lio/reactivex/internal/functions/ObjectHelper;->hashCode(Ljava/lang/Object;)I"),
        "M_GET_CC": d6.find_idx("method", "Lcom/liesheng/haylou/ui/main/WebViewActivity;->getCountryCode()I"),
        # Collision-free MMKV keys reusing Kotlin data-class toString() fragments
        "STR_KEY_AUTO_PAUSED": d6.find_idx("string", ", hideCyclingForbiddenRoads="),
        "STR_KEY_AUTO_TRIGGER": d6.find_idx("string", ", movingTime="),
        "STR_KEY_LOW_SINCE": d6.find_idx("string", ", freeTime="),
        "STR_KEY_LAST_TIME": d6.find_idx("string", ", stepHour="),
        "STR_KEY_LAST_LAT": d6.find_idx("string", ", avgStepStride="),
        "STR_KEY_LAST_LON": d6.find_idx("string", ", stride="),
        "STR_KEY_STREAK": d6.find_idx("string", ", step="),
    }

    def _swap_or_refresh(target_info, host_info, regs, ins, outs, build_fn, swapped_min_words, stub_ret_int=False):
        if target_info["insns_size"] >= swapped_min_words:
            insns = build_fn(target_info["insns_size"])
            struct.pack_into("<4H2I", buf, target_info["code_off"], regs, ins, outs, 0, 0, target_info["insns_size"])
            buf[target_info["code_off"] + 16 : target_info["code_off"] + 16 + len(insns)] = insns
            return
        assert target_info["code_pos_len"] == 4 and host_info["code_pos_len"] == 4
        insns = build_fn(host_info["insns_size"])
        struct.pack_into("<4H2I", buf, host_info["code_off"], regs, ins, outs, 0, 0, host_info["insns_size"])
        buf[host_info["code_off"] + 16 : host_info["code_off"] + 16 + len(insns)] = insns

        stub = DalvikAssembler()
        stub.const4(0, 0)
        if stub_ret_int:
            stub.return_int(0)
        else:
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

    # 1) ObjectHelper.hashCode(Object)I <-> SportTable.copy$default (649w)
    m_obj_hash = d6.find_method_info(
        "Lio/reactivex/internal/functions/ObjectHelper;",
        "Lio/reactivex/internal/functions/ObjectHelper;->hashCode(Ljava/lang/Object;)I",
    )
    m_host_sport = d6.find_method_info(
        "Lcom/liesheng/lib_room/table/SportTable;",
        "Lcom/liesheng/lib_room/table/SportTable;->copy$default(Lcom/liesheng/lib_room/table/SportTable;Ljava/util/Date;Ljava/lang/String;Ljava/util/Date;IIIIILjava/lang/String;FIIIIIIIIII[I[I[ILjava/util/List;IZZZLjava/lang/Integer;IIIII[IIIIIJLjava/lang/String;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;IIIILjava/lang/Object;)Lcom/liesheng/lib_room/table/SportTable;",
    )
    _swap_or_refresh(
        m_obj_hash, m_host_sport, regs=26, ins=1, outs=9,
        build_fn=lambda pad: _build_cycling_obj_helper_insns(d6, refs, pad),
        swapped_min_words=600,
    )

    # 2) WebViewActivity.getCountryCode()I <-> SportBasicTable.copy$default (571w)
    m_get_cc = d6.find_method_info(
        "Lcom/liesheng/haylou/ui/main/WebViewActivity;",
        "Lcom/liesheng/haylou/ui/main/WebViewActivity;->getCountryCode()I",
    )
    # Promote getCountryCode() from private static (0x0a) to public static (0x09) so
    # SportRecordWidgetDataLoader and CommonUtil can invoke it across packages
    if m_get_cc["access_flags"] == 0x0A:
        buf[m_get_cc["acc_pos"]] = 0x09
    m_host_basic = d6.find_method_info(
        "Lcom/liesheng/lib_room/table/SportBasicTable;",
        "Lcom/liesheng/lib_room/table/SportBasicTable;->copy$default(Lcom/liesheng/lib_room/table/SportBasicTable;Ljava/util/Date;Ljava/lang/String;Ljava/util/Date;IIIIILjava/lang/String;FIIIIIIIIIIIZZZLjava/lang/Integer;IIIIIIIIIJLjava/lang/String;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;IIIIILjava/lang/Object;)Lcom/liesheng/lib_room/table/SportBasicTable;",
    )
    _swap_or_refresh(
        m_get_cc, m_host_basic, regs=33, ins=0, outs=9,
        build_fn=lambda pad: _build_cycling_backfill_insns(d6, refs, pad),
        swapped_min_words=500,
    )

    # 3) IDataHelper.N(StepDataTable)V <-> StepDetailsList.copy$default (255w)
    m_idh_n = d6.find_method_info(
        "Lcom/liesheng/haylou/db/datahelper/IDataHelper;",
        "Lcom/liesheng/haylou/db/datahelper/IDataHelper;->N(Lcom/liesheng/lib_room/table/StepDataTable;)V",
    )
    m_host_step_det = d6.find_method_info(
        "Lcom/liesheng/module_home/bean/StepDetailsBean$StepDetailsList;",
        "Lcom/liesheng/module_home/bean/StepDetailsBean$StepDetailsList;->copy$default(Lcom/liesheng/module_home/bean/StepDetailsBean$StepDetailsList;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IFLjava/lang/String;FFIIII[I[I[II[F[F[ILjava/lang/String;ILjava/lang/Object;)Lcom/liesheng/module_home/bean/StepDetailsBean$StepDetailsList;",
    )
    pre = DalvikAssembler()
    pre.const4(0, 0)
    pre.invoke_virtual([4, 0], refs["M_STEP_SET_BASE"])
    pre.invoke_static([4], refs["M_OBJ_HASH"])
    pre_bytes = pre.assemble()

    if m_idh_n["insns_size"] < 200:
        assert m_idh_n["code_pos_len"] == 4 and m_host_step_det["code_pos_len"] == 4
        orig_n_bytes = dex_bytes[m_idh_n["code_off"] + 16 : m_idh_n["code_off"] + 16 + m_idh_n["insns_size"] * 2]
        combined = pre_bytes + orig_n_bytes
        pad_w = m_host_step_det["insns_size"] - len(combined) // 2
        assert pad_w >= 0
        struct.pack_into(
            "<4H2I", buf, m_host_step_det["code_off"],
            m_idh_n["regs_size"], m_idh_n["ins_size"], max(m_idh_n["outs_size"], 2), 0, 0, m_host_step_det["insns_size"],
        )
        buf[m_host_step_det["code_off"] + 16 : m_host_step_det["code_off"] + 16 + m_host_step_det["insns_size"] * 2] = (
            combined + b"\x00\x00" * pad_w
        )
        stub = DalvikAssembler()
        stub.const4(0, 0)
        stub.return_object(0)
        stub_bytes = stub.assemble(pad_to_words=m_idh_n["insns_size"])
        struct.pack_into("<4H2I", buf, m_idh_n["code_off"], m_host_step_det["ins_size"] + 1, m_host_step_det["ins_size"], 0, 0, 0, m_idh_n["insns_size"])
        buf[m_idh_n["code_off"] + 16 : m_idh_n["code_off"] + 16 + len(stub_bytes)] = stub_bytes
        buf[m_idh_n["code_pos"] : m_idh_n["code_pos"] + 4] = encode_uleb128_4bytes(m_host_step_det["code_off"])
        buf[m_host_step_det["code_pos"] : m_host_step_det["code_pos"] + 4] = encode_uleb128_4bytes(m_idh_n["code_off"])
    else:
        n_off = m_idh_n["code_off"] + 16
        n_total = m_idh_n["insns_size"] * 2
        cur_n = bytes(buf[n_off : n_off + n_total])
        if pre_bytes not in cur_n:
            end = n_total
            while end >= 2 and cur_n[end - 2 : end] == b"\x00\x00":
                end -= 2
            combined = pre_bytes + cur_n[:end]
            assert len(combined) <= n_total
            struct.pack_into(
                "<4H2I", buf, m_idh_n["code_off"],
                m_idh_n["regs_size"], m_idh_n["ins_size"], max(m_idh_n["outs_size"], 2), 0, 0, m_idh_n["insns_size"],
            )
            buf[n_off : n_off + n_total] = combined + b"\x00" * (n_total - len(combined))

    # 4) IDataHelper.u(RealStepData)V <-> UserInfoTable.copy$default (420w)
    m_idh_u = d6.find_method_info(
        "Lcom/liesheng/haylou/db/datahelper/IDataHelper;",
        "Lcom/liesheng/haylou/db/datahelper/IDataHelper;->u(Lcom/yingsheng/protocol/data/bean/RealStepData;)V",
    )
    m_host_user = d6.find_method_info(
        "Lcom/liesheng/lib_room/table/UserInfoTable;",
        "Lcom/liesheng/lib_room/table/UserInfoTable;->copy$default(Lcom/liesheng/lib_room/table/UserInfoTable;Ljava/lang/Long;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IILjava/lang/String;IILjava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;FIILjava/lang/Object;)Lcom/liesheng/lib_room/table/UserInfoTable;",
    )
    _swap_or_refresh(
        m_idh_u, m_host_user, regs=20, ins=2, outs=11,
        build_fn=lambda pad: _build_idata_u_insns(d6, refs, pad),
        swapped_min_words=300,
    )

    # 5) SportRunningManager.h(Context, Z)V <-> ClockReminderHelperKt.parseCustomReminder2Code(String)I (207w)
    m_srm_h = d6.find_method_info(
        "Lcom/liesheng/hayloufun/sport/running/SportRunningManager;",
        "Lcom/liesheng/hayloufun/sport/running/SportRunningManager;->h(Landroid/content/Context;Z)V",
    )
    m_host_clock = d6.find_method_info(
        "Lcom/liesheng/haylou/ui/device/data/ClockReminderHelperKt;",
        "Lcom/liesheng/haylou/ui/device/data/ClockReminderHelperKt;->parseCustomReminder2Code(Ljava/lang/String;)I",
    )
    if m_srm_h["insns_size"] < 200:
        assert m_srm_h["code_pos_len"] == 4 and m_host_clock["code_pos_len"] == 4
        orig_h = dex_bytes[m_srm_h["code_off"] + 16 : m_srm_h["code_off"] + 16 + m_srm_h["insns_size"] * 2]
        # Split at +0083 (131 words = 262 bytes), right before `new-instance v6, Intent` (0x22)
        assert orig_h[0x83 * 2] == 0x22, f"Unexpected opcode at SportRunningManager.h+0083: 0x{orig_h[0x83*2]:02x}"
        mid = DalvikAssembler()
        mid.invoke_static([], refs["M_MMKV_DEFAULT"])
        mid.move_result_object(0)
        mid.if_eqz(0, "h_stop_gps")
        mid.const_string(2, refs["STR_KEY_AUTO_TRIGGER"])
        mid.const4(3, 0)
        mid.invoke_virtual([0, 2, 3], refs["M_MMKV_DEC_BOOL"])
        mid.move_result(4)
        mid.if_eqz(4, "h_manual")
        mid.invoke_virtual([0, 2, 3], refs["M_MMKV_ENC_BOOL"])  # clear autoTrigger, keep GPS alive!
        mid.return_void()
        mid.label("h_manual")
        mid.const_string(2, refs["STR_KEY_AUTO_PAUSED"])
        mid.invoke_virtual([0, 2, 3], refs["M_MMKV_ENC_BOOL"])  # clear autoPaused on manual pause
        mid.label("h_stop_gps")
        combined_h = orig_h[: 0x83 * 2] + mid.assemble() + orig_h[0x83 * 2 :]
        pad_w = m_host_clock["insns_size"] - len(combined_h) // 2
        assert pad_w >= 0, f"SportRunningManager.h overflow: {len(combined_h)//2} > {m_host_clock['insns_size']}"
        struct.pack_into(
            "<4H2I", buf, m_host_clock["code_off"],
            m_srm_h["regs_size"], m_srm_h["ins_size"], max(m_srm_h["outs_size"], 3), 0, 0, m_host_clock["insns_size"],
        )
        buf[m_host_clock["code_off"] + 16 : m_host_clock["code_off"] + 16 + m_host_clock["insns_size"] * 2] = (
            combined_h + b"\x00\x00" * pad_w
        )
        stub = DalvikAssembler()
        stub.const4(0, 0)
        stub.return_int(0)
        stub_bytes = stub.assemble(pad_to_words=m_srm_h["insns_size"])
        struct.pack_into("<4H2I", buf, m_srm_h["code_off"], m_host_clock["ins_size"] + 1, m_host_clock["ins_size"], 0, 0, 0, m_srm_h["insns_size"])
        buf[m_srm_h["code_off"] + 16 : m_srm_h["code_off"] + 16 + len(stub_bytes)] = stub_bytes
        buf[m_srm_h["code_pos"] : m_srm_h["code_pos"] + 4] = encode_uleb128_4bytes(m_host_clock["code_off"])
        buf[m_host_clock["code_pos"] : m_host_clock["code_pos"] + 4] = encode_uleb128_4bytes(m_srm_h["code_off"])

    # 6) SportRunningManager.b(Context, Z)V in-place (+001a..+002c): clear auto-pause flags on resume
    m_srm_b = d6.find_method_info(
        "Lcom/liesheng/hayloufun/sport/running/SportRunningManager;",
        "Lcom/liesheng/hayloufun/sport/running/SportRunningManager;->b(Landroid/content/Context;Z)V",
    )
    b_insns = m_srm_b["code_off"] + 16
    b_patch = DalvikAssembler()
    b_patch.invoke_static([], refs["M_MMKV_DEFAULT"])
    b_patch.move_result_object(4)
    b_patch.if_eqz(4, "b_clr_done")
    b_patch.const_string(5, refs["STR_KEY_AUTO_PAUSED"])
    b_patch.invoke_virtual([4, 5, 2], refs["M_MMKV_ENC_BOOL"])  # v2 is 0 (false)
    b_patch.const_string(5, refs["STR_KEY_LOW_SINCE"])
    b_patch.const_wide16(6, 0)
    b_patch.invoke_virtual([4, 5, 6, 7], refs["M_MMKV_ENC_LONG"])
    b_patch.label("b_clr_done")
    b_patch_bytes = b_patch.assemble(pad_to_words=0x2D - 0x1A)
    assert len(b_patch_bytes) == (0x2D - 0x1A) * 2
    if bytes(buf[b_insns + 0x1A * 2 : b_insns + 0x2D * 2]) != b_patch_bytes:
        assert buf[b_insns + 0x1A * 2] == 0x22, "Unexpected bytecode at SportRunningManager.b+001a"
        buf[b_insns + 0x1A * 2 : b_insns + 0x2D * 2] = b_patch_bytes
        buf[b_insns + 0x42 * 2 : b_insns + 0x47 * 2] = b"\x00\x00" * 5  # nop dead Log("startLocation")

    # 7) SportRunningManager.onLocationChange(Location)V in-place (+001a..+0033, outside all try blocks)
    m_on_loc = d6.find_method_info(
        "Lcom/liesheng/hayloufun/sport/running/SportRunningManager;",
        "Lcom/liesheng/hayloufun/sport/running/SportRunningManager;->onLocationChange(Landroid/location/Location;)V",
        allow_tries=True,
    )
    loc_insns = m_on_loc["code_off"] + 16
    loc_hook = DalvikAssembler()
    loc_hook.invoke_static_range(33, 1, refs["M_OBJ_HASH"])
    loc_hook.move_result(0)
    loc_hook.if_nez(0, "loc_continue")
    loc_hook.return_void()
    for _ in range((0x34 - 0x1A) - 7):
        loc_hook.nop()
    loc_hook.label("loc_continue")
    loc_hook_bytes = loc_hook.assemble()
    assert len(loc_hook_bytes) == (0x34 - 0x1A) * 2
    if bytes(buf[loc_insns + 0x1A * 2 : loc_insns + 0x34 * 2]) != loc_hook_bytes:
        assert buf[loc_insns + 0x1A * 2] == 0x63, "Unexpected bytecode at onLocationChange+001a"
        buf[loc_insns + 0x1A * 2 : loc_insns + 0x34 * 2] = loc_hook_bytes

    # 8) CommonUtil.z(SportTable, Z, String)V in-place (+0146..+018a, inside existing try block):
    #    run cycling backfill immediately after SportDao.insert (before Cloud/Strava upload)
    call_cc_seq = struct.pack("<HHH", 0x0071, refs["M_GET_CC"], 0x0000)
    _hook_common_util_z(buf, d6, call_cc_seq)

    # 9) Home IO backfill trigger on SportRecordWidgetDataLoader.f() (runs on Dispatchers.IO on every
    #    Home open, right before reading SportTable — 100% independent of --vitality-vo2 / --unlock-cards!)
    _hook_sport_record_loader(buf, d6, call_cc_seq)

    out = recompute_dex_checksums(buf)
    print(f"[+] classes6.dex Cycling Fixes patched (Adler: {struct.unpack_from('<I', out, 8)[0]:08x})")
    return out


def _hook_common_util_z(buf: bytearray, d6: DexFile, seq_bytes: bytes) -> None:
    """Append a composable, idempotent hook at CommonUtil.z+0146..+018a (before return-void)."""
    m_cz = d6.find_method_info(
        "Lcom/liesheng/haylou/utils/CommonUtil;",
        "Lcom/liesheng/haylou/utils/CommonUtil;->z(Lcom/liesheng/lib_room/table/SportTable;ZLjava/lang/String;)V",
        allow_tries=True,
    )
    base = m_cz["code_off"] + 16 + 0x146 * 2
    slot_bytes = (0x18B - 0x146) * 2
    cur = bytes(buf[base : base + slot_bytes])

    if cur[0] == 0x1A:
        new_body = seq_bytes + b"\x0e\x00"
    elif cur[0] in (0x12, 0x71):
        end = slot_bytes
        while end >= 2 and cur[end - 2 : end] == b"\x00\x00":
            end -= 2
        assert end >= 2 and cur[end - 2 : end] == b"\x0e\x00", (
            f"Unexpected terminator at CommonUtil.z+0146: {cur[:min(end, 16)].hex()}"
        )
        body = cur[: end - 2]
        if seq_bytes in body:
            return
        new_body = body + seq_bytes + b"\x0e\x00"
    else:
        raise AssertionError(f"Unexpected bytecode at CommonUtil.z+0146: {cur[:8].hex()}")

    assert len(new_body) <= slot_bytes
    buf[base : base + slot_bytes] = new_body + b"\x00" * (slot_bytes - len(new_body))


def _hook_sport_record_loader(buf: bytearray, d6: DexFile, seq_bytes: bytes) -> None:
    """Prepend a composable, idempotent hook onto SportRecordWidgetDataLoader.f() (runs on Dispatchers.IO)."""
    m_sr = d6.find_method_info(
        "Lcom/liesheng/module_home/homeV2/dataloader/SportRecordWidgetDataLoader;",
        "Lcom/liesheng/module_home/homeV2/dataloader/SportRecordWidgetDataLoader;->f(Lkotlin/coroutines/jvm/internal/SuspendLambda;)Ljava/lang/Object;",
    )
    m_host = d6.find_method_info(
        "Lcom/liesheng/lib_service/bean/SportRecordUiModel;",
        "Lcom/liesheng/lib_service/bean/SportRecordUiModel;->copy$default(Lcom/liesheng/lib_service/bean/SportRecordUiModel;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;JIFLjava/lang/String;IJJIIILjava/lang/String;IIIIIIILjava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;ILjava/lang/Integer;ILjava/lang/Object;)Lcom/liesheng/lib_service/bean/SportRecordUiModel;",
    )
    if m_sr["insns_size"] < 200:
        assert m_sr["code_pos_len"] == 4 and m_host["code_pos_len"] == 4
        orig_sr = bytes(buf[m_sr["code_off"] + 16 : m_sr["code_off"] + 16 + m_sr["insns_size"] * 2])
        combined = seq_bytes + orig_sr
        pad_w = m_host["insns_size"] - len(combined) // 2
        assert pad_w >= 0
        struct.pack_into(
            "<4H2I", buf, m_host["code_off"],
            m_sr["regs_size"], m_sr["ins_size"], m_sr["outs_size"], 0, 0, m_host["insns_size"],
        )
        buf[m_host["code_off"] + 16 : m_host["code_off"] + 16 + m_host["insns_size"] * 2] = (
            combined + b"\x00\x00" * pad_w
        )
        stub = DalvikAssembler()
        stub.const4(0, 0)
        stub.return_object(0)
        stub_bytes = stub.assemble(pad_to_words=m_sr["insns_size"])
        struct.pack_into(
            "<4H2I", buf, m_sr["code_off"],
            m_host["ins_size"] + 1, m_host["ins_size"], 0, 0, 0, m_sr["insns_size"],
        )
        buf[m_sr["code_off"] + 16 : m_sr["code_off"] + 16 + len(stub_bytes)] = stub_bytes
        buf[m_sr["code_pos"] : m_sr["code_pos"] + 4] = encode_uleb128_4bytes(m_host["code_off"])
        buf[m_host["code_pos"] : m_host["code_pos"] + 4] = encode_uleb128_4bytes(m_sr["code_off"])
        return

    # Already swapped into 409w host slot: parse leading hooks, skip if already present, else append before orig_sr
    body_off = m_sr["code_off"] + 16
    total_bytes = m_sr["insns_size"] * 2
    cur = bytes(buf[body_off : body_off + total_bytes])
    # Trim trailing 0x0000 nop padding (orig_sr ends with return-object 0x11, never 0x0000)
    end = total_bytes
    while end >= 2 and cur[end - 2 : end] == b"\x00\x00":
        end -= 2
    active = cur[:end]
    # Scan existing leading hooks (6-byte 0x0071 invoke-static{} or 8-byte 0x0012+0x1071 const4+invoke-static{v0})
    pos = 0
    hooks = []
    while pos < len(active):
        if pos + 6 <= len(active) and active[pos : pos + 2] == b"\x71\x00":
            hooks.append(active[pos : pos + 6])
            pos += 6
        elif pos + 8 <= len(active) and active[pos : pos + 2] == b"\x12\x00" and active[pos + 2 : pos + 4] == b"\x71\x10":
            hooks.append(active[pos : pos + 8])
            pos += 8
        else:
            break
    if seq_bytes in hooks:
        return
    hooks.append(seq_bytes)
    combined = b"".join(hooks) + active[pos:]
    assert len(combined) <= total_bytes
    buf[body_off : body_off + total_bytes] = combined + b"\x00" * (total_bytes - len(combined))


# --------------------------------------------------------------------------- #
# 3e. classes6.dex — VoIP Incoming Call Alerts + Wrist Reject (--voip-calls)
# --------------------------------------------------------------------------- #

def _encode_uleb128(val: int) -> bytes:
    out = bytearray()
    while True:
        b = val & 0x7F
        val >>= 7
        if val:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _build_voip_call_helper_insns(refs: dict, insns_words: int = 792) -> tuple[bytes, list[tuple[int, int, int]]]:
    """
    Build Lcom/jieli/jl_bt_ota/util/CommonUtil;->checkAllNotNull([Ljava/lang/Object;)V
    (swapped into OtaCmdHandler.parseDataToCmd, 812w -> 792w insns + 3 try_items/catch_alls,
    regs=14, ins=1, outs=6, p0=v13).

    Dispatch on Object[] arr (v13):
      - len == 2 ({sbn, sbn}):    Notification posted -> detect VoIP incoming call (WhatsApp,
                                  WhatsApp Business, Messenger, Instagram, Telegram, Viber, Discord)
                                  via BOTH modern Android 12+ Notification.CallStyle extras
                                  ("android.declineIntent" / "android.hangUpIntent" /
                                  "android.callPerson") AND legacy 2-action call notifications,
                                  ring Watch 4S with real caller name via BLE 0x41, cache Decline
                                  PendingIntent, set arr[0]=null to suppress duplicate text alert.
      - len == 1, arr[0] != null: Notification removed -> stop Watch 4S ringing if matching VoIP pkg
                                  AND removed notification was a call (ongoing/insistent or has
                                  "android.declineIntent"), ignoring unrelated chat dismissals.
      - len == 1, arr[0] == null: Watch 4S REJECT_INCOMING (IDataHelper.g) -> execute cached VoIP
                                  Decline PendingIntent inside try/catch, stop ringing, set arr[0]=arr.
      - len == 0 ({}):            Phone answered/missed (AppApplication$b.a/.c) -> stop VoIP ringing.
    """
    KEY_DECLINE = b"android.declineIntent"
    KEY_HANGUP = b"android.hangUpIntent"
    KEY_PERSON = b"android.callPerson"

    a = DalvikAssembler()

    def emit_str(dst_reg: int, tmp_reg: int, raw_len: int, payload_label: str):
        a.const16(tmp_reg, raw_len)
        a.new_array(tmp_reg, tmp_reg, refs["T_BYTE_ARR"])
        a.fill_array_data(tmp_reg, payload_label)
        a.new_instance(dst_reg, refs["T_STRING"])
        a.invoke_direct([dst_reg, tmp_reg], refs["M_STR_INIT_BYTES"])

    a.if_eqz(13, "v_ret")
    a.sget_object(12, refs["F_Z7I_A"])
    a.if_eqz(12, "v_ret")

    a.array_length(0, 13)
    a.if_eqz(0, "br_clear")
    a.const4(1, 2)
    a.if_eq(0, 1, "br_posted")
    a.const4(1, 0)
    a.aget_object(11, 13, 1)
    a.if_eqz(11, "br_reject")

    # ---- Branch B: Notification removed (arr = {sbn}) ----
    a.check_cast(11, refs["T_SBN"])
    a.invoke_virtual([11], refs["M_SBN_PKG"])
    a.move_result_object(10)
    a.if_eqz(10, "v_ret")
    a.const_string(0, refs["STR_KEY_INCOMING"])
    a.invoke_virtual([12, 0], refs["M_MAP_GET"])
    a.move_result_object(1)
    a.if_eqz(1, "v_ret")
    a.invoke_virtual([10, 1], refs["M_STR_EQ"])
    a.move_result(0)
    a.if_eqz(0, "v_ret")
    # Only clear ringing if removed notification was actually a call (ongoing/insistent or CallStyle declineIntent)
    a.invoke_virtual([11], refs["M_SBN_NOTIF"])
    a.move_result_object(9)
    a.if_eqz(9, "br_clear")
    a.iget(0, 9, refs["F_NOTIF_FLAGS"])
    a.and_int_lit8(0, 0, 6)
    a.if_nez(0, "br_clear")
    a.iget_object(5, 9, refs["F_NOTIF_EXTRAS"])
    a.if_eqz(5, "v_ret")
    emit_str(1, 0, len(KEY_DECLINE), "data_decline")
    a.invoke_virtual([5, 1], refs["M_BASE_CONTAINS_KEY"])
    a.move_result(0)
    a.if_eqz(0, "v_ret")

    # ---- Branch D: Clear active VoIP call & send BLE 0x41 off-hook ----
    a.label("br_clear")
    a.const_string(0, refs["STR_KEY_INCOMING"])
    a.invoke_virtual([12, 0], refs["M_MAP_REMOVE"])
    a.move_result_object(6)
    a.const_string(0, refs["STR_KEY_REJECT"])
    a.invoke_virtual([12, 0], refs["M_MAP_REMOVE"])
    a.if_eqz(6, "v_ret")

    a.label("send_offhook")
    a.const_class(0, refs["T_Z7D"])
    a.invoke_static([0], refs["M_Z7I_C"])
    a.move_result_object(0)
    a.if_eqz(0, "v_ret")
    a.check_cast(0, refs["T_Z7D"])
    a.invoke_static([], refs["M_SYS_TIME"])
    a.move_result_wide(1)
    a.const4(3, 0)  # isIncoming = false -> sendCall0ffHook()
    a.const_string(4, refs["STR_EMPTY"])
    a.const_string(5, refs["STR_EMPTY"])
    a.invoke_interface_range(0, 6, refs["M_Z7D_C"])
    a.return_void()

    # ---- Branch C: Watch 4S Reject button -> fire cached Decline PendingIntent ----
    a.label("br_reject")
    a.const_string(0, refs["STR_KEY_REJECT"])
    a.invoke_virtual([12, 0], refs["M_MAP_REMOVE"])
    a.move_result_object(6)
    a.const_string(0, refs["STR_KEY_INCOMING"])
    a.invoke_virtual([12, 0], refs["M_MAP_REMOVE"])
    a.if_eqz(6, "v_ret")
    a.check_cast(6, refs["T_PENDING_INTENT"])
    a.const4(0, 0)
    a.aput_object(13, 13, 0)  # arr[0] = non-null -> handled VoIP reject
    a.move_object(0, 6)
    a.invoke_static([], refs["M_HYAPP_CTX"])
    a.move_result_object(1)
    a.const4(2, 0)
    a.const4(3, 0)
    a.label("try_pi_start")
    a.invoke_virtual([0, 1, 2, 3], refs["M_PI_SEND"])
    a.label("try_pi_end")
    a.goto16("send_offhook")
    a.label("catch_pi")
    a.move_exception(0)
    a.goto16("send_offhook")

    # ---- Branch A: Notification posted (arr = {sbn, sbn}) ----
    a.label("br_posted")
    a.const4(0, 0)
    a.aget_object(11, 13, 0)
    a.if_eqz(11, "v_ret")
    a.check_cast(11, refs["T_SBN"])
    a.invoke_virtual([11], refs["M_SBN_PKG"])
    a.move_result_object(10)
    a.if_eqz(10, "v_ret")

    # Match supported VoIP packages
    for skey in (
        "STR_PKG_WA", "STR_PKG_WAB", "STR_PKG_ORCA",
        "STR_PKG_IG", "STR_PKG_TG", "STR_PKG_VIBER", "STR_PKG_DISCORD",
    ):
        a.const_string(0, refs[skey])
        a.invoke_virtual([10, 0], refs["M_STR_EQ"])
        a.move_result(0)
        a.if_nez(0, "post_pkg_ok")
    a.goto16("v_ret")

    a.label("post_pkg_ok")
    a.invoke_virtual([11], refs["M_SBN_NOTIF"])
    a.move_result_object(9)
    a.if_eqz(9, "v_ret")
    a.iget_object(5, 9, refs["F_NOTIF_EXTRAS"])

    # Path 1: Modern Android 12+ Notification.CallStyle extras ("android.declineIntent" / "android.hangUpIntent")
    a.if_eqz(5, "post_legacy_check")
    emit_str(1, 0, len(KEY_DECLINE), "data_decline")
    a.invoke_virtual([5, 1], refs["M_BASE_CONTAINS_KEY"])
    a.move_result(0)
    a.if_eqz(0, "post_chk_hangup")
    a.label("try_dec_start")
    a.invoke_virtual([5, 1], refs["M_BUNDLE_GET_PARCELABLE"])
    a.label("try_dec_end")
    a.move_result_object(6)
    a.instance_of(0, 6, refs["T_PENDING_INTENT"])
    a.if_eqz(0, "post_legacy_check")
    a.check_cast(6, refs["T_PENDING_INTENT"])
    a.goto16("post_have_decline")

    a.label("catch_dec")
    a.move_exception(0)
    a.goto16("post_legacy_check")

    # CallStyle ongoing call transition ("android.hangUpIntent"): stop watch ringing if we were ringing for this pkg
    a.label("post_chk_hangup")
    emit_str(1, 0, len(KEY_HANGUP), "data_hangup")
    a.invoke_virtual([5, 1], refs["M_BASE_CONTAINS_KEY"])
    a.move_result(0)
    a.if_eqz(0, "post_legacy_check")
    a.const_string(0, refs["STR_KEY_INCOMING"])
    a.invoke_virtual([12, 0], refs["M_MAP_GET"])
    a.move_result_object(1)
    a.if_eqz(1, "v_ret")
    a.invoke_virtual([10, 1], refs["M_STR_EQ"])
    a.move_result(0)
    a.if_eqz(0, "v_ret")
    a.const4(0, 0)
    a.const4(1, 0)
    a.aput_object(1, 13, 0)  # consume ongoing-call transition notification
    a.goto16("br_clear")

    # Path 2: Legacy / custom non-CallStyle incoming call notifications
    a.label("post_legacy_check")
    # Must have FLAG_ONGOING_EVENT (0x02) or FLAG_INSISTENT (0x04) — excludes all regular chat notifications
    a.iget(0, 9, refs["F_NOTIF_FLAGS"])
    a.and_int_lit8(0, 0, 6)
    a.if_eqz(0, "v_ret")

    a.iget_object(8, 9, refs["F_NOTIF_ACTIONS"])
    a.if_eqz(8, "v_ret")
    a.array_length(0, 8)
    a.const4(1, 2)
    a.if_eq(0, 1, "post_chk_2act")

    # Legacy 1-action ongoing call transition while ringing -> clear watch alert
    a.const4(1, 1)
    a.if_ne(0, 1, "v_ret")
    a.const_string(0, refs["STR_KEY_INCOMING"])
    a.invoke_virtual([12, 0], refs["M_MAP_GET"])
    a.move_result_object(1)
    a.if_eqz(1, "v_ret")
    a.invoke_virtual([10, 1], refs["M_STR_EQ"])
    a.move_result(0)
    a.if_eqz(0, "v_ret")
    a.const4(0, 0)
    a.const4(1, 0)
    a.aput_object(1, 13, 0)
    a.goto16("br_clear")

    # Legacy incoming call notification: exactly 2 actions (Decline, Answer), neither with RemoteInput
    a.label("post_chk_2act")
    a.const4(0, 0)
    a.aget_object(7, 8, 0)  # v7 = actions[0] (Decline)
    a.if_eqz(7, "v_ret")
    a.invoke_virtual([7], refs["M_ACT_REMOTE"])
    a.move_result_object(0)
    a.if_eqz(0, "act0_ok")
    a.array_length(0, 0)
    a.if_nez(0, "v_ret")

    a.label("act0_ok")
    a.const4(0, 1)
    a.aget_object(1, 8, 0)  # v1 = actions[1] (Answer)
    a.if_eqz(1, "v_ret")
    a.invoke_virtual([1], refs["M_ACT_REMOTE"])
    a.move_result_object(0)
    a.if_eqz(0, "act1_ok")
    a.array_length(0, 0)
    a.if_nez(0, "v_ret")

    a.label("act1_ok")
    a.iget_object(6, 7, refs["F_ACT_INTENT"])  # v6 = Decline PendingIntent
    a.if_eqz(6, "v_ret")

    # Common incoming call path (v6 = Decline PendingIntent, v5 = Notification.extras or null)
    a.label("post_have_decline")
    a.const_string(0, refs["STR_KEY_REJECT"])
    a.invoke_virtual([12, 0, 6], refs["M_MAP_PUT"])

    # Dedupe reposted ringing updates for the same VoIP package
    a.const_string(0, refs["STR_KEY_INCOMING"])
    a.invoke_virtual([12, 0], refs["M_MAP_GET"])
    a.move_result_object(1)
    a.if_eqz(1, "post_start_ring")
    a.invoke_virtual([10, 1], refs["M_STR_EQ"])
    a.move_result(0)
    a.if_nez(0, "post_consume")

    a.label("post_start_ring")
    a.const_string(0, refs["STR_KEY_INCOMING"])
    a.invoke_virtual([12, 0, 10], refs["M_MAP_PUT"])

    # Extract real caller display name:
    #   1) extras["android.title"]
    #   2) CallStyle extras["android.callPerson"].getName() (reflection inside try/catch)
    #   3) fallback to package name (v10)
    a.const_string(4, refs["STR_EMPTY"])
    a.if_eqz(5, "title_fb")
    a.const_string(1, refs["STR_ANDROID_TITLE"])
    a.invoke_virtual([5, 1], refs["M_BUNDLE_GET_CS"])
    a.move_result_object(0)
    a.if_eqz(0, "title_try_person")
    a.invoke_virtual([0], refs["M_OBJ_TOSTR"])
    a.move_result_object(4)
    a.if_eqz(4, "title_try_person")
    a.invoke_virtual([4], refs["M_STR_LEN"])
    a.move_result(0)
    a.if_gtz(0, "title_ok")

    a.label("title_try_person")
    emit_str(1, 0, len(KEY_PERSON), "data_person")
    a.invoke_virtual([5, 1], refs["M_BASE_CONTAINS_KEY"])
    a.move_result(0)
    a.if_eqz(0, "title_fb")
    a.label("try_per_start")
    a.invoke_virtual([5, 1], refs["M_BUNDLE_GET_PARCELABLE"])
    a.move_result_object(0)
    a.if_eqz(0, "title_fb")
    a.invoke_virtual([0], refs["M_OBJ_GET_CLASS"])
    a.move_result_object(1)
    a.const_string(2, refs["STR_GET_NAME"])
    a.filled_new_array([], refs["T_CLASS_ARR"])
    a.move_result_object(3)
    a.invoke_virtual([1, 2, 3], refs["M_CLS_GET_METHOD"])
    a.move_result_object(1)
    a.filled_new_array([], refs["T_OBJ_ARR"])
    a.move_result_object(3)
    a.invoke_virtual([1, 0, 3], refs["M_METH_INVOKE"])
    a.move_result_object(0)
    a.if_eqz(0, "title_fb")
    a.invoke_virtual([0], refs["M_OBJ_TOSTR"])
    a.label("try_per_end")
    a.move_result_object(0)
    a.if_eqz(0, "title_fb")
    a.invoke_virtual([0], refs["M_STR_LEN"])
    a.move_result(1)
    a.if_lez(1, "title_fb")
    a.move_object(4, 0)
    a.goto16("title_ok")

    a.label("catch_per")
    a.move_exception(0)

    a.label("title_fb")
    a.move_object(4, 10)

    a.label("title_ok")
    a.const_class(0, refs["T_Z7D"])
    a.invoke_static([0], refs["M_Z7I_C"])
    a.move_result_object(0)
    a.if_eqz(0, "post_consume")
    a.check_cast(0, refs["T_Z7D"])
    a.invoke_static([], refs["M_SYS_TIME"])
    a.move_result_wide(1)
    a.const4(3, 1)  # isIncoming = true -> sendCallContactName(title, maxLen)
    a.const_string(5, refs["STR_EMPTY"])
    a.invoke_interface_range(0, 6, refs["M_Z7D_C"])

    a.label("post_consume")
    a.const4(0, 0)
    a.const4(1, 0)
    a.aput_object(1, 13, 0)  # arr[0] = null -> suppress regular message banner

    a.label("v_ret")
    a.return_void()

    # 4-byte aligned fill-array-data payloads (unreachable after return-void)
    a.array_data_bytes("data_decline", KEY_DECLINE)
    a.array_data_bytes("data_hangup", KEY_HANGUP)
    a.array_data_bytes("data_person", KEY_PERSON)

    insns = a.assemble(pad_to_words=insns_words)
    lbl = a.last_labels
    tries = [
        (lbl["try_pi_start"], lbl["try_pi_end"] - lbl["try_pi_start"], lbl["catch_pi"]),
        (lbl["try_dec_start"], lbl["try_dec_end"] - lbl["try_dec_start"], lbl["catch_dec"]),
        (lbl["try_per_start"], lbl["try_per_end"] - lbl["try_per_start"], lbl["catch_per"]),
    ]
    assert tries[0][0] < tries[1][0] < tries[2][0]
    assert all(cnt > 0 for _, cnt, _ in tries)
    return insns, tries


def patch_classes6_voip_calls(dex_bytes: bytes) -> bytes:
    """
    Patch classes6.dex with VoIP incoming call alerts & wrist reject for Watch 4S:
      1) CommonUtil.checkAllNotNull([Object;)V <-> OtaCmdHandler.parseDataToCmd (812w -> 792w + 3 try/catches)
      2) MsgNotifyService.onNotificationPosted in-place (+0006..+0022, outside try block)
      3) MsgNotifyService.onNotificationRemoved <-> Route.copy$default (187w)
      4) IDataHelper.g()V (REJECT_INCOMING) <-> WeatherInfo.copy$default (193w)
      5) AppApplication$b.a/.c (onCallMissedOrRejected / onCallAnswered) <->
         UploadSleepDetailsBean.copy$default (181w) & DialDetail.copy$default (179w)
    """
    print("[*] Patching classes6.dex (VoIP Incoming Call Alerts + Wrist Reject)...")
    d6 = DexFile(dex_bytes)
    buf = bytearray(dex_bytes)

    refs = {
        "T_SBN": d6.find_idx("type", "Landroid/service/notification/StatusBarNotification;"),
        "T_PENDING_INTENT": d6.find_idx("type", "Landroid/app/PendingIntent;"),
        "T_OBJ_ARR": d6.find_idx("type", "[Ljava/lang/Object;"),
        "T_CLASS_ARR": d6.find_idx("type", "[Ljava/lang/Class;"),
        "T_BYTE_ARR": d6.find_idx("type", "[B"),
        "T_STRING": d6.find_idx("type", "Ljava/lang/String;"),
        "T_Z7D": d6.find_idx("type", "Lz7/d;"),
        "F_Z7I_A": d6.find_idx("field", "Lz7/i;->a:Ljava/util/HashMap;"),
        "F_NOTIF_FLAGS": d6.find_idx("field", "Landroid/app/Notification;->flags:I"),
        "F_NOTIF_ACTIONS": d6.find_idx("field", "Landroid/app/Notification;->actions:[Landroid/app/Notification$Action;"),
        "F_NOTIF_EXTRAS": d6.find_idx("field", "Landroid/app/Notification;->extras:Landroid/os/Bundle;"),
        "F_ACT_INTENT": d6.find_idx("field", "Landroid/app/Notification$Action;->actionIntent:Landroid/app/PendingIntent;"),
        "M_VOIP_HELPER": d6.find_idx("method", "Lcom/jieli/jl_bt_ota/util/CommonUtil;->checkAllNotNull([Ljava/lang/Object;)V"),
        "M_SBN_PKG": d6.find_idx("method", "Landroid/service/notification/StatusBarNotification;->getPackageName()Ljava/lang/String;"),
        "M_SBN_NOTIF": d6.find_idx("method", "Landroid/service/notification/StatusBarNotification;->getNotification()Landroid/app/Notification;"),
        "M_ACT_REMOTE": d6.find_idx("method", "Landroid/app/Notification$Action;->getRemoteInputs()[Landroid/app/RemoteInput;"),
        "M_PI_SEND": d6.find_idx("method", "Landroid/app/PendingIntent;->send(Landroid/content/Context;ILandroid/content/Intent;)V"),
        "M_BUNDLE_GET_CS": d6.find_idx("method", "Landroid/os/Bundle;->getCharSequence(Ljava/lang/String;)Ljava/lang/CharSequence;"),
        "M_BUNDLE_GET_PARCELABLE": d6.find_idx("method", "Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;"),
        "M_BASE_CONTAINS_KEY": d6.find_idx("method", "Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z"),
        "M_STR_INIT_BYTES": d6.find_idx("method", "Ljava/lang/String;-><init>([B)V"),
        "M_OBJ_GET_CLASS": d6.find_idx("method", "Ljava/lang/Object;->getClass()Ljava/lang/Class;"),
        "M_CLS_GET_METHOD": d6.find_idx("method", "Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;"),
        "M_METH_INVOKE": d6.find_idx("method", "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;"),
        "M_OBJ_TOSTR": d6.find_idx("method", "Ljava/lang/Object;->toString()Ljava/lang/String;"),
        "M_STR_LEN": d6.find_idx("method", "Ljava/lang/String;->length()I"),
        "M_STR_EQ": d6.find_idx("method", "Ljava/lang/String;->equals(Ljava/lang/Object;)Z"),
        "M_MAP_GET": d6.find_idx("method", "Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;"),
        "M_MAP_PUT": d6.find_idx("method", "Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;"),
        "M_MAP_REMOVE": d6.find_idx("method", "Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;"),
        "M_Z7I_C": d6.find_idx("method", "Lz7/i;->c(Ljava/lang/Class;)Ljava/lang/Object;"),
        "M_Z7D_C": d6.find_idx("method", "Lz7/d;->c(JZLjava/lang/String;Ljava/lang/String;)V"),
        "M_HYAPP_CTX": d6.find_idx("method", "Lcom/liesheng/haylou/app/HyApplication;->getContext()Lcom/liesheng/haylou/app/HyApplication;"),
        "M_HANGUP_END": d6.find_idx("method", "Lcom/yingsheng/protocol/util/HangUpTelephonyUtil;->endCall(Landroid/content/Context;)Z"),
        "M_SYS_TIME": d6.find_idx("method", "Ljava/lang/System;->currentTimeMillis()J"),
        "STR_PKG_WA": d6.find_idx("string", "com.whatsapp"),
        "STR_PKG_WAB": d6.find_idx("string", "com.whatsapp.w4b"),
        "STR_PKG_ORCA": d6.find_idx("string", "com.facebook.orca"),
        "STR_PKG_IG": d6.find_idx("string", "com.instagram.android"),
        "STR_PKG_TG": d6.find_idx("string", "org.telegram.messenger"),
        "STR_PKG_VIBER": d6.find_idx("string", "com.viber.voip"),
        "STR_PKG_DISCORD": d6.find_idx("string", "com.discord"),
        "STR_ANDROID_TITLE": d6.find_idx("string", "android.title"),
        "STR_GET_NAME": d6.find_idx("string", "getName"),
        "STR_KEY_INCOMING": d6.find_idx("string", "INCOMING_CALL"),
        "STR_KEY_REJECT": d6.find_idx("string", "CALL_REJECT"),
        "STR_EMPTY": d6.find_idx("string", ""),
    }

    # 1) CommonUtil.checkAllNotNull([Ljava/lang/Object;)V (len=3) <-> OtaCmdHandler.parseDataToCmd (len=3, 812w)
    m_voip = d6.find_method_info(
        "Lcom/jieli/jl_bt_ota/util/CommonUtil;",
        "Lcom/jieli/jl_bt_ota/util/CommonUtil;->checkAllNotNull([Ljava/lang/Object;)V",
        allow_tries=True,
    )
    m_host_ota = d6.find_method_info(
        "Lcom/jieli/jl_rcsp/model/cmdHandler/OtaCmdHandler;",
        "Lcom/jieli/jl_rcsp/model/cmdHandler/OtaCmdHandler;->parseDataToCmd(Landroid/bluetooth/BluetoothDevice;Lcom/jieli/jl_rcsp/model/base/BasePacket;)Lcom/jieli/jl_rcsp/model/base/CommandBase;",
    )
    slot_bytes = 812 * 2  # Original OtaCmdHandler.parseDataToCmd body size (4-byte aligned code_item boundary)
    raw_insns, tries = _build_voip_call_helper_insns(refs, insns_words=None)
    handlers_buf = bytearray(_encode_uleb128(len(tries)))
    tries_buf = bytearray()
    for t_start, t_len, catch_pc in tries:
        h_off = len(handlers_buf)
        handlers_buf += b"\x00" + _encode_uleb128(catch_pc)
        tries_buf += struct.pack("<IHH", t_start, t_len, h_off)
    try_blob = bytes(tries_buf + handlers_buf)
    # Pick even helper_words so align4(16 + helper_words*2 + len(try_blob)) == 16 + slot_bytes EXACTLY,
    # keeping DEX sequential TYPE_CODE_ITEM iteration aligned with the very next code_item!
    helper_words = 2 * ((slot_bytes - len(try_blob)) // 4)
    assert len(raw_insns) <= helper_words * 2
    insns_voip = raw_insns + b"\x00" * (helper_words * 2 - len(raw_insns))
    assert ((len(insns_voip) + len(try_blob) + 3) & ~3) == slot_bytes

    if m_voip["insns_size"] >= 500:
        target_off = m_voip["code_off"]
        struct.pack_into("<4H2I", buf, target_off, 14, 1, 6, len(tries), 0, helper_words)
        buf[target_off + 16 : target_off + 16 + len(insns_voip)] = insns_voip
        buf[target_off + 16 + len(insns_voip) : target_off + 16 + len(insns_voip) + len(try_blob)] = try_blob
        rem = slot_bytes - len(insns_voip) - len(try_blob)
        buf[target_off + 16 + len(insns_voip) + len(try_blob) : target_off + 16 + slot_bytes] = b"\x00" * rem
    else:
        assert m_voip["code_pos_len"] == 3 and m_host_ota["code_pos_len"] == 3
        assert m_host_ota["insns_size"] * 2 == slot_bytes
        target_off = m_host_ota["code_off"]
        struct.pack_into("<4H2I", buf, target_off, 14, 1, 6, len(tries), 0, helper_words)
        buf[target_off + 16 : target_off + 16 + len(insns_voip)] = insns_voip
        buf[target_off + 16 + len(insns_voip) : target_off + 16 + len(insns_voip) + len(try_blob)] = try_blob
        rem = slot_bytes - len(insns_voip) - len(try_blob)
        buf[target_off + 16 + len(insns_voip) + len(try_blob) : target_off + 16 + slot_bytes] = b"\x00" * rem

        stub = DalvikAssembler()
        stub.const4(0, 0)
        stub.return_object(0)
        stub_bytes = stub.assemble(pad_to_words=m_voip["insns_size"])
        struct.pack_into(
            "<4H2I", buf, m_voip["code_off"],
            m_host_ota["ins_size"] + 1, m_host_ota["ins_size"], 0, 0, 0, m_voip["insns_size"],
        )
        buf[m_voip["code_off"] + 16 : m_voip["code_off"] + 16 + len(stub_bytes)] = stub_bytes
        enc_host = _encode_uleb128(m_host_ota["code_off"])
        enc_voip = _encode_uleb128(m_voip["code_off"])
        assert len(enc_host) == 3 and len(enc_voip) == 3
        buf[m_voip["code_pos"] : m_voip["code_pos"] + 3] = enc_host
        buf[m_host_ota["code_pos"] : m_host_ota["code_pos"] + 3] = enc_voip

    # 2) MsgNotifyService.onNotificationPosted(StatusBarNotification)V in-place (+0006..+0022, outside try[0])
    m_posted = d6.find_method_info(
        "Lcom/liesheng/haylou/service/MsgNotifyService;",
        "Lcom/liesheng/haylou/service/MsgNotifyService;->onNotificationPosted(Landroid/service/notification/StatusBarNotification;)V",
        allow_tries=True,
    )
    p_insns = m_posted["code_off"] + 16
    p_hook = DalvikAssembler()
    p_hook.filled_new_array([8, 8], refs["T_OBJ_ARR"])
    p_hook.move_result_object(1)
    p_hook.invoke_static([1], refs["M_VOIP_HELPER"])
    p_hook.const4(2, 0)
    p_hook.aget_object(2, 1, 2)
    p_hook.if_nez(2, "posted_cont")
    p_hook.return_void()
    for _ in range((0x23 - 0x06) - 13):
        p_hook.nop()
    p_hook.label("posted_cont")
    p_hook_bytes = p_hook.assemble()
    assert len(p_hook_bytes) == (0x23 - 0x06) * 2
    if bytes(buf[p_insns + 0x06 * 2 : p_insns + 0x23 * 2]) != p_hook_bytes:
        assert buf[p_insns + 0x06 * 2] == 0x55, "Unexpected bytecode at onNotificationPosted+0006"
        buf[p_insns + 0x06 * 2 : p_insns + 0x23 * 2] = p_hook_bytes

    def _prepend_and_swap(m_target, m_host, pre_bytes, swapped_min_words=150):
        if m_target["insns_size"] >= swapped_min_words:
            return
        assert m_target["code_pos_len"] == 4 and m_host["code_pos_len"] == 4
        orig_bytes = dex_bytes[m_target["code_off"] + 16 : m_target["code_off"] + 16 + m_target["insns_size"] * 2]
        combined = pre_bytes + orig_bytes
        pad_w = m_host["insns_size"] - len(combined) // 2
        assert pad_w >= 0
        struct.pack_into(
            "<4H2I", buf, m_host["code_off"],
            m_target["regs_size"], m_target["ins_size"], max(m_target["outs_size"], 2), 0, 0, m_host["insns_size"],
        )
        buf[m_host["code_off"] + 16 : m_host["code_off"] + 16 + m_host["insns_size"] * 2] = combined + b"\x00\x00" * pad_w
        stub = DalvikAssembler()
        stub.const4(0, 0)
        stub.return_object(0)
        stub_bytes = stub.assemble(pad_to_words=m_target["insns_size"])
        struct.pack_into(
            "<4H2I", buf, m_target["code_off"],
            m_host["ins_size"] + 1, m_host["ins_size"], 0, 0, 0, m_target["insns_size"],
        )
        buf[m_target["code_off"] + 16 : m_target["code_off"] + 16 + len(stub_bytes)] = stub_bytes
        buf[m_target["code_pos"] : m_target["code_pos"] + 4] = encode_uleb128_4bytes(m_host["code_off"])
        buf[m_host["code_pos"] : m_host["code_pos"] + 4] = encode_uleb128_4bytes(m_target["code_off"])

    # 3) MsgNotifyService.onNotificationRemoved <-> Route.copy$default (187w)
    m_rem = d6.find_method_info(
        "Lcom/liesheng/haylou/service/MsgNotifyService;",
        "Lcom/liesheng/haylou/service/MsgNotifyService;->onNotificationRemoved(Landroid/service/notification/StatusBarNotification;)V",
    )
    m_host_route = d6.find_method_info(
        "Lcom/liesheng/hayloufun/sport/routes/Route;",
        "Lcom/liesheng/hayloufun/sport/routes/Route;->copy$default(Lcom/liesheng/hayloufun/sport/routes/Route;Ljava/lang/String;DDDLcom/liesheng/hayloufun/sport/routes/Point;Lcom/liesheng/hayloufun/sport/routes/Point;Lcom/liesheng/hayloufun/sport/routes/Point;ZLjava/util/List;DLjava/lang/String;JJJZILjava/lang/Object;)Lcom/liesheng/hayloufun/sport/routes/Route;",
    )
    rem_pre = DalvikAssembler()
    rem_pre.if_eqz(2, "rem_orig")
    rem_pre.filled_new_array([2], refs["T_OBJ_ARR"])
    rem_pre.move_result_object(0)
    rem_pre.invoke_static([0], refs["M_VOIP_HELPER"])
    rem_pre.label("rem_orig")
    _prepend_and_swap(m_rem, m_host_route, rem_pre.assemble())

    # 4) IDataHelper.g()V (REJECT_INCOMING) <-> WeatherInfo.copy$default (193w)
    m_idh_g = d6.find_method_info(
        "Lcom/liesheng/haylou/db/datahelper/IDataHelper;",
        "Lcom/liesheng/haylou/db/datahelper/IDataHelper;->g()V",
    )
    m_host_weather = d6.find_method_info(
        "Lcom/liesheng/lib_common/bean/WeatherInfo;",
        "Lcom/liesheng/lib_common/bean/WeatherInfo;->copy$default(Lcom/liesheng/lib_common/bean/WeatherInfo;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/Object;)Lcom/liesheng/lib_common/bean/WeatherInfo;",
    )
    def _build_idh_g(pad_w):
        g = DalvikAssembler()
        g.const4(0, 0)
        g.filled_new_array([0], refs["T_OBJ_ARR"])
        g.move_result_object(1)
        g.invoke_static([1], refs["M_VOIP_HELPER"])
        g.aget_object(0, 1, 0)
        g.if_nez(0, "g_done")
        g.invoke_static([], refs["M_HYAPP_CTX"])
        g.move_result_object(0)
        g.invoke_static([0], refs["M_HANGUP_END"])
        g.label("g_done")
        g.return_void()
        return g.assemble(pad_to_words=pad_w)

    if m_idh_g["insns_size"] >= 150:
        g_bytes = _build_idh_g(m_idh_g["insns_size"])
        struct.pack_into("<4H2I", buf, m_idh_g["code_off"], 3, 1, 1, 0, 0, m_idh_g["insns_size"])
        buf[m_idh_g["code_off"] + 16 : m_idh_g["code_off"] + 16 + len(g_bytes)] = g_bytes
    else:
        assert m_idh_g["code_pos_len"] == 4 and m_host_weather["code_pos_len"] == 4
        g_bytes = _build_idh_g(m_host_weather["insns_size"])
        struct.pack_into("<4H2I", buf, m_host_weather["code_off"], 3, 1, 1, 0, 0, m_host_weather["insns_size"])
        buf[m_host_weather["code_off"] + 16 : m_host_weather["code_off"] + 16 + len(g_bytes)] = g_bytes
        stub = DalvikAssembler()
        stub.const4(0, 0)
        stub.return_object(0)
        stub_bytes = stub.assemble(pad_to_words=m_idh_g["insns_size"])
        struct.pack_into(
            "<4H2I", buf, m_idh_g["code_off"],
            m_host_weather["ins_size"] + 1, m_host_weather["ins_size"], 0, 0, 0, m_idh_g["insns_size"],
        )
        buf[m_idh_g["code_off"] + 16 : m_idh_g["code_off"] + 16 + len(stub_bytes)] = stub_bytes
        buf[m_idh_g["code_pos"] : m_idh_g["code_pos"] + 4] = encode_uleb128_4bytes(m_host_weather["code_off"])
        buf[m_host_weather["code_pos"] : m_host_weather["code_pos"] + 4] = encode_uleb128_4bytes(m_idh_g["code_off"])

    # 5) AppApplication$b.a (onCallMissedOrRejected) & .c (onCallAnswered) -> dismiss VoIP watch ringing
    clr_pre = DalvikAssembler()
    clr_pre.filled_new_array([], refs["T_OBJ_ARR"])
    clr_pre.move_result_object(0)
    clr_pre.invoke_static([0], refs["M_VOIP_HELPER"])
    clr_pre_bytes = clr_pre.assemble()

    m_app_a = d6.find_method_info(
        "Lcom/liesheng/hayloufun/app/AppApplication$b;",
        "Lcom/liesheng/hayloufun/app/AppApplication$b;->a(Landroid/content/Context;Ljava/lang/String;)V",
    )
    m_host_us = d6.find_method_info(
        "Lcom/liesheng/module_home/bean/UploadSleepDetailsBean;",
        "Lcom/liesheng/module_home/bean/UploadSleepDetailsBean;->copy$default(Lcom/liesheng/module_home/bean/UploadSleepDetailsBean;JLjava/lang/String;JJLjava/util/List;IIIIIIIIILjava/util/List;ILjava/lang/Object;)Lcom/liesheng/module_home/bean/UploadSleepDetailsBean;",
    )
    _prepend_and_swap(m_app_a, m_host_us, clr_pre_bytes)

    m_app_c = d6.find_method_info(
        "Lcom/liesheng/hayloufun/app/AppApplication$b;",
        "Lcom/liesheng/hayloufun/app/AppApplication$b;->c(Ljava/lang/String;)V",
    )
    m_host_dd = d6.find_method_info(
        "Lcom/liesheng/module_device/entity/DialDetail;",
        "Lcom/liesheng/module_device/entity/DialDetail;->copy$default(Lcom/liesheng/module_device/entity/DialDetail;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;JILjava/lang/String;Ljava/lang/Integer;Lcom/liesheng/lib_room/table/OtherConfig;ZLandroid/graphics/Bitmap;IILjava/lang/Object;)Lcom/liesheng/module_device/entity/DialDetail;",
    )
    _prepend_and_swap(m_app_c, m_host_dd, clr_pre_bytes)

    out = recompute_dex_checksums(buf)
    print(f"[+] classes6.dex VoIP Calls patched (Adler: {struct.unpack_from('<I', out, 8)[0]:08x})")
    return out


# --------------------------------------------------------------------------- #
# 3f. classes6.dex — Workout Analytics Engine (--workout-analytics)
# --------------------------------------------------------------------------- #

def _build_workout_analytics_insns(refs: dict, pad_words: int) -> bytes:
    """
    Build Lcom/liesheng/haylou/ui/device/data/ClockReminderHelperKt;->parseReminderCode(I)Ljava/lang/String;
    (swapped into TestBleEventActivity.onClickView(View)V, 1760 words, regs=31, ins=1, outs=6, p0=v30).

    Walks the last 30 days of ALL workouts (idempotently, and runs live inside CommonUtil.z
    before Haylou Cloud upload) and populates the 4 native SportDetailActivity panels that
    Watch 4S leaves blank:
      1) Aerobic & Anaerobic Training Effect (0.2-5.0) -> SportTable.effectInfo ("X.Y_A.B")
      2) Exercise Load / EPOC (5-450)                  -> SportTable.sportsLoad ("<int>")
      3) Recovery Time (minutes, 2h-72h)               -> SportTable.recoveryTime (recHours*60)
      4) Per-Workout VO2 Max (mL/kg/min)               -> SportTable.maxMet (<int>)
    """
    a = DalvikAssembler()

    # Load AppDatabase (v29), SportDao (v28), HeartRateDataDao (v27)
    a.sget_object(0, refs["F_APPDB_A"])
    a.invoke_virtual([0], refs["M_APPDB_B"])
    a.move_result_object(0)
    a.move_object(29, 0)
    a.invoke_virtual([0], refs["M_APPDB_SPORT_DAO"])
    a.move_result_object(1)
    a.move_object(28, 1)
    a.invoke_virtual([0], refs["M_APPDB_HR_DAO"])
    a.move_result_object(1)
    a.move_object(27, 1)

    # Read latest Vo2MaxTable (v26 = latestVo2, 0 if empty)
    a.const4(1, 0)
    a.move(26, 1)
    a.invoke_virtual([0], refs["M_APPDB_VO2_DAO"])
    a.move_result_object(1)
    a.const4(2, 1)
    a.invoke_interface([1, 2], refs["M_VO2_DESC"])
    a.move_result_object(1)
    a.if_eqz(1, "wa_age")
    a.invoke_interface([1], refs["M_LIST_SIZE"])
    a.move_result(2)
    a.if_lez(2, "wa_age")
    a.const4(2, 0)
    a.invoke_interface([1, 2], refs["M_LIST_GET"])
    a.move_result_object(1)
    a.check_cast(1, refs["T_VO2_TABLE"])
    a.invoke_virtual([1], refs["M_VO2_GET"])
    a.move_result(1)
    a.move(26, 1)

    # Read UserInfoTable age -> userMaxHr = 220 - age (v25, fallback age=30 -> 190)
    a.label("wa_age")
    a.const16(1, 30)
    a.move_object(0, 29)
    a.invoke_virtual([0], refs["M_APPDB_USER_DAO"])
    a.move_result_object(2)
    a.invoke_interface([2], refs["M_USER_ALL"])
    a.move_result_object(2)
    a.if_eqz(2, "wa_age_ok")
    a.invoke_interface([2], refs["M_LIST_SIZE"])
    a.move_result(3)
    a.if_lez(3, "wa_age_ok")
    a.const4(3, 0)
    a.invoke_interface([2, 3], refs["M_LIST_GET"])
    a.move_result_object(2)
    a.check_cast(2, refs["T_USER_TABLE"])
    a.invoke_virtual([2], refs["M_USER_AGE"])
    a.move_result(3)
    a.const16(4, 10)
    a.if_lt(3, 4, "wa_age_ok")
    a.const16(4, 90)
    a.if_gt(3, 4, "wa_age_ok")
    a.move(1, 3)

    a.label("wa_age_ok")
    a.rsub_int_lit16(1, 1, 220)
    a.move(25, 1)  # v25 = userMaxHr

    a.invoke_static([], refs["M_SYS_TIME"])
    a.move_result_wide(23)  # v23,v24 = nowMs

    # Walk last 30 days (v22 = dayOffset 0..29)
    a.const16(22, 0)
    a.label("wa_day_loop")
    a.move(0, 22)
    a.const16(1, 30)
    a.if_ge(0, 1, "wa_done")

    a.int_to_long(0, 0)
    a.const_wide32(2, 86400000)
    a.mul_long_2addr(0, 2)
    a.move_wide(2, 23)
    a.sub_long_2addr(2, 0)

    a.invoke_static([2, 3], refs["M_IDATA_Z"])
    a.move_result_object(0)
    a.if_eqz(0, "wa_day_next")
    a.invoke_virtual([0], refs["M_DATE_GET_TIME"])
    a.move_result_wide(20)  # v20,v21 = chinaMidMs

    a.move_wide(0, 20)
    a.invoke_static([0, 1], refs["M_CHINA_TO_LOCAL"])
    a.move_result_wide(18)  # v18,v19 = localMidMs

    a.move_object(0, 28)
    a.move_wide(1, 18)
    a.const_wide32(3, 86400000)
    a.add_long_2addr(3, 1)
    a.invoke_interface([0, 1, 2, 3, 4], refs["M_SPORT_BY_DATE"])
    a.move_result_object(17)
    a.if_eqz(17, "wa_day_next")
    a.move_object(0, 17)
    a.invoke_interface([0], refs["M_LIST_SIZE"])
    a.move_result(16)
    a.if_lez(16, "wa_day_next")

    # Day's resting HR (v13, clamped 48..72, default 60)
    a.const16(13, 60)
    a.move_object(0, 27)
    a.move_wide(1, 20)
    a.invoke_interface([0, 1, 2], refs["M_HR_BY_DATE"])
    a.move_result_object(0)
    a.if_eqz(0, "wa_rhr_ok")
    a.invoke_virtual([0], refs["M_HR_MIN"])
    a.move_result(1)
    a.const16(2, 38)
    a.if_lt(1, 2, "wa_rhr_ok")
    a.const16(2, 100)
    a.if_gt(1, 2, "wa_rhr_ok")
    a.const16(2, 48)
    a.if_ge(1, 2, "wa_rhr_lo")
    a.move(1, 2)
    a.label("wa_rhr_lo")
    a.const16(2, 72)
    a.if_le(1, 2, "wa_rhr_hi")
    a.move(1, 2)
    a.label("wa_rhr_hi")
    a.move(13, 1)

    a.label("wa_rhr_ok")
    a.const4(15, 0)  # spIdx = 0

    a.label("wa_sp_loop")
    a.move(0, 16)
    a.if_ge(15, 0, "wa_day_next")
    a.move_object(0, 17)
    a.invoke_interface([0, 15], refs["M_LIST_GET"])
    a.move_result_object(14)
    a.check_cast(14, refs["T_SPORT_TABLE"])

    # Require duration >= 180s (3 min)
    a.invoke_virtual([14], refs["M_SPORT_GET_DUR"])
    a.move_result(11)
    a.const16(0, 180)
    a.if_lt(11, 0, "wa_sp_next")

    # Skip if already has effectInfo + recoveryTime + maxMet
    a.invoke_virtual([14], refs["M_SPORT_GET_EFFECT"])
    a.move_result_object(0)
    a.if_eqz(0, "wa_compute")
    a.invoke_virtual([0], refs["M_STR_LEN"])
    a.move_result(0)
    a.if_lez(0, "wa_compute")
    a.invoke_virtual([14], refs["M_SPORT_GET_REC"])
    a.move_result(0)
    a.if_lez(0, "wa_compute")
    a.invoke_virtual([14], refs["M_SPORT_GET_MAXMET"])
    a.move_result(0)
    a.if_gtz(0, "wa_sp_next")

    # Compute effMaxHr (v12) = max(userMaxHr, sp.maxHeartRate, hrRest + 40)
    a.label("wa_compute")
    a.move(12, 25)
    a.invoke_virtual([14], refs["M_SPORT_GET_MAXHR"])
    a.move_result(0)
    a.if_le(0, 12, "wa_mh_chk")
    a.const16(1, 225)
    a.if_gt(0, 1, "wa_mh_chk")
    a.move(12, 0)
    a.label("wa_mh_chk")
    a.add_int_lit8(0, 13, 40)
    a.if_ge(12, 0, "wa_mh_ok")
    a.move(12, 0)

    # Scan sp.getHeartrate() -> raw aeroSum (v10), anaeroSum (v9), validCnt (v6)
    a.label("wa_mh_ok")
    a.const4(10, 0)  # 0.0f
    a.const4(9, 0)   # 0.0f
    a.const4(6, 0)   # validCnt = 0
    a.move(7, 12)
    a.sub_int_2addr(7, 13)  # v7 = hrSpan = effMaxHr - hrRest (>= 40)

    a.invoke_virtual([14], refs["M_SPORT_GET_HRARR"])
    a.move_result_object(8)
    a.if_eqz(8, "wa_hr_fallback")
    a.array_length(5, 8)
    a.if_lez(5, "wa_hr_fallback")
    a.const4(4, 0)  # i = 0

    a.label("wa_hr_loop")
    a.if_ge(4, 5, "wa_hr_done")
    a.aget(0, 8, 4)
    a.const16(1, 45)
    a.if_lt(0, 1, "wa_hr_next")
    a.const16(1, 225)
    a.if_gt(0, 1, "wa_hr_next")

    # hrrPct (v0) = (hr - hrRest) * 100 / hrSpan
    a.sub_int_2addr(0, 13)
    a.if_gez(0, "wa_hp_pos")
    a.const4(0, 0)
    a.label("wa_hp_pos")
    a.mul_int_lit8(0, 0, 100)
    a.div_int_2addr(0, 7)

    # Aerobic zone weight -> v2
    a.const16(1, 50)
    a.if_ge(0, 1, "wa_z2")
    a.const_float(2, 0.5)
    a.goto16("wa_add_aero")
    a.label("wa_z2")
    a.const16(1, 65)
    a.if_ge(0, 1, "wa_z3")
    a.const_float(2, 1.1)
    a.goto16("wa_add_aero")
    a.label("wa_z3")
    a.const16(1, 78)
    a.if_ge(0, 1, "wa_z4")
    a.const_float(2, 2.0)
    a.goto16("wa_add_aero")
    a.label("wa_z4")
    a.const16(1, 88)
    a.if_ge(0, 1, "wa_z5")
    a.const_float(2, 3.2)
    a.goto16("wa_add_aero")
    a.label("wa_z5")
    a.const_float(2, 4.5)
    a.label("wa_add_aero")
    a.add_float_2addr(10, 2)

    # Anaerobic impulse weight -> v2
    a.const16(1, 72)
    a.if_lt(0, 1, "wa_hr_cnt")
    a.const16(1, 80)
    a.if_ge(0, 1, "wa_an4")
    a.const_float(2, 0.6)
    a.goto16("wa_add_an")
    a.label("wa_an4")
    a.const16(1, 88)
    a.if_ge(0, 1, "wa_an5")
    a.const_float(2, 1.8)
    a.goto16("wa_add_an")
    a.label("wa_an5")
    a.const_float(2, 3.5)
    a.label("wa_add_an")
    a.add_float_2addr(9, 2)

    a.label("wa_hr_cnt")
    a.add_int_lit8(6, 6, 1)
    a.label("wa_hr_next")
    a.add_int_lit8(4, 4, 1)
    a.goto16("wa_hr_loop")

    # Normalize sums to actual workout duration in minutes
    a.label("wa_hr_done")
    a.if_lez(6, "wa_hr_fallback")
    a.int_to_float(0, 11)
    a.const_float(1, 60.0)
    a.div_float_2addr(0, 1)  # durMin
    a.int_to_float(1, 6)
    a.div_float_2addr(0, 1)  # scale = durMin / validCnt
    a.mul_float_2addr(10, 0)
    a.mul_float_2addr(9, 0)
    a.goto16("wa_scores")

    # Fallback when heartrate[] is empty: use avrHeartRate over durMin
    a.label("wa_hr_fallback")
    a.invoke_virtual([14], refs["M_SPORT_GET_AVGHR"])
    a.move_result(0)
    a.const16(1, 50)
    a.if_ge(0, 1, "wa_fb_hr_ok")
    a.add_int_lit8(0, 13, 35)
    a.label("wa_fb_hr_ok")
    a.sub_int_2addr(0, 13)
    a.if_gez(0, "wa_fb_pos")
    a.const4(0, 0)
    a.label("wa_fb_pos")
    a.mul_int_lit8(0, 0, 100)
    a.div_int_2addr(0, 7)
    a.int_to_float(1, 11)
    a.const_float(2, 60.0)
    a.div_float_2addr(1, 2)  # v1 = durMin
    a.const_float(10, 1.5)
    a.const16(2, 65)
    a.if_lt(0, 2, "wa_fb_mul")
    a.const_float(10, 2.5)
    a.const_float(9, 0.8)
    a.label("wa_fb_mul")
    a.mul_float_2addr(10, 1)
    a.mul_float_2addr(9, 1)

    # Compute Exercise Load (v3), Aerobic TE tenths (v4), Anaerobic TE tenths (v5)
    a.label("wa_scores")
    a.const_float(0, 0.6)
    a.mul_float(0, 9, 0)
    a.add_float_2addr(0, 10)
    a.const_float(1, 0.5)
    a.add_float_2addr(0, 1)
    a.float_to_int(3, 0)
    a.const4(1, 5)
    a.if_ge(3, 1, "wa_ld_lo")
    a.move(3, 1)
    a.label("wa_ld_lo")
    a.const16(1, 450)
    a.if_le(3, 1, "wa_ld_hi")
    a.move(3, 1)
    a.label("wa_ld_hi")

    # Set SportTable.sportsLoad = String.valueOf(load)
    a.invoke_static([3], refs["M_STR_VAL_INT"])
    a.move_result_object(0)
    a.invoke_virtual([14, 0], refs["M_SPORT_SET_LOAD"])

    # aeroTenths (v4) = clamp(int((0.5 + 4.5 * load / (load + 55.0)) * 10 + 0.5), 5, 50)
    a.int_to_float(0, 3)
    a.const_float(1, 55.0)
    a.add_float(1, 0, 1)
    a.const_float(2, 45.0)
    a.mul_float_2addr(0, 2)
    a.div_float_2addr(0, 1)
    a.const_float(1, 5.5)
    a.add_float_2addr(0, 1)
    a.float_to_int(4, 0)
    a.const4(1, 5)
    a.if_ge(4, 1, "wa_ae_lo")
    a.move(4, 1)
    a.label("wa_ae_lo")
    a.const16(1, 50)
    a.if_le(4, 1, "wa_ae_hi")
    a.move(4, 1)
    a.label("wa_ae_hi")

    # anaeroTenths (v5) = clamp(int((0.2 + 4.8 * anaero / (anaero + 35.0)) * 10 + 0.5), 2, 50)
    a.const_float(1, 35.0)
    a.add_float(1, 9, 1)
    a.const_float(2, 48.0)
    a.mul_float(0, 9, 2)
    a.div_float_2addr(0, 1)
    a.const_float(1, 2.5)
    a.add_float_2addr(0, 1)
    a.float_to_int(5, 0)
    a.const4(1, 2)
    a.if_ge(5, 1, "wa_an_lo")
    a.move(5, 1)
    a.label("wa_an_lo")
    a.const16(1, 50)
    a.if_le(5, 1, "wa_an_hi")
    a.move(5, 1)
    a.label("wa_an_hi")

    # Format effectInfo = "<aInt>.<aDec>_<nInt>.<nDec>" via StringBuilder
    a.new_instance(0, refs["T_SB"])
    a.invoke_direct([0], refs["M_SB_INIT"])
    a.div_int_lit8(1, 4, 10)
    a.invoke_virtual([0, 1], refs["M_SB_APP_INT"])
    a.const_string(2, refs["STR_DOT"])
    a.invoke_virtual([0, 2], refs["M_SB_APP_STR"])
    a.rem_int_lit8(1, 4, 10)
    a.invoke_virtual([0, 1], refs["M_SB_APP_INT"])
    a.const_string(1, refs["STR_UNDERSCORE"])
    a.invoke_virtual([0, 1], refs["M_SB_APP_STR"])
    a.div_int_lit8(1, 5, 10)
    a.invoke_virtual([0, 1], refs["M_SB_APP_INT"])
    a.invoke_virtual([0, 2], refs["M_SB_APP_STR"])
    a.rem_int_lit8(1, 5, 10)
    a.invoke_virtual([0, 1], refs["M_SB_APP_INT"])
    a.invoke_virtual([0], refs["M_SB_TOSTR"])
    a.move_result_object(0)
    a.invoke_virtual([14, 0], refs["M_SPORT_SET_EFFECT"])

    # Recovery Time in MINUTES: recHours = clamp(int(load * 0.28 + 0.5), 2, 72); recoveryTime = recHours * 60
    a.int_to_float(0, 3)
    a.const_float(1, 0.28)
    a.mul_float_2addr(0, 1)
    a.const_float(1, 0.5)
    a.add_float_2addr(0, 1)
    a.float_to_int(0, 0)
    a.const4(1, 2)
    a.if_ge(0, 1, "wa_rc_lo")
    a.move(0, 1)
    a.label("wa_rc_lo")
    a.const16(1, 72)
    a.if_le(0, 1, "wa_rc_hi")
    a.move(0, 1)
    a.label("wa_rc_hi")
    a.mul_int_lit8(0, 0, 60)
    a.invoke_virtual([14, 0], refs["M_SPORT_SET_REC"])

    # Per-workout VO2 Max (if not already set): use latest Vo2MaxTable, else Uth 15.3 * effMaxHr / hrRest
    a.invoke_virtual([14], refs["M_SPORT_GET_MAXMET"])
    a.move_result(0)
    a.if_gtz(0, "wa_save_sp")
    a.move(0, 26)
    a.if_gtz(0, "wa_set_vo2")
    a.int_to_float(0, 12)
    a.const_float(1, 15.3)
    a.mul_float_2addr(0, 1)
    a.int_to_float(1, 13)
    a.div_float_2addr(0, 1)
    a.float_to_int(0, 0)
    a.const16(1, 28)
    a.if_ge(0, 1, "wa_v_lo")
    a.move(0, 1)
    a.label("wa_v_lo")
    a.const16(1, 72)
    a.if_le(0, 1, "wa_set_vo2")
    a.move(0, 1)
    a.label("wa_set_vo2")
    a.invoke_virtual([14, 0], refs["M_SPORT_SET_MAXMET"])

    a.label("wa_save_sp")
    a.move_object(0, 28)
    a.invoke_interface([0, 14], refs["M_SPORT_UPDATE"])

    a.label("wa_sp_next")
    a.add_int_lit8(15, 15, 1)
    a.goto16("wa_sp_loop")

    a.label("wa_day_next")
    a.add_int_lit8(22, 22, 1)
    a.goto16("wa_day_loop")

    a.label("wa_done")
    a.const4(0, 0)
    a.return_object(0)
    return a.assemble(pad_to_words=pad_words)


def patch_classes6_workout_analytics(dex_bytes: bytes) -> bytes:
    """
    Patch classes6.dex with Workout Analytics Engine (Aerobic/Anaerobic Training Effect,
    Exercise Load / EPOC, Recovery Time, and Per-Workout VO2 Max for all Watch 4S workouts).
    """
    print("[*] Patching classes6.dex (Workout Analytics: Training Effect + Load + Recovery + VO2 Max)...")
    d6 = DexFile(dex_bytes)
    buf = bytearray(dex_bytes)

    refs = {
        "T_SPORT_TABLE": d6.find_idx("type", "Lcom/liesheng/lib_room/table/SportTable;"),
        "T_USER_TABLE": d6.find_idx("type", "Lcom/liesheng/lib_room/table/UserInfoTable;"),
        "T_VO2_TABLE": d6.find_idx("type", "Lcom/liesheng/lib_room/table/Vo2MaxTable;"),
        "T_SB": d6.find_idx("type", "Ljava/lang/StringBuilder;"),
        "F_APPDB_A": d6.find_idx("field", "Lcom/liesheng/AppDatabase;->a:Lcom/liesheng/AppDatabase$a;"),
        "M_APPDB_B": d6.find_idx("method", "Lcom/liesheng/AppDatabase$a;->b()Lcom/liesheng/AppDatabase;"),
        "M_APPDB_SPORT_DAO": d6.find_idx("method", "Lcom/liesheng/AppDatabase;->u()Lcom/liesheng/lib_room/dao/SportDao;"),
        "M_APPDB_HR_DAO": d6.find_idx("method", "Lcom/liesheng/AppDatabase;->l()Lcom/liesheng/lib_room/dao/HeartRateDataDao;"),
        "M_APPDB_VO2_DAO": d6.find_idx("method", "Lcom/liesheng/AppDatabase;->A()Lcom/liesheng/lib_room/dao/Vo2MaxDao;"),
        "M_APPDB_USER_DAO": d6.find_idx("method", "Lcom/liesheng/AppDatabase;->y()Lcom/liesheng/lib_room/dao/UserInfoDao;"),
        "M_SPORT_BY_DATE": d6.find_idx("method", "Lcom/liesheng/lib_room/dao/SportDao;->getSportDataByDate(JJ)Ljava/util/List;"),
        "M_SPORT_UPDATE": d6.find_idx("method", "Lcom/liesheng/lib_room/dao/SportDao;->update(Lcom/liesheng/lib_room/table/SportTable;)V"),
        "M_HR_BY_DATE": d6.find_idx("method", "Lcom/liesheng/lib_room/dao/HeartRateDataDao;->getHeartDataByDate(J)Lcom/liesheng/lib_room/table/HeartRateDataTable;"),
        "M_HR_MIN": d6.find_idx("method", "Lcom/liesheng/lib_room/table/HeartRateDataTable;->getMinHeartRate()I"),
        "M_VO2_DESC": d6.find_idx("method", "Lcom/liesheng/lib_room/dao/Vo2MaxDao;->getDataOrderDesc(I)Ljava/util/List;"),
        "M_VO2_GET": d6.find_idx("method", "Lcom/liesheng/lib_room/table/Vo2MaxTable;->getMaxMet()I"),
        "M_USER_ALL": d6.find_idx("method", "Lcom/liesheng/lib_room/dao/UserInfoDao;->getAllUserInfo()Ljava/util/List;"),
        "M_USER_AGE": d6.find_idx("method", "Lcom/liesheng/lib_room/table/UserInfoTable;->getAge()I"),
        "M_SPORT_GET_DUR": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getDuration()I"),
        "M_SPORT_GET_HRARR": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getHeartrate()[I"),
        "M_SPORT_GET_AVGHR": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getAvrHeartRate()I"),
        "M_SPORT_GET_MAXHR": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getMaxHeartRate()I"),
        "M_SPORT_GET_EFFECT": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getEffectInfo()Ljava/lang/String;"),
        "M_SPORT_SET_EFFECT": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->setEffectInfo(Ljava/lang/String;)V"),
        "M_SPORT_SET_LOAD": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->setSportsLoad(Ljava/lang/String;)V"),
        "M_SPORT_GET_REC": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getRecoveryTime()I"),
        "M_SPORT_SET_REC": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->setRecoveryTime(I)V"),
        "M_SPORT_GET_MAXMET": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getMaxMet()I"),
        "M_SPORT_SET_MAXMET": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->setMaxMet(I)V"),
        "M_IDATA_Z": d6.find_idx("method", "Lcom/liesheng/haylou/db/datahelper/IDataHelper;->z(J)Ljava/util/Date;"),
        "M_CHINA_TO_LOCAL": d6.find_idx("method", "Lcom/liesheng/lib_common/ktx/c;->b(J)J"),
        "M_UTC_TO_LOCAL": d6.find_idx("method", "Lcom/liesheng/lib_common/ktx/c;->g(J)J"),
        "M_DATE_GET_TIME": d6.find_idx("method", "Ljava/util/Date;->getTime()J"),
        "M_SYS_TIME": d6.find_idx("method", "Ljava/lang/System;->currentTimeMillis()J"),
        "M_LIST_SIZE": d6.find_idx("method", "Ljava/util/List;->size()I"),
        "M_LIST_GET": d6.find_idx("method", "Ljava/util/List;->get(I)Ljava/lang/Object;"),
        "M_STR_LEN": d6.find_idx("method", "Ljava/lang/String;->length()I"),
        "M_STR_VAL_INT": d6.find_idx("method", "Ljava/lang/String;->valueOf(I)Ljava/lang/String;"),
        "M_SB_INIT": d6.find_idx("method", "Ljava/lang/StringBuilder;-><init>()V"),
        "M_SB_APP_INT": d6.find_idx("method", "Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;"),
        "M_SB_APP_STR": d6.find_idx("method", "Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;"),
        "M_SB_TOSTR": d6.find_idx("method", "Ljava/lang/StringBuilder;->toString()Ljava/lang/String;"),
        "STR_DOT": d6.find_idx("string", "."),
        "STR_UNDERSCORE": d6.find_idx("string", "_"),
    }

    # 1) ClockReminderHelperKt.parseReminderCode(I)String (0-caller, 130w, len=4)
    #    <-> TestBleEventActivity.onClickView(View)V (1760w, len=4)
    m_wa = d6.find_method_info(
        "Lcom/liesheng/haylou/ui/device/data/ClockReminderHelperKt;",
        "Lcom/liesheng/haylou/ui/device/data/ClockReminderHelperKt;->parseReminderCode(I)Ljava/lang/String;",
    )
    m_host = d6.find_method_info(
        "Lcom/liesheng/haylou/ui/TestBleEventActivity;",
        "Lcom/liesheng/haylou/ui/TestBleEventActivity;->onClickView(Landroid/view/View;)V",
    )
    if m_wa["insns_size"] >= 1000:
        insns = _build_workout_analytics_insns(refs, pad_words=m_wa["insns_size"])
        struct.pack_into("<4H2I", buf, m_wa["code_off"], 31, 1, 6, 0, 0, m_wa["insns_size"])
        buf[m_wa["code_off"] + 16 : m_wa["code_off"] + 16 + len(insns)] = insns
    else:
        assert m_wa["code_pos_len"] == 4 and m_host["code_pos_len"] == 4
        insns = _build_workout_analytics_insns(refs, pad_words=m_host["insns_size"])
        struct.pack_into("<4H2I", buf, m_host["code_off"], 31, 1, 6, 0, 0, m_host["insns_size"])
        buf[m_host["code_off"] + 16 : m_host["code_off"] + 16 + len(insns)] = insns
        stub = DalvikAssembler()
        stub.return_void()
        stub_bytes = stub.assemble(pad_to_words=m_wa["insns_size"])
        struct.pack_into(
            "<4H2I", buf, m_wa["code_off"],
            m_host["ins_size"], m_host["ins_size"], 0, 0, 0, m_wa["insns_size"],
        )
        buf[m_wa["code_off"] + 16 : m_wa["code_off"] + 16 + len(stub_bytes)] = stub_bytes
        buf[m_wa["code_pos"] : m_wa["code_pos"] + 4] = encode_uleb128_4bytes(m_host["code_off"])
        buf[m_host["code_pos"] : m_host["code_pos"] + 4] = encode_uleb128_4bytes(m_wa["code_off"])

    call_wa_seq = struct.pack("<HHHH", 0x0012, 0x1071, m_wa["method_idx"], 0x0000)

    # 2) Live trigger inside CommonUtil.z (immediately after cycling cleanup, before Cloud/Strava upload)
    _hook_common_util_z(buf, d6, call_wa_seq)

    # 3) Home Dispatchers.IO 30-day backfill trigger on SportRecordWidgetDataLoader.f()
    _hook_sport_record_loader(buf, d6, call_wa_seq)

    out = recompute_dex_checksums(buf)
    print(f"[+] classes6.dex Workout Analytics patched (Adler: {struct.unpack_from('<I', out, 8)[0]:08x})")
    return out


# --------------------------------------------------------------------------- #
# 3g. classes6.dex — Stress-Derived HRV + Active/Standing Hours (--hrv-active)
# --------------------------------------------------------------------------- #

def _build_hrv_active_insns(refs: dict, pad_words: int) -> bytes:
    """
    Build Lcom/liesheng/haylou/ui/device/data/ClockReminderHelperKt;->parseCustomReminder(Ljava/util/Set;)Ljava/lang/String;
    (swapped into TestBleEventActivity.initData()V, 600 words, regs=28, ins=1, outs=11, p0=v27).

    Walks the last 30 days (idempotently, refreshing today whenever new Stress/HR samples arrive):
      Part A) Converts Watch 4S's 30-minute optical PPG Stress readings (StressTable.items) +
              quietest daily HR into 30-minute RMSSD HRV points (HrvItem(hrv, hour, min))
              and stores HrvTable in HrvDao so the Data Hub HRV card & charts work live.
      Part B) Populates StepDataTable.activeItems[24] (1 = active hour, 0 = inactive) from
              hourly steps (>=100, 24h or 48 half-hour slots), sport minutes (>0), and all-day HR
              elevation (dynamic hrArr.length/24 slots/hr, >= RHR+24) so the Daily Activities
              Active/Standing Hours (12h) bar chart works live.
    """
    a = DalvikAssembler()

    # Load StressDao (v26), HrvDao (v25), HeartRateDataDao (v24), StepDataDao (v23), nowMs (v21,v22)
    a.sget_object(0, refs["F_APPDB_A"])
    a.invoke_virtual([0], refs["M_APPDB_B"])
    a.move_result_object(0)
    a.invoke_virtual([0], refs["M_APPDB_STRESS_DAO"])
    a.move_result_object(1)
    a.move_object(26, 1)
    a.invoke_virtual([0], refs["M_APPDB_HRV_DAO"])
    a.move_result_object(1)
    a.move_object(25, 1)
    a.invoke_virtual([0], refs["M_APPDB_HR_DAO"])
    a.move_result_object(1)
    a.move_object(24, 1)
    a.invoke_virtual([0], refs["M_APPDB_STEP_DAO"])
    a.move_result_object(1)
    a.move_object(23, 1)
    a.invoke_static([], refs["M_SYS_TIME"])
    a.move_result_wide(21)

    a.const16(20, 0)  # dayOffset = 0..29
    a.label("ha_day_loop")
    a.move(0, 20)
    a.const16(1, 30)
    a.if_ge(0, 1, "ha_done")

    # chinaMidMs (v18,v19) = IDataHelper.z(nowMs - dayOffset * 86400000L).getTime()
    a.int_to_long(0, 0)
    a.const_wide32(2, 86400000)
    a.mul_long_2addr(0, 2)
    a.move_wide(2, 21)
    a.sub_long_2addr(2, 0)
    a.invoke_static([2, 3], refs["M_IDATA_Z"])
    a.move_result_object(0)
    a.if_eqz(0, "ha_day_next")
    a.invoke_virtual([0], refs["M_DATE_GET_TIME"])
    a.move_result_wide(18)

    # Fetch HeartRateDataTable (v17) & compute dayRhr (v16, clamped 45..85, default 62)
    a.const16(16, 62)
    a.move_object(0, 24)
    a.move_wide(1, 18)
    a.invoke_interface([0, 1, 2], refs["M_HR_BY_DATE"])
    a.move_result_object(17)
    a.if_eqz(17, "ha_part_a")
    a.move_object(0, 17)
    a.invoke_virtual([0], refs["M_HR_MIN"])
    a.move_result(1)
    a.const16(2, 38)
    a.if_lt(1, 2, "ha_part_a")
    a.const16(2, 100)
    a.if_gt(1, 2, "ha_part_a")
    a.const16(2, 45)
    a.if_ge(1, 2, "ha_rhr_lo")
    a.move(1, 2)
    a.label("ha_rhr_lo")
    a.const16(2, 85)
    a.if_le(1, 2, "ha_rhr_hi")
    a.move(1, 2)
    a.label("ha_rhr_hi")
    a.move(16, 1)

    # ---- Part A: Stress-Derived 30-min HRV Engine ----
    a.label("ha_part_a")
    a.move_object(0, 26)
    a.move_wide(1, 18)
    a.invoke_interface([0, 1, 2], refs["M_STRESS_BY_DATE"])
    a.move_result_object(15)
    a.if_eqz(15, "ha_part_b")
    a.invoke_virtual([15], refs["M_STRESS_ITEMS"])
    a.move_result_object(13)
    a.if_eqz(13, "ha_part_b")
    a.invoke_interface([13], refs["M_LIST_SIZE"])
    a.move_result(12)
    a.if_lez(12, "ha_part_b")

    # Skip if HrvTable already exists with >= stress item count (idempotent & updates live on new samples)
    a.move_object(0, 25)
    a.move_wide(1, 18)
    a.invoke_interface([0, 1, 2], refs["M_HRV_BY_DATE"])
    a.move_result_object(0)
    a.if_eqz(0, "ha_hrv_build")
    a.invoke_virtual([0], refs["M_HRV_LIST"])
    a.move_result_object(0)
    a.if_eqz(0, "ha_hrv_build")
    a.invoke_interface([0], refs["M_LIST_SIZE"])
    a.move_result(0)
    a.if_ge(0, 12, "ha_part_b")

    a.label("ha_hrv_build")
    a.new_instance(14, refs["T_ARRAYLIST"])
    a.invoke_direct([14, 12], refs["M_AL_INIT_CAP"])
    # rhrBonus (v11) = (62 - dayRhr) * 6 / 10
    a.move(0, 16)
    a.rsub_int_lit16(11, 0, 62)
    a.mul_int_lit8(11, 11, 6)
    a.div_int_lit8(11, 11, 10)

    a.const16(9, 999)  # minHrv
    a.const4(8, 0)     # maxHrv
    a.const4(7, 0)     # sumHrv
    a.const4(6, 0)     # cnt
    a.const4(5, 0)     # i = 0

    a.label("ha_hrv_loop")
    a.if_ge(5, 12, "ha_hrv_done")
    a.invoke_interface([13, 5], refs["M_LIST_GET"])
    a.move_result_object(4)
    a.if_eqz(4, "ha_hrv_next")
    a.check_cast(4, refs["T_STRESS_ITEM"])
    a.invoke_virtual([4], refs["M_SI_PRESS"])
    a.move_result(1)  # v1 = pressure (1..99)
    a.const4(0, 1)
    a.if_lt(1, 0, "ha_hrv_next")
    a.const16(0, 99)
    a.if_gt(1, 0, "ha_hrv_next")

    # hrv (v1) = clamp(105 - (p * 115) / 100 + (p * p) / 400 + rhrBonus, 12, 120)
    a.mul_int_lit16(2, 1, 115)
    a.div_int_lit8(2, 2, 100)
    a.move(3, 1)
    a.mul_int_2addr(3, 1)
    a.div_int_lit16(3, 3, 400)
    a.const16(1, 105)
    a.sub_int_2addr(1, 2)
    a.add_int_2addr(1, 3)
    a.add_int_2addr(1, 11)
    a.const16(0, 12)
    a.if_ge(1, 0, "ha_h_lo")
    a.move(1, 0)
    a.label("ha_h_lo")
    a.const16(0, 120)
    a.if_le(1, 0, "ha_h_hi")
    a.move(1, 0)
    a.label("ha_h_hi")

    # Track min (v9), max (v8), sum (v7), cnt (v6)
    a.if_ge(1, 9, "ha_h_min")
    a.move(9, 1)
    a.label("ha_h_min")
    a.if_le(1, 8, "ha_h_max")
    a.move(8, 1)
    a.label("ha_h_max")
    a.add_int_2addr(7, 1)
    a.add_int_lit8(6, 6, 1)

    # Create HrvItem(hrv=v1, hour=v2, min=v3) and add to hrvList (v14)
    a.invoke_virtual([4], refs["M_SI_HOUR"])
    a.move_result(2)
    a.invoke_virtual([4], refs["M_SI_MIN"])
    a.move_result(3)
    a.new_instance(0, refs["T_HRV_ITEM"])
    a.invoke_direct([0, 1, 2, 3], refs["M_HRV_ITEM_INIT"])
    a.invoke_virtual([14, 0], refs["M_AL_ADD"])

    a.label("ha_hrv_next")
    a.add_int_lit8(5, 5, 1)
    a.goto16("ha_hrv_loop")

    a.label("ha_hrv_done")
    a.if_lez(6, "ha_part_b")
    a.div_int_2addr(7, 6)  # v7 = avgHrv; v8 = maxHrv; v9 = minHrv
    a.invoke_virtual([15], refs["M_STRESS_DATE"])
    a.move_result_object(1)
    a.if_eqz(1, "ha_part_b")
    a.invoke_virtual([1], refs["M_DATE_GET_TIME"])
    a.move_result_wide(3)  # v3,v4 = recMs
    a.move_wide(5, 3)      # v5,v6 = recMs
    a.const_string(2, refs["STR_EMPTY"])
    a.move_object(10, 14)  # v10 = hrvList
    a.new_instance(0, refs["T_HRV_TABLE"])
    a.invoke_direct_range(0, 11, refs["M_HRV_INIT"])
    a.move_object(1, 25)
    a.invoke_interface([1, 0], refs["M_HRV_INSERT"])

    # ---- Part B: Hourly Active / Standing Hours (StepDataTable.activeItems[24]) ----
    a.label("ha_part_b")
    a.move_object(0, 23)
    a.move_wide(1, 18)
    a.invoke_interface([0, 1, 2], refs["M_STEP_BY_DATE"])
    a.move_result_object(15)
    a.if_eqz(15, "ha_day_next")

    # Allocate int[24] act (v14)
    a.const16(0, 24)
    a.new_array(14, 0, refs["T_INT_ARR"])
    # Load hrArr (v13) from hrDay (v17)
    a.const4(13, 0)
    a.if_eqz(17, "ha_act_thr")
    a.move_object(0, 17)
    a.invoke_virtual([0], refs["M_HR_ITEMS"])
    a.move_result_object(13)

    # hrThresh (v11) = clamp(dayRhr + 24, 82, 106); hrHigh (v10) = hrThresh + 10
    a.label("ha_act_thr")
    a.move(0, 16)
    a.add_int_lit8(11, 0, 24)
    a.const16(0, 82)
    a.if_ge(11, 0, "ha_th_lo")
    a.move(11, 0)
    a.label("ha_th_lo")
    a.const16(0, 106)
    a.if_le(11, 0, "ha_th_hi")
    a.move(11, 0)
    a.label("ha_th_hi")
    a.add_int_lit8(10, 11, 10)

    a.invoke_virtual([15], refs["M_STEP_GET_ITEMS"])
    a.move_result_object(9)   # v9 = stepItems[24] or null
    a.invoke_virtual([15], refs["M_STEP_GET_STIME"])
    a.move_result_object(8)   # v8 = sportTimeItems[24] or null
    a.const4(7, 0)            # v7 = activeHoursCount
    a.const4(12, 0)           # v12 = h (0..23)

    a.label("ha_h_loop")
    a.const16(0, 24)
    a.if_ge(12, 0, "ha_h_done")

    # Criterion 1: hourly steps >= 100 (supports both 24-hour and 48 half-hour stepItems[])
    a.if_eqz(9, "ha_chk_st")
    a.array_length(1, 9)
    a.const16(2, 48)
    a.if_lt(1, 2, "ha_st24")
    a.add_int_2addr(12, 12)     # temporary idx = 2*h
    a.aget(1, 9, 12)
    a.add_int_lit8(2, 12, 1)
    a.aget(2, 9, 2)
    a.add_int_2addr(1, 2)
    a.div_int_lit8(12, 12, 2)   # restore h
    a.goto16("ha_st_cmp")
    a.label("ha_st24")
    a.if_lt(1, 0, "ha_chk_st")
    a.aget(1, 9, 12)
    a.label("ha_st_cmp")
    a.const16(2, 100)
    a.if_ge(1, 2, "ha_mark_act")

    # Criterion 2: sportTimeItems[h] > 0.0f
    a.label("ha_chk_st")
    a.if_eqz(8, "ha_chk_hr")
    a.array_length(1, 8)
    a.if_lt(1, 0, "ha_chk_hr")
    a.aget(1, 8, 12)
    a.const4(2, 0)
    a.cmpl_float(1, 1, 2)
    a.if_gtz(1, "ha_mark_act")

    # Criterion 3: HR elevation in hour h using dynamic slotsPerHour = hrArr.length / 24
    # (Watch 4S stores 144 x 10-min slots = 6/hr; also supports 288 x 5-min = 12/hr or 48 = 2/hr)
    a.label("ha_chk_hr")
    a.if_eqz(13, "ha_h_next")
    a.array_length(3, 13)
    a.div_int_lit8(3, 3, 24)   # v3 = slotsPerHour
    a.if_lez(3, "ha_h_next")
    a.move(1, 12)
    a.mul_int_2addr(1, 3)      # k = h * slotsPerHour
    a.move(2, 1)
    a.add_int_2addr(2, 3)      # end = (h + 1) * slotsPerHour
    a.array_length(4, 13)
    a.if_lt(4, 2, "ha_h_next")
    a.const4(4, 0)             # elevCnt = 0

    a.label("ha_k_loop")
    a.if_ge(1, 2, "ha_h_next")
    a.aget(5, 13, 1)
    a.if_ge(5, 10, "ha_mark_act")
    a.if_lt(5, 11, "ha_k_next")
    a.add_int_lit8(4, 4, 1)
    a.const4(5, 2)
    a.if_ge(4, 5, "ha_mark_act")
    a.label("ha_k_next")
    a.add_int_lit8(1, 1, 1)
    a.goto16("ha_k_loop")

    a.label("ha_mark_act")
    a.const4(1, 1)
    a.aput(1, 14, 12)
    a.add_int_lit8(7, 7, 1)

    a.label("ha_h_next")
    a.add_int_lit8(12, 12, 1)
    a.goto16("ha_h_loop")

    # Write activeItems only if activeHoursCount > 0 AND different from stored activeItems
    a.label("ha_h_done")
    a.if_lez(7, "ha_day_next")
    a.invoke_virtual([15], refs["M_STEP_GET_ACTIVE"])
    a.move_result_object(0)
    a.if_eqz(0, "ha_act_save")
    a.array_length(1, 0)
    a.const16(2, 24)
    a.if_ne(1, 2, "ha_act_save")
    a.const4(3, 0)
    a.label("ha_cmp_loop")
    a.if_ge(3, 2, "ha_day_next")  # identical -> skip DB write
    a.aget(4, 0, 3)
    a.aget(5, 14, 3)
    a.if_ne(4, 5, "ha_act_save")
    a.add_int_lit8(3, 3, 1)
    a.goto16("ha_cmp_loop")

    a.label("ha_act_save")
    a.invoke_virtual([15, 14], refs["M_STEP_SET_ACTIVE"])
    a.move_object(0, 23)
    a.invoke_interface([0, 15], refs["M_STEP_INSERT"])

    a.label("ha_day_next")
    a.add_int_lit8(20, 20, 1)
    a.goto16("ha_day_loop")

    a.label("ha_done")
    a.const4(0, 0)
    a.return_object(0)
    return a.assemble(pad_to_words=pad_words)


def patch_classes6_hrv_active(dex_bytes: bytes) -> bytes:
    """
    Patch classes6.dex with Stress-derived 30-min HRV engine (HrvTable) and Hourly Active/Standing
    Hours engine (StepDataTable.activeItems[24]), plus live preservation guard in IDataHelper.N.
    """
    print("[*] Patching classes6.dex (HRV Engine from 24/7 PPG Stress + Hourly Active/Standing Hours)...")
    d6 = DexFile(dex_bytes)
    buf = bytearray(dex_bytes)

    refs = {
        "T_ARRAYLIST": d6.find_idx("type", "Ljava/util/ArrayList;"),
        "T_INT_ARR": d6.find_idx("type", "[I"),
        "T_STRESS_ITEM": d6.find_idx("type", "Lcom/liesheng/lib_room/table/StressItem;"),
        "T_HRV_TABLE": d6.find_idx("type", "Lcom/liesheng/lib_room/table/HrvTable;"),
        "T_HRV_ITEM": d6.find_idx("type", "Lcom/liesheng/lib_room/table/HrvItem;"),
        "F_APPDB_A": d6.find_idx("field", "Lcom/liesheng/AppDatabase;->a:Lcom/liesheng/AppDatabase$a;"),
        "M_APPDB_B": d6.find_idx("method", "Lcom/liesheng/AppDatabase$a;->b()Lcom/liesheng/AppDatabase;"),
        "M_APPDB_STRESS_DAO": d6.find_idx("method", "Lcom/liesheng/AppDatabase;->x()Lcom/liesheng/lib_room/dao/StressDao;"),
        "M_APPDB_HRV_DAO": d6.find_idx("method", "Lcom/liesheng/AppDatabase;->m()Lcom/liesheng/lib_room/dao/HrvDao;"),
        "M_APPDB_HR_DAO": d6.find_idx("method", "Lcom/liesheng/AppDatabase;->l()Lcom/liesheng/lib_room/dao/HeartRateDataDao;"),
        "M_APPDB_STEP_DAO": d6.find_idx("method", "Lcom/liesheng/AppDatabase;->w()Lcom/liesheng/lib_room/dao/StepDataDao;"),
        "M_STRESS_BY_DATE": d6.find_idx("method", "Lcom/liesheng/lib_room/dao/StressDao;->getSpo2DataByDate(J)Lcom/liesheng/lib_room/table/StressTable;"),
        "M_STRESS_DATE": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StressTable;->getRecordDate()Ljava/util/Date;"),
        "M_STRESS_ITEMS": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StressTable;->getItems()Ljava/util/List;"),
        "M_SI_HOUR": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StressItem;->getHour()I"),
        "M_SI_MIN": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StressItem;->getMin()I"),
        "M_SI_PRESS": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StressItem;->getPressure()I"),
        "M_HRV_BY_DATE": d6.find_idx("method", "Lcom/liesheng/lib_room/dao/HrvDao;->getDataByDate(J)Lcom/liesheng/lib_room/table/HrvTable;"),
        "M_HRV_INSERT": d6.find_idx("method", "Lcom/liesheng/lib_room/dao/HrvDao;->insert(Lcom/liesheng/lib_room/table/HrvTable;)V"),
        "M_HRV_LIST": d6.find_idx("method", "Lcom/liesheng/lib_room/table/HrvTable;->getHrvList()Ljava/util/List;"),
        "M_HRV_INIT": d6.find_idx("method", "Lcom/liesheng/lib_room/table/HrvTable;-><init>(Ljava/util/Date;Ljava/lang/String;JJIIILjava/util/List;)V"),
        "M_HRV_ITEM_INIT": d6.find_idx("method", "Lcom/liesheng/lib_room/table/HrvItem;-><init>(III)V"),
        "M_HR_BY_DATE": d6.find_idx("method", "Lcom/liesheng/lib_room/dao/HeartRateDataDao;->getHeartDataByDate(J)Lcom/liesheng/lib_room/table/HeartRateDataTable;"),
        "M_HR_MIN": d6.find_idx("method", "Lcom/liesheng/lib_room/table/HeartRateDataTable;->getMinHeartRate()I"),
        "M_HR_ITEMS": d6.find_idx("method", "Lcom/liesheng/lib_room/table/HeartRateDataTable;->getItems()[I"),
        "M_STEP_BY_DATE": d6.find_idx("method", "Lcom/liesheng/lib_room/dao/StepDataDao;->getStepDataByDate(J)Lcom/liesheng/lib_room/table/StepDataTable;"),
        "M_STEP_INSERT": d6.find_idx("method", "Lcom/liesheng/lib_room/dao/StepDataDao;->insert(Lcom/liesheng/lib_room/table/StepDataTable;)V"),
        "M_STEP_GET_RECDATE": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->getRecordDate()Ljava/util/Date;"),
        "M_STEP_GET_ITEMS": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->getItems()[I"),
        "M_STEP_GET_STIME": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->getSportTimeItems()[F"),
        "M_STEP_GET_ACTIVE": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->getActiveItems()[I"),
        "M_STEP_SET_ACTIVE": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->setActiveItems([I)V"),
        "M_IDATA_Z": d6.find_idx("method", "Lcom/liesheng/haylou/db/datahelper/IDataHelper;->z(J)Ljava/util/Date;"),
        "M_DATE_GET_TIME": d6.find_idx("method", "Ljava/util/Date;->getTime()J"),
        "M_SYS_TIME": d6.find_idx("method", "Ljava/lang/System;->currentTimeMillis()J"),
        "M_LIST_SIZE": d6.find_idx("method", "Ljava/util/List;->size()I"),
        "M_LIST_GET": d6.find_idx("method", "Ljava/util/List;->get(I)Ljava/lang/Object;"),
        "M_AL_INIT_CAP": d6.find_idx("method", "Ljava/util/ArrayList;-><init>(I)V"),
        "M_AL_ADD": d6.find_idx("method", "Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z"),
        "STR_EMPTY": d6.find_idx("string", ""),
    }

    # 1) ClockReminderHelperKt.parseCustomReminder(Set)String (0-caller, 139w, len=4)
    #    <-> TestBleEventActivity.initData()V (600w, len=4)
    m_ha = d6.find_method_info(
        "Lcom/liesheng/haylou/ui/device/data/ClockReminderHelperKt;",
        "Lcom/liesheng/haylou/ui/device/data/ClockReminderHelperKt;->parseCustomReminder(Ljava/util/Set;)Ljava/lang/String;",
    )
    m_host = d6.find_method_info(
        "Lcom/liesheng/haylou/ui/TestBleEventActivity;",
        "Lcom/liesheng/haylou/ui/TestBleEventActivity;->initData()V",
    )
    if m_ha["insns_size"] >= 500:
        insns = _build_hrv_active_insns(refs, pad_words=m_ha["insns_size"])
        struct.pack_into("<4H2I", buf, m_ha["code_off"], 28, 1, 11, 0, 0, m_ha["insns_size"])
        buf[m_ha["code_off"] + 16 : m_ha["code_off"] + 16 + len(insns)] = insns
    else:
        assert m_ha["code_pos_len"] == 4 and m_host["code_pos_len"] == 4
        insns = _build_hrv_active_insns(refs, pad_words=m_host["insns_size"])
        struct.pack_into("<4H2I", buf, m_host["code_off"], 28, 1, 11, 0, 0, m_host["insns_size"])
        buf[m_host["code_off"] + 16 : m_host["code_off"] + 16 + len(insns)] = insns
        stub = DalvikAssembler()
        stub.return_void()
        stub_bytes = stub.assemble(pad_to_words=m_ha["insns_size"])
        struct.pack_into(
            "<4H2I", buf, m_ha["code_off"],
            m_host["ins_size"], m_host["ins_size"], 0, 0, 0, m_ha["insns_size"],
        )
        buf[m_ha["code_off"] + 16 : m_ha["code_off"] + 16 + len(stub_bytes)] = stub_bytes
        buf[m_ha["code_pos"] : m_ha["code_pos"] + 4] = encode_uleb128_4bytes(m_host["code_off"])
        buf[m_host["code_pos"] : m_host["code_pos"] + 4] = encode_uleb128_4bytes(m_ha["code_off"])

    # 2) Home Dispatchers.IO trigger on SportRecordWidgetDataLoader.f(): const4 v0,0; invoke-static {v0}, parseCustomReminder
    call_ha_seq = struct.pack("<HHHH", 0x0012, 0x1071, m_ha["method_idx"], 0x0000)
    _hook_sport_record_loader(buf, d6, call_ha_seq)

    # 3) Live preservation guard in IDataHelper.N(StepDataTable)V so bulk Watch 4S step syncs
    #    (which send activeItems=[]) never blank out already-computed Active/Standing Hours
    m_idh_n = d6.find_method_info(
        "Lcom/liesheng/haylou/db/datahelper/IDataHelper;",
        "Lcom/liesheng/haylou/db/datahelper/IDataHelper;->N(Lcom/liesheng/lib_room/table/StepDataTable;)V",
    )
    m_host_step_det = d6.find_method_info(
        "Lcom/liesheng/module_home/bean/StepDetailsBean$StepDetailsList;",
        "Lcom/liesheng/module_home/bean/StepDetailsBean$StepDetailsList;->copy$default(Lcom/liesheng/module_home/bean/StepDetailsBean$StepDetailsList;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IFLjava/lang/String;FFIIII[I[I[II[F[F[ILjava/lang/String;ILjava/lang/Object;)Lcom/liesheng/module_home/bean/StepDetailsBean$StepDetailsList;",
    )
    pa = DalvikAssembler()
    pa.invoke_virtual([4], refs["M_STEP_GET_ACTIVE"])
    pa.move_result_object(0)
    pa.if_eqz(0, "pa_fetch")
    pa.array_length(0, 0)
    pa.const16(1, 24)
    pa.if_eq(0, 1, "pa_done")
    pa.label("pa_fetch")
    pa.invoke_virtual([4], refs["M_STEP_GET_RECDATE"])
    pa.move_result_object(0)
    pa.if_eqz(0, "pa_done")
    pa.invoke_virtual([0], refs["M_DATE_GET_TIME"])
    pa.move_result_wide(0)
    pa.sget_object(2, refs["F_APPDB_A"])
    pa.invoke_virtual([2], refs["M_APPDB_B"])
    pa.move_result_object(2)
    pa.invoke_virtual([2], refs["M_APPDB_STEP_DAO"])
    pa.move_result_object(2)
    pa.invoke_interface([2, 0, 1], refs["M_STEP_BY_DATE"])
    pa.move_result_object(2)
    pa.if_eqz(2, "pa_done")
    pa.invoke_virtual([2], refs["M_STEP_GET_ACTIVE"])
    pa.move_result_object(0)
    pa.if_eqz(0, "pa_done")
    pa.array_length(1, 0)
    pa.const16(2, 24)
    pa.if_ne(1, 2, "pa_done")
    pa.invoke_virtual([4, 0], refs["M_STEP_SET_ACTIVE"])
    pa.label("pa_done")
    pa_bytes = pa.assemble()

    if m_idh_n["insns_size"] < 200:
        assert m_idh_n["code_pos_len"] == 4 and m_host_step_det["code_pos_len"] == 4
        orig_n = bytes(buf[m_idh_n["code_off"] + 16 : m_idh_n["code_off"] + 16 + m_idh_n["insns_size"] * 2])
        combined = pa_bytes + orig_n
        pad_w = m_host_step_det["insns_size"] - len(combined) // 2
        assert pad_w >= 0
        struct.pack_into(
            "<4H2I", buf, m_host_step_det["code_off"],
            m_idh_n["regs_size"], m_idh_n["ins_size"], max(m_idh_n["outs_size"], 3), 0, 0, m_host_step_det["insns_size"],
        )
        buf[m_host_step_det["code_off"] + 16 : m_host_step_det["code_off"] + 16 + m_host_step_det["insns_size"] * 2] = (
            combined + b"\x00\x00" * pad_w
        )
        stub = DalvikAssembler()
        stub.const4(0, 0)
        stub.return_object(0)
        stub_bytes = stub.assemble(pad_to_words=m_idh_n["insns_size"])
        struct.pack_into(
            "<4H2I", buf, m_idh_n["code_off"],
            m_host_step_det["ins_size"] + 1, m_host_step_det["ins_size"], 0, 0, 0, m_idh_n["insns_size"],
        )
        buf[m_idh_n["code_off"] + 16 : m_idh_n["code_off"] + 16 + len(stub_bytes)] = stub_bytes
        buf[m_idh_n["code_pos"] : m_idh_n["code_pos"] + 4] = encode_uleb128_4bytes(m_host_step_det["code_off"])
        buf[m_host_step_det["code_pos"] : m_host_step_det["code_pos"] + 4] = encode_uleb128_4bytes(m_idh_n["code_off"])
    else:
        n_off = m_idh_n["code_off"] + 16
        n_total = m_idh_n["insns_size"] * 2
        cur_n = bytes(buf[n_off : n_off + n_total])
        if pa_bytes not in cur_n:
            end = n_total
            while end >= 2 and cur_n[end - 2 : end] == b"\x00\x00":
                end -= 2
            combined = pa_bytes + cur_n[:end]
            assert len(combined) <= n_total
            struct.pack_into(
                "<4H2I", buf, m_idh_n["code_off"],
                m_idh_n["regs_size"], m_idh_n["ins_size"], max(m_idh_n["outs_size"], 3), 0, 0, m_idh_n["insns_size"],
            )
            buf[n_off : n_off + n_total] = combined + b"\x00" * (n_total - len(combined))

    out = recompute_dex_checksums(buf)
    print(f"[+] classes6.dex HRV + Active Hours patched (Adler: {struct.unpack_from('<I', out, 8)[0]:08x})")
    return out


# --------------------------------------------------------------------------- #
# 3h. classes6.dex — Hourly Steps, Calories & Exercise Charts (--hourly-charts)
# --------------------------------------------------------------------------- #

def _build_hourly_charts_insns(refs: dict, pad_words: int) -> bytes:
    """
    Build Lcom/liesheng/module_device/CustomCameraActivity;->start(Landroid/content/Context;)V
    (swapped into NadalWatchControlHelper$sendMsgToDevice$1.invokeSuspend(Object), 1244 words,
    regs=32, ins=1, outs=6, p0=v31 unused Context).

    Walks the last 30 days (idempotently) and populates StepDataTable hourly charts for Watch 4S:
      1) Hourly Exercise Minutes (sportTimeItems[24]) from exact synced SportTable workout
         intervals (splitting accurately across hour boundaries) + any remaining watch totalDur.
      2) Hourly Steps (items[24]):
           - Today (dayOffset==0): ingests Watch 4S's REAL 48 half-hour hardware step histogram
             from BLE 0x59 (cached in SharedPreferences("CRPSDK") by classes5.dex), collapses to
             24 hours, deducts stripped cycling phantom steps (baseSteps) from cycling hours, and
             reconciles cleanly with StepDataTable.totalSteps.
           - Past days (or before 0x59 arrives): preserves any previously saved non-zero 24-hour
             hardware items[]; otherwise distributes totalSteps across waking active hours weighted
             by Watch 4S's real 10-min HR elevation (excluding cycling hours).
      3) Hourly Calories (kcalItems[24]): allocates real SportTable workout calories into exact
         workout hours and distributes remaining daily totalKcal proportionally across hourly steps.
    """
    a = DalvikAssembler()

    # Load StepDataDao (v30), SportDao (v29), HeartRateDataDao (v28), nowMs (v26,v27)
    a.sget_object(0, refs["F_APPDB_A"])
    a.invoke_virtual([0], refs["M_APPDB_B"])
    a.move_result_object(0)
    a.invoke_virtual([0], refs["M_APPDB_STEP_DAO"])
    a.move_result_object(1)
    a.move_object(30, 1)
    a.invoke_virtual([0], refs["M_APPDB_SPORT_DAO"])
    a.move_result_object(1)
    a.move_object(29, 1)
    a.invoke_virtual([0], refs["M_APPDB_HR_DAO"])
    a.move_result_object(1)
    a.move_object(28, 1)
    a.invoke_static([], refs["M_SYS_TIME"])
    a.move_result_wide(26)

    a.const16(25, 0)  # dayOffset = 0..29
    a.label("hc_day_loop")
    a.move(0, 25)
    a.const16(1, 30)
    a.if_ge(0, 1, "hc_done")

    # chinaMidMs (v23,v24), localMidMs (v21,v22)
    a.int_to_long(0, 0)
    a.const_wide32(2, 86400000)
    a.mul_long_2addr(0, 2)
    a.move_wide(2, 26)
    a.sub_long_2addr(2, 0)
    a.invoke_static([2, 3], refs["M_IDATA_Z"])
    a.move_result_object(0)
    a.if_eqz(0, "hc_day_next")
    a.invoke_virtual([0], refs["M_DATE_GET_TIME"])
    a.move_result_wide(23)
    a.move_wide(0, 23)
    a.invoke_static([0, 1], refs["M_CHINA_TO_LOCAL"])
    a.move_result_wide(0)
    a.invoke_static([0, 1], refs["M_UTC_TO_LOCAL"])
    a.move_result_wide(21)

    # Fetch StepDataTable (v20)
    a.move_object(0, 30)
    a.move_wide(1, 23)
    a.invoke_interface([0, 1, 2], refs["M_STEP_BY_DATE"])
    a.move_result_object(20)
    a.if_eqz(20, "hc_day_next")

    # Allocate float[24] stArr (v19), wKcal (v18), int[24] stepArr (v16), float[24] kcalArr (v15),
    # and int[76] cycMeta (v17): [0..47]=cycling sec/30m slot, [48]=cycCount, [49]=maxCycEndSec/isFresh0x59,
    # [50]=exactPhantom, [51]=dirtyFlag, [52..75]=hourPhantom[0..23]
    a.const16(1, 24)
    a.new_array(0, 1, refs["T_FLOAT_ARR"])
    a.move_object(19, 0)
    a.new_array(0, 1, refs["T_FLOAT_ARR"])
    a.move_object(18, 0)
    a.new_array(0, 1, refs["T_INT_ARR"])
    a.move_object(16, 0)
    a.new_array(15, 1, refs["T_FLOAT_ARR"])
    a.const16(1, 76)
    a.new_array(0, 1, refs["T_INT_ARR"])
    a.move_object(17, 0)

    # Fetch HeartRateDataTable (v14) & dayRhr (v13, default 62, clamped 45..85)
    a.const16(13, 62)
    a.move_object(0, 28)
    a.move_wide(1, 23)
    a.invoke_interface([0, 1, 2], refs["M_HR_BY_DATE"])
    a.move_result_object(14)
    a.if_eqz(14, "hc_workouts")
    a.invoke_virtual([14], refs["M_HR_MIN"])
    a.move_result(1)
    a.const16(2, 38)
    a.if_lt(1, 2, "hc_workouts")
    a.const16(2, 100)
    a.if_gt(1, 2, "hc_workouts")
    a.const16(2, 45)
    a.if_ge(1, 2, "hc_rhr_lo")
    a.move(1, 2)
    a.label("hc_rhr_lo")
    a.const16(2, 85)
    a.if_le(1, 2, "hc_rhr_hi")
    a.move(1, 2)
    a.label("hc_rhr_hi")
    a.move(13, 1)

    # ---- Part 1: Workouts -> stArr (exercise min), wKcal (workout kcal), cycMin (cycling min) ----
    a.label("hc_workouts")
    a.move_object(0, 29)
    a.move_wide(1, 21)
    a.const_wide32(3, 86400000)
    a.add_long_2addr(3, 1)
    a.invoke_interface([0, 1, 2, 3, 4], refs["M_SPORT_BY_DATE"])
    a.move_result_object(12)
    a.if_eqz(12, "hc_extra_dur")
    a.invoke_interface([12], refs["M_LIST_SIZE"])
    a.move_result(11)
    a.const4(10, 0)  # spIdx

    a.label("hc_sp_loop")
    a.if_ge(10, 11, "hc_extra_dur")
    a.invoke_interface([12, 10], refs["M_LIST_GET"])
    a.move_result_object(9)
    a.if_eqz(9, "hc_sp_next")
    a.check_cast(9, refs["T_SPORT_TABLE"])
    a.invoke_virtual([9], refs["M_SPORT_GET_DUR"])
    a.move_result(8)  # v8 = durSec
    a.if_lez(8, "hc_sp_next")
    a.invoke_virtual([9], refs["M_SPORT_GET_START"])
    a.move_result_object(0)
    a.if_eqz(0, "hc_sp_next")
    a.invoke_virtual([0], refs["M_DATE_GET_TIME"])
    a.move_result_wide(0)
    a.move_wide(2, 21)
    a.sub_long_2addr(0, 2)
    a.const_wide16(2, 1000)
    a.div_long_2addr(0, 2)
    a.long_to_int(6, 0)  # v6 = startSec
    a.if_gez(6, "hc_ss_lo")
    a.const4(6, 0)
    a.label("hc_ss_lo")
    a.const32(0, 86399)
    a.if_le(6, 0, "hc_ss_hi")
    a.goto16("hc_sp_next")
    a.label("hc_ss_hi")
    a.move(7, 6)
    a.add_int_2addr(7, 8)  # v7 = endSec = startSec + durSec
    a.const32(0, 86400)
    a.if_le(7, 0, "hc_es_hi")
    a.move(7, 0)
    a.label("hc_es_hi")
    a.if_le(7, 6, "hc_sp_next")

    # spKcal (v5, float): if cal > 5000 -> cal / 1000.0f else (float)cal
    a.invoke_virtual([9], refs["M_SPORT_GET_CAL"])
    a.move_result(0)
    a.const4(5, 0)
    a.if_lez(0, "hc_cal_ok")
    a.int_to_float(5, 0)
    a.const16(1, 5000)
    a.if_le(0, 1, "hc_cal_ok")
    a.const_float(1, 1000.0)
    a.div_float_2addr(5, 1)
    a.label("hc_cal_ok")

    # isCyc (v4): 1 if SportTypeManager.INSTANCE.getMainTypeByType(type) == 2 (all cycling types)
    a.const4(4, 0)
    a.invoke_virtual([9], refs["M_SPORT_GET_TYPE"])
    a.move_result(1)
    a.sget_object(0, refs["F_STM_INST"])
    a.invoke_virtual([0, 1], refs["M_STM_MAIN_TYPE"])
    a.move_result(0)
    a.const4(1, 2)
    a.if_ne(0, 1, "hc_ov_init")
    a.const4(4, 1)

    # Split workout overlap across hours h = startSec/3600 .. 23
    a.label("hc_ov_init")
    a.div_int_lit16(3, 6, 3600)  # v3 = h
    a.label("hc_ov_loop")
    a.const16(0, 24)
    a.if_ge(3, 0, "hc_cyc_slots")
    a.mul_int_lit16(0, 3, 3600)  # hStart
    a.const16(1, 3600)
    a.move(2, 0)
    a.add_int_2addr(2, 1)        # hEnd = hStart + 3600
    a.if_ge(0, 6, "hc_ov_s")
    a.move(0, 6)                 # ovStart = max(startSec, hStart)
    a.label("hc_ov_s")
    a.if_le(2, 7, "hc_ov_e")
    a.move(2, 7)                 # ovEnd = min(endSec, hEnd)
    a.label("hc_ov_e")
    a.sub_int_2addr(2, 0)        # ovSec = ovEnd - ovStart
    a.if_lez(2, "hc_cyc_slots")

    # ovMin (v0, float) = ovSec / 60.0f
    a.int_to_float(0, 2)
    a.const_float(1, 60.0)
    a.div_float_2addr(0, 1)
    a.aget(1, 19, 3)             # stArr[h] += ovMin
    a.add_float_2addr(1, 0)
    a.aput(1, 19, 3)

    a.const4(0, 0)
    a.cmpl_float(0, 5, 0)
    a.if_lez(0, "hc_ov_next")
    a.int_to_float(0, 2)
    a.int_to_float(1, 8)
    a.div_float_2addr(0, 1)      # ovSec / durSec
    a.mul_float_2addr(0, 5)      # share of spKcal
    a.aget(1, 18, 3)
    a.add_float_2addr(1, 0)
    a.aput(1, 18, 3)

    a.label("hc_ov_next")
    a.add_int_lit8(3, 3, 1)
    a.goto16("hc_ov_loop")

    # For cycling workouts, record exact 30-min slot overlaps (cycMeta[0..47]), cycCount ([48]), & maxCycEndSec ([49])
    a.label("hc_cyc_slots")
    a.if_eqz(4, "hc_sp_next")
    a.const16(0, 48)
    a.aget(1, 17, 0)
    a.add_int_lit8(1, 1, 1)
    a.aput(1, 17, 0)

    # Use wall-clock endTime if within durSec + 900s (covers brief traffic-light stops, excludes long cafe breaks)
    a.invoke_virtual([9], refs["M_SPORT_END"])
    a.move_result_object(0)
    a.if_eqz(0, "hc_cs_max")
    a.invoke_virtual([0], refs["M_DATE_GET_TIME"])
    a.move_result_wide(0)
    a.move_wide(2, 21)
    a.sub_long_2addr(0, 2)
    a.const_wide16(2, 1000)
    a.div_long_2addr(0, 2)
    a.long_to_int(0, 0)          # v0 = endTimeSec
    a.if_le(0, 7, "hc_cs_max")
    a.const16(1, 900)
    a.move(2, 7)
    a.add_int_2addr(2, 1)
    a.if_gt(0, 2, "hc_cs_max")
    a.const32(1, 86400)
    a.if_le(0, 1, "hc_cs_cl")
    a.move(0, 1)
    a.label("hc_cs_cl")
    a.move(7, 0)

    a.label("hc_cs_max")
    a.const16(0, 49)
    a.aget(1, 17, 0)
    a.if_le(7, 1, "hc_cs_go")
    a.aput(7, 17, 0)

    a.label("hc_cs_go")
    a.div_int_lit16(3, 6, 1800)  # s = startSec / 1800 (0..47)
    a.label("hc_cs_loop")
    a.const16(0, 48)
    a.if_ge(3, 0, "hc_sp_next")
    a.mul_int_lit16(0, 3, 1800)  # sStart
    a.const16(1, 1800)
    a.move(2, 0)
    a.add_int_2addr(2, 1)        # sEnd = sStart + 1800
    a.if_ge(0, 6, "hc_cs_s")
    a.move(0, 6)                 # ovStart = max(startSec, sStart)
    a.label("hc_cs_s")
    a.if_le(2, 7, "hc_cs_e")
    a.move(2, 7)                 # ovEnd = min(cycEndSec, sEnd)
    a.label("hc_cs_e")
    a.sub_int_2addr(2, 0)        # ovSec = ovEnd - ovStart
    a.if_lez(2, "hc_sp_next")
    a.aget(0, 17, 3)
    a.add_int_2addr(0, 2)
    a.if_le(0, 1, "hc_cs_put")
    a.move(0, 1)
    a.label("hc_cs_put")
    a.aput(0, 17, 3)
    a.add_int_lit8(3, 3, 1)
    a.goto16("hc_cs_loop")

    a.label("hc_sp_next")
    a.add_int_lit8(10, 10, 1)
    a.goto16("hc_sp_loop")

    # If stepRow.totalDur > sum(stArr) + 1.0f, place remaining exercise minutes on peak active HR hour
    a.label("hc_extra_dur")
    a.const4(0, 0)  # stSum (float)
    a.const4(1, 0)
    a.label("hc_stsum_l")
    a.const16(2, 24)
    a.if_ge(1, 2, "hc_stsum_d")
    a.aget(2, 19, 1)
    a.add_float_2addr(0, 2)
    a.add_int_lit8(1, 1, 1)
    a.goto16("hc_stsum_l")
    a.label("hc_stsum_d")
    a.move_object(1, 20)
    a.invoke_virtual([1], refs["M_STEP_GET_DUR"])
    a.move_result(1)
    a.if_lez(1, "hc_steps_start")
    a.int_to_float(1, 1)
    a.sub_float_2addr(1, 0)  # v1 = remDur (float)
    a.const_float(2, 1.0)
    a.cmpl_float(2, 1, 2)
    a.if_lez(2, "hc_steps_start")
    # Find hour with highest HR (default 12)
    a.const16(3, 12)
    a.if_eqz(14, "hc_add_remdur")
    a.invoke_virtual([14], refs["M_HR_ITEMS"])
    a.move_result_object(4)
    a.if_eqz(4, "hc_add_remdur")
    a.array_length(5, 4)
    a.div_int_lit8(6, 5, 24)
    a.if_lez(6, "hc_add_remdur")
    a.const4(7, 0)  # bestHr
    a.const4(8, 0)  # k
    a.label("hc_pkhr_l")
    a.if_ge(8, 5, "hc_add_remdur")
    a.aget(9, 4, 8)
    a.if_le(9, 7, "hc_pkhr_n")
    a.move(7, 9)
    a.move(3, 8)
    a.div_int_2addr(3, 6)
    a.label("hc_pkhr_n")
    a.add_int_lit8(8, 8, 1)
    a.goto16("hc_pkhr_l")
    a.label("hc_add_remdur")
    a.const16(2, 23)
    a.if_le(3, 2, "hc_rd_ok")
    a.move(3, 2)
    a.label("hc_rd_ok")
    a.aget(2, 19, 3)
    a.add_float_2addr(2, 1)
    a.aput(2, 19, 3)

    # ---- Part 2: Hourly Steps (stepArr -> v16) ----
    a.label("hc_steps_start")
    a.move_object(0, 20)
    a.invoke_virtual([0], refs["M_STEP_GET_TOTAL"])
    a.move_result(12)  # v12 = totalSteps
    a.if_gtz(12, "hc_st_go")
    a.invoke_virtual([0], refs["M_STEP_GET_BASE"])
    a.move_result(1)
    a.if_lez(1, "hc_kcal_start")
    a.label("hc_st_go")

    # Case A (dayOffset == 0): ingest Watch 4S BLE 0x59 48 half-hour hardware steps from SharedPreferences("CRPSDK")
    a.move(0, 25)
    a.if_nez(0, "hc_steps_keep_or_hr")
    a.invoke_static([], refs["M_HYAPP_CTX"])
    a.move_result_object(0)
    a.if_eqz(0, "hc_steps_keep_or_hr")
    a.const_string(1, refs["STR_CRPSDK"])
    a.const4(2, 0)
    a.invoke_virtual([0, 1, 2], refs["M_GET_SP"])
    a.move_result_object(11)
    a.if_eqz(11, "hc_steps_keep_or_hr")
    a.const_string(1, refs["STR_TIME"])
    a.const_wide16(2, 0)
    a.invoke_interface([11, 1, 2, 3], refs["M_SP_GET_LONG"])
    a.move_result_wide(0)
    # Require ts >= localMidMs && ts < localMidMs + 86400000L
    a.move_wide(2, 21)
    a.cmp_long(4, 0, 2)
    a.if_ltz(4, "hc_steps_keep_or_hr")
    a.const_wide32(4, 86400000)
    a.add_long_2addr(2, 4)
    a.cmp_long(4, 0, 2)
    a.if_gez(4, "hc_steps_keep_or_hr")

    # Record whether 0x59 snapshot is fresh enough to cover today's latest cycling ride (spTimeSec + 120 >= maxCycEndSec)
    a.move_wide(2, 21)
    a.sub_long_2addr(0, 2)
    a.const_wide16(2, 1000)
    a.div_long_2addr(0, 2)
    a.long_to_int(0, 0)
    a.add_int_lit8(0, 0, 120)
    a.const16(1, 49)
    a.aget(2, 17, 1)
    a.const4(3, 0)
    a.if_lt(0, 2, "hc_sp_fresh")
    a.const4(3, 1)
    a.label("hc_sp_fresh")
    a.aput(3, 17, 1)

    a.const_string(1, refs["STR_STEPS"])
    a.const_string(2, refs["STR_EMPTY"])
    a.invoke_interface([11, 1, 2], refs["M_SP_GET_STR"])
    a.move_result_object(10)
    a.if_eqz(10, "hc_steps_keep_or_hr")
    a.const_string(1, refs["STR_TODAY"])
    a.invoke_virtual([10, 1], refs["M_STR_CONTAINS"])
    a.move_result(0)
    a.if_eqz(0, "hc_steps_keep_or_hr")
    a.const_string(1, refs["STR_LBRACK"])
    a.invoke_virtual([10, 1], refs["M_STR_INDEXOF"])
    a.move_result(9)  # v9 = pos of '['
    a.if_ltz(9, "hc_steps_keep_or_hr")
    a.add_int_lit8(9, 9, 1)
    a.invoke_virtual([10], refs["M_STR_LEN"])
    a.move_result(8)  # v8 = strLen
    a.const4(7, 0)    # v7 = slot (0..47)
    a.const4(6, 0)    # v6 = rawSum

    # Compact charAt integer parser for 48 half-hour slots
    a.label("hc_p_skip")
    a.const16(0, 48)
    a.if_ge(7, 0, "hc_p_done")
    a.if_ge(9, 8, "hc_p_done")
    a.invoke_virtual([10, 9], refs["M_STR_CHARAT"])
    a.move_result(0)
    a.const16(1, 93)  # ']'
    a.if_eq(0, 1, "hc_p_done")
    a.const16(1, 48)  # '0'
    a.if_lt(0, 1, "hc_p_adv")
    a.const16(2, 57)  # '9'
    a.if_gt(0, 2, "hc_p_adv")
    # Parse number into v5
    a.const4(5, 0)
    a.label("hc_p_num")
    a.sub_int_2addr(0, 1)
    a.mul_int_lit8(5, 5, 10)
    a.add_int_2addr(5, 0)
    a.add_int_lit8(9, 9, 1)
    a.if_ge(9, 8, "hc_p_store")
    a.invoke_virtual([10, 9], refs["M_STR_CHARAT"])
    a.move_result(0)
    a.if_lt(0, 1, "hc_p_store")
    a.if_gt(0, 2, "hc_p_store")
    a.goto16("hc_p_num")

    a.label("hc_p_store")
    a.div_int_lit8(3, 7, 2)  # h = slot / 2
    a.aget(4, 16, 3)
    a.add_int_2addr(4, 5)
    a.aput(4, 16, 3)
    a.add_int_2addr(6, 5)
    a.if_lez(5, "hc_p_snext")
    a.aget(1, 17, 7)         # v1 = cycSlotSec[slot] (0..1800)
    a.if_lez(1, "hc_p_snext")
    # Exact 30-min overlap phantom steps: phantom = (rawSlotSteps * cycSlotSec + 900) / 1800
    a.move(2, 5)
    a.mul_int_2addr(2, 1)
    a.const16(1, 900)
    a.add_int_2addr(2, 1)
    a.div_int_lit16(2, 2, 1800)
    a.if_lez(2, "hc_p_snext")
    a.const16(1, 50)
    a.aget(0, 17, 1)
    a.add_int_2addr(0, 2)
    a.aput(0, 17, 1)         # cycMeta[50] += phantom (exactPhantom)
    a.add_int_lit8(1, 3, 52)
    a.aget(0, 17, 1)
    a.add_int_2addr(0, 2)
    a.aput(0, 17, 1)         # cycMeta[52 + h] += phantom (hourPhantom[h])
    a.label("hc_p_snext")
    a.add_int_lit8(7, 7, 1)
    a.goto16("hc_p_skip")

    a.label("hc_p_adv")
    a.add_int_lit8(9, 9, 1)
    a.goto16("hc_p_skip")

    a.label("hc_p_done")
    a.if_lez(6, "hc_steps_keep_or_hr")

    # If today has cycling workouts & fresh 0x59 data, persist exact 0x59 phantom steps into
    # local-only SportTable.sportcounter (survives midnight & bulk syncs!) and invoke cleanStepTable
    a.const16(0, 48)
    a.aget(1, 17, 0)         # cycCount
    a.if_lez(1, "hc_reconcile")
    a.const16(0, 49)
    a.aget(1, 17, 0)         # isFresh0x59
    a.if_eqz(1, "hc_ded_chk")

    a.const16(0, 50)
    a.aget(8, 17, 0)         # v8 = exactPhantom
    a.if_gtz(8, "hc_sc_val_ok")
    a.const4(8, -1)          # -1 encodes measured 0 phantom steps
    a.label("hc_sc_val_ok")

    a.move_object(0, 29)
    a.move_wide(1, 21)
    a.const_wide32(3, 86400000)
    a.add_long_2addr(3, 1)
    a.invoke_interface([0, 1, 2, 3, 4], refs["M_SPORT_BY_DATE"])
    a.move_result_object(10)
    a.if_eqz(10, "hc_run_clean")
    a.invoke_interface([10], refs["M_LIST_SIZE"])
    a.move_result(9)
    a.const4(7, 0)           # idx = 0
    a.const4(6, 0)           # assigned = 0
    a.label("hc_sc_loop")
    a.if_ge(7, 9, "hc_run_clean")
    a.invoke_interface([10, 7], refs["M_LIST_GET"])
    a.move_result_object(5)
    a.if_eqz(5, "hc_sc_next")
    a.check_cast(5, refs["T_SPORT_TABLE"])
    a.invoke_virtual([5], refs["M_SPORT_GET_TYPE"])
    a.move_result(1)
    a.sget_object(0, refs["F_STM_INST"])
    a.invoke_virtual([0, 1], refs["M_STM_MAIN_TYPE"])
    a.move_result(0)
    a.const4(1, 2)
    a.if_ne(0, 1, "hc_sc_next")
    a.invoke_virtual([5], refs["M_SPORT_GET_STEPS"])
    a.move_result(0)
    a.if_gtz(0, "hc_sc_next")
    a.move(4, 8)
    a.if_eqz(6, "hc_sc_first")
    a.const4(4, 0)
    a.label("hc_sc_first")
    a.const4(6, 1)
    a.invoke_virtual([5], refs["M_SPORT_GET_COUNTER"])
    a.move_result(0)
    a.if_eq(0, 4, "hc_sc_next")
    a.invoke_virtual([5, 4], refs["M_SPORT_SET_COUNTER"])
    a.move_object(0, 29)
    a.invoke_interface([0, 5], refs["M_SPORT_UPDATE"])
    a.label("hc_sc_next")
    a.add_int_lit8(7, 7, 1)
    a.goto16("hc_sc_loop")

    # Run cleanStepTable (harmless no-op if --cycling-fixes is not applied)
    a.label("hc_run_clean")
    a.move_object(0, 20)
    a.invoke_virtual([0], refs["M_STEP_GET_BASE"])
    a.move_result(4)         # oldBase
    a.move(3, 12)            # oldTotal
    a.invoke_static([0], refs["M_OBJ_HASH"])
    a.invoke_virtual([0], refs["M_STEP_GET_TOTAL"])
    a.move_result(12)        # newTotal
    a.invoke_virtual([0], refs["M_STEP_GET_BASE"])
    a.move_result(5)         # newBase
    a.if_ne(5, 4, "hc_mark_dirty")
    a.if_eq(12, 3, "hc_ded_chk")
    a.label("hc_mark_dirty")
    a.const16(0, 51)
    a.const4(1, 1)
    a.aput(1, 17, 0)         # cycMeta[51] = dirty = 1

    # Deduct exact per-hour 0x59 phantom steps from stepArr[0..23] only if cycling-fixes stripped baseSteps > 0
    a.label("hc_ded_chk")
    a.move_object(0, 20)
    a.invoke_virtual([0], refs["M_STEP_GET_BASE"])
    a.move_result(5)
    a.if_lez(5, "hc_reconcile")
    a.const4(0, 0)
    a.label("hc_hded_l")
    a.const16(1, 24)
    a.if_ge(0, 1, "hc_hded_done")
    a.add_int_lit8(2, 0, 52)
    a.aget(3, 17, 2)
    a.if_lez(3, "hc_hded_n")
    a.aget(4, 16, 0)
    a.sub_int_2addr(4, 3)
    a.if_gez(4, "hc_hded_pos")
    a.const4(4, 0)
    a.label("hc_hded_pos")
    a.aput(4, 16, 0)
    a.label("hc_hded_n")
    a.add_int_lit8(0, 0, 1)
    a.goto16("hc_hded_l")
    a.label("hc_hded_done")
    a.if_lez(12, "hc_kcal_start")

    # Reconcile stepArr[0..23] to match totalSteps (v12) exactly
    a.label("hc_reconcile")
    a.const4(6, 0)  # curSum
    a.const4(7, 0)  # maxH
    a.const4(8, 0)  # maxV
    a.const4(0, 0)
    a.label("hc_rs_l")
    a.const16(1, 24)
    a.if_ge(0, 1, "hc_rs_d")
    a.aget(1, 16, 0)
    a.add_int_2addr(6, 1)
    a.if_le(1, 8, "hc_rs_n")
    a.move(8, 1)
    a.move(7, 0)
    a.label("hc_rs_n")
    a.add_int_lit8(0, 0, 1)
    a.goto16("hc_rs_l")
    a.label("hc_rs_d")
    a.if_lez(6, "hc_steps_keep_or_hr")
    a.if_eq(6, 12, "hc_kcal_start")
    a.int_to_float(5, 12)
    a.int_to_float(4, 6)
    a.div_float_2addr(5, 4)  # v5 = scale = totalSteps / curSum
    a.const4(6, 0)           # newSum
    a.const4(0, 0)
    a.label("hc_sc_l")
    a.const16(1, 24)
    a.if_ge(0, 1, "hc_sc_d")
    a.aget(1, 16, 0)
    a.if_lez(1, "hc_sc_n")
    a.int_to_float(1, 1)
    a.mul_float_2addr(1, 5)
    a.const_float(2, 0.5)
    a.add_float_2addr(1, 2)
    a.float_to_int(1, 1)
    a.aput(1, 16, 0)
    a.add_int_2addr(6, 1)
    a.label("hc_sc_n")
    a.add_int_lit8(0, 0, 1)
    a.goto16("hc_sc_l")
    a.label("hc_sc_d")
    # Fix rounding delta on maxH (v7)
    a.move(0, 12)
    a.sub_int_2addr(0, 6)
    a.aget(1, 16, 7)
    a.add_int_2addr(1, 0)
    a.if_gez(1, "hc_sc_pos")
    a.const4(1, 0)
    a.label("hc_sc_pos")
    a.aput(1, 16, 7)
    a.goto16("hc_kcal_start")

    # Case B (past days or before 0x59): preserve existing valid items[24], else distribute by HR activity
    a.label("hc_steps_keep_or_hr")
    a.move_object(0, 20)
    a.invoke_virtual([0], refs["M_STEP_GET_ITEMS"])
    a.move_result_object(10)
    a.if_eqz(10, "hc_steps_hr")
    a.array_length(1, 10)
    a.const16(2, 24)
    a.if_ne(1, 2, "hc_steps_hr")
    a.const4(3, 0)  # sumOld
    a.const4(0, 0)
    a.label("hc_ko_l")
    a.if_ge(0, 2, "hc_ko_d")
    a.aget(1, 10, 0)
    a.add_int_2addr(3, 1)
    a.add_int_lit8(0, 0, 1)
    a.goto16("hc_ko_l")
    a.label("hc_ko_d")
    a.if_lez(3, "hc_steps_hr")
    # Keep existing if within 25 steps of totalSteps (preserves saved hardware 0x59 histograms!)
    a.move(4, 3)
    a.sub_int_2addr(4, 12)
    a.if_gez(4, "hc_ko_abs")
    a.rsub_int_lit16(4, 4, 0)
    a.label("hc_ko_abs")
    a.const16(5, 25)
    a.if_gt(4, 5, "hc_steps_hr")
    a.const4(0, 0)
    a.label("hc_ko_cp")
    a.if_ge(0, 2, "hc_kcal_start")
    a.aget(1, 10, 0)
    a.aput(1, 16, 0)
    a.add_int_lit8(0, 0, 1)
    a.goto16("hc_ko_cp")

    # Fallback HR-weighted hourly step distribution (for historical days before 0x59 was saved)
    a.label("hc_steps_hr")
    a.if_eqz(14, "hc_kcal_start")
    a.invoke_virtual([14], refs["M_HR_ITEMS"])
    a.move_result_object(10)
    a.if_eqz(10, "hc_kcal_start")
    a.array_length(9, 10)
    a.div_int_lit8(8, 9, 24)  # slotsPerHour
    a.if_lez(8, "hc_kcal_start")
    a.add_int_lit8(7, 13, 12)  # baseHr = dayRhr + 12
    a.const4(6, 0)             # totalW
    a.const4(5, 0)             # h = 0
    a.label("hc_hrw_h")
    a.const16(0, 24)
    a.if_ge(5, 0, "hc_hrw_done")
    a.move(1, 5)
    a.mul_int_2addr(1, 8)      # k = h * slotsPerHour
    a.move(2, 1)
    a.add_int_2addr(2, 8)      # end
    a.if_lt(9, 2, "hc_hrw_hn")
    a.const4(3, 0)             # w = 0
    a.label("hc_hrw_k")
    a.if_ge(1, 2, "hc_hrw_kd")
    a.aget(4, 10, 1)
    a.if_le(4, 7, "hc_hrw_kn")
    a.sub_int_2addr(4, 7)
    a.add_int_2addr(3, 4)
    a.label("hc_hrw_kn")
    a.add_int_lit8(1, 1, 1)
    a.goto16("hc_hrw_k")
    a.label("hc_hrw_kd")
    # Down-weight cycling hours so phantom cycling HR doesn't absorb walking steps
    a.mul_int_lit8(0, 5, 2)
    a.aget(4, 17, 0)
    a.add_int_lit8(0, 0, 1)
    a.aget(0, 17, 0)
    a.add_int_2addr(4, 0)
    a.if_lez(4, "hc_hrw_put")
    a.if_lez(3, "hc_hrw_put")
    a.div_int_lit8(3, 3, 6)
    a.label("hc_hrw_put")
    a.aput(3, 16, 5)
    a.add_int_2addr(6, 3)
    a.label("hc_hrw_hn")
    a.add_int_lit8(5, 5, 1)
    a.goto16("hc_hrw_h")

    a.label("hc_hrw_done")
    a.if_lez(6, "hc_kcal_start")
    # Reuse hc_reconcile to scale weights in stepArr (v16) to totalSteps (v12)!
    a.goto16("hc_reconcile")

    # ---- Part 3: Hourly Calories (kcalArr -> v15) ----
    a.label("hc_kcal_start")
    a.move_object(0, 20)
    a.invoke_virtual([0], refs["M_STEP_GET_KCAL"])
    a.move_result(12)  # v12 = totalKcal (float)
    a.const4(0, 0)
    a.cmpl_float(0, 12, 0)
    a.if_lez(0, "hc_save_check")

    # Sum wKcal (v18) -> v11 (float)
    a.const4(11, 0)
    a.const4(0, 0)
    a.label("hc_wks_l")
    a.const16(1, 24)
    a.if_ge(0, 1, "hc_wks_d")
    a.aget(1, 18, 0)
    a.add_float_2addr(11, 1)
    a.add_int_lit8(0, 0, 1)
    a.goto16("hc_wks_l")
    a.label("hc_wks_d")

    # Clamp wKcal scale <= 1.0 so workout kcal never exceeds daily totalKcal
    a.const_float(10, 1.0)
    a.cmpl_float(0, 11, 12)
    a.if_lez(0, "hc_wk_cp")
    a.div_float(10, 12, 11)
    a.move(11, 12)
    a.label("hc_wk_cp")
    a.const4(0, 0)
    a.label("hc_wk_l")
    a.const16(1, 24)
    a.if_ge(0, 1, "hc_wk_d")
    a.aget(1, 18, 0)
    a.mul_float_2addr(1, 10)
    a.aput(1, 15, 0)
    a.add_int_lit8(0, 0, 1)
    a.goto16("hc_wk_l")

    # Distribute remKcal = totalKcal - wKcalSum proportionally across stepArr (v16)
    a.label("hc_wk_d")
    a.sub_float(9, 12, 11)  # v9 = remKcal
    a.const_float(0, 0.1)
    a.cmpl_float(0, 9, 0)
    a.if_lez(0, "hc_save_check")
    a.const4(8, 0)  # stepSum
    a.const4(0, 0)
    a.label("hc_ssum_l")
    a.const16(1, 24)
    a.if_ge(0, 1, "hc_ssum_d")
    a.aget(1, 16, 0)
    a.add_int_2addr(8, 1)
    a.add_int_lit8(0, 0, 1)
    a.goto16("hc_ssum_l")
    a.label("hc_ssum_d")
    a.if_lez(8, "hc_save_check")
    a.int_to_float(8, 8)
    a.div_float(9, 9, 8)  # kcalPerStep
    a.const4(0, 0)
    a.label("hc_kdist_l")
    a.const16(1, 24)
    a.if_ge(0, 1, "hc_save_check")
    a.aget(1, 16, 0)
    a.if_lez(1, "hc_kdist_n")
    a.int_to_float(1, 1)
    a.mul_float_2addr(1, 9)
    a.aget(2, 15, 0)
    a.add_float_2addr(2, 1)
    a.aput(2, 15, 0)
    a.label("hc_kdist_n")
    a.add_int_lit8(0, 0, 1)
    a.goto16("hc_kdist_l")

    # ---- Part 4: Idempotent change check & StepDataDao.insert(stepRow) ----
    a.label("hc_save_check")
    a.const16(0, 51)
    a.aget(11, 17, 0)  # dirty = cycMeta[51] (1 if cleanStepTable updated stepRow)

    # Check stepArr (v16) non-empty & changed
    a.const4(6, 0)
    a.const4(0, 0)
    a.label("hc_cs1_l")
    a.const16(1, 24)
    a.if_ge(0, 1, "hc_cs1_d")
    a.aget(1, 16, 0)
    a.add_int_2addr(6, 1)
    a.add_int_lit8(0, 0, 1)
    a.goto16("hc_cs1_l")
    a.label("hc_cs1_d")
    a.if_lez(6, "hc_chk_k")
    a.move_object(0, 20)
    a.invoke_virtual([0], refs["M_STEP_GET_ITEMS"])
    a.move_result_object(2)
    a.if_eqz(2, "hc_set_s")
    a.array_length(3, 2)
    a.const16(1, 24)
    a.if_ne(3, 1, "hc_set_s")
    a.const4(0, 0)
    a.label("hc_cs2_l")
    a.if_ge(0, 1, "hc_chk_k")
    a.aget(3, 2, 0)
    a.aget(4, 16, 0)
    a.if_ne(3, 4, "hc_set_s")
    a.add_int_lit8(0, 0, 1)
    a.goto16("hc_cs2_l")
    a.label("hc_set_s")
    a.move_object(0, 20)
    a.move_object(1, 16)
    a.invoke_virtual([0, 1], refs["M_STEP_SET_ITEMS"])
    a.const4(11, 1)

    # Check kcalArr (v15) non-empty & changed (compare integer kcal)
    a.label("hc_chk_k")
    a.const4(6, 0)
    a.const4(0, 0)
    a.label("hc_ck1_l")
    a.const16(1, 24)
    a.if_ge(0, 1, "hc_ck1_d")
    a.aget(1, 15, 0)
    a.add_float_2addr(6, 1)
    a.add_int_lit8(0, 0, 1)
    a.goto16("hc_ck1_l")
    a.label("hc_ck1_d")
    a.const4(1, 0)
    a.cmpl_float(1, 6, 1)
    a.if_lez(1, "hc_chk_st")
    a.move_object(0, 20)
    a.invoke_virtual([0], refs["M_STEP_GET_KITEMS"])
    a.move_result_object(2)
    a.if_eqz(2, "hc_set_k")
    a.array_length(3, 2)
    a.const16(1, 24)
    a.if_ne(3, 1, "hc_set_k")
    a.const4(0, 0)
    a.label("hc_ck2_l")
    a.if_ge(0, 1, "hc_chk_st")
    a.aget(3, 2, 0)
    a.float_to_int(3, 3)
    a.aget(4, 15, 0)
    a.float_to_int(4, 4)
    a.if_ne(3, 4, "hc_set_k")
    a.add_int_lit8(0, 0, 1)
    a.goto16("hc_ck2_l")
    a.label("hc_set_k")
    a.move_object(0, 20)
    a.invoke_virtual([0, 15], refs["M_STEP_SET_KITEMS"])
    a.const4(11, 1)

    # Check stArr (v19) non-empty & changed (compare integer minutes)
    a.label("hc_chk_st")
    a.const4(6, 0)
    a.const4(0, 0)
    a.label("hc_ct1_l")
    a.const16(1, 24)
    a.if_ge(0, 1, "hc_ct1_d")
    a.aget(1, 19, 0)
    a.add_float_2addr(6, 1)
    a.add_int_lit8(0, 0, 1)
    a.goto16("hc_ct1_l")
    a.label("hc_ct1_d")
    a.const4(1, 0)
    a.cmpl_float(1, 6, 1)
    a.if_lez(1, "hc_do_save")
    a.move_object(0, 20)
    a.invoke_virtual([0], refs["M_STEP_GET_STIME"])
    a.move_result_object(2)
    a.if_eqz(2, "hc_set_st")
    a.array_length(3, 2)
    a.const16(1, 24)
    a.if_ne(3, 1, "hc_set_st")
    a.const4(0, 0)
    a.label("hc_ct2_l")
    a.if_ge(0, 1, "hc_do_save")
    a.aget(3, 2, 0)
    a.float_to_int(3, 3)
    a.aget(4, 19, 0)
    a.float_to_int(4, 4)
    a.if_ne(3, 4, "hc_set_st")
    a.add_int_lit8(0, 0, 1)
    a.goto16("hc_ct2_l")
    a.label("hc_set_st")
    a.move_object(0, 20)
    a.move_object(1, 19)
    a.invoke_virtual([0, 1], refs["M_STEP_SET_STIME"])
    a.const4(11, 1)

    a.label("hc_do_save")
    a.if_eqz(11, "hc_day_next")
    a.move_object(0, 30)
    a.move_object(1, 20)
    a.invoke_interface([0, 1], refs["M_STEP_INSERT"])

    a.label("hc_day_next")
    a.add_int_lit8(25, 25, 1)
    a.goto16("hc_day_loop")

    a.label("hc_done")
    a.return_void()
    return a.assemble(pad_to_words=pad_words)


def patch_classes6_hourly_charts(dex_bytes: bytes) -> bytes:
    """
    Patch classes6.dex with:
      1) Unhide 24-hour mini bar charts on Home Data Hub Calories & Steps cards (bypass CommonUtil.B()).
      2) Hourly Steps (from BLE 0x59 hardware histograms + HR fallback), Calories, and Exercise engine.
      3) Live preservation guard in IDataHelper.N so Watch 4S bulk step syncs never wipe hourly arrays.
    """
    print("[*] Patching classes6.dex (Hourly Steps/Calories/Exercise Engine + Home Mini Charts)...")
    d6 = DexFile(dex_bytes)
    buf = bytearray(dex_bytes)

    # 1) Bypass CommonUtil.B() in Home Data Hub Calories (dataloader/a) and Steps (dataloader/l) cards
    mid_b = d6.find_idx("method", "Lcom/liesheng/haylou/utils/CommonUtil;->B()Z")
    for cls, pc_off, dst_reg in (
        ("Lcom/liesheng/module_home/homeV2/dataloader/a;", 0x19, 3),
        ("Lcom/liesheng/module_home/homeV2/dataloader/l;", 0x0A, 1),
    ):
        info = d6.find_method_info(cls, f"{cls}->f(Lkotlin/coroutines/jvm/internal/SuspendLambda;)Ljava/lang/Object;", allow_tries=True)
        off = info["code_off"] + 16 + pc_off * 2
        expected = struct.pack("<HHHH", 0x0071, mid_b, 0x0000, 0x000A | (dst_reg << 8))
        patched = struct.pack("<HHHH", 0x0012 | (dst_reg << 8), 0x0000, 0x0000, 0x0000)
        cur = bytes(buf[off : off + 8])
        if cur != patched:
            assert cur == expected, f"Unexpected bytes at {cls}.f()+{pc_off:04x}: {cur.hex()}"
            buf[off : off + 8] = patched

    refs = {
        "T_INT_ARR": d6.find_idx("type", "[I"),
        "T_FLOAT_ARR": d6.find_idx("type", "[F"),
        "T_SPORT_TABLE": d6.find_idx("type", "Lcom/liesheng/lib_room/table/SportTable;"),
        "F_APPDB_A": d6.find_idx("field", "Lcom/liesheng/AppDatabase;->a:Lcom/liesheng/AppDatabase$a;"),
        "M_APPDB_B": d6.find_idx("method", "Lcom/liesheng/AppDatabase$a;->b()Lcom/liesheng/AppDatabase;"),
        "M_APPDB_STEP_DAO": d6.find_idx("method", "Lcom/liesheng/AppDatabase;->w()Lcom/liesheng/lib_room/dao/StepDataDao;"),
        "M_APPDB_SPORT_DAO": d6.find_idx("method", "Lcom/liesheng/AppDatabase;->u()Lcom/liesheng/lib_room/dao/SportDao;"),
        "M_APPDB_HR_DAO": d6.find_idx("method", "Lcom/liesheng/AppDatabase;->l()Lcom/liesheng/lib_room/dao/HeartRateDataDao;"),
        "M_STEP_BY_DATE": d6.find_idx("method", "Lcom/liesheng/lib_room/dao/StepDataDao;->getStepDataByDate(J)Lcom/liesheng/lib_room/table/StepDataTable;"),
        "M_STEP_INSERT": d6.find_idx("method", "Lcom/liesheng/lib_room/dao/StepDataDao;->insert(Lcom/liesheng/lib_room/table/StepDataTable;)V"),
        "M_STEP_GET_RECDATE": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->getRecordDate()Ljava/util/Date;"),
        "M_STEP_GET_TOTAL": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->getTotalSteps()I"),
        "M_STEP_GET_BASE": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->getBaseSteps()I"),
        "M_STEP_GET_KCAL": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->getTotalKcal()F"),
        "M_STEP_GET_DUR": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->getTotalDur()I"),
        "M_STEP_GET_ITEMS": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->getItems()[I"),
        "M_STEP_SET_ITEMS": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->setItems([I)V"),
        "M_STEP_GET_KITEMS": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->getKcalItems()[F"),
        "M_STEP_SET_KITEMS": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->setKcalItems([F)V"),
        "M_STEP_GET_STIME": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->getSportTimeItems()[F"),
        "M_STEP_SET_STIME": d6.find_idx("method", "Lcom/liesheng/lib_room/table/StepDataTable;->setSportTimeItems([F)V"),
        "M_SPORT_BY_DATE": d6.find_idx("method", "Lcom/liesheng/lib_room/dao/SportDao;->getSportDataByDate(JJ)Ljava/util/List;"),
        "M_SPORT_UPDATE": d6.find_idx("method", "Lcom/liesheng/lib_room/dao/SportDao;->update(Lcom/liesheng/lib_room/table/SportTable;)V"),
        "M_SPORT_GET_DUR": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getDuration()I"),
        "M_SPORT_GET_START": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getStartTime()Ljava/util/Date;"),
        "M_SPORT_END": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getEndTime()Ljava/util/Date;"),
        "M_SPORT_GET_CAL": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getCal()I"),
        "M_SPORT_GET_TYPE": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getType()I"),
        "M_SPORT_GET_STEPS": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getSteps()I"),
        "M_SPORT_GET_COUNTER": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->getSportcounter()I"),
        "M_SPORT_SET_COUNTER": d6.find_idx("method", "Lcom/liesheng/lib_room/table/SportTable;->setSportcounter(I)V"),
        "M_OBJ_HASH": d6.find_idx("method", "Lio/reactivex/internal/functions/ObjectHelper;->hashCode(Ljava/lang/Object;)I"),
        "F_STM_INST": d6.find_idx("field", "Lcom/liesheng/hayloufun/sport/data/SportTypeManager;->INSTANCE:Lcom/liesheng/hayloufun/sport/data/SportTypeManager;"),
        "M_STM_MAIN_TYPE": d6.find_idx("method", "Lcom/liesheng/hayloufun/sport/data/SportTypeManager;->getMainTypeByType(I)I"),
        "M_HR_BY_DATE": d6.find_idx("method", "Lcom/liesheng/lib_room/dao/HeartRateDataDao;->getHeartDataByDate(J)Lcom/liesheng/lib_room/table/HeartRateDataTable;"),
        "M_HR_MIN": d6.find_idx("method", "Lcom/liesheng/lib_room/table/HeartRateDataTable;->getMinHeartRate()I"),
        "M_HR_ITEMS": d6.find_idx("method", "Lcom/liesheng/lib_room/table/HeartRateDataTable;->getItems()[I"),
        "M_HYAPP_CTX": d6.find_idx("method", "Lcom/liesheng/haylou/app/HyApplication;->getContext()Lcom/liesheng/haylou/app/HyApplication;"),
        "M_GET_SP": d6.find_idx("method", "Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;"),
        "M_SP_GET_STR": d6.find_idx("method", "Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"),
        "M_SP_GET_LONG": d6.find_idx("method", "Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J"),
        "M_IDATA_Z": d6.find_idx("method", "Lcom/liesheng/haylou/db/datahelper/IDataHelper;->z(J)Ljava/util/Date;"),
        "M_CHINA_TO_LOCAL": d6.find_idx("method", "Lcom/liesheng/lib_common/ktx/c;->b(J)J"),
        "M_UTC_TO_LOCAL": d6.find_idx("method", "Lcom/liesheng/lib_common/ktx/c;->g(J)J"),
        "M_DATE_GET_TIME": d6.find_idx("method", "Ljava/util/Date;->getTime()J"),
        "M_SYS_TIME": d6.find_idx("method", "Ljava/lang/System;->currentTimeMillis()J"),
        "M_LIST_SIZE": d6.find_idx("method", "Ljava/util/List;->size()I"),
        "M_LIST_GET": d6.find_idx("method", "Ljava/util/List;->get(I)Ljava/lang/Object;"),
        "M_STR_LEN": d6.find_idx("method", "Ljava/lang/String;->length()I"),
        "M_STR_CHARAT": d6.find_idx("method", "Ljava/lang/String;->charAt(I)C"),
        "M_STR_INDEXOF": d6.find_idx("method", "Ljava/lang/String;->indexOf(Ljava/lang/String;)I"),
        "M_STR_CONTAINS": d6.find_idx("method", "Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z"),
        "STR_CRPSDK": d6.find_idx("string", "CRPSDK"),
        "STR_STEPS": d6.find_idx("string", "steps"),
        "STR_TIME": d6.find_idx("string", "time"),
        "STR_TODAY": d6.find_idx("string", "TODAY"),
        "STR_LBRACK": d6.find_idx("string", "["),
        "STR_EMPTY": d6.find_idx("string", ""),
    }

    # 2) CustomCameraActivity.start(Context)V (0-caller, 30w, len=4)
    #    <-> NadalWatchControlHelper$sendMsgToDevice$1.invokeSuspend(Object)Object (1244w, len=4)
    m_hc = d6.find_method_info(
        "Lcom/liesheng/module_device/CustomCameraActivity;",
        "Lcom/liesheng/module_device/CustomCameraActivity;->start(Landroid/content/Context;)V",
    )
    m_host = d6.find_method_info(
        "Lcom/liesheng/haylou/service/watch/nadal/NadalWatchControlHelper$sendMsgToDevice$1;",
        "Lcom/liesheng/haylou/service/watch/nadal/NadalWatchControlHelper$sendMsgToDevice$1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;",
    )
    if m_hc["insns_size"] >= 1000:
        insns = _build_hourly_charts_insns(refs, pad_words=m_hc["insns_size"])
        struct.pack_into("<4H2I", buf, m_hc["code_off"], 32, 1, 6, 0, 0, m_hc["insns_size"])
        buf[m_hc["code_off"] + 16 : m_hc["code_off"] + 16 + len(insns)] = insns
    else:
        assert m_hc["code_pos_len"] == 4 and m_host["code_pos_len"] == 4
        insns = _build_hourly_charts_insns(refs, pad_words=m_host["insns_size"])
        struct.pack_into("<4H2I", buf, m_host["code_off"], 32, 1, 6, 0, 0, m_host["insns_size"])
        buf[m_host["code_off"] + 16 : m_host["code_off"] + 16 + len(insns)] = insns
        stub = DalvikAssembler()
        stub.const4(0, 0)
        stub.return_object(0)
        stub_bytes = stub.assemble(pad_to_words=m_hc["insns_size"])
        struct.pack_into(
            "<4H2I", buf, m_hc["code_off"],
            m_host["ins_size"] + 1, m_host["ins_size"], 0, 0, 0, m_hc["insns_size"],
        )
        buf[m_hc["code_off"] + 16 : m_hc["code_off"] + 16 + len(stub_bytes)] = stub_bytes
        buf[m_hc["code_pos"] : m_hc["code_pos"] + 4] = encode_uleb128_4bytes(m_host["code_off"])
        buf[m_host["code_pos"] : m_host["code_pos"] + 4] = encode_uleb128_4bytes(m_hc["code_off"])

    call_hc_seq = struct.pack("<HHHH", 0x0012, 0x1071, m_hc["method_idx"], 0x0000)

    # 3) Trigger on CommonUtil.z (after workout save) & SportRecordWidgetDataLoader.f() (Home IO)
    _hook_common_util_z(buf, d6, call_hc_seq)
    _hook_sport_record_loader(buf, d6, call_hc_seq)

    # 4) Live preservation guard in IDataHelper.N so bulk Watch 4S step syncs (items=[]) never wipe
    #    saved 24-hour items[], kcalItems[], and sportTimeItems[]
    m_idh_n = d6.find_method_info(
        "Lcom/liesheng/haylou/db/datahelper/IDataHelper;",
        "Lcom/liesheng/haylou/db/datahelper/IDataHelper;->N(Lcom/liesheng/lib_room/table/StepDataTable;)V",
    )
    m_host_step_det = d6.find_method_info(
        "Lcom/liesheng/module_home/bean/StepDetailsBean$StepDetailsList;",
        "Lcom/liesheng/module_home/bean/StepDetailsBean$StepDetailsList;->copy$default(Lcom/liesheng/module_home/bean/StepDetailsBean$StepDetailsList;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;IFLjava/lang/String;FFIIII[I[I[II[F[F[ILjava/lang/String;ILjava/lang/Object;)Lcom/liesheng/module_home/bean/StepDetailsBean$StepDetailsList;",
    )
    ph = DalvikAssembler()
    ph.invoke_virtual([4], refs["M_STEP_GET_ITEMS"])
    ph.move_result_object(0)
    ph.if_eqz(0, "ph_fetch")
    ph.array_length(1, 0)
    ph.const16(2, 24)
    ph.if_ne(1, 2, "ph_fetch")
    ph.const4(1, 0)
    ph.label("ph_chk")
    ph.if_ge(1, 2, "ph_fetch")
    ph.aget(2, 0, 1)
    ph.if_nez(2, "ph_done")
    ph.add_int_lit8(1, 1, 1)
    ph.const16(2, 24)
    ph.goto16("ph_chk")
    ph.label("ph_fetch")
    ph.invoke_virtual([4], refs["M_STEP_GET_RECDATE"])
    ph.move_result_object(0)
    ph.if_eqz(0, "ph_done")
    ph.invoke_virtual([0], refs["M_DATE_GET_TIME"])
    ph.move_result_wide(0)
    ph.sget_object(2, refs["F_APPDB_A"])
    ph.invoke_virtual([2], refs["M_APPDB_B"])
    ph.move_result_object(2)
    ph.invoke_virtual([2], refs["M_APPDB_STEP_DAO"])
    ph.move_result_object(2)
    ph.invoke_interface([2, 0, 1], refs["M_STEP_BY_DATE"])
    ph.move_result_object(2)
    ph.if_eqz(2, "ph_done")
    # Preserve items[24]
    ph.invoke_virtual([2], refs["M_STEP_GET_ITEMS"])
    ph.move_result_object(0)
    ph.if_eqz(0, "ph_k")
    ph.array_length(1, 0)
    ph.add_int_lit8(1, 1, -24)
    ph.if_nez(1, "ph_k")
    ph.invoke_virtual([4, 0], refs["M_STEP_SET_ITEMS"])
    # Preserve kcalItems[24]
    ph.label("ph_k")
    ph.invoke_virtual([2], refs["M_STEP_GET_KITEMS"])
    ph.move_result_object(0)
    ph.if_eqz(0, "ph_st")
    ph.array_length(1, 0)
    ph.add_int_lit8(1, 1, -24)
    ph.if_nez(1, "ph_st")
    ph.invoke_virtual([4, 0], refs["M_STEP_SET_KITEMS"])
    # Preserve sportTimeItems[24]
    ph.label("ph_st")
    ph.invoke_virtual([2], refs["M_STEP_GET_STIME"])
    ph.move_result_object(0)
    ph.if_eqz(0, "ph_done")
    ph.array_length(1, 0)
    ph.add_int_lit8(1, 1, -24)
    ph.if_nez(1, "ph_done")
    ph.invoke_virtual([4, 0], refs["M_STEP_SET_STIME"])
    ph.label("ph_done")
    ph_bytes = ph.assemble()

    if m_idh_n["insns_size"] < 200:
        assert m_idh_n["code_pos_len"] == 4 and m_host_step_det["code_pos_len"] == 4
        orig_n = bytes(buf[m_idh_n["code_off"] + 16 : m_idh_n["code_off"] + 16 + m_idh_n["insns_size"] * 2])
        combined = ph_bytes + orig_n
        pad_w = m_host_step_det["insns_size"] - len(combined) // 2
        assert pad_w >= 0
        struct.pack_into(
            "<4H2I", buf, m_host_step_det["code_off"],
            m_idh_n["regs_size"], m_idh_n["ins_size"], max(m_idh_n["outs_size"], 3), 0, 0, m_host_step_det["insns_size"],
        )
        buf[m_host_step_det["code_off"] + 16 : m_host_step_det["code_off"] + 16 + m_host_step_det["insns_size"] * 2] = (
            combined + b"\x00\x00" * pad_w
        )
        stub = DalvikAssembler()
        stub.const4(0, 0)
        stub.return_object(0)
        stub_bytes = stub.assemble(pad_to_words=m_idh_n["insns_size"])
        struct.pack_into(
            "<4H2I", buf, m_idh_n["code_off"],
            m_host_step_det["ins_size"] + 1, m_host_step_det["ins_size"], 0, 0, 0, m_idh_n["insns_size"],
        )
        buf[m_idh_n["code_off"] + 16 : m_idh_n["code_off"] + 16 + len(stub_bytes)] = stub_bytes
        buf[m_idh_n["code_pos"] : m_idh_n["code_pos"] + 4] = encode_uleb128_4bytes(m_host_step_det["code_off"])
        buf[m_host_step_det["code_pos"] : m_host_step_det["code_pos"] + 4] = encode_uleb128_4bytes(m_idh_n["code_off"])
    else:
        n_off = m_idh_n["code_off"] + 16
        n_total = m_idh_n["insns_size"] * 2
        cur_n = bytes(buf[n_off : n_off + n_total])
        if ph_bytes not in cur_n:
            end = n_total
            while end >= 2 and cur_n[end - 2 : end] == b"\x00\x00":
                end -= 2
            combined = ph_bytes + cur_n[:end]
            assert len(combined) <= n_total, f"IDataHelper.N overflow: {len(combined)//2}w > {n_total//2}w"
            struct.pack_into(
                "<4H2I", buf, m_idh_n["code_off"],
                m_idh_n["regs_size"], m_idh_n["ins_size"], max(m_idh_n["outs_size"], 3), 0, 0, m_idh_n["insns_size"],
            )
            buf[n_off : n_off + n_total] = combined + b"\x00" * (n_total - len(combined))

    out = recompute_dex_checksums(buf)
    print(f"[+] classes6.dex Hourly Charts patched (Adler: {struct.unpack_from('<I', out, 8)[0]:08x})")
    return out


# --------------------------------------------------------------------------- #
# 4. classes7.dex — WatchConfig Unlocks + 3-Card Resting Heart Rate UI
# --------------------------------------------------------------------------- #

def patch_classes7_hourly_charts(dex_bytes: bytes) -> bytes:
    """
    Bypass the 5 CommonUtil.B() (CRP watch) gates in classes7.dex that hide hourly
    Steps & Calories bar charts in DailyActDetailsActivity and remove the Day (D) tab
    in StepDetailsActivity and ConsumeDetailsActivity.
    """
    print("[*] Patching classes7.dex (Unhide Daily Activities hourly bars + Steps/Calories Day tabs)...")
    d7 = DexFile(dex_bytes)
    buf = bytearray(dex_bytes)
    mid_b = d7.find_idx("method", "Lcom/liesheng/haylou/utils/CommonUtil;->B()Z")
    changed = 0

    targets = (
        (
            "Lcom/liesheng/module_home/v2/daily/DailyActDetailsActivity;",
            "Lcom/liesheng/module_home/v2/daily/DailyActDetailsActivity;->initData$lambda$34$lambda$32(Lcom/liesheng/module_home/v2/daily/DailyActDetailsActivity;ZZLcom/liesheng/module_home/bean/StepDetailsBean$StepDetailsList;)Lkotlin/q;",
            0xF3,
            11,
        ),
        (
            "Lcom/liesheng/module_home/v2/step/StepDetailsActivity;",
            "Lcom/liesheng/module_home/v2/step/StepDetailsActivity;->buildTabs()[Ljava/lang/String;",
            0x00,
            0,
        ),
        (
            "Lcom/liesheng/module_home/v2/step/StepDetailsActivity;",
            "Lcom/liesheng/module_home/v2/step/StepDetailsActivity;->buildDetailsFragment(I)Landroidx/fragment/app/Fragment;",
            0x00,
            0,
        ),
        (
            "Lcom/liesheng/module_home/v2/step/ConsumeDetailsActivity;",
            "Lcom/liesheng/module_home/v2/step/ConsumeDetailsActivity;->buildTabs()[Ljava/lang/String;",
            0x00,
            0,
        ),
        (
            "Lcom/liesheng/module_home/v2/step/ConsumeDetailsActivity;",
            "Lcom/liesheng/module_home/v2/step/ConsumeDetailsActivity;->buildDetailsFragment(I)Landroidx/fragment/app/Fragment;",
            0x00,
            0,
        ),
    )
    for cls, desc, pc_off, dst_reg in targets:
        info = d7.find_method_info(cls, desc, allow_tries=True)
        off = info["code_off"] + 16 + pc_off * 2
        expected = struct.pack("<HHHH", 0x0071, mid_b, 0x0000, 0x000A | (dst_reg << 8))
        patched = struct.pack("<HHHH", 0x0012 | (dst_reg << 8), 0x0000, 0x0000, 0x0000)
        cur = bytes(buf[off : off + 8])
        if cur != patched:
            assert cur == expected, f"Unexpected bytes at {desc}+{pc_off:04x}: {cur.hex()}"
            buf[off : off + 8] = patched
            changed += 1

    out = recompute_dex_checksums(buf) if changed else bytes(buf)
    print(f"[+] classes7.dex Hourly Charts UI unhidden ({changed} sites patched)")
    return out

def patch_classes7_hrv_active(dex_bytes: bytes) -> bytes:
    """
    Ensure HRV and Active/Standing Hours WatchConfig flags are unlocked, and unhide the
    Standing / Active Hours card in DailyActDetailsActivity (v2) when both Exercise and
    Distance are already supported on Watch 4S.
    """
    d7 = DexFile(dex_bytes)
    buf = bytearray(dex_bytes)
    patched_pattern = bytes([0x12, 0x10, 0x0F, 0x00, 0x00, 0x00])
    changed = 0
    for label, desc in (
        ("HRV", "Lcom/yingsheng/protocol/config/WatchConfig;->isSupportHrv()Z"),
        ("Active/Standing Hours", "Lcom/yingsheng/protocol/config/WatchConfig;->isSupportActiveByHour()Z"),
    ):
        info = d7.find_method_info("Lcom/yingsheng/protocol/config/WatchConfig;", desc)
        insns_off = info["code_off"] + 16
        cur = bytes(buf[insns_off : insns_off + 6])
        if cur == patched_pattern:
            continue
        assert cur[0] == 0x55 and cur[4:6] == b"\x0f\x00", f"Unexpected bytes for {label}: {cur.hex()}"
        buf[insns_off : insns_off + 6] = patched_pattern
        changed += 1

    # DailyActDetailsActivity.initData()+00b9: replace `if-nez v6, +00cf` (39 06 16 00) with
    # `goto +00cf; nop` (28 16 00 00) so binding.m (Standing / Active Hours 12h card + bar chart)
    # stays visible alongside Exercise, Calories, and Distance on Watch 4S.
    m_da = d7.find_method_info(
        "Lcom/liesheng/module_home/v2/daily/DailyActDetailsActivity;",
        "Lcom/liesheng/module_home/v2/daily/DailyActDetailsActivity;->initData()V",
        allow_tries=True,
    )
    da_off = m_da["code_off"] + 16 + 0xB9 * 2
    cur_da = bytes(buf[da_off : da_off + 4])
    patched_da = bytes([0x28, 0x16, 0x00, 0x00])
    if cur_da != patched_da:
        assert cur_da == bytes([0x39, 0x06, 0x16, 0x00]), (
            f"Unexpected bytes at DailyActDetailsActivity.initData()+00b9: {cur_da.hex()}"
        )
        buf[da_off : da_off + 4] = patched_da
        changed += 1
        print("    [+] Unhid Standing / Active Hours (12h) card in DailyActDetailsActivity")

    if changed:
        return recompute_dex_checksums(buf)
    return bytes(buf)


def patch_classes7_unlock_cards(dex_bytes: bytes) -> bytes:
    print("[*] Patching classes7.dex (WatchConfig unlocks: PAI, VO2 Max, HRV, Active Hours, HR Alert, Naps)...")
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

    restored = 0
    for label, desc, fdesc in WATCHCONFIG_RESTORE_STOCK:
        info = d7.find_method_info("Lcom/yingsheng/protocol/config/WatchConfig;", desc)
        fidx = d7.find_idx("field", fdesc)
        stock_pattern = struct.pack("<HHH", 0x1055, fidx, 0x000F)  # iget-boolean v0, v1, field; return v0
        insns_off = info["code_off"] + 16
        cur = bytes(buf[insns_off : insns_off + 6])
        if cur == stock_pattern:
            continue
        assert cur == patched_pattern, f"Unexpected bytes for {label}: {cur.hex()}"
        buf[insns_off : insns_off + 6] = stock_pattern
        restored += 1
        print(f"    [+] Restored {label} to stock WatchConfig field (unsupported in Watch 4S firmware)")

    out = recompute_dex_checksums(buf)
    print(f"[+] classes7.dex WatchConfig unlocks complete ({unlocked} unlocked, {restored} restored to stock)")
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
    cycling_fixes: bool = True,
    voip_calls: bool = True,
    workout_analytics: bool = True,
    hrv_active: bool = True,
    hourly_charts: bool = True,
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

        if noclock or night_raise_to_wake or hourly_charts:
            c3 = zf.read("classes3.dex")
            if noclock:
                c3 = patch_classes3_dex_fb_bypass(c3)
            if night_raise_to_wake:
                c3 = patch_classes3_night_quickview(c3)
            if hourly_charts:
                c3 = patch_classes3_hourly_charts(c3)
            replacements["classes3.dex"] = c3

        if hourly_charts:
            replacements["classes5.dex"] = patch_classes5_hourly_charts(zf.read("classes5.dex"))

        if (
            noclock or vitality_vo2 or night_raise_to_wake or cycling_fixes
            or voip_calls or workout_analytics or hrv_active or hourly_charts
        ):
            c6 = zf.read("classes6.dex")
            if noclock:
                c6 = patch_classes6_sideload(c6, mode=mode)
            if vitality_vo2:
                c6 = patch_classes6_vitality_vo2(c6)
            if night_raise_to_wake:
                c6 = patch_classes6_night_quickview(c6, night_start=night_hours[0], night_end=night_hours[1])
            if cycling_fixes:
                c6 = patch_classes6_cycling_fixes(c6)
            if workout_analytics:
                c6 = patch_classes6_workout_analytics(c6)
            if hourly_charts:
                c6 = patch_classes6_hourly_charts(c6)
            if hrv_active:
                c6 = patch_classes6_hrv_active(c6)
            if voip_calls:
                c6 = patch_classes6_voip_calls(c6)
            replacements["classes6.dex"] = c6

        if unlock_cards or rhr or night_raise_to_wake or hrv_active or hourly_charts:
            c7 = zf.read("classes7.dex")
            if unlock_cards:
                c7 = patch_classes7_unlock_cards(c7)
            if hrv_active:
                c7 = patch_classes7_hrv_active(c7)
            if hourly_charts:
                c7 = patch_classes7_hourly_charts(c7)
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
    parser.add_argument(
        "--unlock-cards",
        action="store_true",
        help="Unlock Watch 4S features (PAI, VO2 Max, HRV, Active Hours, High/Low HR Alert, Daytime Sleep Naps)",
    )
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
    parser.add_argument(
        "--cycling-fixes",
        action="store_true",
        help="Cycling phantom-step removal + post-sync GPS moving time/avg speed + live GPS auto-pause/resume",
    )
    parser.add_argument(
        "--voip-calls",
        action="store_true",
        help="VoIP incoming call alerts + wrist reject (WhatsApp, Messenger, Instagram, Telegram, Viber, Discord)",
    )
    parser.add_argument(
        "--workout-analytics",
        action="store_true",
        help="Compute Aerobic/Anaerobic Training Effect, Exercise Load, Recovery Time, and Per-Workout VO2 Max",
    )
    parser.add_argument(
        "--hrv-active",
        action="store_true",
        help="Stress-derived 30-min HRV engine + Hourly Active/Standing Hours (12h) engine",
    )
    parser.add_argument(
        "--hourly-charts",
        action="store_true",
        help="Unlock Watch 4S BLE 0x59 hourly step histograms + hourly Steps/Calories/Exercise Day charts",
    )
    parser.add_argument("--verify-only", metavar="APK", help="Only verify v2/v3 signatures of an existing APK")
    args = parser.parse_args()

    if args.verify_only:
        ver = verify_apk_signatures(args.verify_only)
        print(f"[+] Verified {args.verify_only}: {ver}")
        return

    any_specific = (
        args.noclock or args.unlock_cards or args.rhr
        or args.vitality_vo2 or args.night_raise_to_wake or args.cycling_fixes
        or args.voip_calls or args.workout_analytics or args.hrv_active or args.hourly_charts
    )
    use_all = args.all or not any_specific
    do_noclock = use_all or args.noclock
    do_unlock = use_all or args.unlock_cards
    do_rhr = use_all or args.rhr
    do_pai_vo2 = use_all or args.vitality_vo2
    do_night_qv = use_all or args.night_raise_to_wake
    do_cycling = use_all or args.cycling_fixes
    do_voip = use_all or args.voip_calls
    do_wa = use_all or args.workout_analytics
    do_ha = use_all or args.hrv_active
    do_hc = use_all or args.hourly_charts

    out_path = args.out or (
        DEFAULT_OUT_FULL
        if (do_unlock or do_rhr or do_pai_vo2 or do_night_qv or do_cycling or do_voip or do_wa or do_ha or do_hc)
        else DEFAULT_OUT_NOCLOCK
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
        cycling_fixes=do_cycling,
        voip_calls=do_voip,
        workout_analytics=do_wa,
        hrv_active=do_ha,
        hourly_charts=do_hc,
    )


if __name__ == "__main__":
    main()
