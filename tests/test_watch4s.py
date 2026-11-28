"""Automated regression tests for Haylou Watch 4S compiler, DEX/APK signer, and Studio security."""

from __future__ import annotations

import hashlib
import os
import struct
import sys
import tempfile
import unittest
import zipfile
import zlib

from PIL import Image

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS_DIR = os.path.join(REPO_ROOT, "scripts")
STUDIO_DIR = os.path.join(REPO_ROOT, "studio")
for p in (SCRIPTS_DIR, STUDIO_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

import amazfit_unpacker
import apk_signer
import dex_patcher_lib
import jieli_fw_unpacker
import server as studio_server
import watchface_bin_maker
import watchface_compiler


class TestWatchfaceCompiler(unittest.TestCase):
    def test_pure_gradient_bin_valid_and_within_budget(self):
        cfg = {
            "background": {"mode": "gradient", "c1": "#08101c", "c2": "#13294b"},
            "digital_clock": {"enabled": False},
            "analog_hands": {"enabled": False},
        }
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "pure.bin")
            prev = os.path.join(td, "prev.png")
            watchface_compiler.compile_config_to_bin(cfg, out, save_preview_path=prev)
            with open(out, "rb") as f:
                raw = f.read()
            info = watchface_compiler.inspect_watchface_bin(raw)
            self.assertTrue(info["valid"], info.get("errors"))
            self.assertTrue(info["within_flash_budget"])
            self.assertLessEqual(len(raw), watchface_compiler.MAX_WATCH_BIN_BYTES)
            self.assertTrue(os.path.isfile(prev))
            decoded = watchface_compiler.decode_bin_preview(out)
            self.assertEqual(decoded.size, (466, 466))

    def test_multilayer_digital_weather_bt_gauge_compiles(self):
        cfg = {
            "background": {"mode": "gradient", "c1": "#04070d", "c2": "#0d1b2a"},
            "bezel": {"enabled": True, "style": "minimal_dots", "color": "#38bdf8"},
            "digital_clock": {"enabled": True, "layout": "horizontal", "x": 233, "y": 180, "font_size": 56},
            "weather": {"enabled": True, "x": 233, "y": 110},
            "bluetooth": {"enabled": True, "x": 233, "y": 72},
            "gauges": [{"id": "g1", "enabled": True, "metric": "battery", "style": "outer_ring", "color": "#30d158"}],
            "telemetry": {"enabled": True, "steps": {"enabled": True, "x": 150, "y": 310}},
        }
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "hud.bin")
            watchface_compiler.compile_config_to_bin(cfg, out)
            with open(out, "rb") as f:
                raw = f.read()
            info = watchface_compiler.inspect_watchface_bin(raw)
            self.assertTrue(info["valid"], info.get("errors"))
            self.assertTrue(info["within_flash_budget"])
            opcodes = set(info["opcodes"])
            for expected in ("01 00", "01 02", "01 07", "01 12", "01 14", "01 1b"):
                self.assertIn(expected, opcodes, f"Missing expected opcode {expected} in {opcodes}")

    def test_analog_tap_switch_emits_anim_header_and_dummy_dt0_invariant(self):
        """Regression test for Watch 4S Error Code 3: 01 1a without digital numbers must still emit DT#0."""
        cfg = {
            "background": {"mode": "omnitrix", "omni_style": "alien_force", "omni_color": "green"},
            "tap_switch": {"enabled": True, "mode": "omnitrix"},
            "digital_clock": {"enabled": False},
            "analog_hands": {"enabled": True, "style": "omnitrix_glass"},
        }
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "tap.bin")
            watchface_compiler.compile_config_to_bin(cfg, out)
            with open(out, "rb") as f:
                raw = f.read()
            info = watchface_compiler.inspect_watchface_bin(raw)
            self.assertTrue(info["valid"], info.get("errors"))
            self.assertTrue(info["has_anim_header"])
            self.assertGreaterEqual(info["digit_tables"], 1)
            self.assertIn("01 1a", info["opcodes"])

    def test_rle_encoder_non_empty_and_4byte_aligned(self):
        img = Image.new("RGBA", (32, 32), (57, 255, 20, 255))
        blob = bytearray(watchface_bin_maker.encode_image_rle_argb565(img))
        watchface_bin_maker.pad4_ff(blob)
        self.assertGreater(len(blob), 32 * 4)
        self.assertEqual(len(blob) % 4, 0)

    def test_builtin_pipboy_3000_template_compiles_under_budget(self):
        pdir = os.path.join(REPO_ROOT, "studio", "assets", "pipboy_3000")
        frames = []
        for name in ("green", "amber", "cyan", "red"):
            fp = os.path.join(pdir, f"bg_pipboy_{name}.png")
            self.assertTrue(os.path.isfile(fp), f"Missing {fp}")
            frames.append({"label": name, "image_path": fp})
        cfg = {
            "layer_order": ["background", "tap_switch", "gauges", "weather", "weekday", "date", "clock", "telemetry"],
            "background": {"mode": "solid", "color": "#000000", "color2": "#000000", "brightness": 100, "vignette": 0},
            "tap_switch": {"enabled": True, "mode": "custom_images", "size": 466, "circular": True, "opacity": 100, "brightness": 100, "x": 233, "y": 233, "frames": frames},
            "weekday": {"enabled": True, "x": 233, "y": 36, "font_size": 28, "color": "#f0fff6", "stroke_width": 0, "uppercase": True},
            "date": {"enabled": True, "format": "DD/MM", "show_year": True, "x": 125, "y": 90, "font_size": 18, "color": "#f0fff6", "stroke_width": 0},
            "weather": {"enabled": True, "show_icon": True, "icon_style": "mono", "icon_color": "#f0fff6", "icon_size": 30, "icon_x": 332, "icon_y": 92, "show_temp": True, "temp_x": 386, "temp_y": 92, "font_size": 22, "color": "#f0fff6", "stroke_width": 0},
            "digital_clock": {"enabled": True, "layout": "stacked", "x": 374, "y": 232, "font_size": 82, "color": "#ffffff", "color2": "#e0ffe8", "stroke_width": 0, "glow_radius": 1, "spacing": 12, "show_colon": False, "show_seconds": True, "seconds_x": 376, "seconds_y": 348, "seconds_size": 22, "seconds_color": "#f0fff6", "show_ampm": True, "ampm_x": 376, "ampm_y": 376, "ampm_size": 20, "ampm_color": "#f0fff6"},
            "gauges": [
                {"id": "g_kcal", "enabled": True, "metric": "calories", "style": "bar", "x": 134, "y": 166, "width": 86, "height": 10, "color": "#f0fff6", "track_color": "#182420"},
                {"id": "g_hr",   "enabled": True, "metric": "active",   "style": "bar", "x": 122, "y": 230, "width": 84, "height": 10, "color": "#f0fff6", "track_color": "#182420"},
                {"id": "g_dist", "enabled": True, "metric": "distance", "style": "bar", "x": 134, "y": 294, "width": 86, "height": 10, "color": "#f0fff6", "track_color": "#182420"},
                {"id": "g_step", "enabled": True, "metric": "steps",    "style": "bar", "x": 233, "y": 344, "width": 84, "height": 10, "color": "#f0fff6", "track_color": "#182420"},
            ],
            "telemetry": {"enabled": True, "show_icons": False, "font_size": 22, "color": "#f0fff6", "stroke_width": 0, "calories": {"enabled": True, "x": 56, "y": 158, "align": 2}, "heart_rate": {"enabled": True, "x": 44, "y": 222, "align": 2}, "distance": {"enabled": True, "x": 56, "y": 286, "align": 2}, "battery_pct": {"enabled": True, "x": 94, "y": 374, "align": 2}, "steps": {"enabled": True, "x": 233, "y": 372, "align": 2}},
        }
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "pipboy3000_4theme.bin")
            watchface_compiler.compile_config_to_bin(cfg, out)
            with open(out, "rb") as f:
                raw = f.read()
            info = watchface_compiler.inspect_watchface_bin(raw)
            self.assertTrue(info["valid"], info.get("errors"))
            self.assertTrue(info["within_flash_budget"])
            self.assertIn("01 1a", info["opcodes"])
            self.assertLessEqual(len(raw), watchface_compiler.MAX_WATCH_BIN_BYTES)

    def test_builtin_rpg_boss_battle_template_compiles_under_budget(self):
        rdir = os.path.join(REPO_ROOT, "studio", "assets", "rpg_boss_battle")
        boss_files = ["bg_01_slime.png", "bg_02_dragon.png", "bg_03_mecha.png", "bg_04_lich.png"]
        frames = []
        for fn in boss_files:
            fp = os.path.join(rdir, fn)
            self.assertTrue(os.path.isfile(fp), f"Missing {fp}")
            frames.append({"label": fn, "image_path": fp})
        hero_fp = os.path.join(rdir, "hero_knight_idle.webp")
        self.assertTrue(os.path.isfile(hero_fp), f"Missing {hero_fp}")

        # Verify inverted pixel_bar gauge produces 11 frames where step=0 (full Boss HP) != step=10 (K.O.!)
        _gx, _gy, g_frames = watchface_compiler.build_battery_widget({
            "metric": "steps", "style": "pixel_bar", "invert": True, "ko_text": "K.O.!",
            "color": "#ef4444", "width": 196, "height": 18, "x": 248, "y": 108,
        })
        self.assertEqual(len(g_frames), 11)
        self.assertNotEqual(g_frames[0].tobytes(), g_frames[10].tobytes())

        cfg = {
            "layer_order": ["background", "tap_switch", "anim:an_hero", "gauge:g_boss_hp", "gauge:g_hero_mp", "weather", "weekday", "date", "clock", "telemetry", "bluetooth"],
            "background": {"mode": "solid", "color": "#080a14", "color2": "#080a14", "brightness": 100, "vignette": 0},
            "tap_switch": {"enabled": True, "mode": "custom_images", "size": 466, "circular": True, "opacity": 100, "brightness": 100, "x": 233, "y": 233, "frames": frames},
            "anim_sprites": [{"id": "an_hero", "name": "Pixel Hero Knight", "enabled": True, "image_path": hero_fp, "frames": 6, "fps": 4, "size": 84, "circular": False, "brightness": 100, "x": 120, "y": 306}],
            "gauges": [
                {"id": "g_boss_hp", "enabled": True, "kind": "progress", "metric": "steps", "style": "pixel_bar", "invert": True, "ko_text": "K.O.!", "color": "#ef4444", "track_color": "#161020", "border_color": "#f1f5f9", "width": 196, "height": 18, "thickness": 8, "x": 248, "y": 108},
                {"id": "g_hero_mp", "enabled": True, "kind": "progress", "metric": "battery", "style": "pixel_bar", "invert": False, "color": "#38bdf8", "track_color": "#0c182c", "border_color": "#bae6fd", "width": 132, "height": 14, "thickness": 6, "x": 280, "y": 353},
            ],
            "weekday": {"enabled": True, "x": 158, "y": 50, "font_size": 16, "color": "#fde047", "stroke_width": 1, "uppercase": True},
            "date": {"enabled": True, "format": "MM/DD", "show_year": False, "x": 229, "y": 50, "font_size": 15, "color": "#f8fafc", "stroke_width": 1},
            "weather": {"enabled": True, "show_icon": True, "icon_style": "color", "icon_color": "#38bdf8", "icon_size": 20, "icon_x": 283, "icon_y": 50, "show_temp": True, "temp_x": 312, "temp_y": 50, "font_size": 14, "color": "#e2e8f0", "stroke_width": 1},
            "digital_clock": {"enabled": True, "layout": "horizontal", "x": 263, "y": 306, "font_size": 42, "color": "#ffffff", "color2": "#fde047", "stroke_width": 2, "stroke_color": "#080a14", "glow_radius": 1, "spacing": 2, "show_colon": True, "show_seconds": True, "seconds_size": 18, "seconds_color": "#38bdf8", "show_ampm": False},
            "telemetry": {"enabled": True, "show_icons": False, "font_size": 17, "color": "#f8fafc", "stroke_width": 1, "align": 0, "steps": {"enabled": True, "x": 150, "y": 396, "align": 0}, "heart_rate": {"enabled": True, "x": 266, "y": 396, "align": 0}, "battery_pct": {"enabled": True, "x": 354, "y": 344, "align": 0}},
            "bluetooth": {"enabled": True, "style": "dot_ring", "connected_color": "#38bdf8", "disconnected_color": "#ef4444", "size": 16, "x": 233, "y": 440},
            "analog_hands": {"enabled": False}, "bezel": {"enabled": False},
        }
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "rpg_boss_battle.bin")
            watchface_compiler.compile_config_to_bin(cfg, out)
            with open(out, "rb") as f:
                raw = f.read()
            info = watchface_compiler.inspect_watchface_bin(raw)
            self.assertTrue(info["valid"], info.get("errors"))
            self.assertTrue(info["within_flash_budget"])
            self.assertTrue(info["has_anim_header"])
            for op in ("01 1a", "01 2e", "01 12", "01 1b", "01 1c", "01 02", "01 18", "01 07", "01 06", "01 15", "01 14"):
                self.assertIn(op, info["opcodes"])
            self.assertLessEqual(len(raw), watchface_compiler.MAX_WATCH_BIN_BYTES)

    def test_builtin_xray_caseback_template_compiles_under_budget(self):
        xdir = os.path.join(REPO_ROOT, "studio", "assets", "xray_caseback")
        layer_files = ["layer_01_dress.png", "layer_02_skeleton.png", "layer_03_blueprint.png", "layer_04_thermal.png"]
        frames = []
        for fn in layer_files:
            fp = os.path.join(xdir, fn)
            self.assertTrue(os.path.isfile(fp), f"Missing {fp}")
            frames.append({"label": fn, "image_path": fp})
        tourb_fp = os.path.join(xdir, "tourbillon_wheel.webp")
        self.assertTrue(os.path.isfile(tourb_fp), f"Missing {tourb_fp}")

        # Verify subdial_arc produces 11 frames at requested compact size
        _gx, _gy, a_frames = watchface_compiler.build_battery_widget({
            "metric": "battery", "style": "subdial_arc", "color": "#f59e0b",
            "thickness": 5, "size": 80, "start_angle": 125, "end_angle": 235, "x": 122, "y": 233,
        })
        self.assertEqual(len(a_frames), 11)
        self.assertEqual(a_frames[0].size, (80, 80))

        cfg = {
            "layer_order": ["background", "tap_switch", "anim:an_tourbillon", "gauge:g_reserve", "weekday", "date", "telemetry", "hands"],
            "background": {"mode": "solid", "color": "#080a10", "color2": "#080a10", "brightness": 100, "vignette": 0},
            "tap_switch": {"enabled": True, "mode": "custom_images", "size": 466, "circular": True, "opacity": 100, "brightness": 100, "x": 233, "y": 233, "frames": frames},
            "anim_sprites": [{"id": "an_tourbillon", "name": "Spinning Tourbillon", "enabled": True, "image_path": tourb_fp, "frames": 8, "fps": 6, "size": 80, "circular": True, "brightness": 100, "x": 233, "y": 326}],
            "gauges": [{"id": "g_reserve", "enabled": True, "kind": "progress", "metric": "battery", "style": "subdial_arc", "color": "#f59e0b", "track_color": "#26303d", "thickness": 5, "size": 80, "start_angle": 125, "end_angle": 235, "x": 122, "y": 233}],
            "weekday": {"enabled": True, "x": 233, "y": 128, "font_size": 17, "color": "#cbd5e1", "stroke_width": 1, "uppercase": True},
            "date": {"enabled": True, "format": "DD", "show_year": False, "x": 348, "y": 233, "font_size": 21, "color": "#f8fafc", "stroke_width": 1},
            "telemetry": {"enabled": True, "show_icons": False, "font_size": 16, "color": "#e2e8f0", "stroke_width": 1, "align": 2, "heart_rate": {"enabled": True, "x": 132, "y": 219, "align": 2}},
            "analog_hands": {"enabled": True, "style": "dauphine", "color": "#f59e0b", "accent_color": "#f1f5f9", "show_seconds": True, "center_cap": True},
            "digital_clock": {"enabled": False}, "bezel": {"enabled": False}, "weather": {"enabled": False}, "bluetooth": {"enabled": False},
        }
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "xray_caseback.bin")
            watchface_compiler.compile_config_to_bin(cfg, out)
            with open(out, "rb") as f:
                raw = f.read()
            info = watchface_compiler.inspect_watchface_bin(raw)
            self.assertTrue(info["valid"], info.get("errors"))
            self.assertTrue(info["within_flash_budget"])
            self.assertTrue(info["has_anim_header"])
            for op in ("01 1a", "01 2e", "01 12", "01 0a", "01 04", "01 0d", "01 06"):
                self.assertIn(op, info["opcodes"])
            self.assertLessEqual(len(raw), watchface_compiler.MAX_WATCH_BIN_BYTES)

    def test_amazfit_huami_bitmap_unpacker(self):
        # Build a synthetic Huami BM\xff\xff 64x64 32-bit BGRA bitmap inside a payload
        w, h = 64, 64
        px = bytes([0x79, 0xF2, 0x02, 0xFF]) * (w * h)
        blob = b"\x00" * 64 + b"BM\xff\xff" + struct.pack("<IIIII", w, h, 32, 24, 1) + px
        res = amazfit_unpacker.unpack_amazfit_bin(blob)
        self.assertEqual(res["source_size"], (64, 64))
        self.assertEqual(res["background"].size, (466, 466))
        self.assertEqual(res["total_images"], 1)


class TestDexAndApkSigner(unittest.TestCase):
    def test_dex_checksum_recomputation(self):
        buf = bytearray(b"dex\n035\x00" + b"\x00" * 120)
        out = dex_patcher_lib.recompute_dex_checksums(buf)
        self.assertEqual(out[12:32], hashlib.sha1(out[32:]).digest())
        expected_adler = zlib.adler32(out[12:]) & 0xFFFFFFFF
        self.assertEqual(struct.unpack_from("<I", out, 8)[0], expected_adler)

    def test_uleb128_4bytes_encoding(self):
        val = 0x234567
        enc = dex_patcher_lib.encode_uleb128_4bytes(val)
        self.assertEqual(len(enc), 4)
        decoded = (enc[0] & 0x7F) | ((enc[1] & 0x7F) << 7) | ((enc[2] & 0x7F) << 14) | ((enc[3] & 0x7F) << 21)
        self.assertEqual(decoded, val)

    def test_pure_python_apk_align_sign_and_verify(self):
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "in.apk")
            out = os.path.join(td, "out.apk")
            ks = os.path.join(td, "debug.keystore")
            with zipfile.ZipFile(src, "w") as zf:
                zf.writestr("AndroidManifest.xml", b"manifest-placeholder")
                zf.writestr("resources.arsc", b"arsc-placeholder")
                zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)
            apk_signer.repack_align_and_sign_apk(src, out, {}, ks)
            self.assertTrue(os.path.isfile(out))
            v = apk_signer.verify_apk_signatures(out)
            self.assertTrue(v.get("v2"), f"v2 verify failed: {v}")
            self.assertTrue(v.get("v3"), f"v3 verify failed: {v}")


class TestStudioSecurity(unittest.TestCase):
    def test_safe_preset_dir_blocks_traversal(self):
        for bad in ("", ".", "..", "../etc", "a/b", "a\\b", "/abs", "C:\\Windows"):
            self.assertIsNone(studio_server.safe_preset_dir(bad), f"Should reject {bad!r}")
        self.assertIsNotNone(studio_server.safe_preset_dir("valid_preset_123"))

    def test_host_and_origin_guards(self):
        self.assertTrue(studio_server.host_allowed({"Host": "127.0.0.1:8466"}))
        self.assertTrue(studio_server.host_allowed({"Host": "localhost:8466"}))
        self.assertFalse(studio_server.host_allowed({"Host": "evil.example:8466"}))
        self.assertTrue(studio_server.origin_allowed({"Origin": f"http://127.0.0.1:{studio_server.PORT}"}))
        self.assertFalse(studio_server.origin_allowed({"Origin": "https://evil.example"}))


class TestJieliFirmwareUnpacker(unittest.TestCase):
    def test_lfsr_and_sfc_xor_roundtrip_across_0x400_boundary(self):
        # Verify 32-byte block SFC XOR encryption/decryption across the 0x400 bit-flip boundary
        plain = bytes((i * 37 + 11) & 0xFF for i in range(1500))
        enc = jieli_fw_unpacker.sfc_xor_decrypt(plain, 0x0120, sfc_key=0x1607)
        self.assertNotEqual(enc, plain)
        dec = jieli_fw_unpacker.sfc_xor_decrypt(enc, 0x0120, sfc_key=0x1607)
        self.assertEqual(dec, plain)
        self.assertEqual(jieli_fw_unpacker.jl_crc16(dec), jieli_fw_unpacker.jl_crc16(plain))

    def test_jlfs_entry_parse_and_att_db_parser(self):
        # Build a valid synthetic 32-byte JLFS directory entry encrypted with 0x1607
        payload = struct.pack("<HIIBBH", 0xA19F, 0x0120, 0x1000, 0x82, 0xFF, 0) + b"app.bin\x00" + b"\xff" * 8
        entry_plain = struct.pack("<H", jieli_fw_unpacker.jl_crc16(payload)) + payload
        entry_enc = jieli_fw_unpacker.jl_enc_stream(entry_plain, 0x1607)
        parsed = jieli_fw_unpacker.parse_jlfs_entry(entry_enc, 0x1607)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["name"], "app.bin")
        self.assertEqual(parsed["data_crc"], 0xA19F)

        # Build a minimal BTstack ATT DB (GAP 0x1800 + MoYoung 0xFEEA + terminator)
        att_blob = (
            struct.pack("<HHHHH", 10, 0x0002, 0x0001, 0x2800, 0x1800)
            + struct.pack("<HHHHH", 10, 0x0002, 0x001B, 0x2800, 0xFEEA)
            + b"\x00\x00"
        )
        rows = jieli_fw_unpacker.parse_att_db(att_blob)
        self.assertEqual(len(rows), 2)
        self.assertIn("0x1800", rows[0]["detail"])
        self.assertIn("0xFEEA", rows[1]["detail"])


if __name__ == "__main__":
    unittest.main()
