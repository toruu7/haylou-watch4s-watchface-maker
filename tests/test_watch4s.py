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

import apk_signer
import dex_patcher_lib
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


if __name__ == "__main__":
    unittest.main()
