"""Teste com um PE x64 sintético (não precisa do CS2)."""
import json, struct, tempfile
from pathlib import Path
import dumper


def build_pe(code: bytes) -> bytes:
    hdr = bytearray(0x400)
    hdr[:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, 0x80)
    hdr[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", hdr, 0x84, 0x8664, 1, 0, 0, 0, 240, 0x22)
    opt = 0x98
    struct.pack_into("<H", hdr, opt, 0x20B)
    struct.pack_into("<Q", hdr, opt + 24, 0x180000000)
    sec = opt + 240
    hdr[sec:sec + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", hdr, sec + 8, len(code), 0x1000, len(code), 0x400)
    struct.pack_into("<I", hdr, sec + 36, 0x60000020)
    return bytes(hdr) + code


def test_rip_resolution():
    code = bytearray(b"\x90" * 0x100)
    at = 0x20                                   # RVA = 0x1020
    target = 0x5000
    disp = target - (0x1000 + at + 7)
    code[at:at + 16] = b"\x48\x8B\x0D" + struct.pack("<i", disp) + bytes.fromhex("48897C24 00 8BFA C1EB".replace(" ", ""))
    with tempfile.TemporaryDirectory() as t:
        Path(t, "client.dll").write_bytes(build_pe(bytes(code)))
        sig = [{"module": "client.dll", "name": "dwEntityList",
                "pattern": "48 8B 0D ? ? ? ? 48 89 7C 24 ? 8B FA C1 EB"}]
        Path(t, "sig.json").write_text(json.dumps(sig))
        rc = dumper.main(["--bin-dir", t, "--signatures", f"{t}/sig.json", "--out", f"{t}/out"])
        assert rc == 0
        got = json.loads(Path(t, "out/offsets.json").read_text())
        assert got["client.dll"]["dwEntityList"] == target, got


if __name__ == "__main__":
    test_rip_resolution()
    print("ok")
