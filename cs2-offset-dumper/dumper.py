#!/usr/bin/env python3
"""Dumper estático de offsets para CS2.

Lê as DLLs do jogo do disco (sem abrir o processo, sem ler memória, sem
injeção), procura assinaturas de bytes e resolve instruções RIP-relativas.
O resultado é o RVA (offset a partir da base do módulo).

Uso:
    python dumper.py --bin-dir "C:/.../Counter-Strike Global Offensive/game/csgo/bin/win64" \
                     --bin-dir "C:/.../Counter-Strike Global Offensive/game/bin/win64"
"""
import argparse
import json
import re
import struct
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

SCN_MEM_EXECUTE = 0x20000000


@dataclass
class Section:
    name: str
    va: int
    vsize: int
    raw_ptr: int
    raw_size: int
    chars: int


class PE:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        d = self.data
        if d[:2] != b"MZ":
            raise ValueError(f"{path.name}: não é um PE (MZ ausente)")
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        if d[pe:pe + 4] != b"PE\0\0":
            raise ValueError(f"{path.name}: assinatura PE inválida")
        n_sections, = struct.unpack_from("<H", d, pe + 6)
        opt_size, = struct.unpack_from("<H", d, pe + 20)
        opt = pe + 24
        if struct.unpack_from("<H", d, opt)[0] != 0x20B:
            raise ValueError(f"{path.name}: esperado PE32+ (x64)")
        self.image_base, = struct.unpack_from("<Q", d, opt + 24)
        self.sections = []
        sec = opt + opt_size
        for i in range(n_sections):
            o = sec + i * 40
            name = d[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
            vsize, va, rsize, rptr = struct.unpack_from("<IIII", d, o + 8)
            chars, = struct.unpack_from("<I", d, o + 36)
            self.sections.append(Section(name, va, vsize, rptr, rsize, chars))

    def file_to_rva(self, off: int):
        for s in self.sections:
            if s.raw_ptr <= off < s.raw_ptr + s.raw_size:
                return s.va + (off - s.raw_ptr)
        return None


def compile_pattern(text: str) -> re.Pattern:
    parts = []
    for tok in text.split():
        parts.append(b"." if tok in ("?", "??") else re.escape(bytes([int(tok, 16)])))
    return re.compile(b"".join(parts), re.DOTALL)


def scan(pe: PE, sig: dict):
    """Devolve (rva, n_matches) ou (None, n_matches)."""
    rx = compile_pattern(sig["pattern"])
    hits = []
    for s in pe.sections:
        if not s.chars & SCN_MEM_EXECUTE:
            continue
        blob = pe.data[s.raw_ptr:s.raw_ptr + s.raw_size]
        for m in rx.finditer(blob):
            hits.append(s.va + m.start())
    if not hits:
        return None, 0
    rva = hits[0]
    kind = sig.get("type", "rip")
    if kind == "rip":
        off = sig.get("rip_offset", 3)
        length = sig.get("rip_length", 7)
        file_off = next(s.raw_ptr + (rva - s.va) for s in pe.sections
                        if s.va <= rva < s.va + s.raw_size)
        disp, = struct.unpack_from("<i", pe.data, file_off + off)
        rva = rva + length + disp
    rva += sig.get("extra", 0)
    return rva, len(hits)


def find_module(name: str, dirs):
    for d in dirs:
        p = Path(d) / name
        if p.is_file():
            return p
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin-dir", action="append", required=True, help="pasta com as DLLs (repetível)")
    ap.add_argument("--signatures", default=str(Path(__file__).with_name("signatures.json")))
    ap.add_argument("--out", default="output", help="pasta de saída")
    args = ap.parse_args(argv)

    sigs = json.loads(Path(args.signatures).read_text(encoding="utf-8"))
    cache, results, failed = {}, {}, []

    for sig in sigs:
        mod, name = sig["module"], sig["name"]
        if mod not in cache:
            p = find_module(mod, args.bin_dir)
            cache[mod] = PE(p) if p else None
        pe = cache[mod]
        if pe is None:
            print(f"[!] {mod} não encontrado", file=sys.stderr)
            failed.append(name)
            continue
        rva, n = scan(pe, sig)
        if rva is None:
            print(f"[x] {mod}!{name}: assinatura não encontrada (desatualizada?)", file=sys.stderr)
            failed.append(name)
            continue
        if n > 1:
            print(f"[~] {mod}!{name}: {n} matches, usando o primeiro", file=sys.stderr)
        results.setdefault(mod, {})[name] = rva
        print(f"[+] {mod}!{name} = 0x{rva:X}")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    (out / "offsets.json").write_text(json.dumps(results, indent=2), encoding="utf-8")

    hpp = [f"// Gerado em {stamp}", "#pragma once", "#include <cstddef>", ""]
    for mod, items in results.items():
        hpp.append(f"namespace {mod.replace('.dll', '').replace('.', '_')} {{")
        hpp += [f"    constexpr std::ptrdiff_t {k} = 0x{v:X};" for k, v in items.items()]
        hpp += ["}", ""]
    (out / "offsets.hpp").write_text("\n".join(hpp), encoding="utf-8")

    print(f"\n{sum(map(len, results.values()))} offsets, {len(failed)} falhas -> {out}/")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
