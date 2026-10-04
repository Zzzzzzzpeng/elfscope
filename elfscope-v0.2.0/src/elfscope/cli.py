from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .analysis import analyse

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
DIM = "\033[2m"


def colour(enabled: bool, text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if enabled else text


def banner(enabled: bool) -> None:
    print(colour(enabled, "ELFscope", CYAN + BOLD))
    print(colour(enabled, "Static ELF triage for defensive reverse engineering", DIM))
    print("═" * 68)


def choose_mode() -> int:
    print()
    print("  [1] ⚡ Quick triage")
    print("      Fast identity, hardening, imports, strings and signals")
    print()
    print("  [2] 🔬 Deep ELF analysis")
    print("      Headers, segments, sections, mapping, symbols, relocations, notes, DWARF")
    print()
    print("  [3] 🧪 Full static analysis")
    print("      Deep analysis + entry-point bytes, anomalies, overlay and optional disassembly")
    print()
    while True:
        choice = input("Choose analysis [1/2/3]: ").strip()
        if choice in {"1", "2", "3"}:
            return int(choice)
        print("Choose 1, 2, or 3.")


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _severity_text(enabled: bool, severity: str) -> str:
    icon = {"high": "✖", "medium": "⚠", "low": "•", "info": "ℹ"}.get(severity, "•")
    code = {"high": RED, "medium": YELLOW, "low": BLUE, "info": DIM}.get(severity, DIM)
    return colour(enabled, f"[{icon} {severity.upper():6}]", code)


def _print_header(report: dict[str, Any], c: bool) -> None:
    file_info = report["file"]
    elf = report["elf"]
    hdr = elf["header"]
    print()
    print(colour(c, "◆ Identity", BOLD + CYAN))
    print(f"  File        : {file_info['path']}")
    print(f"  Size        : {file_info['size']} bytes")
    print(f"  SHA-256     : {file_info['hashes']['sha256']}")
    print()
    print(colour(c, "◆ ELF", BOLD + CYAN))
    print(f"  Class       : ELF{hdr['class']}")
    print(f"  Data        : {hdr['data']}")
    print(f"  Type        : {hdr['type']}")
    print(f"  Machine     : {hdr['machine']} ({hdr['machine_arch']})")
    print(f"  Entry       : {_hex(hdr['entry'])}")
    print(f"  Interpreter : {elf.get('interpreter') or 'none'}")


def _print_security(report: dict[str, Any], c: bool) -> None:
    sec = report["elf"]["security"]
    print()
    print(colour(c, "◆ Hardening", BOLD + CYAN))
    print(f"  RELRO       : {sec['relro'].upper()}")
    print(f"  NX          : {sec['nx'].upper()}")
    print(f"  PIE         : {sec['pie'].upper()}")
    print(f"  Canary      : {sec['stack_canary'].upper()}")
    print(f"  Fortify     : {sec['fortify']['count']} checked imports")
    print(f"  RPATH       : {', '.join(sec['rpath']) if sec['rpath'] else 'none'}")
    print(f"  RUNPATH     : {', '.join(sec['runpath']) if sec['runpath'] else 'none'}")


def _print_quick(report: dict[str, Any], c: bool) -> None:
    _print_header(report, c)
    _print_security(report, c)
    stats = report["elf"]["statistics"]
    print()
    print(colour(c, "◆ Statistics", BOLD + CYAN))
    print(f"  Sections    : {stats['section_count']}")
    print(f"  Segments    : {stats['segment_count']}")
    print(f"  Imports     : {stats['import_count']}")
    print(f"  Exports     : {stats['export_count']}")
    print(f"  Libraries   : {stats['needed_libraries']}")
    print(f"  Entropy     : {stats['overall_entropy']:.3f}/8.000")
    strings = report.get("strings", [])
    print(f"  Strings     : {len(strings)} captured")
    print()
    print(colour(c, "◆ Triage signals", BOLD + CYAN))
    for signal in report.get("signals", []):
        print(f"  {_severity_text(c, signal['severity'])} {signal['code']}: {signal['message']}")
    if not report.get("signals"):
        print("  ✓ No triage signals generated.")


def _print_deep(report: dict[str, Any], c: bool) -> None:
    _print_quick(report, c)
    elf = report["elf"]
    hdr = elf["header"]
    print()
    print(colour(c, "◆ ELF header layout", BOLD + CYAN))
    print(f"  Program headers : offset={_hex(hdr['program_header_offset'])}, size={hdr['program_header_size']}, count={hdr['program_header_count']}")
    print(f"  Section headers : offset={_hex(hdr['section_header_offset'])}, size={hdr['section_header_size']}, count={hdr['section_header_count']}")
    print(f"  Flags           : {_hex(hdr['flags'])}")
    print(f"  OSABI           : {hdr['osabi']}")
    print(f"  ABI version     : {hdr['abiversion']}")

    print()
    print(colour(c, "◆ Program headers", BOLD + CYAN))
    for seg in elf.get("program_headers", []):
        print(f"  #{seg['index']:02} {seg['type']:<14} {seg['flags']:<3} off={_hex(seg['offset']):<12} vaddr={_hex(seg['vaddr']):<12} filesz={_hex(seg['file_size']):<10} memsz={_hex(seg['memory_size'])}")

    print()
    print(colour(c, "◆ Sections", BOLD + CYAN))
    for sec in elf.get("sections", []):
        print(f"  [{sec['index']:02}] {sec['name']:<24} {sec['type']:<14} {sec['flags']:<4} off={_hex(sec['offset']):<12} addr={_hex(sec['address']):<12} size={_hex(sec['size'])}")

    print()
    print(colour(c, "◆ Section → segment mapping", BOLD + CYAN))
    for mapping in elf.get("section_segment_map", []):
        print(f"  {mapping['section']:<28} PT_LOAD {mapping['segment_indices'] if mapping['segment_indices'] else 'none'}")

    dyn = elf.get("dynamic", {})
    print()
    print(colour(c, "◆ Dynamic", BOLD + CYAN))
    print(f"  Present     : {dyn.get('present', False)}")
    print(f"  Libraries   : {', '.join(dyn.get('needed', [])) or 'none'}")
    print(f"  SONAME      : {dyn.get('soname') or 'none'}")
    print(f"  Bind now    : {dyn.get('bind_now')}")
    print(f"  Tags        : {len(dyn.get('tags', []))}")

    symbols = report.get("symbols", {})
    print()
    print(colour(c, "◆ Symbols", BOLD + CYAN))
    print(f"  Imports     : {len(symbols.get('imports', []))}")
    print(f"  Exports     : {len(symbols.get('exports', []))}")
    print(f"  .symtab     : {'present' if symbols.get('has_symtab') else 'absent'}")
    print(f"  .dynsym     : {'present' if symbols.get('has_dynsym') else 'absent'}")
    for name in symbols.get("imports", [])[:80]:
        print(f"    ↳ {name}")

    print()
    print(colour(c, "◆ Relocations", BOLD + CYAN))
    relocs = elf.get("relocations", [])
    if not relocs:
        print("  none")
    for group in relocs:
        print(f"  {group.get('section', '?')}: {group.get('count', 0)}")
        for row in group.get("entries", [])[:80]:
            symbol = f" symbol={row.get('symbol')}" if row.get("symbol") else ""
            print(f"    {_hex(row['offset'])} {row['type']}{symbol}")

    notes = elf.get("notes", {})
    print()
    print(colour(c, "◆ Notes / identity", BOLD + CYAN))
    print(f"  GNU Build ID : {notes.get('build_id') or 'none'}")
    print(f"  Notes        : {len(notes.get('entries', []))}")

    debug = elf.get("debug", {})
    print()
    print(colour(c, "◆ Debug information", BOLD + CYAN))
    print(f"  DWARF        : {debug.get('dwarf')}")
    print(f"  Compile units: {debug.get('compile_units', 0)}")
    print(f"  Debug sections: {', '.join(debug.get('debug_sections', [])) or 'none'}")

    entry = elf.get("entry_point", {})
    print()
    print(colour(c, "◆ Entry point", BOLD + CYAN))
    print(f"  Address      : {_hex(entry.get('virtual_address', 0))}")
    print(f"  Section      : {(entry.get('section') or {}).get('name', 'unresolved')}")
    print(f"  File offset  : {_hex((entry.get('segment') or {}).get('file_offset', 0)) if entry.get('segment') else 'unresolved'}")
    print(f"  Bytes        : {entry.get('bytes_hex') or 'none'}")


def _print_full(report: dict[str, Any], c: bool) -> None:
    _print_deep(report, c)
    analysis = report.get("analysis", {})
    print()
    print(colour(c, "◆ Full static analysis", BOLD + CYAN))
    overlay = analysis.get("overlay", {})
    print(f"  Last known content : {_hex(overlay.get('last_section_end', 0))}")
    print(f"  Last segment end   : {_hex(overlay.get('last_segment_end', 0))}")
    print(f"  File size          : {_hex(overlay.get('file_size', 0))}")
    print(f"  Possible overlay   : {overlay.get('bytes_after_known_content', 0)} bytes")

    dis = analysis.get("entry_disassembly", {})
    print()
    print(colour(c, "◆ Entry-point disassembly", BOLD + CYAN))
    if dis.get("available"):
        for insn in dis.get("instructions", []):
            print(f"  {_hex(insn['address']):>12}  {insn['bytes']:<24} {insn['mnemonic']:<10} {insn['op_str']}")
    else:
        print(f"  {dis.get('error', 'not available')}")

    print()
    print(colour(c, "◆ Executable sections", BOLD + CYAN))
    for sec in analysis.get("executable_sections", []):
        print(f"  [{sec['index']:02}] {sec['name']:<24} addr={_hex(sec['address']):<12} off={_hex(sec['offset']):<12} size={_hex(sec['size'])}")


def render(report: dict[str, Any], *, colour_enabled: bool = True) -> None:
    banner(colour_enabled)
    mode = report["tool"]["mode"]
    if mode == 1:
        _print_quick(report, colour_enabled)
    elif mode == 2:
        _print_deep(report, colour_enabled)
    else:
        _print_full(report, colour_enabled)
    print()
    print(colour(colour_enabled, "Note: signals are triage hints, not proof of maliciousness or vulnerability.", DIM))


def render_markdown(report: dict[str, Any]) -> str:
    file_info = report["file"]
    elf = report["elf"]
    hdr = elf["header"]
    lines = [
        "# ELFscope Report",
        "",
        f"- **Version:** {report['tool']['version']}",
        f"- **Mode:** {report['tool']['mode']}",
        f"- **File:** `{file_info['path']}`",
        f"- **SHA-256:** `{file_info['hashes']['sha256']}`",
        "",
        "## ELF",
        "",
        f"- Class: ELF{hdr['class']}",
        f"- Data: {hdr['data']}",
        f"- Type: {hdr['type']}",
        f"- Machine: {hdr['machine']} ({hdr['machine_arch']})",
        f"- Entry: `{hdr['entry']:#x}`",
        f"- Interpreter: {elf.get('interpreter') or 'none'}",
        "",
        "## Hardening",
        "",
    ]
    for key, value in elf["security"].items():
        lines.append(f"- **{key}:** {value}")
    lines += ["", "## Signals", ""]
    for s in report.get("signals", []):
        lines.append(f"- **{s['severity']}** `{s['code']}`: {s['message']}")
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="elfscope",
        description="Static ELF triage for defensive reverse engineering.",
    )
    parser.add_argument("path", help="ELF file to analyse")
    parser.add_argument("-m", "--mode", choices=["1", "2", "3", "quick", "deep", "full"], help="analysis depth; omit for interactive menu")
    parser.add_argument("--json", metavar="PATH", help="write JSON report")
    parser.add_argument("--markdown", metavar="PATH", help="write Markdown report")
    parser.add_argument("--strings", type=int, default=100, help="maximum printable strings to capture")
    parser.add_argument("--no-colour", "--no-color", action="store_true", help="disable terminal colour")
    parser.add_argument("--no-disassembly", action="store_true", help="skip optional Capstone entry-point disassembly in full mode")
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    use_colour = not args.no_colour and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

    if args.mode is None:
        banner(use_colour)
        mode = choose_mode()
    else:
        aliases = {"quick": 1, "deep": 2, "full": 3}
        mode = aliases.get(args.mode, int(args.mode))

    try:
        report = analyse(
            args.path,
            mode=mode,
            string_limit=args.strings,
            disassemble=False if args.no_disassembly else None,
        )
    except Exception as exc:
        print(colour(use_colour, f"✖ analysis failed: {exc}", RED), file=sys.stderr)
        return 1

    render(report, colour_enabled=use_colour)

    if args.json:
        json_path = Path(args.json)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        print(f"\nJSON report: {json_path}")

    if args.markdown:
        md_path = Path(args.markdown)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(render_markdown(report), encoding="utf-8")
        print(f"Markdown report: {md_path}")

    return 0
