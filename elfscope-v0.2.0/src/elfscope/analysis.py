from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

from elftools.elf.constants import P_FLAGS, SH_FLAGS
from elftools.elf.elffile import ELFFile

from . import __version__

PRINTABLE_RE = re.compile(rb"[ -~]{6,}")
MAX_SECTION_SAMPLE = 8 * 1024 * 1024
MAX_ENTRY_BYTES = 64
MAX_STRING_RESULTS = 200

INTERESTING_SYMBOLS = {
    "execve": "process execution",
    "execveat": "process execution",
    "system": "shell command execution",
    "popen": "shell command execution",
    "fork": "process creation",
    "vfork": "process creation",
    "clone": "process/thread creation",
    "dlopen": "dynamic library loading",
    "dlsym": "dynamic symbol lookup",
    "mprotect": "memory permission changes",
    "memfd_create": "anonymous in-memory file creation",
    "ptrace": "process tracing",
    "setuid": "credential/identity change",
    "setgid": "credential/identity change",
}

PACKER_SECTION_NAMES = {
    ".upx0": "UPX-like section name",
    ".upx1": "UPX-like section name",
    ".aspack": "ASPack-like section name",
    ".adata": "ASPack-like section name",
    ".themida": "Themida-like section name",
}


def _hashes(path: Path) -> dict[str, str]:
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((count / n) * math.log2(count / n) for count in counts.values())


def _sample_bytes(data: bytes, limit: int = MAX_SECTION_SAMPLE) -> tuple[bytes, bool]:
    if len(data) <= limit:
        return data, False
    half = limit // 2
    return data[:half] + data[-half:], True


def _sample_file(path: Path, limit: int = 16 * 1024 * 1024) -> tuple[bytes, bool]:
    size = path.stat().st_size
    if size <= limit:
        return path.read_bytes(), False
    half = limit // 2
    with path.open("rb") as fh:
        head = fh.read(half)
        fh.seek(max(0, size - half))
        tail = fh.read(half)
    return head + tail, True


def _flags_to_text(flags: int) -> str:
    out = ""
    if flags & P_FLAGS.PF_R:
        out += "R"
    if flags & P_FLAGS.PF_W:
        out += "W"
    if flags & P_FLAGS.PF_X:
        out += "E"
    return out or "-"


def _section_flags_to_text(flags: int) -> str:
    out = ""
    if flags & SH_FLAGS.SHF_ALLOC:
        out += "A"
    if flags & SH_FLAGS.SHF_WRITE:
        out += "W"
    if flags & SH_FLAGS.SHF_EXECINSTR:
        out += "X"
    return out or "-"


def _arch_name(elf: ELFFile) -> str:
    try:
        return str(elf.get_machine_arch())
    except Exception:
        return str(elf.header["e_machine"])


def _read_at(path: Path, offset: int, size: int) -> bytes:
    if offset < 0 or size <= 0:
        return b""
    with path.open("rb") as fh:
        fh.seek(offset)
        return fh.read(size)


def _extract_strings(path: Path, minimum: int = 6, limit: int = 100) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    carry = b""
    carry_offset = 0
    with path.open("rb") as fh:
        while True:
            chunk_offset = fh.tell()
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            data = carry + chunk
            data_offset = chunk_offset - len(carry)
            for match in PRINTABLE_RE.finditer(data):
                if len(match.group()) < minimum:
                    continue
                value = match.group().decode("ascii", errors="ignore")
                if not value:
                    continue
                offset = data_offset + match.start()
                if not results or results[-1]["offset"] != offset:
                    results.append({"offset": offset, "value": value})
                if len(results) >= min(limit, MAX_STRING_RESULTS):
                    return results
            carry = data[-(minimum - 1):]
            carry_offset = data_offset + len(data) - len(carry)
    _ = carry_offset
    return results


def _dynamic_info(elf: ELFFile) -> dict[str, Any]:
    result: dict[str, Any] = {
        "present": False,
        "needed": [],
        "rpath": [],
        "runpath": [],
        "soname": None,
        "bind_now": False,
        "tags": [],
    }
    for section in elf.iter_sections():
        if section.header["sh_type"] != "SHT_DYNAMIC":
            continue
        result["present"] = True
        for entry in section.iter_tags():
            tag = str(entry.entry.d_tag)
            item: dict[str, Any] = {"tag": tag}
            if hasattr(entry, "needed"):
                item["value"] = str(entry.needed)
            elif hasattr(entry, "rpath"):
                item["value"] = str(entry.rpath)
            elif hasattr(entry, "runpath"):
                item["value"] = str(entry.runpath)
            elif hasattr(entry, "soname"):
                item["value"] = str(entry.soname)
            else:
                value = getattr(entry.entry, "d_val", None)
                if value is not None:
                    item["value"] = int(value)
            result["tags"].append(item)
            if tag == "DT_NEEDED" and hasattr(entry, "needed"):
                result["needed"].append(str(entry.needed))
            elif tag == "DT_RPATH" and hasattr(entry, "rpath"):
                result["rpath"].append(str(entry.rpath))
            elif tag == "DT_RUNPATH" and hasattr(entry, "runpath"):
                result["runpath"].append(str(entry.runpath))
            elif tag == "DT_SONAME" and hasattr(entry, "soname"):
                result["soname"] = str(entry.soname)
            elif tag == "DT_BIND_NOW":
                result["bind_now"] = True
            elif tag == "DT_FLAGS" and getattr(entry, "flags", 0) & 0x8:
                result["bind_now"] = True
            elif tag == "DT_FLAGS_1" and getattr(entry, "flags_1", 0) & 0x1:
                result["bind_now"] = True
    return result


def _sections(elf: ELFFile) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for index, section in enumerate(elf.iter_sections()):
        hdr = section.header
        info: dict[str, Any] = {
            "index": index,
            "name": section.name,
            "type": str(hdr["sh_type"]),
            "address": int(hdr["sh_addr"]),
            "offset": int(hdr["sh_offset"]),
            "size": int(hdr["sh_size"]),
            "flags": _section_flags_to_text(int(hdr["sh_flags"])),
            "alignment": int(hdr["sh_addralign"]),
            "entry_size": int(hdr["sh_entsize"]),
            "link": int(hdr["sh_link"]),
            "info": int(hdr["sh_info"]),
        }
        try:
            info["entropy"] = round(_entropy(_sample_bytes(section.data())[0]), 3) if info["size"] else None
        except Exception:
            info["entropy"] = None
        result.append(info)
    return result


def _segments(elf: ELFFile, file_size: int) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for index, segment in enumerate(elf.iter_segments()):
        hdr = segment.header
        offset = int(hdr["p_offset"])
        filesz = int(hdr["p_filesz"])
        memsz = int(hdr["p_memsz"])
        vaddr = int(hdr["p_vaddr"])
        info: dict[str, Any] = {
            "index": index,
            "type": str(hdr["p_type"]),
            "offset": offset,
            "vaddr": vaddr,
            "paddr": int(hdr["p_paddr"]),
            "file_size": filesz,
            "memory_size": memsz,
            "flags": _flags_to_text(int(hdr["p_flags"])),
            "alignment": int(hdr["p_align"]),
            "file_end": offset + filesz,
            "vaddr_end": vaddr + memsz,
            "within_file": 0 <= offset <= file_size and offset + filesz <= file_size,
            "filesz_le_memsz": filesz <= memsz,
        }
        result.append(info)
    return result


def _map_sections_to_segments(elf: ELFFile, sections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    mappings: list[dict[str, Any]] = []
    raw_segments = list(elf.iter_segments())
    for section in sections:
        if section["size"] == 0 or section["address"] == 0:
            continue
        containing: list[int] = []
        sec_start = section["address"]
        sec_end = sec_start + section["size"]
        for idx, seg in enumerate(raw_segments):
            if seg.header["p_type"] != "PT_LOAD":
                continue
            seg_start = int(seg.header["p_vaddr"])
            seg_end = seg_start + int(seg.header["p_memsz"])
            if sec_start >= seg_start and sec_end <= seg_end:
                containing.append(idx)
        mappings.append({"section": section["name"], "segment_indices": containing})
    return mappings


def _symbols(elf: ELFFile) -> dict[str, Any]:
    tables: list[dict[str, Any]] = []
    imports: list[str] = []
    exports: list[str] = []
    interesting: dict[str, str] = {}
    canary = False
    fortified: list[str] = []
    symtab_present = False
    dynsym_present = False

    for section in elf.iter_sections():
        if section.header["sh_type"] not in {"SHT_SYMTAB", "SHT_DYNSYM"}:
            continue
        is_dynamic = section.header["sh_type"] == "SHT_DYNSYM"
        symtab_present |= not is_dynamic
        dynsym_present |= is_dynamic
        entries: list[dict[str, Any]] = []
        try:
            for symbol in section.iter_symbols():
                name = symbol.name or ""
                bind = str(symbol["st_info"]["bind"])
                typ = str(symbol["st_info"]["type"])
                visibility = str(symbol["st_other"]["visibility"])
                shndx = symbol["st_shndx"]
                defined = shndx != "SHN_UNDEF"
                row = {
                    "name": name,
                    "value": int(symbol["st_value"]),
                    "size": int(symbol["st_size"]),
                    "bind": bind,
                    "type": typ,
                    "visibility": visibility,
                    "section_index": shndx,
                    "defined": defined,
                }
                entries.append(row)
                if is_dynamic and name:
                    if not defined:
                        imports.append(name)
                    else:
                        exports.append(name)
                if name in INTERESTING_SYMBOLS and is_dynamic and not defined:
                    interesting[name] = INTERESTING_SYMBOLS[name]
                if name in {"__stack_chk_fail", "__stack_chk_fail_local"}:
                    canary = True
                if is_dynamic and name.endswith("_chk"):
                    fortified.append(name)
        except Exception as exc:
            tables.append({"name": section.name, "error": f"symbol parse failed: {exc}"})
            continue
        tables.append({"name": section.name, "count": len(entries), "entries": entries})

    return {
        "tables": tables,
        "imports": sorted(set(imports)),
        "exports": sorted(set(exports)),
        "interesting_imports": interesting,
        "canary_symbol": canary,
        "fortified_imports": sorted(set(fortified)),
        "has_symtab": symtab_present,
        "has_dynsym": dynsym_present,
    }


def _relocations(elf: ELFFile) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for section in elf.iter_sections():
        if not hasattr(section, "iter_relocations"):
            continue
        entry: dict[str, Any] = {"section": section.name, "count": 0, "entries": []}
        try:
            linked = elf.get_section(int(section.header["sh_link"]))
            for reloc in section.iter_relocations():
                row = {
                    "offset": int(reloc["r_offset"]),
                    "type": str(reloc["r_info_type"]),
                    "symbol_index": int(reloc["r_info_sym"]),
                }
                if linked is not None and hasattr(linked, "get_symbol"):
                    try:
                        symbol = linked.get_symbol(row["symbol_index"])
                        row["symbol"] = symbol.name
                    except Exception:
                        row["symbol"] = None
                addend = reloc.entry.get("r_addend")
                if addend is not None:
                    row["addend"] = int(addend)
                entry["entries"].append(row)
            entry["count"] = len(entry["entries"])
        except Exception as exc:
            entry["error"] = f"relocation parse failed: {exc}"
        result.append(entry)
    return result


def _notes(elf: ELFFile) -> dict[str, Any]:
    notes: list[dict[str, Any]] = []
    build_id: str | None = None
    for section in elf.iter_sections():
        if section.header["sh_type"] != "SHT_NOTE" or not hasattr(section, "iter_notes"):
            continue
        try:
            for note in section.iter_notes():
                name = str(note.get("n_name", ""))
                note_type = str(note.get("n_type", ""))
                desc = note.get("n_desc")
                if isinstance(desc, bytes):
                    desc_value = desc.hex()
                else:
                    desc_value = str(desc)
                notes.append({
                    "section": section.name,
                    "name": name,
                    "type": note_type,
                    "description": desc_value,
                })
                if name == "GNU" and note_type == "NT_GNU_BUILD_ID" and isinstance(desc, bytes):
                    build_id = desc.hex()
        except Exception:
            continue
    return {"build_id": build_id, "entries": notes}


def _debug_info(elf: ELFFile) -> dict[str, Any]:
    result: dict[str, Any] = {
        "dwarf": False,
        "compile_units": 0,
        "debug_sections": [],
    }
    for section in elf.iter_sections():
        if section.name.startswith(".debug_") or section.name in {".zdebug_info", ".gnu_debuglink"}:
            result["debug_sections"].append(section.name)
    try:
        result["dwarf"] = elf.has_dwarf_info()
        if result["dwarf"]:
            dwarf = elf.get_dwarf_info()
            result["compile_units"] = sum(1 for _ in dwarf.iter_CUs())
    except Exception as exc:
        result["error"] = f"DWARF parse failed: {exc}"
    return result


def _security(elf: ELFFile, dyn: dict[str, Any], symbols: dict[str, Any]) -> dict[str, Any]:
    relro = any(seg["p_type"] == "PT_GNU_RELRO" for seg in elf.iter_segments())
    if relro and dyn["bind_now"]:
        relro_status = "full"
    elif relro:
        relro_status = "partial"
    else:
        relro_status = "none"

    stack = [seg for seg in elf.iter_segments() if seg["p_type"] == "PT_GNU_STACK"]
    nx = "unknown" if not stack else ("disabled" if any(seg["p_flags"] & P_FLAGS.PF_X for seg in stack) else "enabled")

    e_type = elf.header["e_type"]
    has_interp = any(seg["p_type"] == "PT_INTERP" for seg in elf.iter_segments())
    if e_type == "ET_EXEC":
        pie = "disabled"
    elif e_type == "ET_DYN" and has_interp:
        pie = "enabled"
    elif e_type == "ET_DYN":
        pie = "shared-object"
    else:
        pie = "not-applicable"

    return {
        "relro": relro_status,
        "nx": nx,
        "pie": pie,
        "stack_canary": "present" if symbols["canary_symbol"] else "not-detected",
        "fortify": {
            "count": len(symbols["fortified_imports"]),
            "imports": symbols["fortified_imports"],
        },
        "rpath": dyn["rpath"],
        "runpath": dyn["runpath"],
    }


def _entry_point(path: Path, elf: ELFFile, sections: list[dict[str, Any]]) -> dict[str, Any]:
    entry = int(elf.header["e_entry"])
    segment_match = None
    for index, segment in enumerate(elf.iter_segments()):
        if segment.header["p_type"] != "PT_LOAD":
            continue
        start = int(segment.header["p_vaddr"])
        end = start + int(segment.header["p_memsz"])
        if start <= entry < end:
            file_offset = int(segment.header["p_offset"]) + (entry - start)
            segment_match = {
                "index": index,
                "file_offset": file_offset,
                "segment_vaddr": start,
            }
            break

    section_match = None
    for section in sections:
        start = section["address"]
        end = start + section["size"]
        if section["size"] and start <= entry < end:
            section_match = {
                "index": section["index"],
                "name": section["name"],
                "offset": section["offset"] + (entry - start),
                "executable": "X" in section["flags"],
            }
            break

    data = b""
    if segment_match and 0 <= segment_match["file_offset"] < path.stat().st_size:
        data = _read_at(path, segment_match["file_offset"], MAX_ENTRY_BYTES)

    return {
        "virtual_address": entry,
        "segment": segment_match,
        "section": section_match,
        "bytes_hex": data.hex(" "),
        "bytes_length": len(data),
    }


def _anomalies(elf: ELFFile, file_size: int, sections: list[dict[str, Any]], segments: list[dict[str, Any]], mappings: list[dict[str, Any]], entry: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if any(not seg["within_file"] for seg in segments):
        findings.append({"severity": "high", "code": "SEGMENT_OUT_OF_FILE", "message": "A program segment extends beyond the file size."})
    if any(not seg["filesz_le_memsz"] for seg in segments):
        findings.append({"severity": "high", "code": "SEGMENT_SIZE_INVALID", "message": "A program segment reports p_filesz larger than p_memsz."})
    for sec in sections:
        end = sec["offset"] + sec["size"]
        if sec["size"] and end > file_size and sec["type"] != "SHT_NOBITS":
            findings.append({"severity": "high", "code": "SECTION_OUT_OF_FILE", "message": f"Section {sec['name']!r} extends beyond the file."})
        if sec["size"] and sec["alignment"] and sec["offset"] % sec["alignment"] != 0:
            findings.append({"severity": "info", "code": "SECTION_ALIGNMENT_ODD", "message": f"Section {sec['name']!r} has an offset not aligned to sh_addralign."})
    if entry["segment"] is None:
        findings.append({"severity": "high", "code": "ENTRY_UNMAPPED", "message": "The ELF entry point does not fall inside a PT_LOAD segment."})
    elif entry["section"] is None:
        findings.append({"severity": "medium", "code": "ENTRY_NO_SECTION", "message": "The ELF entry point maps to a loadable segment but not to a named section."})
    elif not entry["section"]["executable"]:
        findings.append({"severity": "high", "code": "ENTRY_NON_EXEC", "message": f"The entry point resolves to non-executable section {entry['section']['name']!r}."})
    if any(not mapping["segment_indices"] and mapping["section"] not in {"", ".shstrtab"} for mapping in mappings):
        findings.append({"severity": "info", "code": "UNMAPPED_SECTIONS", "message": "One or more non-empty sections are not contained by a PT_LOAD segment."})
    return findings


def _signals(elf: ELFFile, security: dict[str, Any], symbols: dict[str, Any], dyn: dict[str, Any], entropy: float, anomalies: list[dict[str, str]]) -> list[dict[str, str]]:
    signals = list(anomalies)
    if security["nx"] == "disabled":
        signals.append({"severity": "high", "code": "EXECUTABLE_STACK", "message": "PT_GNU_STACK permits an executable stack."})
    elif security["nx"] == "unknown":
        signals.append({"severity": "info", "code": "STACK_POLICY_UNKNOWN", "message": "No PT_GNU_STACK segment was found; stack execution policy cannot be confirmed statically."})
    if security["relro"] == "none":
        signals.append({"severity": "medium", "code": "RELRO_NONE", "message": "No GNU_RELRO segment was found."})
    elif security["relro"] == "partial":
        signals.append({"severity": "low", "code": "RELRO_PARTIAL", "message": "GNU_RELRO is present but immediate binding was not detected."})
    if security["pie"] == "disabled":
        signals.append({"severity": "low", "code": "NO_PIE", "message": "Main executable uses ET_EXEC rather than PIE."})
    if not symbols["canary_symbol"] and elf.header["e_type"] in {"ET_EXEC", "ET_DYN"}:
        signals.append({"severity": "low", "code": "CANARY_NOT_DETECTED", "message": "No stack-canary failure symbol was detected in dynamic imports."})
    if entropy >= 7.2:
        signals.append({"severity": "medium", "code": "HIGH_ENTROPY", "message": f"Whole-file Shannon entropy is {entropy:.3f}/8.0; compression or encryption may be present."})
    elif entropy >= 6.8:
        signals.append({"severity": "info", "code": "ELEVATED_ENTROPY", "message": f"Whole-file Shannon entropy is {entropy:.3f}/8.0."})
    for kind, values in (("RPATH", dyn["rpath"]), ("RUNPATH", dyn["runpath"])):
        for value in values:
            signals.append({"severity": "medium", "code": f"{kind}_SET", "message": f"{kind} is set to {value!r}; review library search-path trust and deployment context."})
    for name, reason in symbols["interesting_imports"].items():
        signals.append({"severity": "info", "code": "INTERESTING_IMPORT", "message": f"Imported symbol {name} indicates {reason}."})
    if not symbols["has_symtab"]:
        signals.append({"severity": "info", "code": "NO_SYMTAB", "message": "The static symbol table (.symtab) is absent; the binary is likely stripped."})
    return signals


def _disassemble_entry(path: Path, elf: ELFFile, entry: dict[str, Any], max_instructions: int = 80) -> dict[str, Any]:
    result: dict[str, Any] = {"available": False, "instructions": [], "error": None}
    try:
        from capstone import (CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_MODE_ARM, Cs)
    except Exception:
        result["error"] = "Capstone is not installed. Install python-capstone for entry-point disassembly."
        return result

    arch = _arch_name(elf).lower()
    try:
        if "x86" in arch or "i386" in arch:
            cs_arch = CS_ARCH_X86
            cs_mode = CS_MODE_64 if elf.elfclass == 64 else CS_MODE_32
        elif "aarch64" in arch:
            cs_arch = CS_ARCH_ARM64
            cs_mode = CS_MODE_ARM
        elif arch == "arm":
            cs_arch = CS_ARCH_ARM
            cs_mode = CS_MODE_ARM
        else:
            result["error"] = f"No built-in disassembly mapping for architecture {arch!r}."
            return result
        engine = Cs(cs_arch, cs_mode)
        engine.detail = False
        data = bytes.fromhex(entry["bytes_hex"]) if entry["bytes_hex"] else b""
        instructions = []
        for insn in engine.disasm(data, entry["virtual_address"], count=max_instructions):
            instructions.append({
                "address": int(insn.address),
                "bytes": insn.bytes.hex(" "),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
            })
        result["available"] = True
        result["instructions"] = instructions
    except Exception as exc:
        result["error"] = f"Capstone disassembly failed: {exc}"
    return result


def _header(elf: ELFFile) -> dict[str, Any]:
    hdr = elf.header
    return {
        "class": int(elf.elfclass),
        "data": "little-endian" if elf.little_endian else "big-endian",
        "type": str(hdr["e_type"]),
        "machine": str(hdr["e_machine"]),
        "machine_arch": _arch_name(elf),
        "version": str(hdr["e_version"]),
        "osabi": str(hdr["e_ident"]["EI_OSABI"]),
        "abiversion": int(hdr["e_ident"]["EI_ABIVERSION"]),
        "entry": int(hdr["e_entry"]),
        "program_header_offset": int(hdr["e_phoff"]),
        "section_header_offset": int(hdr["e_shoff"]),
        "flags": int(hdr["e_flags"]),
        "header_size": int(hdr["e_ehsize"]),
        "program_header_size": int(hdr["e_phentsize"]),
        "program_header_count": int(hdr["e_phnum"]),
        "section_header_size": int(hdr["e_shentsize"]),
        "section_header_count": int(hdr["e_shnum"]),
        "section_string_table_index": int(hdr["e_shstrndx"]),
    }


def analyse(path: str | Path, *, mode: int = 2, string_limit: int = 100, disassemble: bool | None = None) -> dict[str, Any]:
    file_path = Path(path).expanduser().resolve()
    if not file_path.is_file():
        raise FileNotFoundError(file_path)
    if mode not in {1, 2, 3}:
        raise ValueError("mode must be 1, 2, or 3")

    with file_path.open("rb") as fh:
        if fh.read(4) != b"\x7fELF":
            raise ValueError(f"{file_path} is not an ELF object")

    size = file_path.stat().st_size
    hashes = _hashes(file_path)

    with file_path.open("rb") as fh:
        elf = ELFFile(fh)
        header = _header(elf)
        sections = _sections(elf)
        segments = _segments(elf, size)
        dyn = _dynamic_info(elf)
        symbols = _symbols(elf)
        security = _security(elf, dyn, symbols)
        file_data, sampled = _sample_file(file_path)
        overall_entropy = _entropy(file_data)
        entry = _entry_point(file_path, elf, sections)

        result: dict[str, Any] = {
            "tool": {"name": "elfscope", "version": __version__, "mode": mode},
            "file": {"path": str(file_path), "name": file_path.name, "size": size, "hashes": hashes},
            "elf": {
                "header": header,
                "interpreter": next((seg.get_interp_name() for seg in elf.iter_segments() if seg.header["p_type"] == "PT_INTERP"), None),
                "security": security,
                "statistics": {
                    "section_count": len(sections),
                    "segment_count": len(segments),
                    "import_count": len(symbols["imports"]),
                    "export_count": len(symbols["exports"]),
                    "needed_libraries": len(dyn["needed"]),
                    "overall_entropy": round(overall_entropy, 3),
                    "entropy_sampled": sampled,
                },
            },
            "signals": [],
        }

        if mode >= 2:
            mappings = _map_sections_to_segments(elf, sections)
            relocations = _relocations(elf)
            notes = _notes(elf)
            debug = _debug_info(elf)
            anomalies = _anomalies(elf, size, sections, segments, mappings, entry)
            result["elf"].update({
                "program_headers": segments,
                "sections": sections,
                "section_segment_map": mappings,
                "dynamic": dyn,
                "notes": notes,
                "debug": debug,
                "entry_point": entry,
                "relocations": relocations,
            })
            result["symbols"] = symbols
            result["signals"] = _signals(elf, security, symbols, dyn, overall_entropy, anomalies)
        else:
            result["elf"]["sections"] = [{
                "index": s["index"],
                "name": s["name"],
                "type": s["type"],
                "flags": s["flags"],
                "size": s["size"],
                "entropy": s["entropy"],
            } for s in sections]
            result["symbols"] = {
                "imports": symbols["imports"],
                "exports": symbols["exports"],
                "interesting_imports": symbols["interesting_imports"],
                "has_symtab": symbols["has_symtab"],
                "has_dynsym": symbols["has_dynsym"],
            }
            result["signals"] = _signals(elf, security, symbols, dyn, overall_entropy, [])

        result["strings"] = _extract_strings(file_path, limit=string_limit)

        if mode >= 3:
            if disassemble is None:
                disassemble = True
            result["analysis"] = {
                "entry_disassembly": _disassemble_entry(file_path, elf, entry) if disassemble else {"available": False, "skipped": True},
                "executable_sections": [
                    {"index": s["index"], "name": s["name"], "offset": s["offset"], "address": s["address"], "size": s["size"], "entropy": s["entropy"]}
                    for s in sections
                    if "X" in s["flags"]
                ],
                "overlay": {
                    "last_section_end": max((s["offset"] + s["size"] for s in sections if s["type"] != "SHT_NOBITS"), default=0),
                    "last_segment_end": max((s["file_end"] for s in segments), default=0),
                    "file_size": size,
                    "bytes_after_known_content": max(0, size - max(
                        max((s["offset"] + s["size"] for s in sections if s["type"] != "SHT_NOBITS"), default=0),
                        max((s["file_end"] for s in segments), default=0),
                    )),
                },
            }
            result["elf"]["strings_detailed"] = result["strings"]

    return result
