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
    length = len(data)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def _sample_file(path: Path, limit: int) -> tuple[bytes, bool]:
    size = path.stat().st_size

    if size <= limit:
        return path.read_bytes(), False

    half = limit // 2

    with path.open("rb") as fh:
        head = fh.read(half)
        fh.seek(max(0, size - half))
        tail = fh.read(half)

    return head + tail, True


def _sample_bytes(
    data: bytes,
    limit: int = 8 * 1024 * 1024,
) -> tuple[bytes, bool]:
    if len(data) <= limit:
        return data, False

    half = limit // 2
    return data[:half] + data[-half:], True


def _extract_strings(
    path: Path,
    minimum: int = 6,
    limit: int = 100,
) -> list[str]:
    out: list[str] = []
    carry = b""

    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)

            if not chunk:
                break

            data = carry + chunk

            for match in PRINTABLE_RE.findall(data):
                if len(match) < minimum:
                    continue

                try:
                    value = match.decode("ascii")
                except UnicodeDecodeError:
                    continue

                if value not in out:
                    out.append(value)

                    if len(out) >= limit:
                        return out

            carry = data[-(minimum - 1):]

    if carry:
        for match in PRINTABLE_RE.findall(carry):
            if len(match) < minimum:
                continue

            value = match.decode(
                "ascii",
                errors="ignore",
            )

            if value and value not in out:
                out.append(value)

                if len(out) >= limit:
                    break

    return out


def _flags_to_text(flags: int) -> str:
    result = ""

    if flags & P_FLAGS.PF_R:
        result += "R"

    if flags & P_FLAGS.PF_W:
        result += "W"

    if flags & P_FLAGS.PF_X:
        result += "E"

    return result or "-"


def _section_flags_to_text(flags: int) -> str:
    result = ""

    if flags & SH_FLAGS.SHF_ALLOC:
        result += "A"

    if flags & SH_FLAGS.SHF_WRITE:
        result += "W"

    if flags & SH_FLAGS.SHF_EXECINSTR:
        result += "X"

    return result or "-"


def _is_main_executable(elf: ELFFile) -> bool:
    return (
        elf.header["e_type"] == "ET_DYN"
        and any(
            segment["p_type"] == "PT_INTERP"
            for segment in elf.iter_segments()
        )
    )


def _dynamic_info(elf: ELFFile) -> dict[str, Any]:
    rpath: list[str] = []
    runpath: list[str] = []
    needed: list[str] = []

    bind_now = False
    has_dynamic = False

    for section in elf.iter_sections():
        if section.header["sh_type"] != "SHT_DYNAMIC":
            continue

        has_dynamic = True

        for entry in section.iter_tags():
            tag = entry.entry.d_tag

            if tag == "DT_RPATH":
                rpath.append(str(entry.rpath))

            elif tag == "DT_RUNPATH":
                runpath.append(str(entry.runpath))

            elif tag == "DT_NEEDED":
                needed.append(str(entry.needed))

            elif tag == "DT_BIND_NOW":
                bind_now = True

            elif tag == "DT_FLAGS":
                if getattr(entry, "flags", 0) & 0x8:
                    bind_now = True

            elif tag == "DT_FLAGS_1":
                if getattr(entry, "flags_1", 0) & 0x1:
                    bind_now = True

    return {
        "has_dynamic": has_dynamic,
        "rpath": rpath,
        "runpath": runpath,
        "needed": needed,
        "bind_now": bind_now,
    }


def _symbols(elf: ELFFile) -> dict[str, Any]:
    dynamic_imports: list[str] = []
    dynamic_exports: list[str] = []

    for section in elf.iter_sections():
        if section.header["sh_type"] not in {
            "SHT_DYNSYM",
            "SHT_SYMTAB",
        }:
            continue

        is_dynamic = section.header["sh_type"] == "SHT_DYNSYM"

        for symbol in section.iter_symbols():
            name = symbol.name

            if not name:
                continue

            if is_dynamic:
                if symbol["st_shndx"] == "SHN_UNDEF":
                    dynamic_imports.append(name)
                else:
                    dynamic_exports.append(name)

    imports = sorted(set(dynamic_imports))
    exports = sorted(set(dynamic_exports))

    interesting = {
        name: INTERESTING_SYMBOLS[name]
        for name in imports
        if name in INTERESTING_SYMBOLS
    }

    canary = any(
        name in {
            "__stack_chk_fail",
            "__stack_chk_fail_local",
        }
        for name in imports
    )

    fortified = sorted(
        {
            name
            for name in imports
            if name.endswith("_chk")
        }
    )

    has_symtab = any(
        section.name == ".symtab"
        for section in elf.iter_sections()
    )

    has_dynsym = any(
        section.name == ".dynsym"
        for section in elf.iter_sections()
    )

    return {
        "imports": imports,
        "exports": exports,
        "interesting_imports": interesting,
        "canary_symbol": canary,
        "fortified_imports": fortified,
        "has_symtab": has_symtab,
        "has_dynsym": has_dynsym,
    }


def _security(
    elf: ELFFile,
    dyn: dict[str, Any],
    symbols: dict[str, Any],
) -> dict[str, Any]:
    relro = any(
        segment["p_type"] == "PT_GNU_RELRO"
        for segment in elf.iter_segments()
    )

    if relro and dyn["bind_now"]:
        relro_status = "full"
    elif relro:
        relro_status = "partial"
    else:
        relro_status = "none"

    stack_segments = [
        segment
        for segment in elf.iter_segments()
        if segment["p_type"] == "PT_GNU_STACK"
    ]

    if not stack_segments:
        nx = "unknown"
    else:
        nx = (
            "disabled"
            if any(
                segment["p_flags"] & P_FLAGS.PF_X
                for segment in stack_segments
            )
            else "enabled"
        )

    e_type = elf.header["e_type"]

    if e_type == "ET_EXEC":
        pie = "disabled"
    elif _is_main_executable(elf):
        pie = "enabled"
    elif e_type == "ET_DYN":
        pie = "shared-object"
    else:
        pie = "not-applicable"

    return {
        "relro": relro_status,
        "nx": nx,
        "pie": pie,
        "stack_canary": (
            "present"
            if symbols["canary_symbol"]
            else "not-detected"
        ),
        "fortify": {
            "checked_imports": len(
                symbols["fortified_imports"]
            ),
            "imports": symbols["fortified_imports"],
        },
        "rpath": dyn["rpath"],
        "runpath": dyn["runpath"],
    }


def _sections(elf: ELFFile) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []

    for section in elf.iter_sections():
        size = int(section.header["sh_size"])

        entropy: float | None = None
        sampled = False

        if (
            size > 0
            and section.header["sh_type"] != "SHT_NOBITS"
        ):
            try:
                data = section.data()
                sample, sampled = _sample_bytes(data)
                entropy = round(
                    _entropy(sample),
                    3,
                )
            except Exception:
                entropy = None

        result.append(
            {
                "name": section.name,
                "type": section.header["sh_type"],
                "flags": _section_flags_to_text(
                    int(section.header["sh_flags"])
                ),
                "address": int(
                    section.header["sh_addr"]
                ),
                "size": size,
                "entropy": entropy,
                "entropy_sampled": sampled,
            }
        )

    return result


def _segments(elf: ELFFile) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []

    for segment in elf.iter_segments():
        result.append(
            {
                "type": segment.header["p_type"],
                "flags": _flags_to_text(
                    int(segment.header["p_flags"])
                ),
                "file_size": int(
                    segment.header["p_filesz"]
                ),
                "memory_size": int(
                    segment.header["p_memsz"]
                ),
                "alignment": int(
                    segment.header["p_align"]
                ),
            }
        )

    return result


def _notes(elf: ELFFile) -> list[dict[str, Any]]:
    notes: list[dict[str, Any]] = []

    for section in elf.iter_sections():
        if section.header["sh_type"] != "SHT_NOTE":
            continue

        try:
            for note in section.iter_notes():
                notes.append(
                    {
                        "section": section.name,
                        "type": str(note["n_type"]),
                        "name": str(note["n_name"]),
                    }
                )
        except Exception:
            continue

    return notes


def _signals(
    elf: ELFFile,
    sections: list[dict[str, Any]],
    segments: list[dict[str, Any]],
    dyn: dict[str, Any],
    security: dict[str, Any],
    symbols: dict[str, Any],
    overall_entropy: float,
) -> list[dict[str, str]]:
    signals: list[dict[str, str]] = []

    if security["nx"] == "disabled":
        signals.append(
            {
                "severity": "high",
                "code": "EXECUTABLE_STACK",
                "message": (
                    "PT_GNU_STACK permits an executable stack."
                ),
            }
        )

    elif security["nx"] == "unknown":
        signals.append(
            {
                "severity": "info",
                "code": "STACK_POLICY_UNKNOWN",
                "message": (
                    "No PT_GNU_STACK segment was found; "
                    "stack policy cannot be confirmed statically."
                ),
            }
        )

    if security["relro"] == "none":
        signals.append(
            {
                "severity": "medium",
                "code": "RELRO_NONE",
                "message": (
                    "No GNU_RELRO segment was found."
                ),
            }
        )

    elif security["relro"] == "partial":
        signals.append(
            {
                "severity": "low",
                "code": "RELRO_PARTIAL",
                "message": (
                    "GNU_RELRO is present but immediate binding "
                    "was not detected."
                ),
            }
        )

    if security["pie"] == "disabled":
        signals.append(
            {
                "severity": "low",
                "code": "NO_PIE",
                "message": (
                    "Main executable uses ET_EXEC rather than PIE."
                ),
            }
        )

    if (
        not symbols["canary_symbol"]
        and elf.header["e_type"] in {
            "ET_EXEC",
            "ET_DYN",
        }
    ):
        signals.append(
            {
                "severity": "low",
                "code": "CANARY_NOT_DETECTED",
                "message": (
                    "No stack-canary failure symbol was detected "
                    "in dynamic imports."
                ),
            }
        )

    for segment in segments:
        if (
            "W" in segment["flags"]
            and "E" in segment["flags"]
            and segment["type"] == "PT_LOAD"
        ):
            signals.append(
                {
                    "severity": "high",
                    "code": "W_X_SEGMENT",
                    "message": (
                        "A PT_LOAD segment is both writable "
                        "and executable."
                    ),
                }
            )

    for section in sections:
        if (
            "W" in section["flags"]
            and "X" in section["flags"]
        ):
            signals.append(
                {
                    "severity": "high",
                    "code": "W_X_SECTION",
                    "message": (
                        f"Section {section['name']!r} "
                        "is writable and executable."
                    ),
                }
            )

        lowered = section["name"].lower()

        if lowered in PACKER_SECTION_NAMES:
            signals.append(
                {
                    "severity": "info",
                    "code": "PACKER_SECTION_NAME",
                    "message": (
                        f"{PACKER_SECTION_NAMES[lowered]} "
                        f"detected: {section['name']}"
                    ),
                }
            )

    if overall_entropy >= 7.2:
        signals.append(
            {
                "severity": "medium",
                "code": "HIGH_ENTROPY",
                "message": (
                    f"Whole-file Shannon entropy is "
                    f"{overall_entropy:.3f}/8.0; compression "
                    "or encryption may be present."
                ),
            }
        )

    elif overall_entropy >= 6.8:
        signals.append(
            {
                "severity": "info",
                "code": "ELEVATED_ENTROPY",
                "message": (
                    f"Whole-file Shannon entropy is "
                    f"{overall_entropy:.3f}/8.0."
                ),
            }
        )

    for path_kind, values in (
        ("RPATH", dyn["rpath"]),
        ("RUNPATH", dyn["runpath"]),
    ):
        for value in values:
            signals.append(
                {
                    "severity": "medium",
                    "code": f"{path_kind}_SET",
                    "message": (
                        f"{path_kind} is set to {value!r}. "
                        "Review library search-path trust "
                        "and deployment context."
                    ),
                }
            )

    for name, reason in symbols["interesting_imports"].items():
        signals.append(
            {
                "severity": "info",
                "code": "INTERESTING_IMPORT",
                "message": (
                    f"Imported symbol {name} indicates {reason}."
                ),
            }
        )

    if not symbols["has_symtab"]:
        signals.append(
            {
                "severity": "info",
                "code": "NO_SYMTAB",
                "message": (
                    "The static symbol table (.symtab) is absent; "
                    "the binary is likely stripped."
                ),
            }
        )

    return signals


def analyse(
    path: str | Path,
    *,
    string_limit: int = 100,
    string_minimum: int = 6,
) -> dict[str, Any]:
    file_path = Path(path).expanduser().resolve()

    if not file_path.is_file():
        raise FileNotFoundError(file_path)

    size = file_path.stat().st_size
    hashes = _hashes(file_path)

    with file_path.open("rb") as fh:
        prefix = fh.read(4)

    if prefix != b"\x7fELF":
        raise ValueError(
            f"{file_path} is not an ELF object"
        )

    with file_path.open("rb") as fh:
        elf = ELFFile(fh)

        dyn = _dynamic_info(elf)

        symbols = _symbols(elf)

        security = _security(
            elf,
            dyn,
            symbols,
        )

        section_info = _sections(elf)
        segment_info = _segments(elf)
        note_info = _notes(elf)

        overall_data, sampled = _sample_file(
            file_path,
            limit=16 * 1024 * 1024,
        )

        overall_entropy = _entropy(overall_data)

        header = {
            "class": elf.elfclass,
            "data": (
                "little-endian"
                if elf.little_endian
                else "big-endian"
            ),
            "type": elf.header["e_type"],
            "type_name": str(
                elf.header["e_type"]
            ),
            "machine": elf.header["e_machine"],
            "machine_name": str(
                elf.header["e_machine"]
            ),
            "entry": int(
                elf.header["e_entry"]
            ),
            "flags": int(
                elf.header["e_flags"]
            ),
        }

        interpreter = None

        for segment in elf.iter_segments():
            if segment.header["p_type"] == "PT_INTERP":
                try:
                    interpreter = segment.get_interp_name()
                except Exception:
                    interpreter = None
                break

        signals = _signals(
            elf,
            section_info,
            segment_info,
            dyn,
            security,
            symbols,
            overall_entropy,
        )

    report: dict[str, Any] = {
        "tool": {
            "name": "elfscope",
            "version": __version__,
        },
        "file": {
            "path": str(file_path),
            "name": file_path.name,
            "size": size,
            "hashes": hashes,
        },
        "elf": {
            "header": header,
            "interpreter": interpreter,
            "sections": section_info,
            "segments": segment_info,
            "notes": note_info,
            "dynamic": dyn,
        },
        "symbols": symbols,
        "security": security,
        "statistics": {
            "overall_entropy": round(
                overall_entropy,
                3,
            ),
            "entropy_sampled": sampled,
            "section_count": len(
                section_info
            ),
            "segment_count": len(
                segment_info
            ),
            "import_count": len(
                symbols["imports"]
            ),
            "export_count": len(
                symbols["exports"]
            ),
            "needed_libraries": len(
                dyn["needed"]
            ),
        },
        "strings": _extract_strings(
            file_path,
            minimum=string_minimum,
            limit=string_limit,
        ),
        "signals": signals,
    }

    return report
