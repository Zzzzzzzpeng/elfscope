# Defensive reverse-engineering research basis

Research date: 2026-10-04

## Problem definition

The first phase of reverse engineering is often triage: determine what the file is, how it is loaded, what it links against, what symbols it exposes or imports, what hardening is present, and whether any observable properties justify deeper work.

A useful triage utility should therefore keep three layers separate:

1. **Evidence**: values read directly from the ELF file.
2. **Derived properties**: hardening and statistical calculations derived from that evidence.
3. **Signals**: prioritisation hints that require human interpretation.

That separation is the central design rule for ELFscope.

## ELF format references

Linux `elf(5)` documents the ELF header and program headers and explains `PT_GNU_STACK` as the GNU extension used to communicate the stack execution policy. The Linux kernel ELF definitions also expose `PT_GNU_STACK`, `PT_GNU_RELRO`, and `PT_GNU_PROPERTY` constants.

GNU Binutils documents `readelf` as an ELF inspection program covering file headers, program headers, sections, symbols, relocations, dynamic data, notes, and related information.

## Parser choice

`pyelftools` is a pure-Python parser for ELF and DWARF and is packaged by Arch Linux as `python-pyelftools`. This is a practical fit for a first release because it avoids compiling a large native dependency and keeps packaging straightforward.

LIEF is a broader executable-format abstraction library with ELF support in C++, Python, and Rust. It is technically attractive for future cross-format and richer binary-analysis features, but it is not necessary for the initial static-ELF scope.

## Hardening model

The first release deliberately focuses on a familiar set of Linux hardening properties.

### RELRO

A GNU RELRO segment is represented by `PT_GNU_RELRO`. Full RELRO additionally requires immediate symbol binding, commonly expressed with bind-now semantics in the dynamic section. ELFscope therefore distinguishes `none`, `partial`, and `full`.

### NX

The `PT_GNU_STACK` segment carries stack permission flags. ELFscope does not silently treat a missing segment as secure or insecure; it reports `unknown` so the absence is visible.

### PIE

PIE detection is contextual. A main executable commonly appears as `ET_DYN` with an interpreter, whereas a shared library can also be `ET_DYN`. ELFscope therefore checks both object type and `PT_INTERP` instead of treating every `ET_DYN` object as a PIE executable.

### Stack canaries

The presence of imports such as `__stack_chk_fail` is a practical static indicator that compiler stack-protector support may have been used. It is not a proof about every function.

### FORTIFY

`_chk` symbol imports are treated as evidence of fortified libc call sites. The result is intentionally labelled as a count of detected fortified imports, not as a complete FORTIFY_SOURCE audit.

## Entropy

Shannon entropy can highlight regions containing compressed or encrypted data. It is not a packer detector. ELFscope therefore uses thresholds only to prioritise review and states the limitation in both terminal output and Markdown reports.

## Existing tooling

`readelf` and `objdump` are established low-level ELF inspection tools. `checksec` is focused specifically on security properties such as RELRO, stack canaries, NX, PIE, RPATH, RUNPATH, and FORTIFY-related checks.

ELFscope should complement these tools rather than attempt to replace them. Its distinguishing feature is a consolidated, deterministic, machine-readable triage report that connects file identity, loader metadata, hardening, symbols, entropy, and human-readable signals.

## Defensive boundary

The tool is designed to inspect a file as data. It does not execute the file, attach to running processes, modify binaries, deliver payloads, bypass access controls, or automate actions against remote targets.

## References

1. GNU Binutils `readelf`: https://sourceware.org/binutils/docs/binutils/readelf.html
2. Linux `elf(5)`: https://man7.org/linux/man-pages/man5/elf.5.html
3. Linux ELF UAPI definitions: https://github.com/torvalds/linux/blob/master/include/uapi/linux/elf.h
4. pyelftools: https://github.com/eliben/pyelftools
5. Arch Linux `python-pyelftools`: https://archlinux.org/packages/extra/any/python-pyelftools/
6. LIEF documentation: https://lief.re/doc/latest/formats/elf/
7. checksec: https://github.com/slimm609/checksec
8. BlackArch PKGBUILD templates: https://github.com/BlackArch/blackarch-pkgbuilds
9. BlackArch package repository: https://github.com/BlackArch/blackarch
