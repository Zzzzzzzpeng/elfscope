# ELFscope design notes

## Design goal

ELFscope is a static first-pass inspection tool. The design favours deterministic output, bounded memory use, direct evidence, and clear separation between observations and interpretation.

## Evidence layers

### 1. File identity

The report records size and cryptographic hashes before semantic parsing. SHA-256 is the primary identifier; MD5 and SHA-1 are retained as compatibility identifiers and are not presented as collision-resistant security guarantees.

### 2. ELF metadata

The ELF header provides class, byte order, object type, machine, entry point, and flags. Program headers describe the segments relevant to process loading. Section headers provide a convenient view for static reverse-engineering triage.

### 3. Dynamic metadata

The dynamic section provides dependencies, RPATH/RUNPATH, and binding-related tags. These are useful because they describe how a binary resolves shared objects and symbols at load time.

### 4. Symbols

Dynamic imports and exports help analysts quickly identify library usage and exposed symbols. The static `.symtab` is treated separately from `.dynsym` because many release binaries keep dynamic symbols while removing the full static symbol table.

### 5. Hardening

The hardening checks are evidence-driven:

- RELRO: presence of `PT_GNU_RELRO`, combined with bind-now state for a full result.
- NX: execute permission on `PT_GNU_STACK`.
- PIE: object type plus presence of an ELF interpreter for an `ET_DYN` main executable.
- Canary: dynamic import of `__stack_chk_fail` or its local variant.
- FORTIFY: imported `_chk` symbols.

None of these checks should be treated as a complete exploitability assessment.

### 6. Statistical signals

Entropy is calculated using Shannon entropy. Large regions are sampled to keep analysis predictable. The sampling policy is explicit in the JSON report so a consumer can distinguish a full calculation from a bounded sample.

### 7. Behavioural signals

The tool records a small, fixed set of imports often worth reviewing during defensive analysis, such as `dlopen`, `dlsym`, `mprotect`, `execve`, `ptrace`, and `memfd_create`. The report calls these "interesting imports" rather than calling them malicious.

## Why pyelftools

The project uses pyelftools because it is a pure-Python ELF/DWARF parsing library with no external runtime dependency beyond Python itself. Arch Linux currently packages it as `python-pyelftools`. This keeps the first release lightweight and easy to package.

LIEF is deliberately not required for 0.1.0. LIEF is a powerful choice for later versions if the project expands into richer cross-format abstractions or needs deeper ELF APIs, but adding it immediately would increase the package surface without being necessary for the first scope.

## Relationship to established tools

GNU `readelf` is an authoritative inspection utility for ELF headers, program headers, sections, symbols, relocations, dynamic information, and notes. ELFscope intentionally overlaps with that evidence but presents a smaller, machine-readable view focused on triage.

`checksec` covers many binary-hardening checks very effectively. ELFscope does not attempt to beat it on coverage. Instead, hardening results are combined with file identity, ELF metadata, symbols, strings, entropy, and explainable signals in one JSON document.

## False-positive policy

A signal should be phrased as an observation or an investigative hint whenever possible. For example:

- good: "Whole-file entropy is 7.35/8.0; compression or encryption may be present."
- bad: "The file is packed."

The same principle applies to APIs. An import of `ptrace` is evidence that the program references `ptrace`; it is not proof of debugging evasion or maliciousness.

## Future directions

Potential later releases can add:

- GNU property-note parsing for architecture-specific control-flow protections;
- build-ID extraction and richer symbol version reporting;
- optional YARA-compatible rule evaluation outside the parser core;
- directory mode with reproducible ordering;
- structured diffing between two ELF samples;
- deeper DWARF metadata summaries;
- richer report schemas with explicit evidence provenance;
- fixture-driven tests for PIE, RELRO, NX, canary, FORTIFY, and W+X cases.
