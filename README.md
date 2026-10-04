# ELFscope

ELFscope is a static ELF triage utility for defensive reverse engineering on Linux. It analyses ELF binaries without executing them and produces a compact, structured view of file identity, ELF metadata, security hardening, dynamic dependencies, symbols, strings, entropy, and explainable triage signals.

The project is designed to provide a fast and reproducible first-pass analysis before deeper reverse engineering or forensic investigation.

## What it does

ELFscope analyses an ELF file and reports:

* ELF class, endianness, machine architecture, file type, entry point, and interpreter;
* sections, program segments, and ELF notes;
* dynamic dependencies;
* imported and exported symbols;
* common binary-hardening indicators including RELRO, NX, PIE, stack-canary symbols, RPATH, RUNPATH, and FORTIFY-related imports;
* MD5, SHA-1, and SHA-256 file hashes;
* Shannon entropy for the complete file and individual sections;
* printable ASCII strings for quick triage;
* executable-stack and W+X segment or section indicators;
* selected suspicious or noteworthy imported APIs;
* unusual section-name indicators;
* stripped-symbol indicators;
* machine-readable JSON reports;
* human-readable Markdown reports.

ELFscope is intentionally static. It does not execute the analysed file, inject into processes, modify binaries, contact remote targets, or perform exploitation.

## Why ELFscope exists

A full reverse-engineering workflow normally involves several specialised tools.

Examples include:

* `file` for basic file identification;
* `readelf` for ELF metadata;
* `objdump` for low-level inspection;
* `nm` for symbol information;
* `strings` for printable strings;
* `checksec` for common hardening properties;
* disassemblers and decompilers for deeper static analysis;
* debuggers and tracing tools for controlled dynamic analysis.

ELFscope does not attempt to replace these tools.

Instead, it provides a small, scriptable aggregation layer for the first stage of an investigation. The goal is to reduce repetitive commands, preserve analysis results in a structured format, and make the initial triage process easier to reproduce.

## Design principles

ELFscope follows several principles:

### Static first

The inspected file is treated as data. ELFscope does not execute the target binary.

### Explainable signals

A signal should identify the observed condition rather than claim a definitive malware classification.

For example, high entropy may indicate compressed or encrypted data, but it can also occur in legitimate software. Likewise, imports such as `ptrace`, `mprotect`, or `dlopen` can have legitimate uses.

### Conservative interpretation

Unknown information is reported as unknown instead of being converted into a false security claim.

### Scriptable output

JSON is provided so that other programs can consume ELFscope results without parsing terminal output.

### Small scope

The project focuses on ELF triage rather than attempting to become a complete reverse-engineering framework.

## Requirements

ELFscope currently targets Linux systems and supports ELF binaries.

The project uses Python and `pyelftools` for ELF parsing.

On Arch Linux:

```bash
sudo pacman -S python python-pyelftools
```

Other Linux distributions should install the equivalent Python and `pyelftools` packages through their native package manager or Python environment.

## Running ELFscope

From a source checkout:

```bash
./run.sh /bin/ls
```

Or:

```bash
python -m elfscope /bin/ls
```

To display the version:

```bash
./run.sh --version
```

## Generating reports

JSON:

```bash
./run.sh /bin/ls \
  --json reports/ls.json
```

Markdown:

```bash
./run.sh /bin/ls \
  --markdown reports/ls.md
```

Both:

```bash
./run.sh /bin/ls \
  --json reports/ls.json \
  --markdown reports/ls.md
```

The generated JSON is intended for automation, while Markdown is intended for human-readable investigation notes and case documentation.

## Example workflow

A simple defensive triage workflow is:

```text
preserve sample
      ↓
record SHA-256
      ↓
run ELFscope
      ↓
review ELF metadata
      ↓
review hardening
      ↓
review dependencies and symbols
      ↓
review strings and entropy
      ↓
review triage signals
      ↓
decide whether deeper analysis is required
```

A typical investigation might therefore begin with:

```bash
sha256sum sample
./run.sh sample \
  --json reports/sample.json \
  --markdown reports/sample.md
```

The resulting report can be retained together with the original evidence and investigation notes.

## Security semantics

### RELRO

ELFscope checks for the GNU `PT_GNU_RELRO` segment and related bind-now semantics.

The result is reported as:

* `full` when RELRO and immediate binding semantics are detected;
* `partial` when a RELRO segment exists without detected immediate binding;
* `none` when no RELRO segment is detected;
* `unknown` when the available ELF metadata is insufficient to make the determination.

These results describe observed ELF properties. They do not prove that a binary is safe or unsafe.

### NX

The Linux `PT_GNU_STACK` program segment communicates the intended stack execution policy.

ELFscope reports:

* `enabled` when the stack segment is present without the execute flag;
* `disabled` when the execute flag is present;
* `unknown` when the required segment information is unavailable.

An unknown result is intentionally not interpreted as a positive or negative security claim.

### PIE

ELFscope distinguishes between position-independent executables and ordinary shared objects.

For an executable:

* `ET_EXEC` is reported as `disabled`;
* `ET_DYN` with a program interpreter is reported as `enabled`.

A plain `ET_DYN` shared object is reported as `shared-object` instead of incorrectly labelling it as a PIE executable.

### Stack canaries

The first release checks for imported symbols such as:

```text
__stack_chk_fail
```

This is useful evidence that stack-protection mechanisms may be present.

It is not proof that every function in the binary is protected.

### FORTIFY

ELFscope identifies imported symbols ending in:

```text
_chk
```

This provides a conservative indication of FORTIFY-related interfaces.

It is not a complete audit of compiler flags, libc configuration, or source-level protection.

### Entropy

ELFscope calculates Shannon entropy for:

* the complete file;
* individual ELF sections.

Higher entropy can be associated with compressed or encrypted content, but it can also occur naturally in compiled binaries and data.

Therefore, ELFscope treats entropy as a triage signal rather than a malware or packer verdict.

## Triage signals

ELFscope produces explainable signals for conditions such as:

* executable stacks;
* writable and executable segments;
* writable and executable sections;
* missing RELRO;
* stripped symbols;
* high entropy;
* unusual section names;
* selected dynamic imports associated with behaviours that may warrant investigation.

A signal does not mean that a binary is malicious.

For example, a legitimate application may:

* use dynamic loading;
* change memory permissions;
* use debugging interfaces;
* contain compressed resources;
* remove symbols for release builds;
* use unusual section names.

Likewise, the absence of a signal does not prove that a binary is benign.

ELFscope is intended to help an analyst decide what to inspect next.

## Output model

JSON output is structured for programmatic use.

The top-level structure includes:

```text
tool
file
elf
symbols
security
statistics
strings
signals
```

A signal contains fields such as:

```text
severity
code
message
```

The design goal is to provide enough context for another program or analyst to understand why the signal was generated without relying on terminal formatting.

## Architecture

The current project is intentionally small:

```text
elfscope/
├── src/
│   └── elfscope/
│       ├── __init__.py
│       ├── __main__.py
│       ├── analysis.py
│       └── cli.py
├── tests/
├── examples/
├── docs/
├── packaging/
├── pyproject.toml
├── Makefile
└── run.sh
```

The analysis layer is kept separate from the CLI so that the underlying functionality can be reused by other Python programs in the future.

## Testing

Install development and test dependencies:

```bash
python -m pip install -e '.[test]'
```

Then run:

```bash
make check
```

The test suite currently covers:

* entropy calculations;
* printable-string extraction;
* CLI version handling;
* basic analysis behaviour.

Future releases can expand this into fixture-driven tests covering multiple ELF architectures, hardening configurations, stripped/unstripped binaries, malformed files, and uncommon ELF layouts.

## Packaging

ELFscope is intentionally distribution-independent.

The core project does not require AUR, BlackArch, Kali, Debian, Fedora, or any other specific Linux distribution.

Distribution packaging can be maintained separately from the core source tree.

Possible future packaging targets include:

* Arch Linux / AUR;
* BlackArch;
* Debian-based distributions;
* Fedora;
* standalone Python environments;
* containers.

The project should remain fully usable without any of these packaging ecosystems.

## Scope

ELFscope currently focuses on ELF binaries used on Linux and Unix-like systems.

The project does not currently attempt to provide:

* disassembly;
* decompilation;
* debugging;
* dynamic tracing;
* sandboxing;
* malware execution;
* exploit development;
* remote scanning;
* process injection;
* binary patching;
* automated exploitation.

Those areas are deliberately outside the scope of the first releases.

## Limitations

Static analysis has inherent limitations.

A binary can behave differently at runtime because of:

* environment variables;
* configuration files;
* dynamically loaded libraries;
* network conditions;
* user interaction;
* runtime-generated code;
* kernel behaviour;
* anti-analysis mechanisms.

ELFscope therefore should be considered a triage tool rather than a complete verdict engine.

Indicators must always be interpreted in context.

## Defensive use

ELFscope is intended for legitimate defensive activities such as:

* malware triage;
* incident-response preparation;
* software supply-chain inspection;
* binary hardening review;
* reverse-engineering preparation;
* suspicious-file investigation;
* educational ELF analysis;
* forensic documentation.

Only analyse binaries that you are authorised to inspect.

## Development goals

The project can evolve in several directions while keeping the core scope focused.

Potential future work includes:

* additional ELF architectures;
* richer relocation analysis;
* GNU build-id extraction;
* DWARF metadata inspection;
* compiler and linker fingerprinting;
* improved packer heuristics;
* more detailed symbol classification;
* reproducible JSON schemas;
* plugin support for custom triage rules;
* SARIF or other machine-readable output formats;
* integration with existing analysis workflows;
* performance improvements for large binaries.

Future functionality should remain evidence-oriented and avoid turning heuristic signals into unsupported conclusions.

## References

* GNU Binutils `readelf`
  https://sourceware.org/binutils/docs/binutils/readelf.html

* Linux `elf(5)`
  https://man7.org/linux/man-pages/man5/elf.5.html

* Linux UAPI ELF definitions
  https://github.com/torvalds/linux/blob/master/include/uapi/linux/elf.h

* pyelftools
  https://github.com/eliben/pyelftools

* LIEF ELF documentation
  https://lief.re/doc/latest/formats/elf/

* checksec
  https://github.com/slimm609/checksec

## Licence

MIT. See `LICENSE`.
