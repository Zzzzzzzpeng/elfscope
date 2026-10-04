# ELFscope

### Static ELF Triage for Defensive Reverse Engineering

ELFscope is a static ELF analysis and triage utility for Linux, designed to help analysts understand a binary before moving into deeper reverse engineering.

It analyses ELF files as static data and produces structured information about their format, memory layout, sections, segments, symbols, relocations, dynamic linking, hardening properties, strings, entropy, notes, entry points, and structural indicators.

The primary goal is simple:

> **Understand the ELF before diving deeper.**

ELFscope does not execute the inspected binary and does not attempt to replace specialised reverse-engineering tools. Instead, it provides a focused first-pass analysis layer that helps determine what should be investigated next.

---

## Features

ELFscope v0.2.0 provides three analysis levels.

### 1. Quick Triage

Fast first-pass inspection for identifying a binary and reviewing the most important security and structural properties.

```text
[1] Quick Triage
```

Includes:

* file identity and cryptographic hashes;
* ELF class and architecture;
* endianness;
* object type;
* entry point;
* interpreter;
* common hardening properties;
* imported libraries;
* imported symbols;
* printable strings;
* entropy;
* explainable triage signals.

---

### 2. Deep ELF Analysis

A structural ELF analysis intended for analysts preparing for deeper reverse engineering.

```text
[2] Deep ELF Analysis
```

Includes:

* complete ELF header information;
* program headers;
* section headers;
* section-to-segment relationships;
* dynamic tags;
* shared-library dependencies;
* symbols;
* relocations;
* ELF notes;
* GNU Build-ID where available;
* debug-information indicators;
* hardening properties;
* structural observations.

---

### 3. Full Static Analysis

The most comprehensive analysis mode available in the current release.

```text
[3] Full Static Analysis
```

Combines deep ELF analysis with additional static triage capabilities such as:

* entry-point resolution;
* entry-point section and segment mapping;
* entry-point file offset;
* entry-point bytes;
* section and file entropy;
* structural anomaly checks;
* possible trailing-data indicators;
* optional entry-point disassembly;
* extended triage signals;
* complete analysis statistics.

All analysis remains static.

---

# CLI Usage

Run ELFscope against an ELF file:

```bash
./run.sh ./sample
```

Interactive mode presents:

```text
┌──────────────────────────────────────────────────────────────┐
│                       ELFscope v0.2.0                       │
│      Static ELF Triage for Defensive Reverse Engineering   │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  [1] ⚡ Quick Triage                                         │
│      Fast first-pass binary inspection                      │
│                                                              │
│  [2] 🔬 Deep ELF Analysis                                   │
│      Structural ELF and reverse-engineering analysis         │
│                                                              │
│  [3] 🧪 Full Static Analysis                                │
│      Deep analysis + entry-point + anomaly inspection       │
│                                                              │
└──────────────────────────────────────────────────────────────┘

Choose analysis [1/2/3]:
```

A mode can also be selected directly:

```bash
./run.sh ./sample --mode 1
```

```bash
./run.sh ./sample --mode 2
```

```bash
./run.sh ./sample --mode 3
```

Display the version:

```bash
./run.sh --version
```

Display command help:

```bash
./run.sh --help
```

---

# Recommended Workflow

ELFscope is intended to sit at the beginning of a reverse-engineering workflow.

```text
                    ┌──────────────────┐
                    │     ELF file     │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │     ELFscope     │
                    │   static triage  │
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
          Identity        Structure      Signals
              │              │              │
              └──────────────┼──────────────┘
                             │
                             ▼
                   Investigation plan
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
           readelf         objdump          nm
              │
              ├──────────► disassembler
              │
              ├──────────► decompiler
              │
              └──────────► debugger
```

A practical workflow is:

```text
1. Preserve the original sample.
2. Record its cryptographic hash.
3. Run ELFscope.
4. Review the ELF structure.
5. Review hardening properties.
6. Review dependencies, symbols, and relocations.
7. Inspect the entry point.
8. Review structural anomalies and triage signals.
9. Decide which deeper analysis technique is appropriate.
10. Continue with specialised reverse-engineering tools.
```

ELFscope is the preparation layer, not the entire reverse-engineering workflow.

---

# ELF Analysis

## ELF Header

ELFscope extracts structural information from the ELF header, including:

```text
Class
Data / Endianness
OS ABI
ABI Version
Object Type
Machine Architecture
Entry Point
Program Header Offset
Section Header Offset
ELF Header Size
Program Header Entry Size
Program Header Count
Section Header Entry Size
Section Header Count
Section String Table Index
Flags
```

These fields establish the basic structure and layout of the binary.

---

## Program Headers

Program headers describe segments used by the loader and provide information about how relevant portions of an ELF file are mapped into memory.

ELFscope inspects segment types including:

```text
PT_LOAD
PT_INTERP
PT_DYNAMIC
PT_NOTE
PT_GNU_STACK
PT_GNU_RELRO
PT_GNU_EH_FRAME
```

For program segments, ELFscope can report:

```text
Type
File Offset
Virtual Address
File Size
Memory Size
Flags
Alignment
```

This is useful for examining:

* executable mappings;
* writable mappings;
* W+X conditions;
* stack-execution policy;
* memory layout;
* dynamic linking;
* loader-related metadata.

---

# Sections

ELFscope enumerates ELF sections and reports properties including:

```text
Name
Type
Address
File Offset
Size
Flags
Entropy
```

Common sections include:

```text
.text
.rodata
.data
.bss
.symtab
.strtab
.dynsym
.dynstr
.rela.dyn
.rela.plt
.init
.fini
.init_array
.fini_array
.debug_*
```

Section information helps identify executable code, read-only data, writable data, symbol information, relocation data, and debugging metadata.

---

# Section-to-Segment Mapping

Sections describe the logical organisation of the ELF file, while segments describe portions relevant to program loading.

ELFscope analyses their relationship.

Example:

```text
PT_LOAD #0  R E
 ├── .text
 ├── .rodata
 └── .eh_frame

PT_LOAD #1  RW
 ├── .data
 ├── .bss
 └── .got
```

This mapping is useful for identifying:

* executable sections;
* writable sections;
* W+X mappings;
* unusual section placement;
* loader-oriented anomalies;
* inconsistencies between logical and loadable layouts.

---

# Dynamic Information

When dynamic linking is present, ELFscope inspects the dynamic section and related metadata.

Examples include:

```text
DT_NEEDED
DT_SONAME
DT_RPATH
DT_RUNPATH
DT_PLTGOT
DT_PLTRELSZ
DT_PLTREL
DT_RELA
DT_RELASZ
DT_REL
DT_RELSZ
DT_BIND_NOW
DT_FLAGS
DT_FLAGS_1
```

This provides context about shared-library dependencies and dynamic loader behaviour.

---

# Shared Libraries

ELFscope reports dynamic dependencies when available.

Example:

```text
Dynamic Libraries

  libc.so.6
  libdl.so.2
  libpthread.so.0
```

This can help determine whether a binary is dynamically linked and which runtime components may be relevant to further analysis.

---

# Symbols

ELFscope analyses static and dynamic symbol tables when available.

Symbol information may include:

```text
Name
Address
Size
Binding
Type
Visibility
Section
Defined / Undefined
```

Examples:

```text
_start
main
malloc
printf
dlopen
mprotect
__stack_chk_fail
```

Symbol availability also provides useful evidence about stripping and build configuration.

---

# Relocations

ELFscope inspects relocation information when present.

Relevant structures include:

```text
REL
RELA
RELR
JMPREL
```

Relocation analysis helps explain how symbolic references and runtime addresses are expected to be resolved.

This is particularly useful for investigating:

* dynamic linking;
* PLT/GOT behaviour;
* imported functions;
* position-independent code;
* unusual relocation layouts.

---

# ELF Notes

ELF notes can contain identification, ABI, build, and toolchain-related information.

ELFscope can inspect information such as:

```text
GNU Build-ID
ABI information
GNU properties
Other ELF notes
```

A Build-ID may help correlate a binary with:

* another copy of the same build;
* debugging information;
* package artefacts;
* external analysis records.

---

# Entry-Point Analysis

The ELF entry point is an important starting location for static reverse engineering.

ELFscope attempts to resolve:

```text
Virtual Address
Containing Section
Containing Segment
File Offset
Entry-Point Bytes
```

Example:

```text
Entry Point
────────────────────────────────────────

Virtual Address : 0x08048060
Section         : .text
File Offset     : 0x00000060
Segment         : PT_LOAD #0

Bytes:
31 c0 40 cd 80
```

When optional disassembly support is available, ELFscope can decode a bounded instruction region around the entry point.

This gives the analyst an immediate starting point before moving into a full disassembler or decompiler.

---

# Debug Information

ELFscope identifies the presence of relevant debug-information structures, including:

```text
.debug_info
.debug_line
.debug_abbrev
.debug_str
.gnu_debuglink
```

The presence or absence of debugging information can help determine how much symbolic and source-level context may be available during deeper analysis.

---

# Security Hardening

ELFscope reports common ELF hardening properties.

### RELRO

```text
FULL
PARTIAL
NONE
```

### NX / Stack Execution

```text
ENABLED
DISABLED
UNKNOWN
```

### PIE

```text
ENABLED
DISABLED
SHARED OBJECT
NOT APPLICABLE
```

### Stack Canary

```text
PRESENT
NOT DETECTED
```

### FORTIFY

ELFscope identifies selected `_chk` imports as static evidence of FORTIFY-related interfaces.

These checks describe observed binary properties. They are not a complete security certification.

---

# Entropy

ELFscope calculates Shannon entropy for:

* the complete file;
* individual sections.

Entropy is reported on a scale of:

```text
0.0 ───────────────────────────── 8.0
```

High entropy can occur in:

* compressed data;
* encrypted data;
* packed content;
* generated data;
* ordinary compiled data.

Therefore:

> **High entropy is a triage signal, not proof of packing or maliciousness.**

---

# Strings

ELFscope extracts printable ASCII strings for quick triage.

Strings can expose useful artefacts such as:

```text
file paths
URLs
error messages
library names
configuration values
command fragments
format strings
debug messages
```

String results should be interpreted together with ELF metadata and other evidence.

---

# Structural Anomalies

ELFscope can identify conditions that may warrant closer inspection, including:

```text
Executable and writable segments
Executable and writable sections
Entry point outside expected executable content
Unexpected section placement
Suspicious offsets
Segment/file-size inconsistencies
Unusual alignment
Missing expected structures
Potential trailing data
```

An anomaly indicates something worth investigating. It is not an automatic malware or vulnerability verdict.

---

# Triage Signals

ELFscope produces explainable signals rather than attempting to classify a binary as simply “safe” or “malicious”.

Example:

```text
[HIGH]   EXECUTABLE_STACK
[MEDIUM] RELRO_NONE
[LOW]    NO_PIE
[INFO]   INTERESTING_IMPORT
[INFO]   HIGH_ENTROPY
```

Each signal should answer:

```text
What was observed?
Why might it matter?
What should be investigated next?
```

Static indicators always require context.

A legitimate program can contain:

* high-entropy data;
* dynamic loading;
* `mprotect`;
* `ptrace`;
* stripped symbols;
* unusual section names.

Likewise, the absence of a signal does not prove that a binary is benign.

---

# Output Formats

ELFscope supports terminal output and structured report generation.

## JSON

```bash
./run.sh ./sample \
  --mode 3 \
  --json reports/sample.json
```

JSON output is intended for:

* automation;
* analysis scripts;
* SIEM or case-management pipelines;
* reproducible investigations;
* future integrations.

---

## Markdown

```bash
./run.sh ./sample \
  --mode 3 \
  --markdown reports/sample.md
```

Markdown reports are useful for:

* investigation notes;
* technical documentation;
* incident-response records;
* research;
* sharing analysis results.

Generate both:

```bash
./run.sh ./sample \
  --mode 3 \
  --json reports/sample.json \
  --markdown reports/sample.md
```

---

# Installation

## Arch Linux

### Required Packages

ELFscope's core analysis requires:

```bash
sudo pacman -S python python-pyelftools
```

Core components:

```text
🐍 Python
🔬 pyelftools
```

`pyelftools` provides ELF and DWARF parsing.

### Optional Disassembly Support

For optional Capstone-based static disassembly:

```bash
sudo pacman -S python-capstone
```

Without Capstone, the core ELF analysis remains available.

### Development and Testing

To run the test suite:

```bash
sudo pacman -S python-pytest
```

Then:

```bash
make check
```

### Recommended Development Setup

```bash
sudo pacman -S \
    python \
    python-pyelftools \
    python-capstone \
    python-pytest
```

Verify the environment:

```bash
python --version
```

```bash
python -c "import elftools; print('pyelftools: OK')"
```

```bash
python -c "import capstone; print('capstone: OK')"
```

```bash
python -c "import pytest; print('pytest: OK')"
```

Then:

```bash
./run.sh --version
./run.sh ./start --mode 3
make check
```

---

# Testing

Run syntax checks:

```bash
python -m py_compile src/elfscope/analysis.py
python -m py_compile src/elfscope/cli.py
```

Run the test suite:

```bash
make check
```

Recommended test coverage includes:

```text
ELF32
ELF64
static ELF
dynamically linked ELF
stripped ELF
unstripped ELF
PIE executable
non-PIE executable
hardened executable
minimal ELF
malformed ELF fixtures
```

Small handcrafted ELF samples are particularly useful because they expose assumptions that may remain invisible when testing only against large system binaries.

---

# Project Structure

```text
elfscope/
├── 📁 docs/
│   ├── design.md
│   └── research.md
│
├── 📁 examples/
│   ├── hello.c
│   ├── Makefile
│   └── README.md
│
├── 📁 packaging/
│
├── 📁 scripts/
│
├── 📁 src/
│   └── elfscope/
│       ├── __init__.py
│       ├── __main__.py
│       ├── analysis.py
│       └── cli.py
│
├── 📁 tests/
│   ├── test_analysis.py
│   └── test_cli.py
│
├── CHANGELOG.md
├── CONTRIBUTING.md
├── LICENSE
├── Makefile
├── pyproject.toml
├── README.md
├── run.sh
└── SECURITY.md
```

---

# Architecture

ELFscope is intentionally divided into analysis and presentation layers.

```text
                 ┌─────────────────────┐
                 │      ELF file       │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │   Analysis Engine   │
                 │                     │
                 │ ELF parsing         │
                 │ Sections            │
                 │ Segments             │
                 │ Symbols              │
                 │ Relocations          │
                 │ Dynamic information  │
                 │ Notes                │
                 │ Security properties  │
                 │ Triage signals       │
                 └──────────┬──────────┘
                            │
                ┌───────────┴───────────┐
                │                       │
                ▼                       ▼
        ┌───────────────┐       ┌───────────────┐
        │ CLI Renderer  │       │ Report Output │
        │               │       │               │
        │ Terminal      │       │ JSON          │
        │ Quick/Deep/   │       │ Markdown      │
        │ Full          │       │               │
        └───────────────┘       └───────────────┘
```

The separation allows the analysis engine to remain reusable independently of the terminal interface.

---

# Dependencies

| Package             | Status      | Purpose            |
| ------------------- | ----------- | ------------------ |
| `python`            | Required    | Runtime            |
| `python-pyelftools` | Required    | ELF/DWARF parsing  |
| `python-capstone`   | Optional    | Static disassembly |
| `python-pytest`     | Development | Test suite         |

ELFscope deliberately keeps the core dependency set small.

A full reverse-engineering suite is not required.

---

# Scope

ELFscope currently focuses on ELF binaries used on Linux and Unix-like systems.

The project does not attempt to provide:

* decompilation;
* full-featured disassembly;
* debugging;
* dynamic tracing;
* sandboxing;
* exploit development;
* remote scanning;
* process injection;
* binary patching;
* automated exploitation.

These capabilities belong to specialised tools and are deliberately outside the core scope.

---

# Limitations

Static analysis cannot completely describe runtime behaviour.

A binary may behave differently because of:

* environment variables;
* configuration;
* dynamically loaded libraries;
* runtime-generated code;
* network conditions;
* user interaction;
* kernel behaviour;
* anti-analysis mechanisms.

ELFscope should therefore be treated as a **triage and investigation-preparation tool**, not a final behavioural verdict engine.

---

# Defensive Use

ELFscope is intended for legitimate defensive and research activities such as:

* malware triage;
* software inspection;
* reverse-engineering preparation;
* binary hardening review;
* incident response;
* forensic analysis;
* software supply-chain inspection;
* educational ELF research.

Only analyse binaries you are authorised to inspect.

---

# Roadmap

## v0.2.x

Current focus:

```text
✅ Multi-level CLI analysis
✅ Quick / Deep / Full modes
✅ Extended ELF metadata
✅ Program headers
✅ Section analysis
✅ Section-to-segment mapping
✅ Dynamic information
✅ Symbols
✅ Relocations
✅ ELF notes
✅ Hashes
✅ Entropy
✅ Strings
✅ Hardening checks
✅ Entry-point inspection
✅ Structural triage
✅ JSON reports
✅ Markdown reports
✅ Optional disassembly support
```

## Future Work

Potential future improvements include:

```text
🔬 richer relocation analysis
🧠 improved symbol classification
📝 deeper DWARF inspection
🔐 expanded GNU property analysis
🎯 improved entry-point analysis
🧮 architecture-aware heuristics
🧩 stronger anomaly detection
📊 versioned JSON schemas
🔌 extensible analysis rules
⚙️ performance improvements for large binaries
```

Future features should preserve the project's central principle:

> **Understand the ELF before diving deeper.**

---

# Contributing

Contributions are welcome.

Useful contributions include:

* ELF parser improvements;
* architecture support;
* test fixtures;
* analysis rules;
* false-positive reduction;
* malformed-ELF handling;
* documentation;
* reporting improvements;
* performance improvements.

Please read:

```text
CONTRIBUTING.md
SECURITY.md
```

before submitting changes.

---

# References

* GNU Binutils
  https://sourceware.org/binutils/

* GNU `readelf`
  https://sourceware.org/binutils/docs/binutils/readelf.html

* Linux ELF specification
  https://man7.org/linux/man-pages/man5/elf.5.html

* pyelftools
  https://github.com/eliben/pyelftools

* Capstone
  https://www.capstone-engine.org/

---

# License

MIT License.

See [`LICENSE`](LICENSE).

---

<div align="center">

## 🔬 ELFscope v0.2.0

**Static ELF Triage for Defensive Reverse Engineering**

`inspect → understand → investigate`

</div>
