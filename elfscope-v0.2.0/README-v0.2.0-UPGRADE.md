# ELFscope v0.2.0 upgrade

This upgrade makes ELFscope a mode-driven static ELF triage workstation.

## Modes

1. Quick triage
2. Deep ELF analysis
3. Full static analysis

Interactive use:

```bash
./run.sh ./start
```

Non-interactive use:

```bash
./run.sh ./start --mode 1
./run.sh ./start --mode 2
./run.sh ./start --mode 3
```

For full entry-point disassembly, install the optional Capstone binding on Arch:

```bash
sudo pacman -S python-capstone
```

The project remains static. It does not execute the analysed ELF.
