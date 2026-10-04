# Manual fixture

This directory contains a small benign C program for checking ELFscope output.

```bash
make
../run.sh ./hello
make hardened
../run.sh ./hello-hardened
```

The `hardened` target uses common compiler and linker hardening options so the reports can be compared.
