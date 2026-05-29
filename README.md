# SiktDec — x86-64 ELF Decompiler

> Turns compiled machine code back into readable pseudo-C.

## What it does
- Parses 64-bit ELF headers
- Disassembles x86-64 instructions
- Handles REX prefixes and two-byte opcodes
- Lifts assembly to pseudo-C

## Quick Start
git clone https://github.com/CoSpiky/siktdec.git
cd siktdec
python3 siktdec.py /bin/ls

## Requirements
Python 3.8+. No dependencies.

## License
MIT
