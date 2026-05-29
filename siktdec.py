#!/usr/bin/env python3
"""SiktDec v0.1 — x86-64 ELF Decompiler. Educational tool."""
import sys, struct

ELF_MAGIC = b'\x7fELF'
ELF_CLASS_64 = 2

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 siktdec.py <elf_file>")
        sys.exit(1)
    
    with open(sys.argv[1], 'rb') as f:
        data = f.read()
    
    if data[:4] != ELF_MAGIC:
        print("Not a valid ELF file")
        sys.exit(1)
    
    if data[4] != ELF_CLASS_64:
        print("Only 64-bit ELF supported")
        sys.exit(1)
    
    entry = struct.unpack_from('<Q', data, 24)[0]
    print(f"\n  ╔══════════════════════════════╗")
    print(f"  ║   SiktDec v0.1              ║")
    print(f"  ║   x86-64 ELF Decompiler     ║")
    print(f"  ╚══════════════════════════════╝\n")
    print(f"  [+] File: {sys.argv[1]}")
    print(f"  [+] Entry point: 0x{entry:x}")
    print(f"  [+] Size: {len(data)} bytes")
    print(f"\n  [*] Full decompiler coming soon.")
    print(f"  [*] github.com/CoSpiky/siktdec\n")

if __name__ == '__main__':
    main()
