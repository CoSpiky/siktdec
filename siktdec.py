#!/usr/bin/env python3
"""
SiktDec v0.1 — x86-64 ELF Decompiler
Turns machine code back into readable pseudo-C.
Educational tool. Not Ghidra. Not yet.
"""
import sys, struct
from dataclasses import dataclass
from typing import List, Optional

ELF_MAGIC = b'\x7fELF'
ELF_CLASS_64 = 2
EM_X86_64 = 62

REGISTERS = {
    0: 'rax', 1: 'rcx', 2: 'rdx', 3: 'rbx',
    4: 'rsp', 5: 'rbp', 6: 'rsi', 7: 'rdi',
    8: 'r8', 9: 'r9', 10: 'r10', 11: 'r11',
    12: 'r12', 13: 'r13', 14: 'r14', 15: 'r15'
}

OPCODES = {
    0x50: ('push', 'rax'), 0x51: ('push', 'rcx'), 0x52: ('push', 'rdx'),
    0x53: ('push', 'rbx'), 0x54: ('push', 'rsp'), 0x55: ('push', 'rbp'),
    0x56: ('push', 'rsi'), 0x57: ('push', 'rdi'),
    0x58: ('pop', 'rax'), 0x59: ('pop', 'rcx'), 0x5A: ('pop', 'rdx'),
    0x5B: ('pop', 'rbx'), 0x5C: ('pop', 'rsp'), 0x5D: ('pop', 'rbp'),
    0x5E: ('pop', 'rsi'), 0x5F: ('pop', 'rdi'),
    0x90: ('nop', ''), 0xC3: ('ret', ''),
    0xE9: ('jmp', 'rel32'), 0xEB: ('jmp', 'rel8'),
    0x74: ('je', 'rel8'), 0x75: ('jne', 'rel8'),
    0xB8: ('mov', 'rax, imm32'), 0xB9: ('mov', 'rcx, imm32'),
    0xBA: ('mov', 'rdx, imm32'), 0xBB: ('mov', 'rbx, imm32'),
    0xBF: ('mov', 'rdi, imm32'), 0xBE: ('mov', 'rsi, imm32'),
    0x48: ('REX.W', 'prefix'),
    0x89: ('mov', 'rm, r'), 0x8B: ('mov', 'r, rm'),
    0x01: ('add', 'rm, r'), 0x29: ('sub', 'rm, r'),
    0x85: ('test', 'r, rm'), 0x39: ('cmp', 'rm, r'),
    0x0F: ('two_byte', 'escape'),
}

TWO_BYTE_OPS = {
    0x84: ('je', 'rel32'), 0x85: ('jne', 'rel32'),
    0x8D: ('lea', 'r, m'), 0xB6: ('movzx', 'r, byte'),
}

@dataclass
class ELFHeader:
    entry_point: int
    program_header_offset: int
    section_header_offset: int
    program_header_count: int
    section_header_count: int
    shstrtab_index: int

@dataclass
class Section:
    name: str
    addr: int
    offset: int
    size: int
    data: bytes

@dataclass
class Instruction:
    address: int
    mnemonic: str
    operands: str
    length: int

class ELFParser:
    def __init__(self, filepath):
        self.filepath = filepath
        self.data = open(filepath, 'rb').read()
        self.header = None
        self.sections = []
        self.text_section = None

    def parse(self):
        if self.data[:4] != ELF_MAGIC:
            raise ValueError("Not a valid ELF file")
        elf_class = self.data[4]
        if elf_class != ELF_CLASS_64:
            raise ValueError("Only 64-bit ELF supported")
        
        entry = struct.unpack_from('<Q', self.data, 24)[0]
        phoff = struct.unpack_from('<Q', self.data, 32)[0]
        shoff = struct.unpack_from('<Q', self.data, 40)[0]
        phentsize = struct.unpack_from('<H', self.data, 54)[0]
        phnum = struct.unpack_from('<H', self.data, 56)[0]
        shentsize = struct.unpack_from('<H', self.data, 58)[0]
        shnum = struct.unpack_from('<H', self.data, 60)[0]
        shstrndx = struct.unpack_from('<H', self.data, 62)[0]
        
        self.header = ELFHeader(entry, phoff, shoff, phnum, shnum, shstrndx)
        self._parse_sections(shoff, shnum, shentsize, shstrndx)
        
        for sec in self.sections:
            if sec.name == '.text':
                self.text_section = sec
                return
        raise ValueError(".text section not found")

    def _parse_sections(self, shoff, shnum, shentsize, shstrndx):
        shstr_offset = struct.unpack_from('<Q', self.data, shoff + shstrndx * shentsize + 24)[0]
        shstr_size = struct.unpack_from('<Q', self.data, shoff + shstrndx * shentsize + 32)[0]
        shstrtab = self.data[shstr_offset:shstr_offset + shstr_size]
        
        for i in range(shnum):
            sh_offset = shoff + i * shentsize
            sh_name_idx = struct.unpack_from('<I', self.data, sh_offset)[0]
            sh_addr = struct.unpack_from('<Q', self.data, sh_offset + 16)[0]
            sh_file_offset = struct.unpack_from('<Q', self.data, sh_offset + 24)[0]
            sh_size = struct.unpack_from('<Q', self.data, sh_offset + 32)[0]
            
            name_end = shstrtab.find(b'\0', sh_name_idx)
            name = shstrtab[sh_name_idx:name_end].decode('ascii', errors='replace')
            section_data = self.data[sh_file_offset:sh_file_offset + sh_size]
            self.sections.append(Section(name, sh_addr, sh_file_offset, sh_size, section_data))

class Disassembler:
    def __init__(self, code_bytes: bytes, base_address: int = 0):
        self.code = code_bytes
        self.base = base_address
        self.pos = 0

    def disassemble(self) -> List[Instruction]:
        instructions = []
        self.pos = 0
        while self.pos < len(self.code):
            addr = self.base + self.pos
            instr = self._decode_one()
            if instr:
                instr.address = addr
                instructions.append(instr)
            else:
                unknown_byte = self.code[self.pos]
                instructions.append(Instruction(addr, 'db', f'0x{unknown_byte:02x}', 1))
                self.pos += 1
        return instructions

    def _decode_one(self) -> Optional[Instruction]:
        if self.pos >= len(self.code):
            return None
        start_pos = self.pos
        byte0 = self.code[self.pos]
        self.pos += 1
        
        rex_w = False
        if byte0 == 0x48:
            rex_w = True
            if self.pos >= len(self.code):
                return None
            byte0 = self.code[self.pos]
            self.pos += 1
        
        if byte0 == 0x0F:
            if self.pos >= len(self.code):
                return None
            byte1 = self.code[self.pos]
            self.pos += 1
            if byte1 in TWO_BYTE_OPS:
                mnemonic, op_type = TWO_BYTE_OPS[byte1]
                operands = self._parse_operands(op_type)
                return Instruction(0, mnemonic, operands, self.pos - start_pos)
            return Instruction(0, '???', f'0x{byte1:02x}', self.pos - start_pos)
        
        if byte0 in OPCODES:
            mnemonic, op_type = OPCODES[byte0]
            if op_type == 'prefix':
                return self._decode_one()
            elif op_type == 'rax, imm32':
                imm = struct.unpack_from('<I', self.code, self.pos)[0]
                self.pos += 4
                return Instruction(0, 'mov', f'rax, 0x{imm:x}', self.pos - start_pos)
            elif op_type == 'rel32':
                offset = struct.unpack_from('<i', self.code, self.pos)[0]
                self.pos += 4
                target = self.base + self.pos + offset
                return Instruction(0, mnemonic, f'0x{target:x}', self.pos - start_pos)
            elif op_type == 'rel8':
                offset = struct.unpack_from('<b', self.code, self.pos)[0]
                self.pos += 1
                target = self.base + self.pos + offset
                return Instruction(0, mnemonic, f'0x{target:x}', self.pos - start_pos)
            else:
                return Instruction(0, mnemonic, '', self.pos - start_pos)
        return None

    def _parse_operands(self, op_type: str) -> str:
        if op_type in ('rel32', 'rel8'):
            if op_type == 'rel32':
                offset = struct.unpack_from('<i', self.code, self.pos)[0]
                self.pos += 4
            else:
                offset = struct.unpack_from('<b', self.code, self.pos)[0]
                self.pos += 1
            target = self.base + self.pos + offset
            return f'0x{target:x}'
        return ''

class Decompiler:
    def __init__(self, instructions: List[Instruction]):
        self.instructions = instructions

    def decompile(self) -> str:
        lines = []
        lines.append("// SiktDec v0.1 — Decompiled output")
        lines.append("// Educational purposes only\n")
        lines.append("void main() {")
        
        for instr in self.instructions:
            prefix = "    "
            if instr.mnemonic == 'push':
                lines.append(f"{prefix}// push {instr.operands}")
            elif instr.mnemonic == 'pop':
                lines.append(f"{prefix}// pop {instr.operands}")
            elif instr.mnemonic == 'mov':
                lines.append(f"{prefix}{instr.operands};")
            elif instr.mnemonic == 'add':
                lines.append(f"{prefix}// {instr.operands}")
            elif instr.mnemonic == 'sub':
                lines.append(f"{prefix}// {instr.operands}")
            elif instr.mnemonic == 'jmp':
                lines.append(f"{prefix}goto {instr.operands};")
            elif instr.mnemonic == 'je':
                lines.append(f"{prefix}if (zero) goto {instr.operands};")
            elif instr.mnemonic == 'jne':
                lines.append(f"{prefix}if (!zero) goto {instr.operands};")
            elif instr.mnemonic == 'ret':
                lines.append(f"{prefix}return;")
            elif instr.mnemonic == 'nop':
                lines.append(f"{prefix}// nop")
            elif instr.mnemonic == 'db':
                lines.append(f"{prefix}// byte {instr.operands}")
            else:
                lines.append(f"{prefix}{instr.mnemonic} {instr.operands};")
        
        lines.append("}")
        return '\n'.join(lines)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 siktdec.py <elf_file>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    print(f"\n  ╔══════════════════════════════════════╗")
    print(f"  ║   SiktDec v0.1 — ELF Decompiler     ║")
    print(f"  ╚══════════════════════════════════════╝\n")
    
    parser = ELFParser(filepath)
    parser.parse()
    
    print(f"  [+] ELF parsed")
    print(f"  [+] Entry point: 0x{parser.header.entry_point:x}")
    print(f"  [+] .text section: {parser.text_section.size} bytes at 0x{parser.text_section.addr:x}")
    
    disasm = Disassembler(parser.text_section.data, parser.text_section.addr)
    instructions = disasm.disassemble()
    
    print(f"  [+] Disassembled {len(instructions)} instructions\n")
    print(f"  {'─' * 55}")
    print(f"  {'ADDRESS':<12} {'MNEMONIC':<10} {'OPERANDS'}")
    print(f"  {'─' * 55}")
    
    for instr in instructions[:30]:
        print(f"  0x{instr.address:08x}  {instr.mnemonic:<10} {instr.operands}")
    
    if len(instructions) > 30:
        print(f"  ... ({len(instructions) - 30} more instructions)")
    print(f"  {'─' * 55}\n")
    
    decomp = Decompiler(instructions[:50])
    print(decomp.decompile())
    print()

if __name__ == '__main__':
    main()
