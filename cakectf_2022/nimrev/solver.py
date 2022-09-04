#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./chall"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

cmd = """
	b *NimMainModule+459
	c
    x/s $rsi+0x10
"""
p = gdb.debug(chall,cmd)

sleep(0.2)
p.sendline(b"hoge")

p.interactive()
