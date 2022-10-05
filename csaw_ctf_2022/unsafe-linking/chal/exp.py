#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./unsafe-linking"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b main
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

def create_note(index: int, size: int, buf):
    p.recvuntil(">")
    p.sendline("1")
    p.recvuntil("0/1")
    p.sendline("0")
    p.sendlineafter("?", str(index))
    p.sendlineafter("?", str(size))
    p.sendlineafter(":", buf)

def delete_note(index: int):
    p.recvuntil(">")
    p.sendline("2")
    p.sendlineafter("?", str(index))

def leak_address(index: int):
    p.recvuntil(">")
    p.sendline("1")
    p.recvuntil("0/1")
    p.sendline("1")
    p.sendlineafter("?", str(index))
    p.sendlineafter(":", "SECRET")
    p.recvuntil(">")
    p.sendline("3")
    p.sendlineafter("?", str(index))



p.interactive()
